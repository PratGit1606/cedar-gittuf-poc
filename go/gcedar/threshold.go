package gcedar

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Threshold expansion: a k-of-n requirement (members may be @roles) becomes
// the list of minimal principal sets that satisfy it, one Cedar permit each.

// MaxCombinations bounds the number of candidate approver sets a single
// threshold may expand to before the compiler refuses it.
const MaxCombinations = 200_000

// ExpansionTooLarge is returned when a threshold expands past MaxCombinations.
type ExpansionTooLarge struct{ DelegationError }

// DuplicateMemberError is returned when a threshold lists the same member twice.
// gittuf accepts such a rule and counts the member once, so the rule can never
// be met (FINDINGS.md, Finding 4). The compiler rejects it instead.
type DuplicateMemberError struct{ DelegationError }

func checkDuplicates(members []string) error {
	seen := map[string]bool{}
	for _, m := range members {
		if seen[m] {
			return &DuplicateMemberError{DelegationError{fmt.Sprintf(
				"member %s is listed more than once; each principal may count only once toward a threshold", m)}}
		}
		seen[m] = true
	}
	return nil
}

// pset is a sorted, deduplicated principal set.
type pset []string

func (s pset) key() string { return strings.Join(s, "\x00") }

func union(sets ...pset) pset {
	m := map[string]bool{}
	for _, s := range sets {
		for _, x := range s {
			m[x] = true
		}
	}
	return sortedKeys(m)
}

func subsetOf(a, b pset) bool { // both sorted
	i := 0
	for _, x := range b {
		if i < len(a) && a[i] == x {
			i++
		}
	}
	return i == len(a)
}

// lessPset orders sets lexicographically as lists, which fixes permit order.
func lessPset(a, b pset) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// minimize drops every set that is a strict superset of another.
func minimize(sets map[string]pset) []pset {
	all := make([]pset, 0, len(sets))
	for _, s := range sets {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool { return len(all[i]) < len(all[j]) })
	var kept []pset
	for _, s := range all {
		ok := true
		for _, k := range kept {
			if len(k) < len(s) && subsetOf(k, s) {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, s)
		}
	}
	return kept
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func satMul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}

func lookupRole(member string, roles map[string]Role, stack []string) (string, Role, error) {
	name := member[1:]
	for _, s := range stack {
		if s == name {
			return "", Role{}, errf("cyclic role reference: %s", strings.Join(push(stack, name), " -> "))
		}
	}
	r, ok := roles[name]
	if !ok {
		return "", Role{}, errf("unknown role @%s; define it under \"roles\"", name)
	}
	return name, r, nil
}

func push(stack []string, name string) []string {
	return append(append([]string{}, stack...), name)
}

func countChoices(member string, roles map[string]Role, stack []string) (uint64, error) {
	if !strings.HasPrefix(member, "@") {
		return 1, nil
	}
	name, r, err := lookupRole(member, roles, stack)
	if err != nil {
		return 0, err
	}
	return CountThreshold(r.Members, r.Threshold, roles, push(stack, name))
}

// CountThreshold is an upper bound on the number of candidate sets a k-of-n
// expansion generates before dedupe and minimization (saturating at MaxUint64).
func CountThreshold(members []string, threshold int, roles map[string]Role, stack []string) (uint64, error) {
	if threshold < 0 {
		return 0, nil
	}
	e := make([]uint64, threshold+1)
	e[0] = 1
	for _, m := range members {
		c, err := countChoices(m, roles, stack)
		if err != nil {
			return 0, err
		}
		for j := threshold; j > 0; j-- {
			e[j] = satAdd(e[j], satMul(e[j-1], c))
		}
	}
	return e[threshold], nil
}

func satisfyingSets(member string, roles map[string]Role, stack []string) ([]pset, error) {
	if !strings.HasPrefix(member, "@") {
		return []pset{{member}}, nil
	}
	name, r, err := lookupRole(member, roles, stack)
	if err != nil {
		return nil, err
	}
	return ExpandThreshold(r.Members, r.Threshold, roles, push(stack, name))
}

// ExpandThreshold returns all minimal principal sets satisfying threshold-of-members.
func ExpandThreshold(members []string, threshold int, roles map[string]Role, stack []string) ([]pset, error) {
	if threshold < 1 || threshold > len(members) {
		return nil, errf("threshold %d impossible with %d members; use a threshold from 1 to %d", threshold, len(members), len(members))
	}
	if err := checkDuplicates(members); err != nil {
		return nil, err
	}
	n, err := CountThreshold(members, threshold, roles, stack)
	if err != nil {
		return nil, err
	}
	if n > MaxCombinations {
		return nil, &ExpansionTooLarge{DelegationError{fmt.Sprintf(
			"%d-of-%d expands to up to %d candidate sets (limit %d); restructure the delegation or count outside Cedar",
			threshold, len(members), n, MaxCombinations)}}
	}
	per := make([][]pset, len(members))
	for i, m := range members {
		if per[i], err = satisfyingSets(m, roles, stack); err != nil {
			return nil, err
		}
	}
	out := map[string]pset{}
	combinations(len(members), threshold, func(chosen []int) {
		product(per, chosen, func(pick []pset) {
			// Each chosen member must be met by its own signers: if two
			// members' witnesses overlap, a signer would count twice.
			u := union(pick...)
			size := 0
			for _, p := range pick {
				size += len(p)
			}
			if len(u) == size {
				out[u.key()] = u
			}
		})
	})
	return minimize(out), nil
}

func combinations(n, k int, f func([]int)) {
	idx := make([]int, k)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == k {
			f(idx)
			return
		}
		for i := start; i <= n-(k-depth); i++ {
			idx[depth] = i
			rec(i+1, depth+1)
		}
	}
	rec(0, 0)
}

func product(per [][]pset, chosen []int, f func([]pset)) {
	pick := make([]pset, len(chosen))
	var rec func(d int)
	rec = func(d int) {
		if d == len(chosen) {
			f(pick)
			return
		}
		for _, s := range per[chosen[d]] {
			pick[d] = s
			rec(d + 1)
		}
	}
	rec(0)
}
