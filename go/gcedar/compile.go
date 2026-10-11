// Package gcedar compiles gittuf-style JSON delegations into Cedar policies.
//
// It is a port of ../gcedar/compile.py. For any input document the compiled
// policy text is intended to be byte-identical to the Python compiler's output
// (see TestPythonByteCompat); error cases agree on "error vs no error" but not
// on message text.
package gcedar

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Schema is the Cedar schema every compiled policy set is written against.
const Schema = `entity User;
entity Ref { name: String };
action write appliesTo {
  principal: User,
  resource: Ref,
  context: { signers: Set<User>, approvals: Set<User>, author: User }
};
`

// MaxCombinations bounds the number of candidate approver sets a single
// threshold may expand to before the compiler refuses it.
const MaxCombinations = 200_000

// Role is a named k-of-n group. Members are principal names or "@role".
type Role struct {
	Threshold int      `json:"threshold"`
	Members   []string `json:"members"`
}

// Rule protects refs matching Pattern. In strict mode the first matching rule
// decides; in gittuf mode any matching rule may.
type Rule struct {
	Name      string   `json:"name"`
	Pattern   string   `json:"pattern"`
	Threshold int      `json:"threshold"`
	Members   []string `json:"members"`
	Source    string   `json:"source,omitempty"`
}

// Doc is a delegation document.
type Doc struct {
	Principals         map[string]string `json:"principals"`
	Roles              map[string]Role   `json:"roles,omitempty"`
	Rules              []Rule            `json:"rules"`
	Default            string            `json:"default,omitempty"` // "allow" or "deny" (default)
	ForbidSelfApproval bool              `json:"forbid_self_approval,omitempty"`
}

func (r Rule) source() string {
	if r.Source == "" {
		return "signers"
	}
	return r.Source
}

func (d *Doc) defaultEffect() string {
	if d.Default == "" {
		return "deny"
	}
	return d.Default
}

type DelegationError struct{ Msg string }

func (e *DelegationError) Error() string { return e.Msg }

type ExpansionTooLarge struct{ DelegationError }

// DuplicateMemberError is returned when a threshold lists the same member twice.
// Python's compile.py accepts this and counts the member twice; gittuf accepts
// it and counts it once (see FINDINGS.md, Finding 4). Both are surprising, so
// the Go compiler rejects it.
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

// checkRuleNames rejects two rules with the same name.
func checkRuleNames(rules []Rule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Name] {
			return errf("duplicate rule name %s", r.Name)
		}
		seen[r.Name] = true
	}
	return nil
}

// entityList renders ids as a Cedar list body: User::"a", User::"b".
func entityList(typ string, ids []string) (string, error) {
	parts := make([]string, len(ids))
	for i, id := range ids {
		q, err := cedarStr(id)
		if err != nil {
			return "", err
		}
		parts[i] = typ + "::" + q
	}
	return strings.Join(parts, ", "), nil
}

func errf(format string, a ...any) error {
	return &DelegationError{fmt.Sprintf(format, a...)}
}

func cedarStr(s string) (string, error) {
	for _, ch := range s {
		if ch < 0x20 || ch == '"' || ch == '\\' {
			return "", errf("unsupported character %q in %q", ch, s)
		}
	}
	return `"` + s + `"`, nil
}

// likePattern converts a gittuf glob into a Cedar `like` pattern. `*` is the
// only wildcard accepted, and in Cedar it matches any sequence including `/`.
func likePattern(p string) (string, error) {
	for _, ch := range p {
		if ch < 0x20 || strings.ContainsRune("\"\\?[]", ch) {
			return "", errf("unsupported glob character %q in %q", ch, p)
		}
	}
	return `"` + p + `"`, nil
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

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

// lessPset orders sets like Python's sorted(list) comparison.
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
		return "", Role{}, errf("unknown role @%s", name)
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
		return nil, errf("threshold %d impossible with %d members", threshold, len(members))
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

// PolicyMeta describes one compiled policy; index i is Cedar id "policy<i>".
type PolicyMeta struct {
	Kind  string   `json:"kind"`
	Rule  string   `json:"rule"`
	Combo []string `json:"combo,omitempty"`
}

// Compiled is the output of Compile.
type Compiled struct {
	Mode     Mode
	Schema   string
	Policies string
	Meta     []PolicyMeta
	NPermit  int
	NForbid  int
	Warnings []string // e.g. rules gittuf accepts that can never be met
}

// Compile translates a delegation document into Cedar policies.
func Compile(doc *Doc) (*Compiled, error) {
	def := doc.defaultEffect()
	if def != "allow" && def != "deny" {
		return nil, errf("default must be 'allow' or 'deny'")
	}
	if err := checkRuleNames(doc.Rules); err != nil {
		return nil, err
	}

	c := &Compiled{Schema: Schema, Mode: ModeStrict}
	var b strings.Builder
	emit := func(kind, body string, m PolicyMeta) {
		fmt.Fprintf(&b, "%s(principal, action == Action::\"write\", resource) when { %s };\n", kind, body)
		m.Kind = kind
		c.Meta = append(c.Meta, m)
		if kind == "permit" {
			c.NPermit++
		} else {
			c.NForbid++
		}
	}

	// Self-approval is a forbid so it overrides every permit.
	if doc.ForbidSelfApproval {
		emit("forbid", "context.approvals.contains(context.author)", PolicyMeta{Rule: "<self-approval>"})
	}

	// negs[j] is "rule j does not match"; strict mode's first-match-wins puts
	// every earlier rule's negation into each permit.
	var negs []string
	for _, rule := range doc.Rules {
		for _, m := range rule.Members {
			if !strings.HasPrefix(m, "@") {
				if _, ok := doc.Principals[m]; !ok {
					return nil, errf("rule %s: unknown principal %s", rule.Name, m)
				}
			}
		}
		src := rule.source()
		if src != "signers" && src != "approvals" {
			return nil, errf("rule %s: bad source %s", rule.Name, src)
		}
		pat, err := likePattern(rule.Pattern)
		if err != nil {
			return nil, err
		}
		match := "resource.name like " + pat
		earlier := ""
		for _, n := range negs {
			earlier += " && " + n
		}
		combos, err := ExpandThreshold(rule.Members, rule.Threshold, doc.Roles, nil)
		if err != nil {
			return nil, err
		}
		sort.Slice(combos, func(a, b int) bool { return lessPset(combos[a], combos[b]) })
		for _, combo := range combos {
			users, err := entityList("User", combo)
			if err != nil {
				return nil, err
			}
			body := fmt.Sprintf("%s%s && context.%s.containsAll([%s])", match, earlier, src, users)
			emit("permit", body, PolicyMeta{Rule: rule.Name, Combo: append([]string{}, combo...)})
		}
		negs = append(negs, "!("+match+")")
	}

	if def == "allow" {
		none := strings.Join(negs, " && ")
		if none == "" {
			none = "true"
		}
		emit("permit", none, PolicyMeta{Rule: "<default-allow>"})
	}

	c.Policies = b.String()
	if c.Policies == "" {
		c.Policies = "\n" // Python: "\n".join([]) + "\n"
	}
	return c, nil
}
