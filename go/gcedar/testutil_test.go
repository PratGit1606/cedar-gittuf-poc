package gcedar

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
)

var testPatterns = []string{"refs/heads/main", "refs/heads/*", "refs/heads/release/*", "refs/tags/*", "*"}

func sample[T any](rng *rand.Rand, pool []T, n int) []T {
	idx := rng.Perm(len(pool))[:n]
	out := make([]T, n)
	for i, j := range idx {
		out[i] = pool[j]
	}
	return out
}

// randomDoc draws a random strict-mode document (roles, globs, approvals).
func randomDoc(rng *rand.Rand) *Doc {
	names := make([]string, 6)
	principals := map[string]string{}
	for i := range names {
		names[i] = fmt.Sprintf("p%d", i)
		principals[names[i]] = strings.Repeat("00", 32)
	}
	nRoles := rng.Intn(4)
	roles := map[string]Role{}
	for i := 0; i < nRoles; i++ {
		pool := append([]string{}, names...)
		for j := i + 1; j < nRoles; j++ {
			pool = append(pool, fmt.Sprintf("@r%d", j))
		}
		ms := sample(rng, pool, 1+rng.Intn(min(4, len(pool))))
		roles[fmt.Sprintf("r%d", i)] = Role{Threshold: 1 + rng.Intn(len(ms)), Members: ms}
	}
	var rules []Rule
	for i, n := 0, 1+rng.Intn(4); i < n; i++ {
		pool := append([]string{}, names...)
		for j := 0; j < nRoles; j++ {
			pool = append(pool, fmt.Sprintf("@r%d", j))
		}
		ms := sample(rng, pool, 1+rng.Intn(min(5, len(pool))))
		src := []string{"signers", "signers", "approvals"}[rng.Intn(3)]
		rules = append(rules, Rule{Name: fmt.Sprintf("rule%d", i), Pattern: testPatterns[rng.Intn(len(testPatterns))],
			Threshold: 1 + rng.Intn(len(ms)), Members: ms, Source: src})
	}
	return &Doc{Principals: principals, Roles: roles, Rules: rules,
		Default: []string{"allow", "deny"}[rng.Intn(2)], ForbidSelfApproval: rng.Float64() < 0.3}
}

// sampleRefs derives refs from the rule patterns plus one unmatched ref.
func sampleRefs(d *Doc) []string {
	m := map[string]bool{"refs/other/zzz": true}
	for _, r := range d.Rules {
		for _, rep := range []string{"x", "a/b", ""} {
			m[strings.ReplaceAll(r.Pattern, "*", rep)] = true
		}
	}
	out := make([]string, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func subsets(items []string) [][]string {
	var out [][]string
	for mask := 0; mask < 1<<len(items); mask++ {
		var s []string
		for i, x := range items {
			if mask&(1<<i) != 0 {
				s = append(s, x)
			}
		}
		out = append(out, s)
	}
	return out
}

func sortedNames(d *Doc) []string {
	out := make([]string, 0, len(d.Principals))
	for n := range d.Principals {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
