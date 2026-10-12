package gcedar

import (
	"strings"
	"time"
)

// GlobMatch reports whether ref matches a strict-mode pattern. The rules are
// Cedar's `like`: `*` matches any sequence including `/`, and every other
// character is literal.
func GlobMatch(pattern, ref string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == ref
	}
	if !strings.HasPrefix(ref, parts[0]) {
		return false
	}
	ref = ref[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(ref, p)
		if i < 0 {
			return false
		}
		ref = ref[i+len(p):]
	}
	return len(ref) >= len(last) && strings.HasSuffix(ref, last)
}

// witnesses lists every subset of avail that can satisfy member on its own.
func witnesses(member string, roles map[string]Role, avail map[string]bool) []map[string]bool {
	if !strings.HasPrefix(member, "@") {
		if avail[member] {
			return []map[string]bool{{member: true}}
		}
		return nil
	}
	r := roles[member[1:]]
	var out []map[string]bool
	pickDisjoint(r.Members, r.Threshold, roles, avail, map[string]bool{}, func(used map[string]bool) {
		out = append(out, copySet(used))
	})
	return out
}

// pickDisjoint calls found with the union of witnesses for every way to meet
// need of members using pairwise-disjoint witnesses drawn from avail.
func pickDisjoint(members []string, need int, roles map[string]Role, avail, used map[string]bool, found func(map[string]bool)) {
	if need == 0 {
		found(used)
		return
	}
	if len(members) < need {
		return
	}
	pickDisjoint(members[1:], need, roles, avail, used, found) // skip members[0]
	free := map[string]bool{}
	for p := range avail {
		if !used[p] {
			free[p] = true
		}
	}
	for _, w := range witnesses(members[0], roles, free) {
		next := copySet(used)
		for p := range w {
			next[p] = true
		}
		pickDisjoint(members[1:], need-1, roles, avail, next, found)
	}
}

func copySet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// thresholdMet reports whether have meets k-of-members with every chosen member
// met by its own signers (no signer counts toward two members).
func thresholdMet(members []string, k int, roles map[string]Role, have map[string]bool) bool {
	met := false
	pickDisjoint(members, k, roles, have, map[string]bool{}, func(map[string]bool) { met = true })
	return met
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ReferenceAllows decides a strict-mode request by backtracking search, with
// no Cedar and no threshold expansion. TestDifferential checks the compiler
// against it. It is not a model of gittuf.
func ReferenceAllows(doc *Doc, f Facts) bool {
	approvals := toSet(f.Approvals)
	if doc.ForbidSelfApproval && approvals[f.Author] {
		return false
	}
	signed := toSet(f.Signers)
	for _, fb := range doc.Forbid {
		if GlobMatch(fb.Pattern, f.Ref) && anyIn(fb.Principals, signed) {
			return false
		}
	}
	for _, rule := range doc.Rules {
		if GlobMatch(rule.Pattern, f.Ref) {
			if anyIn(rule.Except, signed) || !inWindow(rule.Window, f.Now) {
				return false
			}
			for name := range rule.Require {
				if !f.Host[name] {
					return false
				}
			}
			have := toSet(f.Signers)
			if rule.source() == "approvals" {
				have = approvals
			}
			return thresholdMet(rule.Members, rule.Threshold, doc.Roles, have)
		}
	}
	return doc.defaultEffect() == "allow"
}

func anyIn(xs []string, set map[string]bool) bool {
	for _, x := range xs {
		if set[x] {
			return true
		}
	}
	return false
}

// inWindow compares at Cedar's millisecond precision; both bounds inclusive.
func inWindow(w *Window, now time.Time) bool {
	if w == nil {
		return true
	}
	ms := now.UnixMilli()
	if w.NotBefore != "" {
		if t, _ := time.Parse(time.RFC3339, w.NotBefore); ms < t.UnixMilli() {
			return false
		}
	}
	if w.NotAfter != "" {
		if t, _ := time.Parse(time.RFC3339, w.NotAfter); ms > t.UnixMilli() {
			return false
		}
	}
	return true
}
