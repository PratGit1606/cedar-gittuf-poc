package gcedar

import "strings"

// GlobMatch reports whether ref matches pattern, where `*` matches any
// sequence (including `/`) and every other character is literal. This is the
// POC's assumed semantics, identical to Cedar's `like`.
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

func roleOK(member string, roles map[string]Role, have map[string]bool) bool {
	if !strings.HasPrefix(member, "@") {
		return have[member]
	}
	r := roles[member[1:]]
	n := 0
	for _, m := range r.Members {
		if roleOK(m, roles, have) {
			n++
		}
	}
	return n >= r.Threshold
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ReferenceAllows is a direct (no Cedar, no expansion) implementation of the
// POC's semantics, ported from ../gcedar/reference.py. It is a sanity check
// for the Go port, not an oracle for gittuf.
func ReferenceAllows(doc *Doc, f Facts) bool {
	approvals := toSet(f.Approvals)
	if doc.ForbidSelfApproval && approvals[f.Author] {
		return false
	}
	for _, rule := range doc.Rules {
		if GlobMatch(rule.Pattern, f.Ref) {
			have := toSet(f.Signers)
			if rule.source() == "approvals" {
				have = approvals
			}
			n := 0
			for _, m := range rule.Members {
				if roleOK(m, doc.Roles, have) {
					n++
				}
			}
			return n >= rule.Threshold
		}
	}
	return doc.defaultEffect() == "allow"
}
