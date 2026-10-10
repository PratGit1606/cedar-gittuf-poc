package gcedar

import "strings"

// MaxLikeAlternatives bounds how many `like` patterns a bracket class may
// expand to before matching falls back to Phase A.
const MaxLikeAlternatives = 64

func classChar(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '/'
}

// LikeAlternatives rewrites an fnmatch pattern into a disjunction of Cedar
// `like` patterns when that is exact: only `*`, literals and positive bracket
// classes over [A-Za-z0-9._/-] (with a-z style ranges) are accepted. `?`,
// negated classes ([!..], [^..]), escapes and anything else return ok=false:
// `like` has no single-character wildcard, so those need Phase A matching.
func LikeAlternatives(p string, max int) (alts []string, ok bool) {
	alts = []string{""}
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '?' || r == '\\' || r == ']' || r == '"' || r < 0x20:
			return nil, false
		case r != '[':
			for j := range alts {
				alts[j] += string(r)
			}
			continue
		}
		// bracket class
		j := i + 1
		if j >= len(rs) || rs[j] == '!' || rs[j] == '^' || rs[j] == ']' {
			return nil, false
		}
		var set []rune
		for ; j < len(rs) && rs[j] != ']'; j++ {
			c := rs[j]
			if c == '-' && len(set) > 0 && j+1 < len(rs) && rs[j+1] != ']' {
				lo, hi := set[len(set)-1], rs[j+1]
				if !classChar(hi) || hi < lo {
					return nil, false
				}
				for x := lo + 1; x <= hi; x++ {
					set = append(set, x)
				}
				j++
				continue
			}
			if c != '-' && !classChar(c) {
				return nil, false
			}
			set = append(set, c)
		}
		if j >= len(rs) { // unterminated class
			return nil, false
		}
		uniq := map[rune]bool{}
		var next []string
		for _, c := range set {
			if uniq[c] {
				continue
			}
			uniq[c] = true
			for _, a := range alts {
				next = append(next, a+string(c))
			}
		}
		alts = next
		if len(alts) > max {
			return nil, false
		}
		i = j
	}
	return alts, true
}

// NeedsPhaseAMatch reports whether, in gittuf mode, a pattern must be matched
// by the host because no exact `like` rewrite exists.
func NeedsPhaseAMatch(p string) bool {
	if LikeExpressible(p) {
		return false
	}
	_, ok := LikeAlternatives(p, MaxLikeAlternatives)
	return !ok
}

func likeDisjunction(alts []string) string {
	parts := make([]string, len(alts))
	for i, a := range alts {
		parts[i] = `resource.name like "` + a + `"`
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " || ") + ")"
}
