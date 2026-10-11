package gcedar

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danwakefield/fnmatch"
)

// Mode selects the authorization semantics a document is compiled to.
type Mode string

const (
	// ModeStrict is the POC's original semantics (byte-compatible with
	// compile.py): the first matching rule decides, configurable default,
	// principals are names, roles and approvals are supported. It is the
	// "what Cedar could do" variant and is NOT gittuf's semantics.
	ModeStrict Mode = "strict"

	// ModeGittuf mirrors gittuf's verifier at the commit recorded in
	// FINDINGS.md:
	//   - every rule whose pattern matches is an alternative; any one met allows
	//   - refs no rule matches are unprotected and allowed (no default deny)
	//   - principals are identified by key ID, so a key counts at most once and
	//     principals sharing a key collapse
	//   - a member listed twice is rejected (deliberate deviation: gittuf
	//     accepts it and the rule can never be met, FINDINGS.md Finding 4)
	//   - a rule whose distinct keys are fewer than its threshold because two
	//     listed principals share a key is accepted but can never be met, as
	//     in gittuf; Compiled.Warnings reports it
	//   - patterns are fnmatch globs; positive bracket classes are rewritten to a
	//     bounded disjunction of `like` patterns; patterns with no exact `like`
	//     form (?, negated classes, escapes) are matched by the host (Phase A)
	//     and passed in as context.matchedPatterns
	// Roles, approvals and forbid_self_approval have no direct gittuf
	// equivalent and are rejected.
	ModeGittuf Mode = "gittuf"
)

// GittufSchema is the Cedar schema for ModeGittuf.
const GittufSchema = `entity User;
entity Ref { name: String };
action write appliesTo {
  principal: User,
  resource: Ref,
  context: { signers: Set<User>, matchedPatterns: Set<String> }
};
`

// CompileMode compiles doc under the given semantics.
func CompileMode(doc *Doc, mode Mode) (*Compiled, error) {
	switch mode {
	case ModeStrict, "":
		return Compile(doc)
	case ModeGittuf:
		return compileGittuf(doc)
	}
	return nil, errf("unknown mode %q", mode)
}

// LikeExpressible reports whether a gittuf (fnmatch) pattern means the same
// thing as a Cedar `like` pattern with the same text: `*` is the only special
// character in both, and with fnmatch flags 0 it matches `/` in both.
func LikeExpressible(p string) bool {
	return !strings.ContainsAny(p, `?[]\`)
}

// GittufMatch is gittuf's own pattern matcher (Delegation.Matches), applied to
// the "git:"-prefixed pattern and ref exactly as gittuf does.
func GittufMatch(pattern, ref string) bool {
	return fnmatch.Match("git:"+pattern, "git:"+ref, 0)
}

// MatchedPatterns is the Phase A computation for ModeGittuf: the patterns of
// doc that Cedar cannot match itself and that match ref.
func MatchedPatterns(doc *Doc, ref string) []string {
	var out []string
	for _, r := range doc.Rules {
		if NeedsPhaseAMatch(r.Pattern) && GittufMatch(r.Pattern, ref) {
			out = append(out, r.Pattern)
		}
	}
	return out
}

// KeyIDs maps principal names to the identities ModeGittuf uses (their key
// IDs), deduplicated. Unknown names are dropped.
func KeyIDs(doc *Doc, names []string) []string {
	m := map[string]bool{}
	for _, n := range names {
		if k, ok := doc.Principals[n]; ok && k != "" {
			m[k] = true
		}
	}
	return sortedKeys(m)
}

func gittufMatchExpr(p string) (string, error) {
	if LikeExpressible(p) {
		pat, err := likePattern(p)
		if err != nil {
			return "", err
		}
		return "resource.name like " + pat, nil
	}
	if alts, ok := LikeAlternatives(p, MaxLikeAlternatives); ok {
		return likeDisjunction(alts), nil
	}
	if strings.ContainsAny(p, "\"\\") {
		return "", errf("unsupported character in pattern %q", p)
	}
	q, err := cedarStr(p)
	if err != nil {
		return "", err
	}
	return "context.matchedPatterns.contains(" + q + ")", nil
}

func compileGittuf(doc *Doc) (*Compiled, error) {
	if len(doc.Roles) > 0 {
		return nil, errf("gittuf mode: roles have no gittuf equivalent (see CAPABILITIES.md)")
	}
	if doc.ForbidSelfApproval {
		return nil, errf("gittuf mode: forbid_self_approval has no gittuf equivalent")
	}
	if doc.Default == "deny" {
		return nil, errf("gittuf mode: unprotected refs are always allowed; use a catch-all \"*\" rule instead of default deny")
	}
	if doc.Default != "" && doc.Default != "allow" {
		return nil, errf("default must be 'allow' or 'deny'")
	}
	if err := checkRuleNames(doc.Rules); err != nil {
		return nil, err
	}

	c := &Compiled{Schema: GittufSchema, Mode: ModeGittuf}
	var b strings.Builder
	emit := func(body string, m PolicyMeta) {
		fmt.Fprintf(&b, "permit(principal, action == Action::\"write\", resource) when { %s };\n", body)
		m.Kind = "permit"
		c.Meta = append(c.Meta, m)
		c.NPermit++
	}

	var negs []string // "rule j does not match", for the unprotected-ref permit
	for _, rule := range doc.Rules {
		if rule.source() != "signers" {
			return nil, errf("gittuf mode: rule %s: only signers are supported (approvals need GitHub app identities)", rule.Name)
		}
		// Deliberate deviation: gittuf accepts duplicates (FINDINGS Finding 4).
		if err := checkDuplicates(rule.Members); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.Name, err)
		}
		// gittuf's own write-time checks (internal/tuf/v02/targets.go AddRule):
		// every listed principal exists, threshold > 0, len(list) >= threshold.
		ids := make([]string, 0, len(rule.Members))
		for _, m := range rule.Members {
			if strings.HasPrefix(m, "@") {
				return nil, errf("gittuf mode: rule %s: roles have no gittuf equivalent", rule.Name)
			}
			k, ok := doc.Principals[m]
			if !ok {
				return nil, errf("rule %s: unknown principal %s", rule.Name, m)
			}
			if k == "" {
				return nil, errf("gittuf mode: principal %s has no key ID", m)
			}
			ids = append(ids, k)
		}
		if rule.Threshold <= 0 {
			return nil, errf("rule %s: invalid threshold %d", rule.Name, rule.Threshold)
		}
		if len(ids) < rule.Threshold {
			return nil, errf("rule %s: cannot meet threshold %d with %d principals", rule.Name, rule.Threshold, len(ids))
		}
		match, err := gittufMatchExpr(rule.Pattern)
		if err != nil {
			return nil, err
		}
		negs = append(negs, "!("+match+")")

		distinct := union(pset(ids))
		if len(distinct) < rule.Threshold {
			c.Warnings = append(c.Warnings, fmt.Sprintf(
				"rule %s: %d-of-%d listed but only %d distinct keys; gittuf accepts this rule and it can never be met",
				rule.Name, rule.Threshold, len(ids), len(distinct)))
			continue
		}
		combos, err := ExpandThreshold(distinct, rule.Threshold, nil, nil)
		if err != nil {
			return nil, err
		}
		sort.Slice(combos, func(a, b int) bool { return lessPset(combos[a], combos[b]) })
		for _, combo := range combos {
			users, err := entityList("User", combo)
			if err != nil {
				return nil, err
			}
			emit(fmt.Sprintf("%s && context.signers.containsAll([%s])", match, users),
				PolicyMeta{Rule: rule.Name, Combo: append([]string{}, combo...)})
		}
	}

	// Unprotected refs: no rule matches, so gittuf returns success.
	none := strings.Join(negs, " && ")
	if none == "" {
		none = "true"
	}
	emit(none, PolicyMeta{Rule: "<unprotected>"})

	c.Policies = b.String()
	return c, nil
}
