// Package gcedar compiles gittuf-style JSON delegations into Cedar policies
// and decides pushes with them: Compile (this file) turns a Doc into Cedar,
// the Verifier's Phase A (phasea.go) turns signatures into facts, and the
// Evaluator's Phase B (phaseb.go) asks Cedar for the decision.
package gcedar

import (
	"fmt"
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

	// Strict mode only; see extensions.go.
	Except  []string        `json:"except,omitempty"`
	Window  *Window         `json:"window,omitempty"`
	Require map[string]bool `json:"require,omitempty"`
}

// Doc is a delegation document.
type Doc struct {
	Principals         map[string]string `json:"principals"`
	Roles              map[string]Role   `json:"roles,omitempty"`
	Rules              []Rule            `json:"rules"`
	Default            string            `json:"default,omitempty"` // "allow" or "deny" (default)
	ForbidSelfApproval bool              `json:"forbid_self_approval,omitempty"`
	Forbid             []Forbid          `json:"forbid,omitempty"` // strict mode only; see extensions.go
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

// DelegationError is a document the compiler refuses.
type DelegationError struct{ Msg string }

func (e *DelegationError) Error() string { return e.Msg }

// checkRuleNames rejects two rules with the same name.
func checkRuleNames(rules []Rule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Name] {
			return errf("duplicate rule name %s; give each rule a unique name", r.Name)
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

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
	Warnings []string // e.g. rules gittuf accepts that can never be met

	// What the host must put in the request (see extensions.go).
	UsesNow   bool     // context.now
	HostFacts []string // boolean context facts, sorted
}

// Compile turns a delegation document into strict-mode Cedar policies.
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
		}
	}

	// Self-approval is a forbid so it overrides every permit.
	if doc.ForbidSelfApproval {
		emit("forbid", "context.approvals.contains(context.author)", PolicyMeta{Rule: "<self-approval>"})
	}
	if err := compileForbids(doc, emit); err != nil {
		return nil, err
	}
	facts := map[string]bool{}

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
		conds, err := ruleConditions(rule, facts)
		if err != nil {
			return nil, err
		}
		c.UsesNow = c.UsesNow || rule.Window != nil
		// The except is scoped like this rule's permits (this rule matches and
		// no earlier one does), so it applies only where this rule decides.
		if rule.Except != nil {
			users, err := principalList("rule "+rule.Name+": except", rule.Except, doc.Principals)
			if err != nil {
				return nil, err
			}
			emit("forbid", fmt.Sprintf("%s%s && context.signers.containsAny([%s])", match, earlier, users),
				PolicyMeta{Rule: rule.Name, Combo: append([]string{}, rule.Except...)})
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
			body := fmt.Sprintf("%s%s && context.%s.containsAll([%s])%s", match, earlier, src, users, conds)
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

	c.HostFacts = sortedKeys(facts)
	c.Schema = extendSchema(c.UsesNow, c.HostFacts)
	c.Policies = b.String()
	if c.Policies == "" {
		c.Policies = "\n" // an empty policy set is a single newline
	}
	return c, nil
}
