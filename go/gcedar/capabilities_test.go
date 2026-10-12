package gcedar

import (
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cedar-policy/cedar-go"
)

// One test per row of CAPABILITIES.md. Every row evaluates compiler output,
// which NewEvaluator validates against its schema, except the
// schema-validation row, which feeds the validator broken policies on purpose.

func gittufCompiled(t *testing.T, doc *Doc) *Compiled {
	t.Helper()
	c, err := CompileMode(doc, ModeGittuf)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func keyed(names ...string) map[string]string {
	m := map[string]string{}
	for _, n := range names {
		m[n] = n // gittuf mode: key ID = name, for readability
	}
	return m
}

// Row: nested roles (compiler output, strict mode).
func TestCapNestedRoles(t *testing.T) {
	doc := &Doc{Principals: keyed("alice", "bob", "carol", "dave", "erin"),
		Roles: map[string]Role{
			"lead": {Threshold: 1, Members: []string{"alice", "bob"}},
			"team": {Threshold: 2, Members: []string{"carol", "dave", "erin"}}},
		Rules:   []Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"@lead", "@team"}}},
		Default: "deny"}
	c, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(doc, c)
	if err != nil {
		t.Fatal(err)
	}
	for signers, want := range map[string]bool{"alice carol dave": true, "carol dave erin": false, "alice bob": false, "bob dave erin": true} {
		f := Facts{Ref: "refs/heads/main", Pusher: "x", Author: "x", Signers: strings.Fields(signers)}
		if got := ev.Decide(f).Allowed; got != want {
			t.Errorf("%s: got %v want %v", signers, got, want)
		}
	}
}

// Row: glob patterns (compiler output, gittuf mode; `?` needs Phase A).
func TestCapGlobPatterns(t *testing.T) {
	doc := &Doc{Principals: keyed("alice"), Rules: []Rule{
		{Name: "heads", Pattern: "refs/heads/feature/*", Threshold: 1, Members: []string{"alice"}},
		{Name: "rel", Pattern: "refs/heads/rel-[ab]", Threshold: 1, Members: []string{"alice"}},
		{Name: "v", Pattern: "refs/heads/v?", Threshold: 1, Members: []string{"alice"}}}}
	c := gittufCompiled(t, doc)
	ev, err := NewEvaluator(doc, c)
	if err != nil {
		t.Fatal(err)
	}
	for ref, protected := range map[string]bool{
		"refs/heads/feature/a/b": true, "refs/heads/rel-a": true, "refs/heads/rel-c": false,
		"refs/heads/v1": true, "refs/heads/v10": false, "refs/heads/main": false} {
		f := Facts{Ref: ref, MatchedPatterns: MatchedPatterns(doc, ref)} // nobody signed
		if got := !ev.Decide(f).Allowed; got != protected {
			t.Errorf("%s: protected=%v want %v", ref, got, protected)
		}
	}
}

// Row: k-of-n thresholds (compiler output, gittuf mode): allowed iff >= 2 of 3.
func TestCapThreshold(t *testing.T) {
	doc := &Doc{Principals: keyed("a", "b", "c"),
		Rules: []Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"a", "b", "c"}}}}
	ev, err := NewEvaluator(doc, gittufCompiled(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subsets([]string{"a", "b", "c"}) {
		if got := ev.Decide(Facts{Ref: "refs/heads/main", Signers: s}).Allowed; got != (len(s) >= 2) {
			t.Errorf("%v: got %v", s, got)
		}
	}
}

// strictEval compiles doc in strict mode and returns its evaluator.
func strictEval(t *testing.T, doc *Doc) *Evaluator {
	t.Helper()
	c, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(doc, c)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// Row: forbid overrides permits (compiler output, strict mode). mallory is a
// member of main's rule, but a top-level forbid on refs/heads/* wins over the
// permit, and the decision names the forbid.
func TestCapForbidOverridesPermit(t *testing.T) {
	doc := &Doc{Principals: keyed("alice", "mallory"),
		Rules:  []Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 1, Members: []string{"alice", "mallory"}}},
		Forbid: []Forbid{{Name: "no-mallory", Pattern: "refs/heads/*", Principals: []string{"mallory"}}}}
	ev := strictEval(t, doc)
	d := ev.Decide(Facts{Ref: "refs/heads/main", Signers: []string{"mallory"}})
	if d.Allowed || len(d.Reasons) != 1 || d.Reasons[0].Kind != "forbid" || d.Reasons[0].Rule != "no-mallory" {
		t.Errorf("mallory alone: %+v; want deny by forbid no-mallory", d)
	}
	if d := ev.Decide(Facts{Ref: "refs/heads/main", Signers: []string{"alice", "mallory"}}); d.Allowed {
		t.Error("alice+mallory: the forbid must win over alice's permit")
	}
	if d := ev.Decide(Facts{Ref: "refs/heads/main", Signers: []string{"alice"}}); !d.Allowed {
		t.Error("alice alone should be allowed")
	}
	// Control: without the forbid, mallory's permit allows.
	doc.Forbid = nil
	if d := strictEval(t, doc).Decide(Facts{Ref: "refs/heads/main", Signers: []string{"mallory"}}); !d.Allowed {
		t.Error("control: without the forbid mallory should be allowed")
	}
}

// Row: rule exceptions (strict mode). The ref exception comes from first-match
// order: main's rule is first, so the broad rule's permits carry !(main). The
// principal exception is "except" on the broad rule.
func TestCapRuleExceptions(t *testing.T) {
	doc := &Doc{Principals: keyed("alice", "bob", "carol", "mallory"), Rules: []Rule{
		{Name: "main", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"bob", "carol"}},
		{Name: "heads", Pattern: "refs/heads/*", Threshold: 1, Members: []string{"alice", "mallory"}, Except: []string{"mallory"}}}}
	ev := strictEval(t, doc)
	cases := []struct {
		ref     string
		signers []string
		want    bool
	}{
		{"refs/heads/feature", []string{"alice"}, true},
		{"refs/heads/main", []string{"alice"}, false}, // the case gittuf allows (FINDINGS Finding 1)
		{"refs/heads/main", []string{"bob", "carol"}, true},
		{"refs/heads/feature", []string{"alice", "mallory"}, false}, // excepted principal signed
		{"refs/heads/feature", []string{"mallory"}, false},
		{"refs/heads/main", []string{"bob", "carol", "mallory"}, true}, // heads' except does not reach main
	}
	for _, c := range cases {
		if got := ev.Decide(Facts{Ref: c.ref, Signers: c.signers}).Allowed; got != c.want {
			t.Errorf("%s %v: got %v want %v", c.ref, c.signers, got, c.want)
		}
	}
	if d := ev.Decide(Facts{Ref: "refs/heads/feature", Signers: []string{"alice", "mallory"}}); len(d.Reasons) != 1 || d.Reasons[0].Rule != "heads" || d.Reasons[0].Kind != "forbid" {
		t.Errorf("reasons should name heads' except: %+v", d.Reasons)
	}
}

// Row: time windows (compiler output, strict mode): main may only change
// from 2026-01-05 until the start of a freeze, inclusive. now is a host fact.
func TestCapTimeWindow(t *testing.T) {
	doc := &Doc{Principals: keyed("alice"), Rules: []Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 1,
		Members: []string{"alice"}, Window: &Window{NotBefore: "2026-01-05T00:00:00Z", NotAfter: "2026-12-19T23:59:59Z"}}}}
	ev := strictEval(t, doc)
	for when, want := range map[string]bool{
		"2026-01-04T23:59:59Z":     false, // before
		"2026-01-05T00:00:00Z":     true,  // not_before is inclusive
		"2026-10-07T12:00:00Z":     true,
		"2026-12-19T23:59:59Z":     true,  // not_after is inclusive
		"2026-12-20T00:00:00.001Z": false, // freeze
	} {
		now, _ := time.Parse(time.RFC3339Nano, when)
		if got := ev.Decide(Facts{Ref: "refs/heads/main", Signers: []string{"alice"}, Now: now}).Allowed; got != want {
			t.Errorf("%s: got %v want %v", when, got, want)
		}
	}
	if d := ev.Decide(Facts{Ref: "refs/heads/main", Signers: []string{"alice"}}); d.Allowed || len(d.Errors) == 0 {
		t.Errorf("no clock: %+v; want deny with an error", d)
	}
}

// Row: attribute-based conditions (compiler output, strict mode): immutable
// tags (host fact new_ref), and main needs a fast-forward with CI passed.
func TestCapAttributeConditions(t *testing.T) {
	doc := &Doc{Principals: keyed("alice"), Rules: []Rule{
		{Name: "tags", Pattern: "refs/tags/*", Threshold: 1, Members: []string{"alice"}, Require: map[string]bool{"new_ref": true}},
		{Name: "main", Pattern: "refs/heads/main", Threshold: 1, Members: []string{"alice"},
			Require: map[string]bool{"fast_forward": true, "ci_passed": true}}}}
	ev := strictEval(t, doc)
	facts := func(names ...string) map[string]bool { return toSet(names) }
	cases := []struct {
		name string
		f    Facts
		want bool
	}{
		{"new tag", Facts{Ref: "refs/tags/v1", Host: facts("new_ref")}, true},
		{"move existing tag", Facts{Ref: "refs/tags/v1"}, false},
		{"main ff + CI", Facts{Ref: "refs/heads/main", Host: facts("fast_forward", "ci_passed")}, true},
		{"main force push", Facts{Ref: "refs/heads/main", Host: facts("ci_passed")}, false},
		{"main CI failed", Facts{Ref: "refs/heads/main", Host: facts("fast_forward")}, false},
	}
	for _, c := range cases {
		c.f.Signers = []string{"alice"}
		if got := ev.Decide(c.f).Allowed; got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// Row: explainable decisions. Allow names exactly the permits (rule + approver
// set) that were satisfied; deny-by-forbid names the forbid; default deny
// names nothing.
func TestCapExplainableDecisions(t *testing.T) {
	doc := &Doc{Principals: keyed("a", "b", "c"), Rules: []Rule{
		{Name: "two", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"a", "b"}},
		{Name: "c-alone", Pattern: "refs/heads/*", Threshold: 1, Members: []string{"c"}}}}
	ev, err := NewEvaluator(doc, gittufCompiled(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	d := ev.Decide(Facts{Ref: "refs/heads/main", Signers: []string{"a", "b", "c"}})
	var got []string
	for _, r := range d.Reasons {
		got = append(got, r.Rule+":"+strings.Join(r.Combo, "+"))
	}
	sort.Strings(got)
	if !d.Allowed || strings.Join(got, ",") != "c-alone:c,two:a+b" {
		t.Errorf("reasons = %v", got)
	}
	if d := ev.Decide(Facts{Ref: "refs/heads/main", Signers: []string{"a"}}); d.Allowed || len(d.Reasons) != 0 {
		t.Errorf("deny should have no reasons, got %+v", d)
	}
	// deny by forbid: see TestForgeSelfApprovalForbidden (reason <self-approval>).
}

// Row: schema validation. Typos and type errors in policies are caught
// before any request is evaluated.
func TestCapSchemaValidation(t *testing.T) {
	for _, bad := range []string{
		`permit(principal, action == Action::"write", resource) when { context.signerz.contains(User::"a") };`,
		`permit(principal, action == Action::"write", resource) when { context.signers.contains("a") };`,
		`permit(principal, action == Action::"write", resource) when { resource.nmae like "refs/*" };`,
	} {
		ps, err := cedar.NewPolicySetFromBytes("bad.cedar", []byte(bad))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := ValidatePoliciesWith(Schema, ps); err == nil {
			t.Errorf("validator accepted: %s", bad)
		}
	}
}

// Row: rule-order independence. Cedar policy sets are unordered: shuffling the
// compiled policies never changes a verdict (gittuf and strict mode; strict
// mode's first-match order is encoded inside each permit, not in the order).
func TestCapOrderIndependence(t *testing.T) {
	doc := &Doc{Principals: keyed("a", "b", "c", "d"), Default: "allow", Rules: []Rule{
		{Name: "r1", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"a", "b", "c"}},
		{Name: "r2", Pattern: "refs/heads/*", Threshold: 1, Members: []string{"d"}},
		{Name: "r3", Pattern: "*", Threshold: 2, Members: []string{"a", "d"}}}}
	rng := rand.New(rand.NewSource(3))
	refs := []string{"refs/heads/main", "refs/heads/x", "refs/tags/v1"}
	for _, mode := range []Mode{ModeGittuf, ModeStrict} {
		c, err := CompileMode(doc, mode)
		if err != nil {
			t.Fatal(err)
		}
		verdicts := func(text string) string {
			cc := *c
			cc.Policies = text
			ev, err := NewEvaluator(doc, &cc)
			if err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			for _, ref := range refs {
				for _, s := range subsets([]string{"a", "b", "c", "d"}) {
					if ev.Decide(Facts{Ref: ref, Pusher: "x", Author: "x", Signers: s}).Allowed {
						b.WriteByte('1')
					} else {
						b.WriteByte('0')
					}
				}
			}
			return b.String()
		}
		base := verdicts(c.Policies)
		lines := strings.SplitAfter(strings.TrimSuffix(c.Policies, "\n"), "\n")
		for i := 0; i < 20; i++ {
			rng.Shuffle(len(lines), func(a, b int) { lines[a], lines[b] = lines[b], lines[a] })
			text := strings.Join(lines, "")
			if !strings.HasSuffix(text, "\n") {
				text += "\n"
			}
			if verdicts(text) != base {
				t.Fatalf("%s: shuffled policy order changed a verdict", mode)
			}
		}
	}
}
