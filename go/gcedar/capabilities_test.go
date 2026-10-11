package gcedar

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// One test per row of CAPABILITIES.md (rows that reuse an existing test say
// so in the matrix). Rows the JSON compiler does not emit use hand-written
// Cedar; every policy set is validated against its schema with cedar-go's
// validator before evaluation.

// capSchema extends the gittuf-mode schema with the extra Phase A facts the
// capability rows need. Each extra field is a host-computed fact.
const capSchema = `entity User;
entity Ref { name: String, kind: String };
action write appliesTo {
  principal: User,
  resource: Ref,
  context: {
    signers: Set<User>,
    matchedPatterns: Set<String>,
    approvals: Set<User>,
    author: User,
    now: datetime,
    refExists: Bool,
    fastForward: Bool,
    ciPassed: Bool
  }
};
`

type capReq struct {
	ref         string
	kind        string
	signers     []string
	approvals   []string
	author      string
	now         time.Time
	refExists   bool
	fastForward bool
	ciPassed    bool
}

func capEval(t *testing.T, policies string, r capReq) (bool, []string) {
	t.Helper()
	ps, err := cedar.NewPolicySetFromBytes("cap.cedar", []byte(policies))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidatePoliciesWith(capSchema, ps); err != nil {
		t.Fatalf("validation: %v", err)
	}
	if r.kind == "" {
		r.kind = "branch"
	}
	if r.author == "" {
		r.author = "nobody"
	}
	if r.now.IsZero() {
		r.now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	}
	rid := cedar.NewEntityUID("Ref", cedar.String(r.ref))
	ents := cedar.EntityMap{rid: {UID: rid, Attributes: cedar.NewRecord(cedar.RecordMap{
		"name": cedar.String(r.ref), "kind": cedar.String(r.kind)})}}
	d, diag := cedar.Authorize(ps, ents, cedar.Request{
		Principal: cedar.NewEntityUID("User", "pusher"),
		Action:    cedar.NewEntityUID("Action", "write"),
		Resource:  rid,
		Context: cedar.NewRecord(cedar.RecordMap{
			"signers":         userSet(r.signers),
			"matchedPatterns": cedar.NewSet(),
			"approvals":       userSet(r.approvals),
			"author":          cedar.NewEntityUID("User", cedar.String(r.author)),
			"now":             types.NewDatetime(r.now),
			"refExists":       cedar.Boolean(r.refExists),
			"fastForward":     cedar.Boolean(r.fastForward),
			"ciPassed":        cedar.Boolean(r.ciPassed),
		}),
	})
	if len(diag.Errors) > 0 {
		t.Fatalf("evaluation errors: %v", diag.Errors)
	}
	var fired []string
	for _, x := range diag.Reasons {
		fired = append(fired, string(x.PolicyID))
	}
	return d == cedar.Allow, fired
}

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

// Row: forbid overrides permits. Compiled gittuf-mode rule (main: 1-of-{alice})
// plus a hand-written forbid acting like a gittuf global threshold rule:
// "any refs/heads/* update needs 2 distinct signers among all principals".
func TestCapForbidOverridesPermit(t *testing.T) {
	doc := &Doc{Principals: keyed("alice", "bob", "carol"),
		Rules: []Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 1, Members: []string{"alice"}}}}
	compiled := gittufCompiled(t, doc)
	forbidID := fmt.Sprintf("policy%d", len(compiled.Meta)) // positional IDs; the forbid comes last
	pol := compiled.Policies + `@id("global-2")
forbid(principal, action == Action::"write", resource) when { resource.name like "refs/heads/*" } unless {
  context.signers.containsAll([User::"alice", User::"bob"]) || context.signers.containsAll([User::"alice", User::"carol"]) ||
  context.signers.containsAll([User::"bob", User::"carol"]) };
`
	if ok, fired := capEval(t, pol, capReq{ref: "refs/heads/main", signers: []string{"alice"}}); ok || len(fired) != 1 || fired[0] != forbidID {
		t.Errorf("alice alone: allowed=%v fired=%v; want deny by the forbid", ok, fired)
	}
	if ok, _ := capEval(t, pol, capReq{ref: "refs/heads/main", signers: []string{"alice", "bob"}}); !ok {
		t.Error("alice+bob should pass both the rule and the floor")
	}
	if ok, _ := capEval(t, pol, capReq{ref: "refs/heads/other", signers: nil}); ok {
		t.Error("unprotected ref under the floor should be denied")
	}
}

// Row: rule exceptions ("everything under refs/heads/* except main").
func TestCapRuleExceptions(t *testing.T) {
	pol := `permit(principal, action == Action::"write", resource) when {
  resource.name like "refs/heads/*" && !(resource.name == "refs/heads/main") && context.signers.contains(User::"alice") };
permit(principal, action == Action::"write", resource) when {
  resource.name == "refs/heads/main" && context.signers.containsAll([User::"bob", User::"carol"]) };
`
	cases := []struct {
		ref     string
		signers []string
		want    bool
	}{
		{"refs/heads/feature", []string{"alice"}, true},
		{"refs/heads/main", []string{"alice"}, false}, // the case gittuf allows (FINDINGS Finding 1)
		{"refs/heads/main", []string{"bob", "carol"}, true},
	}
	for _, c := range cases {
		if ok, _ := capEval(t, pol, capReq{ref: c.ref, signers: c.signers}); ok != c.want {
			t.Errorf("%s %v: got %v want %v", c.ref, c.signers, ok, c.want)
		}
	}
}

// Row: time windows (cedar-go datetime). Freeze between two instants, and
// only during 09:00-17:00 UTC otherwise.
func TestCapTimeWindow(t *testing.T) {
	pol := `permit(principal, action == Action::"write", resource) when {
  resource.name == "refs/heads/main" && context.signers.contains(User::"alice") &&
  context.now.toTime() >= duration("9h") && context.now.toTime() < duration("17h") };
@id("freeze")
forbid(principal, action == Action::"write", resource) when {
  resource.name == "refs/heads/main" &&
  context.now >= datetime("2026-12-20T00:00:00Z") && context.now < datetime("2027-01-05T00:00:00Z") };
`
	at := func(s string) time.Time { tm, _ := time.Parse(time.RFC3339, s); return tm }
	for when, want := range map[string]bool{
		"2026-10-07T12:00:00Z": true,  // business hours
		"2026-10-07T20:00:00Z": false, // after hours
		"2026-12-22T12:00:00Z": false, // freeze window, business hours
		"2027-01-05T09:00:00Z": true,  // freeze over
	} {
		if ok, _ := capEval(t, pol, capReq{ref: "refs/heads/main", signers: []string{"alice"}, now: at(when)}); ok != want {
			t.Errorf("%s: got %v want %v", when, ok, want)
		}
	}
}

// Row: attribute-based conditions on the ref and context: immutable tags,
// no non-fast-forward on main, CI must pass on main.
func TestCapAttributeConditions(t *testing.T) {
	pol := `permit(principal, action == Action::"write", resource) when { context.signers.contains(User::"alice") };
@id("immutable-tags")
forbid(principal, action == Action::"write", resource) when { resource.kind == "tag" && context.refExists };
@id("no-force-push-main")
forbid(principal, action == Action::"write", resource) when { resource.name == "refs/heads/main" && context.refExists && !context.fastForward };
@id("ci-on-main")
forbid(principal, action == Action::"write", resource) when { resource.name == "refs/heads/main" && !context.ciPassed };
`
	cases := []struct {
		name string
		r    capReq
		want bool
	}{
		{"new tag", capReq{ref: "refs/tags/v1", kind: "tag", signers: []string{"alice"}}, true},
		{"move existing tag", capReq{ref: "refs/tags/v1", kind: "tag", signers: []string{"alice"}, refExists: true}, false},
		{"main ff + CI", capReq{ref: "refs/heads/main", signers: []string{"alice"}, refExists: true, fastForward: true, ciPassed: true}, true},
		{"main force push", capReq{ref: "refs/heads/main", signers: []string{"alice"}, refExists: true, ciPassed: true}, false},
		{"main CI failed", capReq{ref: "refs/heads/main", signers: []string{"alice"}, refExists: true, fastForward: true}, false},
	}
	for _, c := range cases {
		if ok, _ := capEval(t, pol, c.r); ok != c.want {
			t.Errorf("%s: got %v want %v", c.name, ok, c.want)
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
		if err := ValidatePoliciesWith(capSchema, ps); err == nil {
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
