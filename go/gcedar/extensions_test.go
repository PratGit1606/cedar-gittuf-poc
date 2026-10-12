package gcedar

import (
	"strings"
	"testing"
	"time"
)

// Tests for the strict-mode extensions in extensions.go: forbid, except, window,
// require. Their semantics are also covered by TestDifferential.

func extensionDoc() *Doc {
	return &Doc{
		Principals: map[string]string{"alice": "", "bob": "", "mallory": ""},
		Rules: []Rule{
			{Name: "main", Pattern: "refs/heads/main", Threshold: 1, Members: []string{"alice", "bob"},
				Except:  []string{"mallory"},
				Window:  &Window{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2026-12-31T23:59:59Z"},
				Require: map[string]bool{"ci_passed": true}},
			{Name: "heads", Pattern: "refs/heads/*", Threshold: 1, Members: []string{"mallory"}},
		},
		Forbid:  []Forbid{{Name: "no-mallory-tags", Pattern: "refs/tags/*", Principals: []string{"mallory"}}},
		Default: "allow",
	}
}

func TestExtensionValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(d *Doc)
		want string
	}{
		{"empty except", func(d *Doc) { d.Rules[0].Except = []string{} }, "principal list is empty"},
		{"unknown except", func(d *Doc) { d.Rules[0].Except = []string{"eve"} }, "unknown principal eve"},
		{"duplicate except", func(d *Doc) { d.Rules[0].Except = []string{"mallory", "mallory"} }, "more than once"},
		{"empty forbid list", func(d *Doc) { d.Forbid = []Forbid{} }, "forbid is empty"},
		{"forbid no principals", func(d *Doc) { d.Forbid[0].Principals = nil }, "principal list is empty"},
		{"forbid unknown principal", func(d *Doc) { d.Forbid[0].Principals = []string{"eve"} }, "unknown principal eve"},
		{"forbid name clash", func(d *Doc) { d.Forbid[0].Name = "main" }, "name must be non-empty"},
		{"forbid no name", func(d *Doc) { d.Forbid[0].Name = "" }, "name must be non-empty"},
		{"forbid bad pattern", func(d *Doc) { d.Forbid[0].Pattern = "refs/tags/v?" }, "unsupported glob character"},
		{"empty window", func(d *Doc) { d.Rules[0].Window = &Window{} }, "needs not_before or not_after"},
		{"bad timestamp", func(d *Doc) { d.Rules[0].Window.NotAfter = "2026-12-31" }, "bad RFC 3339 timestamp"},
		{"not a date", func(d *Doc) { d.Rules[0].Window.NotBefore = "yesterday" }, "bad RFC 3339 timestamp"},
		{"sub-millisecond", func(d *Doc) { d.Rules[0].Window.NotAfter = "2026-12-31T23:59:59.0001Z" }, "finer than milliseconds"},
		{"year out of range", func(d *Doc) { d.Rules[0].Window.NotAfter = "9999-12-31T23:00:00-05:00" }, "outside years"},
		{"inverted window", func(d *Doc) { d.Rules[0].Window.NotAfter = "2025-01-01T00:00:00Z" }, "not_after is before not_before"},
		{"empty require", func(d *Doc) { d.Rules[0].Require = map[string]bool{} }, "require is empty"},
		{"require false", func(d *Doc) { d.Rules[0].Require = map[string]bool{"ci_passed": false} }, "must be true"},
		{"require bad name", func(d *Doc) { d.Rules[0].Require = map[string]bool{"CI-passed": true} }, "bad fact name"},
		{"require reserved", func(d *Doc) { d.Rules[0].Require = map[string]bool{"signers": true} }, "bad fact name"},
		{"require keyword", func(d *Doc) { d.Rules[0].Require = map[string]bool{"like": true} }, "bad fact name"},
	}
	for _, c := range cases {
		d := extensionDoc()
		c.edit(d)
		if _, err := Compile(d); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
	if _, err := Compile(extensionDoc()); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
}

func TestParseDocStrict(t *testing.T) {
	for in, want := range map[string]string{
		`{"principals":{},"rules":[],"bogus":1}`:                                                                     "unknown field",
		`{"principals":{},"rules":[{"name":"r","pattern":"*","threshold":1,"members":[],"exept":[]}]}`:               "unknown field",
		`{"principals":{},"rules":[{"name":"r","pattern":"*","threshold":1,"members":[],"require":{"ci":"yes"}}]}`:   "cannot unmarshal",
		`{"principals":{},"rules":[{"name":"r","pattern":"*","threshold":1,"members":[],"window":{"not_after":5}}]}`: "cannot unmarshal",
		`{"principals":{},"rules":[]} {}`:                                                                            "trailing data",
	} {
		if _, err := ParseDoc([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", in, err, want)
		}
	}
}

func TestExtensionsRejectedInGittufMode(t *testing.T) {
	keys := map[string]string{"alice": "k1", "mallory": "k2"}
	rule := func() Rule {
		return Rule{Name: "main", Pattern: "refs/heads/main", Threshold: 1, Members: []string{"alice"}}
	}
	docs := map[string]*Doc{"forbid": {Principals: keys, Rules: []Rule{rule()},
		Forbid: []Forbid{{Name: "f", Pattern: "*", Principals: []string{"mallory"}}}}}
	r := rule()
	r.Except = []string{"mallory"}
	docs["except"] = &Doc{Principals: keys, Rules: []Rule{r}}
	r = rule()
	r.Window = &Window{NotAfter: "2026-12-31T00:00:00Z"}
	docs["window"] = &Doc{Principals: keys, Rules: []Rule{r}}
	r = rule()
	r.Require = map[string]bool{"ci_passed": true}
	docs["require"] = &Doc{Principals: keys, Rules: []Rule{r}}
	for name, d := range docs {
		_, err := CompileMode(d, ModeGittuf)
		if err == nil || !strings.Contains(err.Error(), "gittuf cannot express") || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// The schema grows only by what the document uses.
func TestExtensionSchemaOnlyWhenUsed(t *testing.T) {
	d := extensionDoc()
	d.Rules[0].Window, d.Rules[0].Require = nil, nil
	if c, err := Compile(d); err != nil || c.Schema != Schema {
		t.Errorf("except/forbid alone must not change the schema: %v", err)
	}
	c, err := Compile(extensionDoc())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Schema, "author: User, now: datetime, ci_passed: Bool }") || !c.UsesNow ||
		strings.Join(c.HostFacts, ",") != "ci_passed" {
		t.Errorf("schema %q, now %v, facts %v", c.Schema, c.UsesNow, c.HostFacts)
	}
}

func TestExtensionDecisionsAndReasons(t *testing.T) {
	d := extensionDoc()
	c, err := Compile(d)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(d, c)
	if err != nil {
		t.Fatal(err)
	}
	in := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ci := map[string]bool{"ci_passed": true}
	main := "refs/heads/main"
	cases := []struct {
		name   string
		f      Facts
		allow  bool
		reason string // rule named by the deciding policy ("" = none)
	}{
		{"ok", Facts{Ref: main, Signers: []string{"alice"}, Now: in, Host: ci}, true, "main"},
		{"excepted signer", Facts{Ref: main, Signers: []string{"alice", "mallory"}, Now: in, Host: ci}, false, "main"},
		{"before window", Facts{Ref: main, Signers: []string{"alice"}, Now: in.AddDate(-1, 0, 0), Host: ci}, false, ""},
		{"at not_after", Facts{Ref: main, Signers: []string{"alice"}, Now: time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC), Host: ci}, true, "main"},
		{"after window", Facts{Ref: main, Signers: []string{"alice"}, Now: time.Date(2026, 12, 31, 23, 59, 59, 1e6, time.UTC), Host: ci}, false, ""},
		{"CI not passed", Facts{Ref: main, Signers: []string{"alice"}, Now: in}, false, ""},
		{"no clock", Facts{Ref: main, Signers: []string{"alice"}, Host: ci}, false, ""},
		{"mallory on dev", Facts{Ref: "refs/heads/dev", Signers: []string{"mallory"}, Now: in}, true, "heads"},
		{"mallory on a tag", Facts{Ref: "refs/tags/v1", Signers: []string{"mallory"}, Now: in}, false, "no-mallory-tags"},
		{"alice on a tag", Facts{Ref: "refs/tags/v1", Signers: []string{"alice"}, Now: in}, true, "<default-allow>"},
	}
	for _, k := range cases {
		got := ev.Decide(k.f)
		if got.Allowed != k.allow || ReferenceAllows(d, k.f) != k.allow {
			t.Errorf("%s: cedar %v, reference %v, want %v", k.name, got.Allowed, ReferenceAllows(d, k.f), k.allow)
		}
		reason := ""
		if len(got.Reasons) > 0 {
			reason = got.Reasons[0].Rule
		}
		if len(got.Reasons) > 1 || reason != k.reason {
			t.Errorf("%s: reasons %+v, want %q", k.name, got.Reasons, k.reason)
		}
		if !k.allow && k.reason != "" && got.Reasons[0].Kind != "forbid" {
			t.Errorf("%s: deny should name a forbid, got %+v", k.name, got.Reasons)
		}
	}
	if got := ev.Decide(Facts{Ref: main, Signers: []string{"alice"}, Host: ci}); len(got.Errors) == 0 {
		t.Error("missing clock should be reported as an error")
	}
}

// Phase A must verify excepted and forbidden principals' signatures, or a
// forbid could never fire.
func TestPhaseAVerifiesExceptedSigners(t *testing.T) {
	d := &Doc{Principals: map[string]string{"alice": vw.pk["alice"], "erin": vw.pk["erin"]},
		Rules: []Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 1, Members: []string{"alice"},
			Except: []string{"erin"}, Window: &Window{NotAfter: "2026-12-31T00:00:00Z"}}}}
	v, err := NewVerifier(d)
	if err != nil {
		t.Fatal(err)
	}
	v.Clock = func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }
	if got := v.Check(change([]string{"alice"}, "", "", "")); !got.Allowed {
		t.Errorf("alice alone: %v", got)
	}
	got := v.Check(change([]string{"alice", "erin"}, "", "", ""))
	if got.Allowed || len(got.Reasons) != 1 || got.Reasons[0].Kind != "forbid" {
		t.Errorf("alice+erin should be denied by the except: %v %+v", got, got.Reasons)
	}
	v.Clock = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }
	if got := v.Check(change([]string{"alice"}, "", "", "")); got.Allowed {
		t.Errorf("after the window: %v", got)
	}
}
