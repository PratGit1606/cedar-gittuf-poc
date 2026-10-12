package gcedar

import (
	"errors"
	"testing"
)

// Every path where one key could count twice toward a threshold. Phase A
// paths (one key bound to two principal names) are in phasea_test.go and
// fields_test.go.

func TestDuplicateRuleMemberRejected(t *testing.T) {
	for _, mode := range []Mode{ModeStrict, ModeGittuf} {
		doc := &Doc{Principals: map[string]string{"a": "K1", "b": "K2"},
			Rules: []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"a", "a"}}}}
		_, err := CompileMode(doc, mode)
		var dup *DuplicateMemberError
		if !errors.As(err, &dup) {
			t.Errorf("%s: [a,a] should be rejected with DuplicateMemberError, got %v", mode, err)
		}
	}
}

func TestDuplicateRoleMemberRejected(t *testing.T) {
	doc := &Doc{Principals: map[string]string{"a": "", "b": ""},
		Roles: map[string]Role{"r": {Threshold: 1, Members: []string{"b", "b"}}},
		Rules: []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: 1, Members: []string{"a", "@r"}}}}
	var dup *DuplicateMemberError
	if _, err := Compile(doc); !errors.As(err, &dup) {
		t.Errorf("role [b,b] should be rejected, got %v", err)
	}
	doc.Roles["r"] = Role{Threshold: 1, Members: []string{"b"}}
	doc.Rules[0].Members = []string{"@r", "@r"}
	if _, err := Compile(doc); !errors.As(err, &dup) {
		t.Errorf("rule [@r,@r] should be rejected, got %v", err)
	}
}

// One signer must not satisfy two members of the same threshold through
// overlapping roles (or a principal that is also inside a listed role).
func TestOverlappingMembersCountOnce(t *testing.T) {
	cases := []struct {
		name    string
		roles   map[string]Role
		members []string
		k       int
		allow   map[string]bool // signer set (as "a", "ab", ...) -> want
	}{
		{"2-of-[@r1,@r2], a in both", map[string]Role{
			"r1": {Threshold: 1, Members: []string{"a"}},
			"r2": {Threshold: 1, Members: []string{"a", "b"}}},
			[]string{"@r1", "@r2"}, 2, map[string]bool{"a": false, "b": false, "ab": true}},
		{"2-of-[a,@r], a in @r", map[string]Role{
			"r": {Threshold: 1, Members: []string{"a", "b"}}},
			[]string{"a", "@r"}, 2, map[string]bool{"a": false, "ab": true, "b": false}},
		{"2-of-[@r1,@r2], each 2-of-3 sharing b", map[string]Role{
			"r1": {Threshold: 2, Members: []string{"a", "b", "c"}},
			"r2": {Threshold: 2, Members: []string{"b", "d", "e"}}},
			[]string{"@r1", "@r2"}, 2, map[string]bool{"abd": false, "abde": true, "acbd": true, "acde": true}},
	}
	for _, c := range cases {
		doc := &Doc{Principals: map[string]string{"a": "", "b": "", "c": "", "d": "", "e": ""}, Roles: c.roles,
			Rules: []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: c.k, Members: c.members}}}
		comp, err := Compile(doc)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := NewEvaluator(doc, comp)
		if err != nil {
			t.Fatal(err)
		}
		for set, want := range c.allow {
			var signers []string
			for _, r := range set {
				signers = append(signers, string(r))
			}
			f := Facts{Ref: "refs/heads/main", Pusher: "a", Author: "a", Signers: signers}
			if got := ev.Decide(f).Allowed; got != want {
				t.Errorf("%s: signers %v: cedar=%v want %v", c.name, signers, got, want)
			}
			if got := ReferenceAllows(doc, f); got != want {
				t.Errorf("%s: signers %v: reference=%v want %v", c.name, signers, got, want)
			}
		}
	}
}

// The signer set handed to Cedar is a set: listing a signer twice is one signer.
func TestRepeatedSignerInFactsCountsOnce(t *testing.T) {
	doc := &Doc{Principals: map[string]string{"a": "", "b": ""},
		Rules: []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"a", "b"}}}}
	c, _ := Compile(doc)
	ev, err := NewEvaluator(doc, c)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Decide(Facts{Ref: "refs/heads/main", Pusher: "a", Author: "a", Signers: []string{"a", "a"}}).Allowed {
		t.Error("signers [a,a] must not meet 2-of-[a,b]")
	}
}

// Gittuf mode: two principal names bound to the same key collapse into one
// identity, so they cannot meet a threshold together.
func TestGittufModeSharedKeyCountsOnce(t *testing.T) {
	doc := &Doc{Principals: map[string]string{"p1": "K", "p2": "K", "p3": "K3"},
		Rules: []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"p1", "p2", "p3"}}}}
	c, err := CompileMode(doc, ModeGittuf)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(doc, c)
	if err != nil {
		t.Fatal(err)
	}
	f := Facts{Ref: "refs/heads/main", Signers: KeyIDs(doc, []string{"p1", "p2"})}
	if ev.Decide(f).Allowed {
		t.Error("p1+p2 share key K: must count once")
	}
	f.Signers = KeyIDs(doc, []string{"p1", "p3"})
	if !ev.Decide(f).Allowed {
		t.Error("p1+p3 have distinct keys: should meet 2-of")
	}
}
