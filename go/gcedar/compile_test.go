package gcedar

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"testing"
)

// Cedar (via cedar-go) must agree with the Go reference on every input. This
// only checks the port against its own spec; the gittuf oracle is in ../oracle.
func TestDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(1609))
	total, mismatches := 0, 0
	for docN := 0; docN < 150; docN++ {
		doc := randomDoc(rng)
		c, err := Compile(doc)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		ev, err := NewEvaluator(doc, c)
		if err != nil {
			t.Fatal(err)
		}
		names := sortedNames(doc)
		type tc struct {
			s, a []string
			au   string
		}
		var cases []tc
		for _, s := range subsets(names) {
			cases = append(cases, tc{s, nil, names[0]})
		}
		for i := 0; i < 60; i++ {
			cases = append(cases, tc{sample(rng, names, rng.Intn(7)), sample(rng, names, rng.Intn(7)), names[rng.Intn(len(names))]})
		}
		for _, a := range subsets(names) {
			cases = append(cases, tc{nil, a, names[0]})
		}
		for _, ref := range sampleRefs(doc) {
			ents := ev.Entities(ref)
			for _, k := range cases {
				f := Facts{Ref: ref, Pusher: names[0], Author: k.au, Signers: k.s, Approvals: k.a}
				got := ev.DecideWith(ents, f)
				if len(got.Errors) > 0 {
					t.Fatalf("evaluation errors: %v", got.Errors)
				}
				total++
				if want := ReferenceAllows(doc, f); got.Allowed != want {
					mismatches++
					if mismatches <= 5 {
						j, _ := json.Marshal(doc)
						t.Errorf("MISMATCH %+v cedar=%v ref=%v doc=%s", f, got.Allowed, want, j)
					}
				}
			}
		}
	}
	t.Logf("differential: 150 docs, %d verdicts, %d mismatches", total, mismatches)
	if total < 100000 {
		t.Fatalf("too few verdicts: %d", total)
	}
}

func flatDoc(n, k int) *Doc {
	d := &Doc{Principals: map[string]string{}}
	var ms []string
	for i := 0; i < n; i++ {
		name := "p" + string(rune('a'+i))
		d.Principals[name] = ""
		ms = append(ms, name)
	}
	d.Rules = []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: k, Members: ms}}
	return d
}

func nestedDoc(groups, per, outerK, innerK int) *Doc {
	d := &Doc{Principals: map[string]string{}, Roles: map[string]Role{}}
	var outer []string
	for g := 0; g < groups; g++ {
		var ms []string
		for i := 0; i < per; i++ {
			name := fmt.Sprintf("g%dp%d", g, i)
			d.Principals[name] = ""
			ms = append(ms, name)
		}
		d.Roles[fmt.Sprintf("g%d", g)] = Role{Threshold: innerK, Members: ms}
		outer = append(outer, fmt.Sprintf("@g%d", g))
	}
	d.Rules = []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: outerK, Members: outer}}
	return d
}

func TestExpansionSizes(t *testing.T) {
	for _, nk := range [][2]int{{3, 2}, {5, 3}, {10, 5}, {16, 8}} {
		c, err := Compile(flatDoc(nk[0], nk[1]))
		if err != nil {
			t.Fatal(err)
		}
		if c.NPermit != binom(nk[0], nk[1]) {
			t.Errorf("%d-of-%d: %d permits, want C(n,k)=%d", nk[1], nk[0], c.NPermit, binom(nk[0], nk[1]))
		}
	}
	if c, err := Compile(nestedDoc(5, 5, 3, 3)); err != nil || c.NPermit != 10000 {
		t.Errorf("nested 3-of-5 x 3-of-5: %v permits, err %v; want 10000", c, err)
	}
	_, err := Compile(nestedDoc(5, 8, 3, 4))
	var tl *ExpansionTooLarge
	if !errors.As(err, &tl) {
		t.Errorf("3-of-5 roles each 4-of-8 should be refused, got %v", err)
	}
}

func TestForbidOverridesAndReasons(t *testing.T) {
	doc := &Doc{
		Principals:         map[string]string{"a": "", "b": "", "c": ""},
		Rules:              []Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"a", "b", "c"}, Source: "approvals"}},
		ForbidSelfApproval: true,
	}
	c, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(doc, c)
	if err != nil {
		t.Fatal(err)
	}
	d := ev.Decide(Facts{Ref: "refs/heads/main", Pusher: "a", Author: "c", Approvals: []string{"a", "b"}})
	if !d.Allowed || len(d.Reasons) != 1 || d.Reasons[0].Rule != "main" {
		t.Errorf("want allow by main, got %+v", d)
	}
	d = ev.Decide(Facts{Ref: "refs/heads/main", Pusher: "a", Author: "a", Approvals: []string{"a", "b"}})
	if d.Allowed || len(d.Reasons) != 1 || d.Reasons[0].Rule != "<self-approval>" {
		t.Errorf("want deny by self-approval forbid, got %+v", d)
	}
}
