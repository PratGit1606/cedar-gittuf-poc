package gcedar

import (
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// The Go compiler must emit byte-identical Cedar to gcedar/compile.py, and
// fail on exactly the same inputs.
func TestPythonByteCompat(t *testing.T) {
	root, _ := filepath.Abs("../..")
	py := filepath.Join(root, ".venv/bin/python")
	if _, err := os.Stat(py); err != nil {
		t.Skipf("python venv not found at %s", py)
	}
	rng := rand.New(rand.NewSource(42))
	var docs []*Doc
	for i := 0; i < 400; i++ {
		d := randomDoc(rng)
		if i%2 == 1 {
			mutateDoc(rng, d)
		}
		docs = append(docs, d)
	}
	docs = append(docs, flatDoc(10, 5), nestedDoc(5, 5, 3, 3), nestedDoc(5, 8, 3, 4))
	in, _ := json.Marshal(docs)
	dir := t.TempDir()
	inPath := filepath.Join(dir, "docs.json")
	os.WriteFile(inPath, in, 0o644)
	script := `
import json, sys
sys.path.insert(0, sys.argv[1])
from gcedar.compile import compile_delegations, DelegationError
out = []
for d in json.load(open(sys.argv[2])):
    try:
        out.append({"policies": compile_delegations(d).policies})
    except DelegationError as e:
        out.append({"error": type(e).__name__ + ": " + str(e)})
    except Exception as e:  # anything else is a crash, distinct from a DelegationError
        out.append({"crash": type(e).__name__ + ": " + str(e)})
json.dump(out, sys.stdout)
`
	cmd := exec.Command(py, "-c", script, root, inPath)
	cmd.Stderr = os.Stderr
	outB, err := cmd.Output()
	if err != nil {
		t.Fatalf("python: %v", err)
	}
	var pyOut []struct{ Policies, Error, Crash string }
	if err := json.Unmarshal(outB, &pyOut); err != nil {
		t.Fatal(err)
	}
	same, bothErr, diff := 0, 0, 0
	for i, d := range docs {
		c, gerr := Compile(d)
		p := pyOut[i]
		switch {
		case p.Crash != "":
			diff++
			t.Errorf("doc %d: python crashed (%s), go err=%v", i, p.Crash, gerr)
		case gerr != nil && p.Error != "":
			bothErr++
			var gtl *ExpansionTooLarge
			if errors.As(gerr, &gtl) != strings.HasPrefix(p.Error, "ExpansionTooLarge") {
				diff++
				t.Errorf("doc %d: error class differs: go=%v py=%s", i, gerr, p.Error)
			}
		case gerr != nil || p.Error != "":
			diff++
			t.Errorf("doc %d: go err=%v, py err=%q", i, gerr, p.Error)
		case c.Policies != p.Policies:
			diff++
			t.Errorf("doc %d: policy text differs\n go: %.300q\n py: %.300q", i, c.Policies, p.Policies)
		default:
			same++
		}
	}
	t.Logf("python byte-compat: %d identical, %d both rejected, %d differ", same, bothErr, diff)
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
			name := "g" + string(rune('0'+g)) + "p" + string(rune('0'+i))
			d.Principals[name] = ""
			ms = append(ms, name)
		}
		d.Roles["g"+string(rune('0'+g))] = Role{Threshold: innerK, Members: ms}
		outer = append(outer, "@g"+string(rune('0'+g)))
	}
	d.Rules = []Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: outerK, Members: outer}}
	return d
}

func TestExpansionSizes(t *testing.T) {
	binom := func(n, k int) int {
		r := 1
		for i := 1; i <= k; i++ {
			r = r * (n - k + i) / i
		}
		return r
	}
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
