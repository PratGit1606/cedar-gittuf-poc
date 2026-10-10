package oracle

import (
	"testing"

	"github.com/pratham/gcedar/gcedar"
)

type probe struct {
	name string
	doc  *gcedar.Doc
	runs []Scenario
}

func principals(names ...string) map[string]string {
	m := map[string]string{}
	for _, n := range names {
		m[n] = ""
	}
	return m
}

func runProbe(t *testing.T, p probe) (mismatches int) {
	t.Helper()
	w, err := NewWorld(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := Materialize(w, p.doc); err != nil {
		t.Logf("[%s] gittuf REJECTED the policy: %v", p.name, err)
		if _, cerr := gcedar.Compile(p.doc); cerr == nil {
			t.Logf("[%s]   ...but our compiler ACCEPTS it", p.name)
		}
		return 1
	}
	for _, s := range p.runs {
		g, verr, err := PushScenario(w, "refs/heads/main", s)
		if err != nil {
			t.Fatalf("[%s] harness: %v", p.name, err)
		}
		c, err := CedarVerdict(p.doc, "refs/heads/main", s)
		if err != nil {
			t.Logf("[%s] pusher=%-6q attest=%v  gittuf=%v  cedar: compile error %v", p.name, s.Pusher, s.Attestors, g, err)
			mismatches++
			continue
		}
		mark := "agree"
		if g != c {
			mark = "MISMATCH"
			mismatches++
		}
		_ = verr
		t.Logf("[%s] pusher=%-6q attest=%-14v gittuf=%-5v cedar=%-5v %s", p.name, s.Pusher, s.Attestors, g, c, mark)
	}
	return mismatches
}

func TestHandwrittenCedarAgrees(t *testing.T) {
	doc := &gcedar.Doc{
		Principals: principals("alice", "bob", "carol"),
		Rules:      []gcedar.Rule{{Name: "protect-main", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"alice", "bob", "carol"}}},
		Default:    "allow",
	}
	n := runProbe(t, probe{"2-of-3", doc, []Scenario{
		{"alice", []string{"bob"}},
		{"alice", nil},
		{"mallory", []string{"alice", "carol"}},
		{"mallory", []string{"alice"}},
		{"", []string{"bob", "carol"}},
		{"alice", []string{"alice"}},
	}})
	if n != 0 {
		t.Errorf("%d mismatches on the hand-written case", n)
	}
}

// Finding 3 from step 1: duplicate rule members. Logged, not asserted: the
// point is to record what gittuf does.
func TestProbeDuplicateMembers(t *testing.T) {
	runProbe(t, probe{"dup [alice,alice] k=2", &gcedar.Doc{
		Principals: principals("alice", "bob"),
		Rules:      []gcedar.Rule{{Name: "dup", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"alice", "alice"}}},
		Default:    "allow",
	}, []Scenario{{"alice", nil}, {"alice", []string{"alice"}}, {"alice", []string{"bob"}}}})

	runProbe(t, probe{"dup [alice,alice,bob] k=2", &gcedar.Doc{
		Principals: principals("alice", "bob"),
		Rules:      []gcedar.Rule{{Name: "dup", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"alice", "alice", "bob"}}},
		Default:    "allow",
	}, []Scenario{{"alice", nil}, {"bob", nil}, {"alice", []string{"bob"}}}})
}

// Finding 2 from step 1: two principals that share one key. Our model has no
// notion of keys in Phase B: Phase A decides which principals "signed".
func TestProbeSharedKey(t *testing.T) {
	shared, _ := GetKey("shared")
	carol, _ := GetKey("carol")
	for _, tc := range []struct {
		name    string
		members []string
		k       int
		pushes  []struct {
			pusher     *Key
			att        []*Key
			ourSigners []string
		}
	}{
		{"p1,p2 share a key; 2-of-[p1,p2]", []string{"p1", "p2"}, 2, []struct {
			pusher     *Key
			att        []*Key
			ourSigners []string
		}{
			{shared, nil, []string{"p1", "p2"}},
			{shared, []*Key{shared}, []string{"p1", "p2"}},
		}},
		{"p1,p2 share a key; 2-of-[p1,p2,p3]", []string{"p1", "p2", "p3"}, 2, []struct {
			pusher     *Key
			att        []*Key
			ourSigners []string
		}{
			{shared, nil, []string{"p1", "p2"}},
			{shared, []*Key{carol}, []string{"p1", "p2", "p3"}},
		}},
	} {
		w, err := NewWorld(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := w.AddPerson("targets", "p1", shared); err != nil {
			t.Fatal(err)
		}
		if err := w.AddPerson("targets", "p2", shared); err != nil {
			t.Logf("[%s] gittuf REJECTED second person with same key: %v", tc.name, err)
			continue
		}
		if err := w.AddPerson("targets", "p3", carol); err != nil {
			t.Fatal(err)
		}
		if err := w.AddRule("targets", "r", tc.members, []string{"git:refs/heads/main"}, tc.k); err != nil {
			t.Fatal(err)
		}
		if err := w.Apply(); err != nil {
			t.Fatal(err)
		}
		doc := &gcedar.Doc{Principals: principals("p1", "p2", "p3"),
			Rules:   []gcedar.Rule{{Name: "r", Pattern: "refs/heads/main", Threshold: tc.k, Members: tc.members}},
			Default: "allow"}
		for _, p := range tc.pushes {
			verr, err := w.Push("refs/heads/main", p.pusher, p.att)
			if err != nil {
				t.Fatal(err)
			}
			c, err := CedarVerdict(doc, "refs/heads/main", Scenario{Pusher: p.ourSigners[0], Attestors: p.ourSigners[1:]})
			if err != nil {
				t.Fatal(err)
			}
			mark := "agree"
			if (verr == nil) != c {
				mark = "MISMATCH"
			}
			names := []string{}
			for _, k := range p.att {
				names = append(names, k.Name)
			}
			t.Logf("[%s] RSL signed by %s, attest=%v | gittuf=%v | cedar given signers=%v -> %v  %s",
				tc.name, p.pusher.Name, names, verr == nil, p.ourSigners, c, mark)
		}
	}
}
