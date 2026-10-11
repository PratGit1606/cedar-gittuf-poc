package oracle

import (
	"strings"
	"testing"

	"github.com/pratham/gcedar/gcedar"
)

func principals(names ...string) map[string]string {
	m := map[string]string{}
	for _, n := range names {
		m[n] = ""
	}
	return m
}

func TestHandwrittenCedarAgrees(t *testing.T) {
	doc := &gcedar.Doc{
		Principals: principals("alice", "bob", "carol"),
		Rules:      []gcedar.Rule{{Name: "protect-main", Pattern: main, Threshold: 2, Members: []string{"alice", "bob", "carol"}}},
		Default:    "allow",
	}
	mism := compareDoc(t, "2-of-3", doc, []push{
		{main, "alice", []string{"bob"}},
		{main, "alice", nil},
		{main, "mallory", []string{"alice", "carol"}},
		{main, "mallory", []string{"alice"}},
		{main, "", []string{"bob", "carol"}},
		{main, "alice", []string{"alice"}},
	}, ModesUnderTest...)
	for m, n := range mism {
		if n != 0 {
			t.Errorf("%s mode: %d mismatches on the hand-written case", m, n)
		}
	}
}

// Finding 4: duplicate rule members. Logged, not asserted: the point is to
// record what gittuf does (the compiler now rejects these documents).
func TestProbeDuplicateMembers(t *testing.T) {
	compareDoc(t, "dup [alice,alice] k=2", &gcedar.Doc{
		Principals: principals("alice", "bob"),
		Rules:      []gcedar.Rule{{Name: "dup", Pattern: main, Threshold: 2, Members: []string{"alice", "alice"}}},
		Default:    "allow",
	}, []push{{main, "alice", nil}, {main, "alice", []string{"alice"}}, {main, "alice", []string{"bob"}}}, gcedar.ModeStrict)

	compareDoc(t, "dup [alice,alice,bob] k=2", &gcedar.Doc{
		Principals: principals("alice", "bob"),
		Rules:      []gcedar.Rule{{Name: "dup", Pattern: main, Threshold: 2, Members: []string{"alice", "alice", "bob"}}},
		Default:    "allow",
	}, []push{{main, "alice", nil}, {main, "bob", nil}, {main, "alice", []string{"bob"}}}, gcedar.ModeStrict)
}

// Finding 5: two principals (tufv02 persons p1, p2) that share one key.
// Strict mode credits every principal whose key signed, as the Python Phase A
// did; gittuf mode identifies principals by key ID. Logged, not asserted.
func TestProbeSharedKey(t *testing.T) {
	ps := map[string]string{"p1": "key:shared", "p2": "key:shared", "p3": "key:carol"}
	for _, members := range [][]string{{"p1", "p2"}, {"p1", "p2", "p3"}} {
		doc := &gcedar.Doc{Principals: ps, Default: "allow",
			Rules: []gcedar.Rule{{Name: "r", Pattern: main, Threshold: 2, Members: members}}}
		compareDoc(t, "p1,p2 share a key; 2-of-["+strings.Join(members, ",")+"]", doc,
			[]push{{main, "shared", nil}, {main, "shared", []string{"shared"}}, {main, "shared", []string{"carol"}}},
			ModesUnderTest...)
	}
}
