package oracle

import (
	"testing"

	"github.com/pratham/gcedar/gcedar"
)

const main = "refs/heads/main"

// Probe 1: are matching rules alternatives (gittuf, per source reading) or is
// the first matching rule final (our strict compiler)?
func TestProbeRuleMatching(t *testing.T) {
	ps := principals("alice", "bob", "carol")
	two := gcedar.Rule{Name: "two-of-alice-bob", Pattern: main, Threshold: 2, Members: []string{"alice", "bob"}}
	carol := gcedar.Rule{Name: "carol-alone", Pattern: main, Threshold: 1, Members: []string{"carol"}}
	broad := gcedar.Rule{Name: "heads-alice", Pattern: "refs/heads/*", Threshold: 1, Members: []string{"alice"}}
	strictMain := gcedar.Rule{Name: "main-bob-carol", Pattern: main, Threshold: 2, Members: []string{"bob", "carol"}}

	pushes := []push{
		{main, "carol", nil},
		{main, "alice", nil},
		{main, "alice", []string{"bob"}},
		{main, "bob", []string{"carol"}},
	}
	for _, c := range []struct {
		label string
		rules []gcedar.Rule
	}{
		{"[2-of-ab, 1-of-c]", []gcedar.Rule{two, carol}},
		{"[1-of-c, 2-of-ab]", []gcedar.Rule{carol, two}},
		{"[heads/* alice, main 2-of-bc]", []gcedar.Rule{broad, strictMain}},
		{"[main 2-of-bc, heads/* alice]", []gcedar.Rule{strictMain, broad}},
	} {
		compareDoc(t, c.label, &gcedar.Doc{Principals: ps, Rules: c.rules, Default: "allow"}, pushes, ModesUnderTest...)
	}
}
