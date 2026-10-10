package oracle

import (
	"fmt"
	"testing"

	"github.com/pratham/gcedar/gcedar"
)

// Can a nested threshold (our roles) be written in gittuf? Because gittuf
// rules are alternatives, the compiler's own expansion (one minimal approver
// set per permit) can be materialized as one gittuf rule per set with
// threshold = |set|. Compare gittuf on every signer subset against strict-mode
// Cedar on the original role document.
func TestRolesAsExpandedGittufRules(t *testing.T) {
	names := []string{"alice", "bob", "carol", "dave", "erin"}
	for _, doc := range []*gcedar.Doc{
		{ // alice AND 2-of-{carol,dave,erin}, OR bob AND the same team
			Principals: principals(names...),
			Roles: map[string]gcedar.Role{
				"team": {Threshold: 2, Members: []string{"carol", "dave", "erin"}},
				"lead": {Threshold: 1, Members: []string{"alice", "bob"}},
			},
			Rules:   []gcedar.Rule{{Name: "main", Pattern: main, Threshold: 2, Members: []string{"@lead", "@team"}}},
			Default: "allow",
		},
		{ // 2-of-[alice, @a(2-of bob,carol), @b(1-of dave,erin)]
			Principals: principals(names...),
			Roles: map[string]gcedar.Role{
				"a": {Threshold: 2, Members: []string{"bob", "carol"}},
				"b": {Threshold: 1, Members: []string{"dave", "erin"}},
			},
			Rules:   []gcedar.Rule{{Name: "main", Pattern: main, Threshold: 2, Members: []string{"alice", "@a", "@b"}}},
			Default: "allow",
		},
	} {
		c, err := gcedar.Compile(doc)
		if err != nil {
			t.Fatal(err)
		}
		w, err := NewWorld(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := w.AddKeys("targets", keys(t, names...)...); err != nil {
			t.Fatal(err)
		}
		nRules := 0
		for i, m := range c.Meta {
			if len(m.Combo) == 0 { // the default-allow catch-all, not an approver set
				continue
			}
			nRules++
			if err := w.AddRule("targets", fmt.Sprintf("main-%d", i), ids(keys(t, m.Combo...)...), []string{"git:" + main}, len(m.Combo)); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Apply(); err != nil {
			t.Fatal(err)
		}
		mism, n := 0, 0
		for mask := 0; mask < 1<<len(names); mask++ {
			var signers []string
			for i, nm := range names {
				if mask&(1<<i) != 0 {
					signers = append(signers, nm)
				}
			}
			s := Scenario{Attestors: signers}
			g := gittufVerdict(t, w, push{main, "", signers})
			want, err := CedarVerdictMode(doc, gcedar.ModeStrict, main, s)
			if err != nil {
				t.Fatal(err)
			}
			n++
			if g != want {
				mism++
				t.Errorf("signers %v: gittuf(expanded)=%v cedar(roles)=%v", signers, g, want)
			}
		}
		t.Logf("%d permits -> %d gittuf rules; %d/%d signer subsets disagree", c.NPermit, nRules, mism, n)
	}
}
