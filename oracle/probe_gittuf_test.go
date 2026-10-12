package oracle

import (
	"testing"
)

func keys(t *testing.T, names ...string) []*Key {
	t.Helper()
	var out []*Key
	for _, n := range names {
		k, err := GetKey(n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

func ids(ks ...*Key) []string {
	var out []string
	for _, k := range ks {
		out = append(out, k.ID)
	}
	return out
}

func verdict(t *testing.T, label string, run func() (error, error)) bool {
	t.Helper()
	verr, err := run()
	if err != nil {
		t.Fatalf("%s: harness: %v", label, err)
	}
	if verr != nil && !isPolicyDenial(verr) {
		t.Fatalf("%s: unexpected gittuf error (not a policy denial): %v", label, verr)
	}
	t.Logf("%-70s gittuf=%s", label, yn(verr == nil))
	return verr == nil
}

// For git: rules, which signature counts, the commit's or the RSL entry's?
func TestProbeCommitVsRSLSignature(t *testing.T) {
	k := keys(t, "alice", "mallory")
	alice, mallory := k[0], k[1]
	w, err := NewWorld(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddKeys("targets", alice); err != nil {
		t.Fatal(err)
	}
	if err := w.AddRule("targets", "main", ids(alice), []string{"git:" + main}, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Apply(); err != nil {
		t.Fatal(err)
	}
	a := verdict(t, "commit signed by alice, RSL entry unsigned", func() (error, error) { return w.PushSigned(main, nil, nil, alice) })
	b := verdict(t, "commit signed by alice, RSL entry signed by mallory", func() (error, error) { return w.PushSigned(main, mallory, nil, alice) })
	c := verdict(t, "commit signed by mallory, RSL entry signed by alice", func() (error, error) { return w.PushSigned(main, alice, nil, mallory) })
	if a || b || !c {
		t.Errorf("expected only the RSL entry signature to count for git: rules")
	}
}

// Delegated rule files (gittuf's closest analogue to our roles).
func TestProbeDelegatedRuleFile(t *testing.T) {
	k := keys(t, "alice", "bob", "carol", "dave")
	alice, bob, carol, dave := k[0], k[1], k[2], k[3]

	// Rule "team" (main, 2-of-{alice,bob}) delegates to file "team", whose rule
	// "team-main" is main 2-of-{carol,dave}; "other" is 1-of-{bob}. The team
	// file also has a "*" rule for carol, outside the delegator's namespace.
	setup := func(withAnything bool) *World {
		w, err := NewWorld(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(w.AddKeys("targets", alice, bob))
		must(w.AddRule("targets", "team", ids(alice, bob), []string{"git:" + main}, 2))
		must(w.AddRule("targets", "other", ids(bob), []string{"git:refs/heads/other"}, 1))
		must(w.InitRuleFile(alice, "team"))
		must(w.AddKeysAs(alice, "team", carol, dave))
		must(w.AddRuleAs(alice, "team", "team-main", ids(carol, dave), []string{"git:" + main}, 2))
		if withAnything {
			must(w.AddRuleAs(alice, "team", "team-anything", ids(carol), []string{"git:*"}, 1))
		}
		must(w.SignRuleFile(bob, "team"))
		must(w.Apply())
		return w
	}

	w := setup(false)
	verdict(t, "main: alice+bob (delegating rule itself, 2-of-2)", func() (error, error) { return w.Push(main, alice, []*Key{bob}) })
	verdict(t, "main: carol+dave (delegated rule alone, no alice/bob)", func() (error, error) { return w.Push(main, carol, []*Key{dave}) })
	verdict(t, "main: alice+carol (one from each level)", func() (error, error) { return w.Push(main, alice, []*Key{carol}) })
	verdict(t, "main: carol alone", func() (error, error) { return w.Push(main, carol, nil) })

	w = setup(true) // team file also has team-anything: "*" 1-of-{carol}
	verdict(t, "+team-anything: main: carol alone", func() (error, error) { return w.Push(main, carol, nil) })
	verdict(t, "+team-anything: other: carol (delegator 'team' does not match)", func() (error, error) { return w.Push("refs/heads/other", carol, nil) })
	verdict(t, "+team-anything: other: bob", func() (error, error) { return w.Push("refs/heads/other", bob, nil) })
}
