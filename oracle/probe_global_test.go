package oracle

import "testing"

// Capability rows "forbid overrides permits" and "attribute conditions":
// what gittuf's two global rule types do, on real gittuf.
func TestOracleGlobalRules(t *testing.T) {
	k := keys(t, "alice", "bob", "carol")
	alice, bob := k[0], k[1]
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
	must(w.AddKeys("targets", k...))
	must(w.AddRule("targets", "main", ids(alice), []string{"git:" + main}, 1))
	must(w.AddGlobalThreshold("floor-2", []string{"git:refs/heads/*"}, 2))
	must(w.AddGlobalBlockForcePushes("no-force-main", []string{"git:" + main}))
	must(w.Apply())

	a := verdict(t, "main: alice (rule met, global floor 2 not met)", func() (error, error) { return w.Push(main, alice, nil) })
	b := verdict(t, "main: alice+bob (rule and floor met)", func() (error, error) { return w.Push(main, alice, []*Key{bob}) })
	c := verdict(t, "other: unsigned (no rule matches, floor applies)", func() (error, error) { return w.Push("refs/heads/other", nil, nil) })
	d := verdict(t, "other: bob+carol (no rule, floor met by any principals)", func() (error, error) { return w.Push("refs/heads/other", bob, []*Key{k[2]}) })
	e := verdict(t, "main: alice+bob, non-fast-forward (based on initial commit)", func() (error, error) {
		return w.PushFrom(main, "refs/heads/main~2", alice, []*Key{bob})
	})
	if a || !b || c || !d || e {
		t.Errorf("unexpected: floor alone=%v floor+rule=%v unprotected-under-floor=%v floor-any-principals=%v force-push=%v", a, b, c, d, e)
	}

	// Control: same force push without the block-force-pushes rule is allowed,
	// so the denial above comes from that rule.
	w2, err := NewWorld(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	must(w2.AddKeys("targets", k...))
	must(w2.AddRule("targets", "main", ids(alice), []string{"git:" + main}, 1))
	must(w2.Apply())
	verdict(t, "control: main: alice", func() (error, error) { return w2.Push(main, alice, nil) })
	verdict(t, "control: main: alice", func() (error, error) { return w2.Push(main, alice, nil) })
	if !verdict(t, "control (no global rules): main: alice, non-fast-forward", func() (error, error) {
		return w2.PushFrom(main, "refs/heads/main~2", alice, nil)
	}) {
		t.Error("control force push should be allowed without block-force-pushes")
	}
}
