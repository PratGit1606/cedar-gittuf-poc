package oracle

import (
	"testing"
)

// One hand-written case end to end: rule protect-main = 2-of-{alice,bob,carol}
// on git:refs/heads/main, verified by gittuf's real verifier.
func TestHandwritten2of3(t *testing.T) {
	w, err := NewWorld(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := GetKey("alice")
	bob, _ := GetKey("bob")
	carol, _ := GetKey("carol")
	mallory, _ := GetKey("mallory") // not in the policy
	if err := w.AddKeys("targets", alice, bob, carol); err != nil {
		t.Fatal(err)
	}
	if err := w.AddRule("targets", "protect-main", []string{alice.ID, bob.ID, carol.ID}, []string{"git:refs/heads/main"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := w.Apply(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		pusher    *Key
		attestors []*Key
		allow     bool
	}{
		{"alice pushes, bob authorizes", alice, []*Key{bob}, true},
		{"alice pushes alone", alice, nil, false},
		{"mallory pushes, alice+carol authorize", mallory, []*Key{alice, carol}, true},
		{"mallory pushes, alice authorizes", mallory, []*Key{alice}, false},
		{"unsigned push, bob+carol authorize", nil, []*Key{bob, carol}, true},
		{"alice pushes, alice authorizes (same principal twice)", alice, []*Key{alice}, false},
	}
	for _, c := range cases {
		verr, err := w.Push("refs/heads/main", c.pusher, c.attestors)
		if err != nil {
			t.Fatalf("%s: harness error: %v", c.name, err)
		}
		got := verr == nil
		t.Logf("%-55s gittuf allow=%v (err=%v)", c.name, got, verr)
		if got != c.allow {
			t.Errorf("%s: gittuf allow=%v, expected %v", c.name, got, c.allow)
		}
	}
}
