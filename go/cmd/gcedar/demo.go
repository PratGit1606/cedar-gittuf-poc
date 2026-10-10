package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pratham/gcedar/gcedar"
)

// demo is the port of demo.py: JSON delegations -> Cedar, signatures
// verified on the host. demo.py's last section (privilege-escalation check
// via analysis.py) is not ported: the SMT proofs of Step 4 replace it.
func demo() {
	names := []string{"alice", "bob", "carol", "dave", "erin"}
	sks := map[string]ed25519.PrivateKey{}
	pks := map[string]string{}
	for _, n := range names {
		pub, priv, err := ed25519.GenerateKey(nil)
		check(err)
		sks[n], pks[n] = priv, hex.EncodeToString(pub)
	}
	doc := &gcedar.Doc{
		Principals: pks,
		Roles:      map[string]gcedar.Role{"release": {Threshold: 1, Members: []string{"dave", "erin"}}},
		Rules: []gcedar.Rule{{Name: "main", Pattern: "refs/heads/main", Threshold: 2,
			Members: []string{"alice", "bob", "@release"}}},
		Default: "deny",
	}
	c, err := gcedar.Compile(doc)
	check(err)
	fmt.Println("== generated Cedar (2 of [alice, bob, @release(1 of dave,erin)]) ==")
	fmt.Print(c.Policies)
	fmt.Println()

	v, err := gcedar.NewVerifier(doc)
	check(err)
	ref, commit := "refs/heads/main", strings.Repeat("a", 40)
	change := func(who []string, signCommit string) *gcedar.Change {
		sigs := map[string]string{}
		for _, p := range who {
			sigs[p] = hex.EncodeToString(ed25519.Sign(sks[p], gcedar.RSLPayload(ref, signCommit)))
		}
		return &gcedar.Change{Ref: ref, Commit: commit, Pusher: "alice", Author: "carol", Signatures: sigs}
	}
	for _, tc := range []struct {
		label string
		ch    *gcedar.Change
	}{
		{"alice + dave", change([]string{"alice", "dave"}, commit)},
		{"alice alone", change([]string{"alice"}, commit)},
		{"dave + erin (one role satisfied twice)", change([]string{"dave", "erin"}, commit)},
		{"alice + bob, signed a different commit", change([]string{"alice", "bob"}, strings.Repeat("b", 40))},
	} {
		d := v.Check(tc.ch)
		verdict := "DENY "
		if d.Allowed {
			verdict = "ALLOW"
		}
		var fired [][]string
		for _, r := range d.Reasons {
			fired = append(fired, r.Combo)
		}
		fmt.Printf("%-42s -> %s  verified=%v permits_fired=%v\n", tc.label, verdict, d.Signers, fired)
	}
	fmt.Println("\n(privilege-escalation check: see the SMT proofs, Step 4; analysis.py is not ported)")
}
