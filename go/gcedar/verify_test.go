package gcedar

import (
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// Port of tests/test_verifier.py (same cases), plus the shared-key path.

type world struct {
	sk map[string]ed25519.PrivateKey
	pk map[string]string // hex
}

func makeWorld(names ...string) world {
	w := world{sk: map[string]ed25519.PrivateKey{}, pk: map[string]string{}}
	for _, n := range names {
		pub, priv, _ := ed25519.GenerateKey(nil)
		w.sk[n], w.pk[n] = priv, hex.EncodeToString(pub)
	}
	return w
}

func (w world) sign(who, ref, commit string) string {
	return hex.EncodeToString(ed25519.Sign(w.sk[who], RSLPayload(ref, commit)))
}

var (
	vw              = makeWorld("alice", "bob", "carol", "dave", "erin")
	vREF, vC1, vC2  = "refs/heads/main", strings.Repeat("c", 40), strings.Repeat("d", 40)
	verifierTestDoc = func() *Doc {
		return &Doc{
			Principals: vw.pk,
			Roles:      map[string]Role{"release": {Threshold: 1, Members: []string{"dave", "erin"}}},
			Rules: []Rule{
				{Name: "main", Pattern: "refs/heads/main", Threshold: 2, Members: []string{"alice", "bob", "@release"}},
				{Name: "reviewed", Pattern: "refs/heads/feature/*", Threshold: 2, Members: []string{"alice", "bob", "carol"}, Source: "approvals"},
			},
			Default:            "deny",
			ForbidSelfApproval: true,
		}
	}
)

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(verifierTestDoc())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// change mirrors test_verifier.change: signers sign (ref, signCommit or commit).
func change(signers []string, commit, ref, signCommit string) *Change {
	if commit == "" {
		commit = vC1
	}
	if ref == "" {
		ref = vREF
	}
	if signCommit == "" {
		signCommit = commit
	}
	sigs := map[string]string{}
	for _, p := range signers {
		sigs[p] = vw.sign(p, ref, signCommit)
	}
	return &Change{Ref: ref, Commit: commit, Pusher: "alice", Author: "carol", Signatures: sigs}
}

func TestPhaseAThresholdMetWithNestedRole(t *testing.T) {
	d := newTestVerifier(t).Check(change([]string{"alice", "dave"}, "", "", ""))
	if !d.Allowed || !reflect.DeepEqual(d.Signers, []string{"alice", "dave"}) {
		t.Errorf("got %v", d)
	}
}

func TestPhaseAThresholdNotMet(t *testing.T) {
	v := newTestVerifier(t)
	if v.Check(change([]string{"alice"}, "", "", "")).Allowed {
		t.Error("alice alone should not meet 2-of")
	}
	if v.Check(change([]string{"dave", "erin"}, "", "", "")).Allowed {
		t.Error("dave+erin satisfy only the one role")
	}
}

func TestPhaseASignatureOverOtherCommitRejected(t *testing.T) {
	d := newTestVerifier(t).Check(change([]string{"alice", "bob"}, "", "", vC2))
	if d.Allowed || len(d.Signers) != 0 {
		t.Errorf("got %v", d)
	}
}

func TestPhaseAWrongKeyRejected(t *testing.T) {
	c := change([]string{"alice", "bob"}, "", "", "")
	c.Signatures["bob"] = vw.sign("carol", vREF, vC1) // carol signs, claims to be bob
	d := newTestVerifier(t).Check(c)
	if d.Allowed || !reflect.DeepEqual(d.Signers, []string{"alice"}) {
		t.Errorf("got %v", d)
	}
}

func TestPhaseAGarbageSignatureDoesNotCrash(t *testing.T) {
	c := change([]string{"alice", "bob"}, "", "", "")
	c.Signatures["bob"] = "zz"
	if newTestVerifier(t).Check(c).Allowed {
		t.Error("garbage signature accepted")
	}
}

func TestPhaseALazyVerificationOnlyForRelevantPrincipals(t *testing.T) {
	v := newTestVerifier(t)
	all := []string{"alice", "bob", "carol", "dave", "erin"}
	if n := v.Check(change(all, "", "", "")).SigChecks; n != 4 {
		t.Errorf("sig checks = %d, want 4 (carol is not named by the main rule)", n)
	}
	if n := v.Check(change([]string{"alice", "bob", "carol"}, "", "refs/other/x", "")).SigChecks; n != 0 {
		t.Errorf("sig checks = %d, want 0 (no rule matches)", n)
	}
}

// Count-once path: one key bound to two principal names.
func TestSharedKeyRejected(t *testing.T) {
	for _, alias := range []string{vw.pk["alice"], strings.ToUpper(vw.pk["alice"])} {
		doc := verifierTestDoc()
		doc.Principals = map[string]string{}
		for k, v := range vw.pk {
			doc.Principals[k] = v
		}
		doc.Principals["alice2"] = alias
		doc.Rules[0].Members = []string{"alice", "alice2", "bob"}
		if _, err := NewVerifier(doc); err == nil || !strings.Contains(err.Error(), "same public key") {
			t.Errorf("alias %.8s...: want same-public-key error, got %v", alias, err)
		}
	}
}

// --- forge data -------------------------------------------------------

const forgeRef = "refs/heads/feature/x"

func pr(reviews []Review, dismissals []Dismissal, author string) *Change {
	if author == "" {
		author = "carol"
	}
	return &Change{Ref: forgeRef, Commit: vC1, Pusher: "alice", Author: author, Signatures: map[string]string{},
		Forge: &Forge{Head: vC1, Reviews: reviews, Dismissals: dismissals}}
}

func rv(who, state, commit string, at int) Review {
	if state == "" {
		state = "APPROVED"
	}
	if commit == "" {
		commit = vC1
	}
	if at == 0 {
		at = 1
	}
	return Review{Who: who, State: state, Commit: commit, At: at}
}

func TestForgeTwoFreshApprovals(t *testing.T) {
	if !newTestVerifier(t).Check(pr([]Review{rv("alice", "", "", 0), rv("bob", "", "", 0)}, nil, "")).Allowed {
		t.Error("two fresh approvals should allow")
	}
}

func TestForgeStaleApprovalAfterNewCommit(t *testing.T) {
	d := newTestVerifier(t).Check(pr([]Review{rv("alice", "", "", 0), rv("bob", "", vC2, 0)}, nil, ""))
	if d.Allowed || !reflect.DeepEqual(d.Approvals, []string{"alice"}) {
		t.Errorf("got %v", d)
	}
}

func TestForgeDismissedApproval(t *testing.T) {
	d := newTestVerifier(t).Check(pr([]Review{rv("alice", "", "", 1), rv("bob", "", "", 1)}, []Dismissal{{"bob", 2}}, ""))
	if d.Allowed {
		t.Errorf("got %v", d)
	}
}

func TestForgeReapprovalAfterDismissalCounts(t *testing.T) {
	d := newTestVerifier(t).Check(pr([]Review{rv("alice", "", "", 1), rv("bob", "", "", 3)}, []Dismissal{{"bob", 2}}, ""))
	if !d.Allowed {
		t.Errorf("got %v", d)
	}
}

func TestForgeLaterChangesRequestedSupersedesApproval(t *testing.T) {
	d := newTestVerifier(t).Check(pr([]Review{rv("alice", "", "", 1), rv("bob", "", "", 1), rv("bob", "CHANGES_REQUESTED", "", 2)}, nil, ""))
	if d.Allowed {
		t.Errorf("got %v", d)
	}
}

func TestForgeSelfApprovalForbidden(t *testing.T) {
	d := newTestVerifier(t).Check(pr([]Review{rv("alice", "", "", 0), rv("bob", "", "", 0), rv("carol", "", "", 0)}, nil, "carol"))
	if d.Allowed {
		t.Error("carol approved her own PR; forbid should override the permit")
	}
	// Cedar reports the forbid that fired, so the denial is explainable.
	if len(d.Reasons) != 1 || d.Reasons[0].Kind != "forbid" || d.Reasons[0].Rule != "<self-approval>" {
		t.Errorf("reasons = %+v", d.Reasons)
	}
}
