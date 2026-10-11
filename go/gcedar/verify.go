package gcedar

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Two-phase verifier, strict mode.
//
// Phase A (host): everything Cedar must never do itself - parse untrusted
// data, verify ed25519 signatures, interpret forge review data. Its output is
// plain facts: which principals verifiably signed, which approvals are fresh.
//
// Phase B (Cedar): given those facts as request context, decide.

// RSLPayload is the byte string a principal signs to authorize ref -> commit.
// It is this POC's own encoding, not gittuf's RSL entry format.
func RSLPayload(ref, commit string) []byte {
	return []byte("gittuf-rsl\n" + ref + "\n" + commit)
}

// VerifySig checks a hex ed25519 signature by a hex public key. Malformed
// input is simply "not verified".
func VerifySig(pubHex, sigHex string, payload []byte) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

// Review is one forge review event.
type Review struct {
	Who    string `json:"who"`
	State  string `json:"state"` // "APPROVED", "CHANGES_REQUESTED", ...
	Commit string `json:"commit"`
	At     int    `json:"at"`
}

// Dismissal is a forge event dismissing Who's review at time At.
type Dismissal struct {
	Who string `json:"who"`
	At  int    `json:"at"`
}

// Forge is review data for a change. It is trusted as given.
type Forge struct {
	Head       string      `json:"head"`
	Reviews    []Review    `json:"reviews"`
	Dismissals []Dismissal `json:"dismissals"`
}

// FreshApprovals returns approvers whose latest review is an approval of the
// current head and was not dismissed afterwards. Cedar cannot filter or count
// over record sets, so this filtering has to happen in Phase A.
func FreshApprovals(f *Forge) []string {
	if f == nil {
		return nil
	}
	reviews := append([]Review{}, f.Reviews...)
	sort.SliceStable(reviews, func(i, j int) bool { return reviews[i].At < reviews[j].At })
	latest := map[string]Review{}
	for _, r := range reviews {
		latest[r.Who] = r
	}
	dismissedAt := map[string]int{}
	for _, d := range f.Dismissals {
		if at, ok := dismissedAt[d.Who]; !ok || d.At > at {
			dismissedAt[d.Who] = d.At
		}
	}
	var out []string
	for who, r := range latest {
		at, dismissed := dismissedAt[who]
		if r.State == "APPROVED" && r.Commit == f.Head && (!dismissed || at < r.At) {
			out = append(out, who)
		}
	}
	sort.Strings(out)
	return out
}

// Change is an untrusted request to move Ref to Commit.
type Change struct {
	Ref        string            `json:"ref"`
	Commit     string            `json:"commit"`
	Pusher     string            `json:"pusher"`
	Author     string            `json:"author"`
	Signatures map[string]string `json:"signatures"` // principal -> hex signature over RSLPayload
	Forge      *Forge            `json:"forge,omitempty"`
}

// Verdict is the outcome of Check.
type Verdict struct {
	Decision
	Signers   []string
	Approvals []string
	SigChecks int
}

// Verifier runs both phases for a strict-mode document.
type Verifier struct {
	Doc  *Doc
	Eval *Evaluator
}

// NewVerifier compiles doc and refuses documents where two principals are
// bound to the same public key: otherwise one signature filed under both
// names would count twice (FINDINGS.md, Finding 5).
func NewVerifier(doc *Doc) (*Verifier, error) {
	if err := checkSharedKeys(doc.Principals, "principals"); err != nil {
		return nil, err
	}
	c, err := Compile(doc)
	if err != nil {
		return nil, err
	}
	ev, err := NewEvaluator(doc, c)
	if err != nil {
		return nil, err
	}
	return &Verifier{Doc: doc, Eval: ev}, nil
}

// checkSharedKeys rejects two names bound to the same public key (hex,
// case-insensitive): one signature filed under both would count twice.
func checkSharedKeys(keys map[string]string, noun string) error {
	byKey := map[string]string{}
	for _, n := range sortedKeys(keys) {
		k := strings.ToLower(keys[n])
		if other, ok := byKey[k]; ok {
			return errf("%s %s and %s have the same public key; a key may count only once", noun, other, n)
		}
		byKey[k] = n
	}
	return nil
}

// Candidates is the lazy-verification prefilter: only principals named
// (directly or through roles) by rules whose pattern matches ref.
func (v *Verifier) Candidates(ref string) []string {
	out := map[string]bool{}
	var walk func(m string, seen map[string]bool)
	walk = func(m string, seen map[string]bool) {
		if !strings.HasPrefix(m, "@") {
			out[m] = true
			return
		}
		if seen[m] {
			return
		}
		seen[m] = true
		for _, x := range v.Doc.Roles[m[1:]].Members {
			walk(x, seen)
		}
		delete(seen, m)
	}
	for _, r := range v.Doc.Rules {
		if GlobMatch(r.Pattern, ref) {
			for _, m := range r.Members {
				walk(m, map[string]bool{})
			}
		}
	}
	return sortedKeys(out)
}

// PhaseA verifies signatures and interprets forge data.
func (v *Verifier) PhaseA(ch *Change) (signers, approvals []string, checks int) {
	payload := RSLPayload(ch.Ref, ch.Commit)
	for _, p := range v.Candidates(ch.Ref) {
		sig, ok := ch.Signatures[p]
		if !ok {
			continue
		}
		checks++
		if VerifySig(v.Doc.Principals[p], sig, payload) {
			signers = append(signers, p)
		}
	}
	return signers, FreshApprovals(ch.Forge), checks
}

// Check runs Phase A then Phase B.
func (v *Verifier) Check(ch *Change) Verdict {
	signers, approvals, checks := v.PhaseA(ch)
	d := v.Eval.Decide(Facts{Ref: ch.Ref, Pusher: ch.Pusher, Author: ch.Author, Signers: signers, Approvals: approvals})
	return Verdict{Decision: d, Signers: signers, Approvals: approvals, SigChecks: checks}
}

func (v Verdict) String() string {
	return fmt.Sprintf("allowed=%v signers=%v approvals=%v", v.Allowed, v.Signers, v.Approvals)
}
