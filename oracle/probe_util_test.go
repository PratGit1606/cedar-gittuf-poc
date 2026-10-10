package oracle

import (
	"strings"
	"testing"

	"github.com/pratham/gcedar/gcedar"
)

// push is one scenario against a ref.
type push struct {
	ref    string
	pusher string
	att    []string
}

// gittufVerdict runs a push and separates "policy said no" from harness failures.
func gittufVerdict(t *testing.T, w *World, p push) bool {
	t.Helper()
	ok, verr, err := PushScenario(w, p.ref, Scenario{Pusher: p.pusher, Attestors: p.att})
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	if verr != nil && !strings.Contains(verr.Error(), "gittuf policy verification failed") {
		t.Fatalf("unexpected gittuf error (not a policy denial): %v", verr)
	}
	return ok
}

// compareDoc materializes doc in a fresh gittuf world and compares every push
// against each Cedar compile mode. Returns per-mode mismatch counts.
func compareDoc(t *testing.T, label string, doc *gcedar.Doc, pushes []push, modes ...gcedar.Mode) map[gcedar.Mode]int {
	t.Helper()
	w, err := NewWorld(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := Materialize(w, doc); err != nil {
		t.Fatalf("[%s] materialize: %v", label, err)
	}
	mism := map[gcedar.Mode]int{}
	for _, p := range pushes {
		g := gittufVerdict(t, w, p)
		line := ""
		for _, m := range modes {
			c, err := CedarVerdictMode(doc, m, p.ref, Scenario{Pusher: p.pusher, Attestors: p.att})
			if err != nil {
				line += "  " + string(m) + "=ERR(" + err.Error() + ")"
				mism[m]++
				continue
			}
			mark := ""
			if c != g {
				mark = "≠"
				mism[m]++
			}
			line += "  " + string(m) + "=" + yn(c) + mark
		}
		t.Logf("[%s] %-28s pusher=%-6s attest=%-14v gittuf=%s%s", label, p.ref, p.pusher, p.att, yn(g), line)
	}
	return mism
}

func yn(b bool) string {
	if b {
		return "allow"
	}
	return "deny"
}
