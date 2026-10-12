package oracle

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pratham/gcedar/gcedar"
)

// Scenario is one push: who signs the RSL entry (empty = unsigned) and who
// signs a reference authorization attestation for the change.
type Scenario struct {
	Pusher    string
	Attestors []string
}

// keyName is the SSH key backing a doc principal: the principal's own name,
// or "<name>" when the doc gives "key:<name>" (used to make principals share
// a key).
func keyName(doc *gcedar.Doc, principal string) string {
	if v := doc.Principals[principal]; strings.HasPrefix(v, "key:") {
		return strings.TrimPrefix(v, "key:")
	}
	return principal
}

// Materialize writes a role-free doc into w's "targets" rule file. Principals
// that share a key become tufv02 persons named after the principal; the rest
// are plain SSH keys. Members are passed verbatim, duplicates included.
func Materialize(w *World, doc *gcedar.Doc) error {
	ids, err := gittufIDs(doc)
	if err != nil {
		return err
	}
	byKey := map[string][]string{}
	names := make([]string, 0, len(doc.Principals))
	for n := range doc.Principals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		byKey[keyName(doc, n)] = append(byKey[keyName(doc, n)], n)
	}
	for _, n := range names {
		k, err := GetKey(keyName(doc, n))
		if err != nil {
			return err
		}
		if len(byKey[keyName(doc, n)]) > 1 {
			if err := w.AddPerson("targets", n, k); err != nil {
				return err
			}
		} else if err := w.AddKeys("targets", k); err != nil {
			return err
		}
	}
	for _, r := range doc.Rules {
		if r.Source != "" && r.Source != "signers" {
			return fmt.Errorf("rule %s: source %q not materializable", r.Name, r.Source)
		}
		members := make([]string, len(r.Members))
		for i, m := range r.Members {
			members[i] = ids[m]
		}
		if err := w.AddRule("targets", r.Name, members, []string{"git:" + r.Pattern}, r.Threshold); err != nil {
			return fmt.Errorf("add rule %s: %w", r.Name, err)
		}
	}
	return w.Apply()
}

// gittufIDs maps doc principal names to the principal IDs gittuf will use.
func gittufIDs(doc *gcedar.Doc) (map[string]string, error) {
	count := map[string]int{}
	for n := range doc.Principals {
		count[keyName(doc, n)]++
	}
	out := map[string]string{}
	for n := range doc.Principals {
		if count[keyName(doc, n)] > 1 {
			out[n] = n // person
			continue
		}
		k, err := GetKey(keyName(doc, n))
		if err != nil {
			return nil, err
		}
		out[n] = k.ID
	}
	return out, nil
}

// ModesUnderTest are the compile modes compared against gittuf.
var ModesUnderTest = []gcedar.Mode{gcedar.ModeStrict, gcedar.ModeGittuf}

// forMode rewrites a test doc for a compile mode. Gittuf mode identifies
// principals by the key ID of their (possibly shared) SSH key.
func forMode(doc *gcedar.Doc, mode gcedar.Mode) (*gcedar.Doc, error) {
	d := *doc
	d.Principals = map[string]string{}
	for n := range doc.Principals {
		d.Principals[n] = ""
		if mode == gcedar.ModeGittuf {
			k, err := GetKey(keyName(doc, n))
			if err != nil {
				return nil, err
			}
			d.Principals[n] = k.ID
		}
	}
	return &d, nil
}

// CedarVerdictMode runs a scenario through the compiler and cedar-go. Phase A
// is simulated per mode: strict mode reports the principal names whose key
// signed; gittuf mode reports distinct key IDs and the fnmatch-only patterns.
func CedarVerdictMode(doc0 *gcedar.Doc, mode gcedar.Mode, ref string, s Scenario) (bool, error) {
	doc, err := forMode(doc0, mode)
	if err != nil {
		return false, err
	}
	c, err := gcedar.CompileMode(doc, mode)
	if err != nil {
		return false, err
	}
	ev, err := gcedar.NewEvaluator(doc, c)
	if err != nil {
		return false, err
	}
	signed := map[string]bool{} // key names that produced a signature
	for _, n := range append([]string{s.Pusher}, s.Attestors...) {
		if n != "" {
			signed[n] = true
		}
	}
	var names []string // principals whose key signed
	for n := range doc0.Principals {
		if signed[keyName(doc0, n)] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	f := gcedar.Facts{Ref: ref, Pusher: "pusher", Author: "pusher", Signers: names}
	if mode == gcedar.ModeGittuf {
		f.Signers = gcedar.KeyIDs(doc, names)
		f.MatchedPatterns = gcedar.MatchedPatterns(doc, ref)
	}
	d := ev.Decide(f)
	if len(d.Errors) > 0 {
		return false, fmt.Errorf("cedar errors: %v", d.Errors)
	}
	return d.Allowed, nil
}

// PushScenario runs a scenario through gittuf (nil verdict error = allow).
func PushScenario(w *World, ref string, s Scenario) (bool, error, error) {
	var pusher *Key
	if s.Pusher != "" {
		k, err := GetKey(s.Pusher)
		if err != nil {
			return false, nil, err
		}
		pusher = k
	}
	var att []*Key
	for _, a := range s.Attestors {
		k, err := GetKey(a)
		if err != nil {
			return false, nil, err
		}
		att = append(att, k)
	}
	verr, err := w.Push(ref, pusher, att)
	return verr == nil, verr, err
}

// isPolicyDenial distinguishes gittuf's "policy not met" from other failures
// (which would indicate a harness problem, not a verdict).
func isPolicyDenial(verr error) bool {
	return strings.Contains(verr.Error(), "gittuf policy verification failed")
}
