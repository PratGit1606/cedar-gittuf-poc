package oracle

import (
	"fmt"
	"sort"

	"github.com/pratham/gcedar/gcedar"
)

// Scenario is one push: who signs the RSL entry (empty = unsigned) and who
// signs a reference authorization attestation for the change.
type Scenario struct {
	Pusher    string
	Attestors []string
}

// Signers is what our Phase A would hand Cedar for this scenario: every policy
// principal that produced a valid signature (RSL entry or attestation).
func (s Scenario) Signers(doc *gcedar.Doc) []string {
	m := map[string]bool{}
	for _, n := range append([]string{s.Pusher}, s.Attestors...) {
		if _, ok := doc.Principals[n]; ok {
			m[n] = true
		}
	}
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Materialize writes a flat (role-free) delegation doc into w's "targets" rule
// file. Principals are SSH keys named after the doc's principal names; rule
// patterns get gittuf's "git:" scheme prefix. Rule members are passed to gittuf
// verbatim, duplicates included.
func Materialize(w *World, doc *gcedar.Doc) error {
	var keys []*Key
	names := make([]string, 0, len(doc.Principals))
	for n := range doc.Principals {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		k, err := GetKey(n)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	if err := w.AddKeys("targets", keys...); err != nil {
		return err
	}
	for _, r := range doc.Rules {
		if r.Source != "" && r.Source != "signers" {
			return fmt.Errorf("rule %s: source %q not materializable", r.Name, r.Source)
		}
		ids := make([]string, len(r.Members))
		for i, m := range r.Members {
			k, err := GetKey(m)
			if err != nil {
				return err
			}
			ids[i] = k.ID
		}
		if err := w.AddRule("targets", r.Name, ids, []string{"git:" + r.Pattern}, r.Threshold); err != nil {
			return fmt.Errorf("add rule %s: %w", r.Name, err)
		}
	}
	return w.Apply()
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

// CedarVerdict runs the same scenario through our compiler + cedar-go.
func CedarVerdict(doc *gcedar.Doc, ref string, s Scenario) (bool, error) {
	c, err := gcedar.Compile(doc)
	if err != nil {
		return false, err
	}
	ev, err := gcedar.NewEvaluator(doc, c)
	if err != nil {
		return false, err
	}
	pusher := s.Pusher
	if pusher == "" {
		pusher = "<unsigned>"
	}
	d := ev.Decide(gcedar.Facts{Ref: ref, Pusher: pusher, Author: pusher, Signers: s.Signers(doc)})
	if len(d.Errors) > 0 {
		return false, fmt.Errorf("cedar errors: %v", d.Errors)
	}
	return d.Allowed, nil
}
