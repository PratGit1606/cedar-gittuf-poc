package gcedar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Strict-mode extensions: except, top-level forbid, window and require.
// gittuf cannot express them, so gittuf mode rejects them. A document without
// them compiles to the same Cedar and schema as if this file did not exist.

// Window bounds when a rule may allow. Both bounds are inclusive.
type Window struct {
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

// Forbid denies writes to refs matching Pattern signed by any of Principals.
type Forbid struct {
	Name       string   `json:"name"`
	Pattern    string   `json:"pattern"`
	Principals []string `json:"principals"`
}

// ParseDoc decodes a delegation document, rejecting unknown fields, wrong
// types and trailing data.
func ParseDoc(b []byte) (*Doc, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d Doc
	if err := dec.Decode(&d); err != nil {
		return nil, errf("delegation document: %v", err)
	}
	if dec.More() {
		return nil, errf("delegation document: trailing data")
	}
	return &d, nil
}

// usesExtensions reports the strict-only extensions doc uses, for the gittuf
// mode error message.
func (d *Doc) usesExtensions() []string {
	var out []string
	if d.Forbid != nil {
		out = append(out, "forbid")
	}
	for _, r := range d.Rules {
		for _, f := range []struct {
			used bool
			name string
		}{{r.Except != nil, "except"}, {r.Window != nil, "window"}, {r.Require != nil, "require"}} {
			if f.used {
				out = append(out, "rule "+r.Name+": "+f.name)
			}
		}
	}
	return out
}

var factName = regexp.MustCompile(`^[a-z_]+$`)

// reservedFacts are context attributes the schema already has, plus Cedar
// keywords that cannot follow `context.`.
var reservedFacts = map[string]bool{
	"signers": true, "approvals": true, "author": true, "now": true,
	"true": true, "false": true, "if": true, "then": true, "else": true,
	"in": true, "is": true, "like": true, "has": true,
}

// principalList checks a forbid/except list (non-empty, known, no duplicates)
// and renders it as a Cedar list body.
func principalList(where string, ps []string, principals map[string]string) (string, error) {
	if len(ps) == 0 {
		return "", errf("%s: principal list is empty", where)
	}
	if err := checkDuplicates(ps); err != nil {
		return "", fmt.Errorf("%s: %w", where, err)
	}
	for _, p := range ps {
		if _, ok := principals[p]; !ok {
			return "", errf("%s: unknown principal %s", where, p)
		}
	}
	return entityList("User", ps)
}

// cedarDatetime parses an RFC 3339 timestamp and renders it as a Cedar
// datetime literal in UTC. Cedar datetimes have millisecond precision.
func cedarDatetime(where, s string) (string, time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", time.Time{}, errf("%s: bad RFC 3339 timestamp %q", where, s)
	}
	if y := t.UTC().Year(); y < 1 || y > 9999 {
		return "", time.Time{}, errf("%s: %q is outside years 0001-9999", where, s)
	}
	if t.Nanosecond()%int(time.Millisecond) != 0 {
		return "", time.Time{}, errf("%s: %q is finer than milliseconds", where, s)
	}
	layout := "2006-01-02T15:04:05Z"
	if t.Nanosecond() != 0 {
		layout = "2006-01-02T15:04:05.000Z"
	}
	return `datetime("` + t.UTC().Format(layout) + `")`, t, nil
}

// ruleConditions validates a rule's window and require and returns the extra
// conditions for each of its permits (each starting with " && "). Outside the
// window, or with a required fact false, the rule allows nothing.
func ruleConditions(r Rule, facts map[string]bool) (string, error) {
	var b strings.Builder
	if w := r.Window; w != nil {
		where := "rule " + r.Name + ": window"
		if w.NotBefore == "" && w.NotAfter == "" {
			return "", errf("%s: needs not_before or not_after", where)
		}
		var nb, na *time.Time
		if w.NotBefore != "" {
			lit, t, err := cedarDatetime(where, w.NotBefore)
			if err != nil {
				return "", err
			}
			nb = &t
			b.WriteString(" && context.now >= " + lit)
		}
		if w.NotAfter != "" {
			lit, t, err := cedarDatetime(where, w.NotAfter)
			if err != nil {
				return "", err
			}
			na = &t
			b.WriteString(" && context.now <= " + lit)
		}
		if nb != nil && na != nil && na.Before(*nb) {
			return "", errf("%s: not_after is before not_before", where)
		}
	}
	if r.Require != nil {
		if len(r.Require) == 0 {
			return "", errf("rule %s: require is empty", r.Name)
		}
		for _, name := range sortedKeys(r.Require) {
			if !factName.MatchString(name) || reservedFacts[name] {
				return "", errf("rule %s: require: bad fact name %q (want [a-z_]+, not a reserved name)", r.Name, name)
			}
			if !r.Require[name] {
				return "", errf("rule %s: require: %s must be true (only true is supported)", r.Name, name)
			}
			facts[name] = true
			b.WriteString(" && context." + name + " == true")
		}
	}
	return b.String(), nil
}

// extendSchema adds now and the host facts to the context record, only when
// the document uses them.
func extendSchema(usesNow bool, facts []string) string {
	extra := ""
	if usesNow {
		extra += ", now: datetime"
	}
	for _, f := range facts {
		extra += ", " + f + ": Bool"
	}
	if extra == "" {
		return Schema
	}
	return strings.Replace(Schema, "author: User }", "author: User"+extra+" }", 1)
}

// compileForbids emits one forbid per top-level forbid entry. Unlike an
// except, it applies to every ref its pattern matches.
func compileForbids(doc *Doc, emit func(kind, body string, m PolicyMeta)) error {
	if doc.Forbid == nil {
		return nil
	}
	if len(doc.Forbid) == 0 {
		return errf("forbid is empty; remove it or add at least one entry")
	}
	names := map[string]bool{}
	for _, r := range doc.Rules {
		names[r.Name] = true
	}
	for _, f := range doc.Forbid {
		if f.Name == "" || names[f.Name] {
			return errf("forbid %q: name must be non-empty and differ from every rule and forbid name", f.Name)
		}
		names[f.Name] = true
		pat, err := likePattern(f.Pattern)
		if err != nil {
			return err
		}
		users, err := principalList("forbid "+f.Name, f.Principals, doc.Principals)
		if err != nil {
			return err
		}
		emit("forbid", fmt.Sprintf("resource.name like %s && context.signers.containsAny([%s])", pat, users),
			PolicyMeta{Rule: f.Name, Combo: append([]string{}, f.Principals...)})
	}
	return nil
}
