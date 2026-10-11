package gcedar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/cedar-policy/cedar-go"
)

// Signed fields (port of ../gcedar/fields.py): "field X must be signed by a
// threshold of keys in set Y".
//
// A document is a set of fields, each carrying signatures. Phase A verifies the
// signatures over a canonical encoding of (field name, value) and builds one
// Cedar Field entity per field whose `signers` attribute holds only keys that
// verified. Phase B asks Cedar whether each field is accepted. The document is
// accepted iff every field is accepted and every field the policy requires is
// present (the loop over fields is host-side; Cedar has no loops).
//
// Policy document:
//
//	{"keys": {"k1": "<pubkey hex>", ...},
//	 "fields": {"expires": {"threshold": 1, "keys": ["k1", "k2"]},
//	            "targets": {"threshold": 2, "keys": ["k1", "k2", "k3"]}}}

// FieldSchema is the Cedar schema for field policies.
const FieldSchema = `entity Doc;
entity Key;
entity Field { name: String, signers: Set<Key> };
action accept appliesTo { principal: Doc, resource: Field, context: {} };
`

// FieldSpec is the signing requirement for one field.
type FieldSpec struct {
	Threshold int      `json:"threshold"`
	Keys      []string `json:"keys"`
}

// FieldPolicy maps key names to public keys and fields to requirements.
type FieldPolicy struct {
	Keys   map[string]string    `json:"keys"`
	Fields map[string]FieldSpec `json:"fields"`
}

// SignedField is one field of a document: its value and signatures by key name.
type SignedField struct {
	Value any               `json:"value"`
	Sigs  map[string]string `json:"sigs"`
}

// UnmarshalJSON decodes Value with json.Number so integers stay integers:
// the default float64 decoding would encode 1 as "1.0" in Canonical, while
// the signer (and Python's json.dumps) encoded "1".
func (f *SignedField) UnmarshalJSON(b []byte) error {
	var raw struct {
		Value json.RawMessage   `json:"value"`
		Sigs  map[string]string `json:"sigs"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	f.Sigs = raw.Sigs
	f.Value = nil
	if len(raw.Value) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw.Value))
	dec.UseNumber()
	return dec.Decode(&f.Value)
}

// FieldDoc is a document of signed fields.
type FieldDoc struct {
	Fields map[string]SignedField `json:"fields"`
}

// Canonical is the signed encoding of a field: the same bytes as Python's
// json.dumps([name, value], sort_keys=True, separators=(",", ":")), so
// signatures made by the Python tool verify here. Supported values: nil, bool,
// string, int, float64, json.Number, []any, map[string]any.
func Canonical(name string, value any) ([]byte, error) {
	var b strings.Builder
	if err := canon(&b, []any{name, value}); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func canon(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		pyString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		s, err := pyFloat(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			b.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		f, err := x.Float64()
		if err != nil {
			return err
		}
		return canon(b, f)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return pyLess(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			pyString(b, k)
			b.WriteByte(':')
			if err := canon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported value type %T", v)
	}
	return nil
}

// pyLess orders strings by code point, like Python's sorted().
func pyLess(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

// pyString writes s as Python's json.dumps does with ensure_ascii=True.
func pyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || (r > 0x7e && r <= 0xffff):
			fmt.Fprintf(b, `\u%04x`, r)
		case r > 0xffff:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(b, `\u%04x\u%04x`, r1, r2)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// pyFloat formats f like Python's float repr.
func pyFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("canonical: %v is not allowed", f)
	}
	a := math.Abs(f)
	switch {
	case a == 0 || (a >= 1e-4 && a < 1e16):
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.ContainsRune(s, '.') {
			s += ".0"
		}
		return s, nil
	default:
		return strconv.FormatFloat(f, 'e', -1, 64), nil
	}
}

// CompileFields emits one permit per field per minimal key set.
func CompileFields(p *FieldPolicy) (string, error) {
	names := make([]string, 0, len(p.Fields))
	for n := range p.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, fname := range names {
		spec := p.Fields[fname]
		for _, k := range spec.Keys {
			if _, ok := p.Keys[k]; !ok {
				return "", errf("field %s: unknown key %s", fname, k)
			}
		}
		// ExpandThreshold also rejects a key listed twice.
		combos, err := ExpandThreshold(spec.Keys, spec.Threshold, nil, nil)
		if err != nil {
			return "", fmt.Errorf("field %s: %w", fname, err)
		}
		sort.Slice(combos, func(i, j int) bool { return lessPset(combos[i], combos[j]) })
		fq, err := cedarStr(fname)
		if err != nil {
			return "", err
		}
		for _, combo := range combos {
			ks, err := entityList("Key", combo)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "permit(principal, action == Action::\"accept\", resource) when { resource.name == %s && resource.signers.containsAll([%s]) };\n",
				fq, ks)
		}
	}
	if b.Len() == 0 {
		return "\n", nil
	}
	return b.String(), nil
}

// FieldResult is the outcome of FieldVerifier.Check.
type FieldResult struct {
	Accepted  bool
	Fields    map[string]bool
	Missing   []string
	SigChecks int
}

// FieldVerifier checks signed-field documents against a FieldPolicy.
type FieldVerifier struct {
	Policy   *FieldPolicy
	Policies string
	ps       *cedar.PolicySet
}

// NewFieldVerifier compiles and validates the policy. Like NewVerifier, it
// refuses two key names bound to the same public key.
func NewFieldVerifier(p *FieldPolicy) (*FieldVerifier, error) {
	byKey := map[string]string{}
	names := make([]string, 0, len(p.Keys))
	for n := range p.Keys {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		k := strings.ToLower(p.Keys[n])
		if other, ok := byKey[k]; ok {
			return nil, errf("keys %s and %s have the same public key; a key may count only once", other, n)
		}
		byKey[k] = n
	}
	text, err := CompileFields(p)
	if err != nil {
		return nil, err
	}
	ps, err := cedar.NewPolicySetFromBytes("fields.cedar", []byte(text))
	if err != nil {
		return nil, err
	}
	if err := ValidatePoliciesWith(FieldSchema, ps); err != nil {
		return nil, err
	}
	return &FieldVerifier{Policy: p, Policies: text, ps: ps}, nil
}

// Check runs Phase A (signature checks, lazily: only keys the field's rule
// names) and Phase B (one Cedar request per field).
func (v *FieldVerifier) Check(doc *FieldDoc) FieldResult {
	ents := cedar.EntityMap{}
	docUID := cedar.NewEntityUID("Doc", "d")
	ents[docUID] = cedar.Entity{UID: docUID}
	for k := range v.Policy.Keys {
		uid := cedar.NewEntityUID("Key", cedar.String(k))
		ents[uid] = cedar.Entity{UID: uid}
	}
	res := FieldResult{Fields: map[string]bool{}}
	for name, f := range doc.Fields {
		var verified []cedar.Value
		if spec, ok := v.Policy.Fields[name]; ok {
			payload, err := Canonical(name, f.Value)
			for _, k := range spec.Keys {
				sig, ok := f.Sigs[k]
				if !ok || err != nil {
					continue
				}
				res.SigChecks++
				if VerifySig(v.Policy.Keys[k], sig, payload) {
					verified = append(verified, cedar.NewEntityUID("Key", cedar.String(k)))
				}
			}
		}
		uid := cedar.NewEntityUID("Field", cedar.String(name))
		ents[uid] = cedar.Entity{UID: uid, Attributes: cedar.NewRecord(cedar.RecordMap{
			"name": cedar.String(name), "signers": cedar.NewSet(verified...)})}
	}
	for name := range doc.Fields {
		d, _ := cedar.Authorize(v.ps, ents, cedar.Request{
			Principal: docUID, Action: cedar.NewEntityUID("Action", "accept"),
			Resource: cedar.NewEntityUID("Field", cedar.String(name)), Context: cedar.NewRecord(nil)})
		res.Fields[name] = d == cedar.Allow
	}
	for name := range v.Policy.Fields {
		if _, ok := doc.Fields[name]; !ok {
			res.Missing = append(res.Missing, name)
		}
	}
	sort.Strings(res.Missing)
	res.Accepted = len(res.Fields) > 0 && len(res.Missing) == 0
	for _, ok := range res.Fields {
		res.Accepted = res.Accepted && ok
	}
	return res
}
