package gcedar

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Signed-field cases (carried over from the archived prototype's tests),
// plus count-once paths.

var fw = makeWorld("k1", "k2", "k3")

func fieldPolicy() *FieldPolicy {
	return &FieldPolicy{Keys: fw.pk, Fields: map[string]FieldSpec{
		"expires": {Threshold: 1, Keys: []string{"k1", "k2"}},
		"targets": {Threshold: 2, Keys: []string{"k1", "k2", "k3"}},
	}}
}

func field(t *testing.T, name string, value any, signers []string, tamper bool) SignedField {
	t.Helper()
	msg, err := Canonical(name, value)
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		msg = append([]byte("x"), msg...)
	}
	sigs := map[string]string{}
	for _, k := range signers {
		sigs[k] = hex.EncodeToString(ed25519.Sign(fw.sk[k], msg))
	}
	return SignedField{Value: value, Sigs: sigs}
}

func fieldDoc(t *testing.T, over map[string]SignedField) *FieldDoc {
	d := &FieldDoc{Fields: map[string]SignedField{
		"expires": field(t, "expires", "2027-01-01", []string{"k2"}, false),
		"targets": field(t, "targets", map[string]any{"a": 1}, []string{"k1", "k3"}, false),
	}}
	for k, v := range over {
		d.Fields[k] = v
	}
	return d
}

func newFieldVerifier(t *testing.T) *FieldVerifier {
	t.Helper()
	v, err := NewFieldVerifier(fieldPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFieldsAccept(t *testing.T) {
	if r := newFieldVerifier(t).Check(fieldDoc(t, nil)); !r.Accepted {
		t.Errorf("got %+v", r)
	}
}

func TestFieldsValueChangedAfterSigning(t *testing.T) {
	d := fieldDoc(t, nil)
	f := d.Fields["expires"]
	f.Value = "2099-01-01"
	d.Fields["expires"] = f
	r := newFieldVerifier(t).Check(d)
	if r.Accepted || r.Fields["expires"] {
		t.Errorf("got %+v", r)
	}
}

func TestFieldsThresholdOnField(t *testing.T) {
	r := newFieldVerifier(t).Check(fieldDoc(t, map[string]SignedField{
		"targets": field(t, "targets", map[string]any{"a": 1}, []string{"k1"}, false)}))
	if r.Fields["targets"] {
		t.Errorf("got %+v", r)
	}
}

func TestFieldsKeyNotAllowedForField(t *testing.T) {
	r := newFieldVerifier(t).Check(fieldDoc(t, map[string]SignedField{
		"expires": field(t, "expires", "x", []string{"k3"}, false)})) // k3 not in expires' key set
	if r.Fields["expires"] {
		t.Errorf("got %+v", r)
	}
}

func TestFieldsUnknownFieldDeniedByDefault(t *testing.T) {
	r := newFieldVerifier(t).Check(fieldDoc(t, map[string]SignedField{
		"extra": field(t, "extra", 1, []string{"k1", "k2", "k3"}, false)}))
	if r.Fields["extra"] || r.Accepted {
		t.Errorf("got %+v", r)
	}
}

func TestFieldsMissingRequiredField(t *testing.T) {
	d := fieldDoc(t, nil)
	delete(d.Fields, "targets")
	r := newFieldVerifier(t).Check(d)
	if !reflect.DeepEqual(r.Missing, []string{"targets"}) || r.Accepted {
		t.Errorf("got %+v", r)
	}
}

func TestFieldsSignatureReplayedFromOtherField(t *testing.T) {
	d := fieldDoc(t, nil)
	d.Fields["expires"] = SignedField{Value: "2027-01-01", Sigs: d.Fields["targets"].Sigs}
	if r := newFieldVerifier(t).Check(d); r.Fields["expires"] {
		t.Errorf("got %+v", r)
	}
}

// A signature over different bytes (tamper=true) must not verify.
func TestFieldsTamperedSignature(t *testing.T) {
	r := newFieldVerifier(t).Check(fieldDoc(t, map[string]SignedField{
		"expires": field(t, "expires", "2027-01-01", []string{"k2"}, true)}))
	if r.Fields["expires"] {
		t.Errorf("got %+v", r)
	}
}

// Count-once paths for fields.
func TestFieldsKeyListedTwiceRejected(t *testing.T) {
	p := fieldPolicy()
	p.Fields["targets"] = FieldSpec{Threshold: 2, Keys: []string{"k1", "k1"}}
	_, err := NewFieldVerifier(p)
	var dup *DuplicateMemberError
	if !errors.As(err, &dup) {
		t.Errorf("want DuplicateMemberError, got %v", err)
	}
}

func TestFieldsSharedPublicKeyRejected(t *testing.T) {
	p := fieldPolicy()
	p.Keys = map[string]string{"k1": fw.pk["k1"], "k2": fw.pk["k2"], "k3": strings.ToUpper(fw.pk["k1"])}
	if _, err := NewFieldVerifier(p); err == nil || !strings.Contains(err.Error(), "same public key") {
		t.Errorf("want same-public-key error, got %v", err)
	}
}

// A field document read from JSON must verify when the value is an integer:
// default float64 decoding would re-encode 1 as "1.0" and break the signature.
func TestFieldsIntegerValueFromJSON(t *testing.T) {
	signed := field(t, "targets", map[string]any{"a": 1, "big": json.Number("12345678901234")}, []string{"k1", "k3"}, false)
	raw, _ := json.Marshal(map[string]any{"fields": map[string]any{
		"expires": field(t, "expires", "2027-01-01", []string{"k2"}, false),
		"targets": signed,
	}})
	var d FieldDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if r := newFieldVerifier(t).Check(&d); !r.Accepted {
		t.Errorf("integer-valued field decoded from JSON failed verification: %+v", r)
	}
}
