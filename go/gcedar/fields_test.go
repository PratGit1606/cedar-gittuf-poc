package gcedar

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Port of tests/test_fields.py (same cases), plus count-once paths and a
// byte-for-byte check of Canonical against Python's json.dumps.

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

// Python's test helper has a tamper flag; this exercises it.
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

// Canonical must produce Python's exact bytes so signatures interoperate.
func TestCanonicalMatchesPython(t *testing.T) {
	root, _ := filepath.Abs("../..")
	py := filepath.Join(root, ".venv/bin/python")
	if _, err := os.Stat(py); err != nil {
		t.Skipf("python venv not found at %s", py)
	}
	values := `["2027-01-01", {"b": 1, "a": [true, null, 2.5]}, "é ü 日本 😀", "q\"uo\\te\n\t\u0001\u007f", 1.0, 0.0001, 1e-05, 1e16, 123456789.25, -0.0, 12345678901234, {"ä": 1, "z": 2, "A": 3}, []]`
	var vs []any
	dec := json.NewDecoder(strings.NewReader(values))
	dec.UseNumber()
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	script := `
import json, sys
sys.path.insert(0, sys.argv[1])
from gcedar.fields import canonical
for v in json.loads(sys.argv[2]):
    print(canonical("f", v).hex())
`
	out, err := exec.Command(py, "-c", script, root, values).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(out))
	for i, v := range vs {
		got, err := Canonical("f", toPlain(v))
		if err != nil {
			t.Fatal(err)
		}
		w, _ := hex.DecodeString(want[i])
		if string(got) != string(w) {
			t.Errorf("value %d: go %s, python %s", i, got, w)
		}
	}
}

// toPlain keeps json.Number (so ints stay ints) and converts containers.
func toPlain(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toPlain(e)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = toPlain(e)
		}
		return out
	}
	return v
}

// CompileFields emits the same Cedar text as fields.py:compile_fields.
func TestCompileFieldsMatchesPython(t *testing.T) {
	root, _ := filepath.Abs("../..")
	py := filepath.Join(root, ".venv/bin/python")
	if _, err := os.Stat(py); err != nil {
		t.Skipf("python venv not found at %s", py)
	}
	p := fieldPolicy()
	p.Fields["big"] = FieldSpec{Threshold: 2, Keys: []string{"k3", "k1", "k2"}}
	j, _ := json.Marshal(p)
	script := `
import json, sys
sys.path.insert(0, sys.argv[1])
from gcedar.fields import compile_fields
sys.stdout.write(compile_fields(json.loads(sys.argv[2])))
`
	out, err := exec.Command(py, "-c", script, root, string(j)).Output()
	if err != nil {
		t.Fatal(err)
	}
	got, err := CompileFields(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(out) {
		t.Errorf("go:\n%s\npython:\n%s", got, out)
	}
}
