package gcedar

import "testing"

func benchDoc(b *testing.B, d *Doc) {
	c, err := Compile(d)
	if err != nil {
		b.Fatal(err)
	}
	ev, err := NewEvaluator(d, c)
	if err != nil {
		b.Fatal(err)
	}
	names := sortedNames(d)
	f := Facts{Ref: "refs/heads/main", Pusher: names[0], Author: names[0], Signers: names[:1]}
	ents := ev.Entities(f.Ref)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.DecideWith(ents, f)
	}
}

func BenchmarkFlat3of2(b *testing.B)  { benchDoc(b, flatDoc(3, 2)) }
func BenchmarkFlat10of5(b *testing.B) { benchDoc(b, flatDoc(10, 5)) }
func BenchmarkFlat16of8(b *testing.B) { benchDoc(b, flatDoc(16, 8)) }
func BenchmarkNested5x5(b *testing.B) { benchDoc(b, nestedDoc(5, 5, 3, 3)) }
