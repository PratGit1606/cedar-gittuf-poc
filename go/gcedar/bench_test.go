package gcedar

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// Port of bench.py: how badly does threshold expansion blow up, and what does
// it cost per request? Run with:
//
//	go test ./gcedar -run '^$' -bench Expansion -benchtime 300x
//
// Metrics per config: candidates (upper bound before minimization), permits,
// KB of Cedar text, compile-ms, and ns/op = one Phase B authorization. As in
// bench.py, per-request latency is only measured up to 20,000 permits; flat
// configs must produce exactly C(n,k) permits.

type benchConfig struct {
	label string
	doc   *Doc
	flatN int // n, k for flat configs (0 for nested)
	flatK int
}

func benchConfigs() []benchConfig {
	var out []benchConfig
	for _, nk := range [][2]int{{3, 2}, {5, 3}, {7, 4}, {10, 3}, {10, 5}, {12, 6}, {15, 5}, {16, 8}, {20, 10}} {
		out = append(out, benchConfig{fmt.Sprintf("flat_%d-of-%d", nk[1], nk[0]), flatDoc(nk[0], nk[1]), nk[0], nk[1]})
	}
	for _, c := range [][4]int{{3, 3, 2, 2}, {4, 4, 2, 2}, {5, 5, 3, 3}, {6, 6, 3, 3}, {5, 8, 3, 4}, {8, 8, 4, 4}} {
		out = append(out, benchConfig{fmt.Sprintf("roles_%d-of-%d_each_%d-of-%d", c[2], c[0], c[3], c[1]), nestedDoc(c[0], c[1], c[2], c[3]), 0, 0})
	}
	return out
}

func binom(n, k int) int {
	r := 1
	for i := 1; i <= k; i++ {
		r = r * (n - k + i) / i
	}
	return r
}

func BenchmarkExpansion(b *testing.B) {
	for _, cfg := range benchConfigs() {
		b.Run(cfg.label, func(b *testing.B) {
			r := cfg.doc.Rules[0]
			cand, err := CountThreshold(r.Members, r.Threshold, cfg.doc.Roles, nil)
			if err != nil {
				b.Fatal(err)
			}
			start := time.Now()
			c, err := Compile(cfg.doc)
			compileMS := float64(time.Since(start).Microseconds()) / 1000
			var tl *ExpansionTooLarge
			if errors.As(err, &tl) {
				b.Skipf("REFUSED: %d candidates over the %d limit", cand, MaxCombinations)
			}
			if err != nil {
				b.Fatal(err)
			}
			if cfg.flatN > 0 && c.NPermit != binom(cfg.flatN, cfg.flatK) {
				b.Fatalf("%d permits, want C(%d,%d)=%d", c.NPermit, cfg.flatN, cfg.flatK, binom(cfg.flatN, cfg.flatK))
			}
			if c.NPermit > 20000 {
				b.ReportMetric(float64(cand), "candidates")
				b.ReportMetric(float64(c.NPermit), "permits")
				b.ReportMetric(float64(len(c.Policies))/1024, "KB")
				b.ReportMetric(compileMS, "compile-ms")
				b.Skipf("%d permits: latency not measured (bench.py limit 20,000); compile %.0f ms, %.0f KB", c.NPermit, compileMS, float64(len(c.Policies))/1024)
			}
			ev, err := NewEvaluator(cfg.doc, c)
			if err != nil {
				b.Fatal(err)
			}
			names := sortedNames(cfg.doc)
			ents := ev.Entities("refs/heads/main")
			i := 0
			for b.Loop() {
				// as bench.py: signer sets of growing size names[:1], names[:2], ...
				ev.DecideWith(ents, Facts{Ref: "refs/heads/main", Pusher: names[0], Author: names[0], Signers: names[:i%len(names)+1]})
				i++
			}
			b.ReportMetric(float64(cand), "candidates")
			b.ReportMetric(float64(c.NPermit), "permits")
			b.ReportMetric(float64(len(c.Policies))/1024, "KB")
			b.ReportMetric(compileMS, "compile-ms")
		})
	}
}
