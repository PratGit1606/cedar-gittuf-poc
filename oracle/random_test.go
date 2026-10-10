package oracle

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/pratham/gcedar/gcedar"
)

var randPatterns = []string{
	"refs/heads/main", "refs/heads/*", "refs/heads/release/*", "*", "refs/heads/rel-?",
	"refs/heads/rel-[ab]", "refs/heads/rel-[!a]*", "refs/heads/*/b", "refs/heads/rel-*",
}

var randRefs = []string{
	"refs/heads/main", "refs/heads/x", "refs/heads/release/1", "refs/heads/rel-1",
	"refs/heads/rel-10", "refs/heads/rel-a", "refs/heads/rel-c", "refs/heads/q/b",
}

// randomFlatDoc draws a role-free, signers-only document. Some documents list
// a member twice; some give two principals the same key.
func randomFlatDoc(rng *rand.Rand) *gcedar.Doc {
	names := []string{"p0", "p1", "p2", "p3", "p4"}
	ps := map[string]string{}
	for _, n := range names {
		ps[n] = ""
	}
	if rng.Float64() < 0.15 {
		ps["p4"] = "key:p3" // p3 and p4 share p3's key
	}
	var rules []gcedar.Rule
	for i, n := 0, 1+rng.Intn(4); i < n; i++ {
		ms := sample(rng, names, 1+rng.Intn(4))
		if rng.Float64() < 0.15 {
			ms = append(ms, ms[0])
		}
		rules = append(rules, gcedar.Rule{Name: fmt.Sprintf("rule%d", i),
			Pattern:   randPatterns[rng.Intn(len(randPatterns))],
			Threshold: 1 + rng.Intn(len(ms)), Members: ms})
	}
	return &gcedar.Doc{Principals: ps, Rules: rules, Default: "allow"}
}

func sample[T any](rng *rand.Rand, pool []T, n int) []T {
	idx := rng.Perm(len(pool))[:n]
	out := make([]T, n)
	for i, j := range idx {
		out[i] = pool[j]
	}
	return out
}

// randomPush picks a ref and a set of signing keys (possibly including an
// outsider) and splits them between the RSL entry and attestations.
func randomPush(rng *rand.Rand) push {
	keys := sample(rng, []string{"p0", "p1", "p2", "p3", "p4", "mallory"}, rng.Intn(4))
	p := push{ref: randRefs[rng.Intn(len(randRefs))]}
	if len(keys) > 0 && rng.Float64() < 0.8 {
		p.pusher, keys = keys[0], keys[1:]
	}
	p.att = keys
	return p
}

// TestRandomAgainstGittuf compares gittuf against both compile modes on
// random documents. ORACLE_DOCS sets the number of documents (default 40).
func TestRandomAgainstGittuf(t *testing.T) {
	nDocs := 40
	if v, err := strconv.Atoi(os.Getenv("ORACLE_DOCS")); err == nil {
		nDocs = v
	}
	var mu sync.Mutex
	total := 0
	mism := map[gcedar.Mode]int{}
	compileErr := map[gcedar.Mode]int{}
	allows, sharedDocs, dupDocs, phaseADocs := 0, 0, 0, 0
	examples := map[gcedar.Mode][]string{}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for d := 0; d < nDocs; d++ {
		rng := rand.New(rand.NewSource(int64(1000 + d)))
		doc := randomFlatDoc(rng)
		var pushes []push
		for i := 0; i < 8; i++ {
			pushes = append(pushes, randomPush(rng))
		}
		if doc.Principals["p4"] != "" {
			sharedDocs++
		}
		for _, r := range doc.Rules {
			if hasDup(r.Members) {
				dupDocs++
				break
			}
		}
		for _, r := range doc.Rules {
			if gcedar.NeedsPhaseAMatch(r.Pattern) {
				phaseADocs++
				break
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d int) {
			defer wg.Done()
			defer func() { <-sem }()
			w, err := NewWorld(t.TempDir())
			if err != nil {
				t.Error(err)
				return
			}
			if err := Materialize(w, doc); err != nil {
				t.Errorf("doc %d: materialize: %v", d, err)
				return
			}
			for _, p := range pushes {
				ok, verr, err := PushScenario(w, p.ref, Scenario{Pusher: p.pusher, Attestors: p.att})
				if err != nil {
					t.Errorf("doc %d: harness: %v", d, err)
					return
				}
				if verr != nil && !isPolicyDenial(verr) {
					t.Errorf("doc %d: unexpected gittuf error: %v", d, verr)
					return
				}
				mu.Lock()
				total++
				if ok {
					allows++
				}
				for _, m := range ModesUnderTest {
					c, err := CedarVerdictMode(doc, m, p.ref, Scenario{Pusher: p.pusher, Attestors: p.att})
					if err != nil {
						compileErr[m]++
					}
					if err != nil || c != ok {
						mism[m]++
						if len(examples[m]) < 4 {
							j, _ := json.Marshal(doc)
							examples[m] = append(examples[m], fmt.Sprintf("doc %d push %+v gittuf=%v cedar=%v err=%v\n      %s", d, p, ok, c, err, j))
						}
					}
				}
				mu.Unlock()
			}
		}(d)
	}
	wg.Wait()
	t.Logf("%d docs (%d with a shared key, %d with a duplicated member, %d with a Phase-A-only pattern); %d pushes, gittuf allowed %d",
		nDocs, sharedDocs, dupDocs, phaseADocs, total, allows)
	for _, m := range ModesUnderTest {
		t.Logf("mode %-6s: %d/%d verdicts disagree with gittuf (%d of them: document does not compile in this mode)", m, mism[m], total, compileErr[m])
		for _, e := range examples[m] {
			t.Logf("   %s", e)
		}
	}
	if mism[gcedar.ModeGittuf] != 0 {
		t.Errorf("gittuf mode disagrees with gittuf on %d verdicts", mism[gcedar.ModeGittuf])
	}
}

func hasDup(xs []string) bool {
	seen := map[string]bool{}
	for _, x := range xs {
		if seen[x] {
			return true
		}
		seen[x] = true
	}
	return false
}
