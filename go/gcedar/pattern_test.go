package gcedar

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

// cedarMatches evaluates a Cedar boolean expression over resource.name with
// cedar-go itself (not our GlobMatch), for each ref.
func cedarMatches(t *testing.T, expr string, refs []string) []bool {
	t.Helper()
	ps, err := cedar.NewPolicySetFromBytes("p", []byte(`permit(principal, action, resource) when { `+expr+` };`))
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	out := make([]bool, len(refs))
	for i, r := range refs {
		rid := cedar.NewEntityUID("Ref", cedar.String(r))
		ents := cedar.EntityMap{rid: {UID: rid, Attributes: cedar.NewRecord(cedar.RecordMap{"name": cedar.String(r)})}}
		d, _ := cedar.Authorize(ps, ents, cedar.Request{Principal: cedar.NewEntityUID("User", "u"), Action: cedar.NewEntityUID("Action", "write"), Resource: rid, Context: cedar.NewRecord(nil)})
		out[i] = d == cedar.Allow
	}
	return out
}

func corpus(rng *rand.Rand, n int) []string {
	parts := []string{"refs", "heads", "tags", "main", "rel-1", "rel-a", "rel-b", "rel-10", "x", "a", "b", "v1", "v2", ".", "-", "release", "c"}
	out := []string{"refs/heads/main", "refs/heads/a/b", "refs/heads/", "refs/heads/rel-1", "refs/heads/rel-10", "refs/heads/rel-a", "refs/heads/rel-c"}
	for i := 0; i < n; i++ {
		k := 1 + rng.Intn(5)
		var segs []string
		for j := 0; j < k; j++ {
			segs = append(segs, parts[rng.Intn(len(parts))])
		}
		out = append(out, strings.Join(segs, []string{"/", "", "/"}[rng.Intn(3)]))
	}
	return out
}

// `*`-only patterns: Cedar's like and gittuf's fnmatch(flags=0) agree, and
// in both `*` matches across `/`.
func TestStarPatternsAgreeWithFnmatch(t *testing.T) {
	if !GittufMatch("refs/heads/*", "refs/heads/feature/x") {
		t.Fatal("fnmatch flags=0: * should match /")
	}
	rng := rand.New(rand.NewSource(7))
	refs := corpus(rng, 3000)
	for _, p := range []string{"refs/heads/*", "*", "refs/*/main", "refs/heads/rel-*", "*main", "refs/heads/*/*", "**", "refs/heads/main", "*/*a*"} {
		got := cedarMatches(t, `resource.name like "`+p+`"`, refs)
		for i, r := range refs {
			if got[i] != GittufMatch(p, r) {
				t.Errorf("pattern %q ref %q: cedar like=%v fnmatch=%v", p, r, got[i], !got[i])
			}
		}
	}
}

// Positive bracket classes: our bounded rewrite to a disjunction of `like`
// patterns is exact on the corpus.
func TestBracketRewriteMatchesFnmatch(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	refs := corpus(rng, 3000)
	for _, p := range []string{"refs/heads/rel-[ab]", "refs/heads/rel-[a-c]*", "refs/heads/rel-[0-9]", "refs/heads/[mr]*", "refs/heads/rel-[ab-]", "refs/heads/rel-[a-b1]*"} {
		alts, ok := LikeAlternatives(p)
		if !ok {
			t.Fatalf("%q should be rewritable", p)
		}
		got := cedarMatches(t, likeDisjunction(alts), refs)
		for i, r := range refs {
			if got[i] != GittufMatch(p, r) {
				t.Errorf("pattern %q ref %q: cedar=%v fnmatch=%v (alts %v)", p, r, got[i], GittufMatch(p, r), alts)
			}
		}
		t.Logf("%-26s -> %d like alternatives", p, len(alts))
	}
	for _, p := range []string{"refs/heads/rel-?", "refs/heads/rel-[!a]", "refs/heads/rel-[^a]", `refs/heads/a\*`, "refs/heads/[a-z][a-z][a-z]"} {
		if _, ok := LikeAlternatives(p); ok {
			t.Errorf("%q must not be rewritten (no exact like form within bounds)", p)
		}
	}
}

// `?` and negated classes have no `like` equivalent: a search over every like
// pattern up to length 7 finds none with fnmatch's verdicts. (rel-1 and rel-2
// force a trailing `*`, which also matches rel-10.)
func TestLikeCannotExpressQuestionMark(t *testing.T) {
	cases := map[string][]string{
		"rel-?":    {"rel-1", "rel-2", "rel-0", "rel-10", "rel-", "rel-12", "re-1", "rel-11", "rel-21"},
		"rel-[!1]": {"rel-1", "rel-2", "rel-0", "rel-10", "rel-", "rel-12", "rel-21", "rel-01"},
	}
	alphabet := []rune("rel-120*")
	for target, refs := range cases {
		want := make([]bool, len(refs))
		for i, r := range refs {
			want[i] = GittufMatch(target, r)
		}
		found := ""
		var rec func(prefix string)
		tried := 0
		rec = func(prefix string) {
			if found != "" {
				return
			}
			tried++
			ok := true
			for i, r := range refs {
				if GlobMatch(prefix, r) != want[i] {
					ok = false
					break
				}
			}
			if ok {
				found = prefix
				return
			}
			if len(prefix) == 7 {
				return
			}
			for _, c := range alphabet {
				rec(prefix + string(c))
			}
		}
		rec("")
		if found != "" {
			t.Errorf("%s: like pattern %q reproduces fnmatch", target, found)
		}
		t.Logf("%-9s no single like pattern among %d candidates reproduces fnmatch on %v", target, tried, refs)
	}
	// GlobMatch is cedar-go's like semantics; spot-check that claim.
	got := cedarMatches(t, `resource.name like "rel-*"`, []string{"rel-1", "rel-10"})
	if fmt.Sprint(got) != "[true true]" || !GlobMatch("rel-*", "rel-10") {
		t.Fatal("GlobMatch disagrees with cedar-go like")
	}
}
