package oracle

import (
	"testing"

	"github.com/pratham/gcedar/gcedar"
)

func oneRule(pattern string, k int, members ...string) *gcedar.Doc {
	return &gcedar.Doc{Principals: principals("alice", "bob", "carol"), Default: "allow",
		Rules: []gcedar.Rule{{Name: "r", Pattern: pattern, Threshold: k, Members: members}}}
}

// Pattern semantics end to end (`*` vs `/`, ?, [..], [!..]).
func TestProbePatterns(t *testing.T) {
	for _, c := range []struct {
		pattern string
		refs    []string
	}{
		{"refs/heads/*", []string{"refs/heads/feature/x", "refs/heads/x"}},
		{"refs/heads/*/main", []string{"refs/heads/a/b/main", "refs/heads/main"}},
		{"refs/heads/rel-?", []string{"refs/heads/rel-1", "refs/heads/rel-10"}},
		{"refs/heads/rel-[ab]", []string{"refs/heads/rel-a", "refs/heads/rel-c"}},
		{"refs/heads/rel-[!a]*", []string{"refs/heads/rel-a1", "refs/heads/rel-b1"}},
	} {
		var ps []push
		for _, r := range c.refs {
			ps = append(ps, push{r, "bob", nil}, push{r, "alice", nil})
		}
		compareDoc(t, c.pattern, oneRule(c.pattern, 1, "alice"), ps, ModesUnderTest...)
	}
}

// Unprotected refs and default deny.
func TestProbeUnprotected(t *testing.T) {
	doc := oneRule(main, 1, "alice")
	ps := []push{{"refs/heads/other", "", nil}, {"refs/heads/other", "mallory", nil}}
	compareDoc(t, "default allow", doc, ps, ModesUnderTest...)
	deny := *doc
	deny.Default = "deny"
	// gittuf has no default; this doc materializes identically, so gittuf's
	// answer is the same. Strict mode honours default deny; gittuf mode
	// refuses to compile it.
	compareDoc(t, "default deny", &deny, ps, ModesUnderTest...)
	catchAll := *doc
	catchAll.Rules = append(append([]gcedar.Rule{}, doc.Rules...), gcedar.Rule{Name: "catch-all", Pattern: "*", Threshold: 1, Members: []string{"alice", "bob", "carol"}})
	compareDoc(t, "catch-all * rule", &catchAll, append(ps, push{"refs/heads/other", "bob", nil}), ModesUnderTest...)
}

// Duplicate members and shared keys, in both modes.
func TestProbeDuplicatesModes(t *testing.T) {
	ps := []push{{main, "alice", nil}, {main, "alice", []string{"bob"}}, {main, "bob", nil}}
	compareDoc(t, "2-of-[alice,alice]", oneRule(main, 2, "alice", "alice"), ps, ModesUnderTest...)
	compareDoc(t, "2-of-[alice,alice,bob]", oneRule(main, 2, "alice", "alice", "bob"), ps, ModesUnderTest...)

	shared := &gcedar.Doc{Default: "allow",
		Principals: map[string]string{"p1": "key:shared", "p2": "key:shared", "p3": "key:carol"},
		Rules:      []gcedar.Rule{{Name: "r", Pattern: main, Threshold: 2, Members: []string{"p1", "p2", "p3"}}}}
	compareDoc(t, "p1,p2 share key; 2-of-[p1,p2,p3]", shared,
		[]push{{main, "shared", nil}, {main, "shared", []string{"shared"}}, {main, "shared", []string{"carol"}}}, ModesUnderTest...)
}
