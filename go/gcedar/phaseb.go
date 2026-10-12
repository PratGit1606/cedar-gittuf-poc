package gcedar

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

// Facts is everything Phase A (the host) hands to Cedar. Cedar never sees
// signatures or keys, only which principals verifiably signed or approved.
type Facts struct {
	Ref       string
	Pusher    string
	Author    string
	Signers   []string // strict: principal names; gittuf mode: key IDs
	Approvals []string
	// MatchedPatterns (gittuf mode only) lists the rule patterns Cedar cannot
	// match itself that match Ref; see MatchedPatterns.
	MatchedPatterns []string
	// Now and Host feed strict-mode windows and require conditions. Cedar
	// trusts them: Now comes from the host clock, never from a timestamp the
	// signer controls, and a missing Host fact is false.
	Now  time.Time
	Host map[string]bool
}

// Decision is a Phase B verdict plus the compiled policies that determined it.
type Decision struct {
	Allowed bool
	Reasons []PolicyMeta
	Errors  []string // policy evaluation errors (should always be empty)
}

// Evaluator runs Phase B: Cedar authorization over host-provided facts.
type Evaluator struct {
	Compiled *Compiled
	ps       *cedar.PolicySet
	users    []string
}

// NewEvaluator parses the compiled policies and validates them against their
// schema (c.Schema) using cedar-go's experimental validator (strict mode).
func NewEvaluator(doc *Doc, c *Compiled) (*Evaluator, error) {
	ps, err := cedar.NewPolicySetFromBytes("compiled.cedar", []byte(c.Policies))
	if err != nil {
		return nil, fmt.Errorf("parse compiled policies: %w", err)
	}
	if err := ValidatePoliciesWith(c.Schema, ps); err != nil {
		return nil, err
	}
	users := make([]string, 0, len(doc.Principals))
	for u, k := range doc.Principals {
		if c.Mode == ModeGittuf {
			u = k
		}
		users = append(users, u)
	}
	return &Evaluator{Compiled: c, ps: ps, users: users}, nil
}

// ValidatePoliciesWith type-checks a policy set against a Cedar schema.
func ValidatePoliciesWith(schemaText string, ps *cedar.PolicySet) error {
	var s schema.Schema
	if err := s.UnmarshalCedar([]byte(schemaText)); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	rs, err := s.Resolve()
	if err != nil {
		return fmt.Errorf("schema resolve: %w", err)
	}
	v := validate.New(rs, validate.WithStrict())
	var errs []string
	for id, p := range ps.All() {
		if err := v.Policy(string(id), (*ast.Policy)(p.AST())); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("compiled Cedar failed schema validation: %s", strings.Join(errs, "; "))
	}
	return nil
}

func userSet(ids []string) cedar.Set {
	vs := make([]cedar.Value, len(ids))
	for i, id := range ids {
		vs[i] = cedar.NewEntityUID("User", cedar.String(id))
	}
	return cedar.NewSet(vs...)
}

// Entities builds the entity store for one request.
func (e *Evaluator) Entities(ref string) cedar.EntityMap {
	m := cedar.EntityMap{}
	for _, u := range e.users {
		uid := cedar.NewEntityUID("User", cedar.String(u))
		m[uid] = cedar.Entity{UID: uid}
	}
	rid := cedar.NewEntityUID("Ref", cedar.String(ref))
	m[rid] = cedar.Entity{UID: rid, Attributes: cedar.NewRecord(cedar.RecordMap{"name": cedar.String(ref)})}
	return m
}

// RequestMode builds the Cedar request for a set of facts; the context record
// matches c's schema.
func RequestMode(c *Compiled, f Facts) cedar.Request {
	mode := c.Mode
	ctx := cedar.RecordMap{
		"signers":   userSet(f.Signers),
		"approvals": userSet(f.Approvals),
		"author":    cedar.NewEntityUID("User", cedar.String(f.Author)),
	}
	if mode == ModeGittuf {
		pats := make([]cedar.Value, len(f.MatchedPatterns))
		for i, p := range f.MatchedPatterns {
			pats[i] = cedar.String(p)
		}
		ctx = cedar.RecordMap{"signers": userSet(f.Signers), "matchedPatterns": cedar.NewSet(pats...)}
	}
	if c.UsesNow {
		ctx["now"] = types.NewDatetime(f.Now)
	}
	for _, name := range c.HostFacts {
		ctx[cedar.String(name)] = cedar.Boolean(f.Host[name])
	}
	return cedar.Request{
		Principal: cedar.NewEntityUID("User", cedar.String(f.Pusher)),
		Action:    cedar.NewEntityUID("Action", "write"),
		Resource:  cedar.NewEntityUID("Ref", cedar.String(f.Ref)),
		Context:   cedar.NewRecord(ctx),
	}
}

// Decide runs Phase B for one set of facts.
func (e *Evaluator) Decide(f Facts) Decision {
	return e.DecideWith(e.Entities(f.Ref), f)
}

// DecideWith is Decide with a caller-supplied entity store (for batching).
func (e *Evaluator) DecideWith(ents cedar.EntityMap, f Facts) Decision {
	if e.Compiled.UsesNow && f.Now.IsZero() {
		return Decision{Errors: []string{"policy needs context.now but the host supplied no time"}} // fail closed
	}
	dec, diag := cedar.Authorize(e.ps, ents, RequestMode(e.Compiled, f))
	d := Decision{Allowed: dec == cedar.Allow}
	for _, r := range diag.Reasons {
		d.Reasons = append(d.Reasons, e.meta(r.PolicyID))
	}
	for _, er := range diag.Errors {
		d.Errors = append(d.Errors, fmt.Sprintf("%s: %s", er.PolicyID, er.Message))
	}
	return d
}

func (e *Evaluator) meta(id cedar.PolicyID) PolicyMeta {
	i, err := strconv.Atoi(strings.TrimPrefix(string(id), "policy"))
	if err != nil || i < 0 || i >= len(e.Compiled.Meta) {
		return PolicyMeta{Kind: "?", Rule: string(id)}
	}
	return e.Compiled.Meta[i]
}
