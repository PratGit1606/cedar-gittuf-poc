# Cedar × gittuf proof of concept

[gittuf](https://github.com/gittuf/gittuf) adds security policy to Git, such
as "two of these three maintainers must sign before anything lands on
`main`". This repository tests whether [Cedar](https://www.cedarpolicy.com/),
AWS's small policy language with a Go implementation and an SMT-based
analyzer, could decide those policies instead of gittuf's own Go code.

## How it works

One push goes through four steps:

1. **Write a delegation** (JSON): who the principals are and which rules
   protect which refs.
2. **Compile it** to Cedar policies (`gcedar compile`). Each k-of-n rule
   becomes one `permit` per minimal set of signers.
3. **Phase A, on the host:** verify the push's signatures and read forge data.
   The result is plain facts, such as "alice and bob validly signed".
4. **Phase B, in Cedar:** given only those facts, Cedar allows or denies and
   reports which policies fired.

This delegation says that `main` needs both alice and bob:

```json
{"principals": {"alice": "<alice's key>", "bob": "<bob's key>"},
 "rules": [{"name": "main", "pattern": "refs/heads/main", "threshold": 2,
            "members": ["alice", "bob"]}]}
```

It compiles to this Cedar policy:

```
permit(principal, action == Action::"write", resource) when { resource.name like "refs/heads/main" && context.signers.containsAll([User::"alice", User::"bob"]) };
```

Cedar never sees a key or a signature. That keeps it small enough to analyze,
but **Cedar trusts whatever Phase A tells it**.

## Run it

Requirements: Go 1.27+, git and ssh-keygen. The proofs also need Rust 1.89 or
newer, curl and unzip.

```sh
# 1. Unit, differential and capability tests (no network)
cd go && go test ./...

# 2. The demo: compile a delegation, then check four signed pushes
go run ./cmd/gcedar demo
go run ./cmd/gcedar compile -mode gittuf ../smt/docs/p1_broad.json   # print compiled Cedar
go run ./cmd/gcedar compile ../smt/docs/p4_window.json                # strict mode, with a time window

# 3. Compare with real gittuf: clone gittuf at the pinned commit, then run the oracle
cd .. && oracle/setup.sh
cd oracle && go test ./...                 # 2 to 6 min; ORACLE_DOCS=300 for the large random run

# 4. The SMT proofs (downloads cvc5 1.2.1 on the first run)
cd .. && smt/run.sh                        # set CARGO=/path/to/cargo if your Rust is older than 1.89
```

`oracle/setup.sh` puts the gittuf checkout in `.gittuf-oracle/` (gitignored).
Set `GITTUF=/some/dir` to put it elsewhere. If you run the oracle tests
before `setup.sh`, Go stops with `replacement directory ../.gittuf-oracle does
not exist`. Run `oracle/setup.sh` first.

## Repository layout

| Path | What it is |
|---|---|
| `go/gcedar/` | The library, in flow order: `compile.go` and `threshold.go` (JSON → strict-mode Cedar), `gittufmode.go` (gittuf semantics), `extensions.go` (`except`, `forbid`, `window`, `require`), `phasea.go` (signatures and forge data → facts), `phaseb.go` (facts → Cedar decision). `fields.go` is the separate field-signing example; `reference.go` is the independent reference the tests compare against |
| `go/cmd/gcedar/` | CLI: `gcedar compile [-mode strict\|gittuf] [-out dir] doc.json`, `gcedar demo` |
| `oracle/` | Harness that runs real gittuf and compares its verdicts with ours; `setup.sh` pins the gittuf checkout |
| `smt/` | Rust crate with the four SMT proofs (`cedar-policy-symcc` and cvc5); `run.sh` runs them end to end |
| `repro/` | Stand-alone shell reproducer for the gittuf duplicate-member lockout |
| `FINDINGS.md` | What the comparison with gittuf found, with reproducers |
| `CAPABILITIES.md` | What gittuf, GitHub and Cedar can each express, one test per row |
| `PROOFS.md` | What the SMT proofs show, their controls and their assumptions |

**Compile modes.** *Strict* mode is this project's own design: the first
matching rule decides, with an optional default deny, roles and approvals.
*Gittuf* mode copies gittuf's behaviour: any matching rule may allow,
unprotected refs are allowed, and keys count once. The oracle checks gittuf
mode.

## Known limits

* **Host facts are trusted.** Cedar decides only from what Phase A reports.
  Neither the tests nor the proofs check signature verification, key handling
  or forge data inside Cedar; they rely on the Go Phase A being right. The
  same goes for the clock behind `window` and the facts behind `require`: a
  wrong clock defeats a time window.
* **Proofs cover the compiled policies, not the compiler.** Each proof is
  about the Cedar produced for the specific documents in `smt/docs/`. That the
  compiler is correct in general is tested (differential tests, gittuf
  oracle), not proven.
* **Some patterns cannot be expressed in Cedar.** gittuf patterns with `?` or
  `[!…]` have no Cedar `like` equivalent, so the host matches them and passes
  the result in. The solver treats that input as arbitrary.
* **Threshold expansion grows fast.** k-of-n becomes C(n,k) Cedar policies.
  8-of-16 is 12,870 policies (~16 ms per decision); expansions above 200,000
  candidates are refused.
* **gittuf coverage is partial.** The comparison covers ref rules with SSH keys
  and reference authorizations. It does not cover GitHub app approvals, file
  rules, tags, or full-history verification (list in FINDINGS.md).

## Results

* **Compiler vs reference:** on 300 random policy documents (150 of them
  using the strict-mode fields below), the compiled Cedar agrees with an
  independent Go reference implementation on all **356,636** decisions.
  Breaking the compiler in one place per new field makes this test fail.
* **Compared with real gittuf:** a harness builds real gittuf repositories
  with real SSH signatures and runs gittuf's own verifier. In *gittuf mode*
  the compiler agrees with gittuf on **every** compared push: 0 disagreements
  in 1,568 pushes over 300 random documents, plus targeted probes. Documents
  that list a member twice are rejected by us on purpose and are not compared
  (FINDINGS.md). Last run 2026-10-12 at repo commit `52bb4af` against
  gittuf `0b0278ec`, on a fresh clone from `oracle/setup.sh`.
* **Four SMT proofs (cvc5):** (1) adding a broad rule such as
  `refs/heads/* 1-of-{alice}` provably weakens a stricter rule on `main`;
  (2) with the self-approval ban, no request where the author approved their
  own change is ever allowed; (3) with `"except": ["mallory"]` on main's
  rule, no request on main that mallory signed is allowed; (4) with a
  `not_after` on main's rule, no request on main after that time is allowed.
  Each has a control that makes the solver produce a counterexample.
* **Capability matrix:** 12 capabilities (thresholds, globs, forbid rules,
  time windows, field signing and more), each with a test of compiler output,
  compared with what gittuf and GitHub can express today.
* **Findings:** in gittuf every matching rule is an alternative, so a broad
  rule always weakens a narrow one; gittuf accepts a rule that lists a member
  twice and then locks the branch forever (reproducer in `repro/`); and a
  shared-key bug in the original Phase A.

## Strict-mode fields

In **strict mode only**, a rule may also carry the fields below, and the
document may have top-level `forbid` entries. gittuf cannot express any of
them, so gittuf mode rejects them with an error. A document that uses none of
them compiles to exactly the same Cedar as one written before they existed.

| Field | Example | Compiles to |
|---|---|---|
| `except` (on a rule): these principals must not have signed | `"except": ["mallory"]` | `forbid … when { resource.name like "refs/heads/main" && context.signers.containsAny([User::"mallory"]) };` (scoped to the refs this rule decides) |
| `forbid` (top level): deny any matching ref these principals signed | `"forbid": [{"name": "no-mallory-tags", "pattern": "refs/tags/*", "principals": ["mallory"]}]` | `forbid … when { resource.name like "refs/tags/*" && context.signers.containsAny([User::"mallory"]) };` |
| `window` (on a rule): RFC 3339 bounds, either optional, inclusive | `"window": {"not_before": "2026-01-05T00:00:00Z", "not_after": "2026-12-19T23:59:59Z"}` | `… && context.now >= datetime("2026-01-05T00:00:00Z") && context.now <= datetime("2026-12-19T23:59:59Z")` on each of the rule's permits |
| `require` (on a rule): boolean host facts that must be true | `"require": {"ci_passed": true}` | `… && context.ci_passed == true` on each of the rule's permits |

A forbid always beats a permit, and the decision names the forbid that fired
(`Decision.Reasons`). `now` and the `require` facts come from the host
(`Facts.Now`, `Facts.Host`). Cedar trusts them as it trusts the signer set.
With no clock, a policy that needs `now` denies with an error. The schema gains
`now: datetime` and each fact (`ci_passed: Bool`) only when a document uses
them. Empty or unknown principal lists, malformed timestamps and fact names
outside `[a-z_]+` are compile errors; unknown fields and wrong types are
rejected when the JSON is parsed (`ParseDoc`, which the CLI uses).

## More

* [FINDINGS.md](FINDINGS.md): every disagreement with gittuf, how it was
  classified, and the reproducers.
* [CAPABILITIES.md](CAPABILITIES.md): the capability matrix and its evidence
  labels.
* [PROOFS.md](PROOFS.md): the four SMT proofs, their controls and assumptions.

The project began as a prototype in another language. Its behaviour was ported
to Go and checked byte for byte against it; the prototype is archived outside
this repository, and the Go code is the reference implementation.
