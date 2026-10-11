# Cedar × gittuf proof of concept

[gittuf](https://github.com/gittuf/gittuf) adds security policy to Git: rules
such as "two of these three maintainers must sign off before anything lands
on `main`". Today gittuf evaluates those rules with its own Go code.

This repository tests whether **[Cedar](https://www.cedarpolicy.com/)**, a
small policy language from AWS with an official Go implementation and a
formal-analysis toolkit, could be gittuf's policy engine instead. The
attraction: Cedar policies can be *proven* correct with an SMT solver, not
just tested.

## The idea in ten lines

A gittuf-style policy (who must sign what) is written as JSON and compiled to Cedar.
Checking a push then happens in two phases:

1. **Phase A, on the host (Go):** parse the untrusted input, verify every
   signature, read forge data (approvals, who the author is). The output is a
   few plain facts, e.g. "these principals validly signed".
2. **Phase B, in Cedar:** given only those facts, decide allow or deny.

Cedar never sees a key or a signature, and never hashes anything. That keeps
Cedar small and analyzable, but it means **Cedar trusts whatever Phase A
tells it**.

## Results

* **Compiler vs reference:** on 150 random policy documents, the compiled
  Cedar agrees with an independent Go reference implementation on all
  **171,644** decisions.
* **Compared with real gittuf:** a harness builds real gittuf repositories
  with real SSH signatures and runs gittuf's own verifier. In *gittuf mode*
  the compiler agrees with gittuf on **every** compared push: 0 disagreements
  in 1,568 pushes over 300 random documents, plus targeted probes. (Documents
  that list a member twice are rejected by us on purpose and are not compared;
  see FINDINGS.md.)
* **Two SMT proofs (cvc5):** (1) adding a broad rule such as
  `refs/heads/* 1-of-{alice}` provably weakens a stricter rule on `main`;
  (2) with the self-approval ban, no request where the author approved their
  own change is ever allowed. Both have controls that make the solver produce
  counterexamples.
* **Capability matrix:** 12 capabilities (thresholds, globs, forbid rules,
  time windows, field signing, …), each with a test, compared with what gittuf
  and GitHub can express today.
* **Findings:** in gittuf every matching rule is an alternative, so a broad
  rule always weakens a narrow one; gittuf accepts a rule that lists a member
  twice and then locks the branch forever (reproducer in `repro/`); and a
  shared-key bug in the original Phase A.

Details: [FINDINGS.md](FINDINGS.md) · [CAPABILITIES.md](CAPABILITIES.md) · [PROOFS.md](PROOFS.md)

## Try it

Requirements: Go 1.27+, git, ssh-keygen. For the proofs, also Rust ≥ 1.89,
curl and unzip.

```sh
# 1. Compiler, Phase A/B, field signing, capability tests (no network needed)
cd go && go test ./...

# 2. See it work: compile a policy, verify some signed pushes
go run ./cmd/gcedar demo
go run ./cmd/gcedar compile -mode gittuf ../smt/docs/p1_broad.json   # print compiled Cedar

# 3. Compare against real gittuf (clones gittuf at a pinned commit, ~2 s)
cd .. && oracle/setup.sh
cd oracle && go test ./...                 # ~2 min; ORACLE_DOCS=300 for the big random run

# 4. The SMT proofs (downloads cvc5 1.2.1 on first run)
cd .. && smt/run.sh                        # set CARGO=/path/to/cargo if your Rust is older than 1.89
```

`oracle/setup.sh` puts the gittuf checkout in `.gittuf-oracle/` (gitignored).
Set `GITTUF=/some/dir` to put it elsewhere. If you run the oracle tests
before `setup.sh`, Go stops with `replacement directory ../.gittuf-oracle does
not exist`, which means: run `oracle/setup.sh` first.

## Repository layout

| Path | What it is |
|---|---|
| `go/gcedar/` | The library: JSON → Cedar compiler (strict and gittuf modes), Phase A verifier, Phase B evaluator (cedar-go), signed fields |
| `go/cmd/gcedar/` | CLI: `gcedar compile [-mode strict\|gittuf] [-out dir] doc.json`, `gcedar demo` |
| `oracle/` | Harness that runs real gittuf and compares its verdicts with ours; `setup.sh` pins the gittuf checkout |
| `smt/` | Rust crate with the two SMT proofs (`cedar-policy-symcc` + cvc5); `run.sh` runs them end to end |
| `repro/` | Stand-alone shell reproducer for the gittuf duplicate-member lockout |
| `FINDINGS.md` | Everything the comparison with gittuf turned up, with reproducers |
| `CAPABILITIES.md` | What gittuf, GitHub and Cedar can each express, one test per row |
| `PROOFS.md` | What the SMT proofs show, their controls and their assumptions |

**Compile modes.** *Strict* mode is the original design: the first matching
rule decides, with an optional default deny, roles and approvals. *Gittuf*
mode copies gittuf's real behaviour: any matching rule may allow, unprotected
refs are allowed, and keys count once. The oracle checks gittuf mode.

## Known limits

* **Host facts are trusted.** Cedar decides only from what Phase A reports.
  Neither the tests nor the proofs check signature verification, key handling
  or forge data inside Cedar; they rely on the Go Phase A being right.
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

## History

The project started as a Python prototype. Its behaviour was ported to Go and
checked byte for byte against it, and then the prototype was retired; it is
archived outside this repository. The Go code is now the reference
implementation.
