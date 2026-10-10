# SMT proofs

Two properties of Cedar policies **emitted by the Go compiler**, checked with
`cedar-policy-symcc` 0.7.0 and the cvc5 SMT solver. The answer "unsat" means
no well-typed request violates the property: it holds for **all** inputs, not
a sample.

## Reproduce

```
smt/run.sh
```

What it does:
1. Compiles `smt/docs/*.json` with `gcedar compile` into `smt/target/compiled/<doc>/`.
   `p1_*` documents use gittuf mode; `p2_*` documents use strict mode.
2. Downloads cvc5 into `smt/.tools/` (`smt/fetch-cvc5.sh`).
3. Runs `cargo run --release`, which prints each query's counterexample or
   "unsat" and exits non-zero if any outcome differs from the expected one.

Every counterexample is replayed through Cedar's concrete authorizer on both
policy sets. Runtime is about 7 s.

**Requirements:**
* Go.
* **Rust ≥ 1.89**, the MSRV of `cedar-policy-symcc` 0.7.0. This machine's
  system Rust is 1.75, which cannot build the crate. I used the Rust 1.95.0
  toolchain already cached at `~/.cache/puccinialin/rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin`
  by putting it on `PATH`; nothing was installed. Set `CARGO=/path/to/cargo`
  or adjust `PATH` accordingly.
* cvc5, downloaded on first run.

| cvc5 | sha256 of `cvc5-Linux-x86_64-static.zip` | Result |
|---|---|---|
| **1.2.1** (requested; the default in `fetch-cvc5.sh`) | `6d44abc233980a14d72cc5809287d27c3335b1d6ee863381d0b5ffcbd0d8de56` | 11/11 queries as expected |
| 1.3.1 (the version the symcc 0.7.0 README names) | `1a1cda20d2df4938fa4944a69f33ddc9172e319ece0eed0aa09c4d7abede3ed1` | 11/11 queries as expected, same outcomes |

Use `CVC5_VERSION=1.3.1 smt/fetch-cvc5.sh` to get the second one.

## What the policies are

The policies under test are compiler output, not hand-written. For example,
`p1_broad` (gittuf mode: narrow main 2-of-{alice, bob}, plus broad
`refs/heads/*` 1-of-{alice}) compiles to:

```
permit(principal, action == Action::"write", resource) when { resource.name like "refs/heads/main" && context.signers.containsAll([User::"alice", User::"bob"]) };
permit(principal, action == Action::"write", resource) when { resource.name like "refs/heads/*" && context.signers.containsAll([User::"alice"]) };
permit(principal, action == Action::"write", resource) when { !(resource.name like "refs/heads/main") && !(resource.name like "refs/heads/*") };
```

The last permit is gittuf's rule that unprotected refs are allowed.

Two **analysis-only** policies are hand-written in `smt/src/main.rs`, because
they are part of the *question*, not of the policies under test:
* `SCOPE_MAIN`, `forbid … unless { resource.name == "refs/heads/main" }`, is
  added to *both* sides of a query to restrict it to `main`.
* `AUTHOR_IN_APPROVALS`, `permit … when { context.approvals.contains(context.author) }`,
  describes the requests Proof 2 is about.

## Proof 1 (gittuf mode): a broad rule weakens a narrow rule

The narrow set is `main 2-of-{alice, bob}`. The broad version adds `refs/heads/* 1-of-{alice}`.

| Query | Result |
|---|---|
| Does the broad version allow only what the narrow one allows? | **Counterexample**: `refs/heads/main`, signers = {alice}. Broad version Allow, narrow Deny (replayed in Cedar). |
| On `main` only: does the narrow one allow only what the broad version allows? | **unsat**: holds |
| Over all refs: does the narrow one allow only what the broad version allows? | **Counterexample**: `refs/heads/AAAA`, no signers. Narrow Allow (unprotected), broad version Deny |

Solver output for the main result (cvc5 1.2.1):
```
=== P1  [narrow+broad] allows only what [narrow] allows?  (broad refs/heads/* 1-of-{alice})
counterexample:
principal: User::"", action: Action::"write", resource: Ref::""
context: {matchedPatterns: [], signers: [User::"alice"]}
entities: [ User::"bob", User::"", Ref::"" { name: "refs/heads/main", }, User::"alice", Action::"write", ]
replayed in Cedar: A=Allow B=Deny
```

**What this proves.** Restricted to `refs/heads/main`, {narrow} is strictly
contained in {narrow + broad}: everything the narrow set allows, the broad
version allows (unsat), and the broad version allows alice alone (the
counterexample). This is FINDINGS.md Finding 1, now proven for every input
instead of observed on samples.

**Correction to the original claim.** Over *all* refs the two sets are
**incomparable**, not nested. In gittuf mode a ref that no rule matches is
allowed, so the broad rule also *tightens* every other `refs/heads/*` ref:
`refs/heads/AAAA` goes from "anyone" to "alice must sign". The solver found
this case, which I had not anticipated. So "strictly contained" holds only
once the query is scoped to `main`.

### Controls

| Control | Query | Result | Meaning |
|---|---|---|---|
| C1a: disjoint rule `refs/heads/dev 1-of-{alice}` | on `main`: narrow ≡ narrow+dev? | **unsat**: equivalent | a rule for another namespace does not touch `main` |
| C1b: disjoint rule | does narrow+dev allow only what narrow allows (all refs)? | **unsat**: holds | it never weakens anything |
| C1c: disjoint rule | narrow ≡ narrow+dev over **all** refs? | **Counterexample**: `refs/heads/dev`, no signers; narrow Allow, narrow+dev Deny | "equivalent" is true only when scoped: the new rule protects a previously unprotected ref |
| C1d: broad, same threshold and members (`refs/heads/* 2-of-{alice, bob}`) | does broad allow only what narrow allows? | **unsat**: no weakening | |
| C1e: broad, higher threshold (`refs/heads/* 3-of-{alice, bob, carol}`) | same | **unsat**: no weakening | |
| C1f: broad, *same* threshold, *other* members (`refs/heads/* 2-of-{alice, carol}`) | same | **Counterexample**: `main`, signers {alice, carol} | the threshold number alone does not decide; weakening happens whenever some set satisfies the broad rule but not the narrow one |

## Proof 2 (strict mode): self-approval ban

The policies come from strict mode, because gittuf mode rejects
`forbid_self_approval`: gittuf has no equivalent (CAPABILITIES row 5). The
document has `refs/heads/*` needing 2-of-{alice, bob, carol} **approvals**,
`refs/tags/*` needing 1-of-{alice} signers, and **default allow**, so many
requests are allowed. The compiled forbid is:
```
forbid(principal, action == Action::"write", resource) when { context.approvals.contains(context.author) };
```

| Query | Result |
|---|---|
| P2: with the forbid, is any request where the author is among the approvals allowed? (disjointness of the policy set with `AUTHOR_IN_APPROVALS`) | **unsat**: no such request, for all refs, approval sets, signer sets and authors |
| C2: same query without the forbid | **Counterexample**: below |

```
=== C2  without the forbid: no request with author in approvals is allowed?
counterexample:
principal: User::"", action: Action::"write", resource: Ref::""
context: {approvals: [User::"bob", User::"carol"], author: User::"carol", signers: [User::"alice"]}
entities: [ Ref::"" { name: "refs/heads/", }, User::"bob", User::"", Action::"write", User::"alice", User::"carol", ]
replayed in Cedar: A=Allow B=Allow
```
carol authored the change and her own approval made up the 2-of-3.

## What the proofs assume

* **Phase A facts are correct.** The proofs are about Cedar's decision given
  its inputs. They say **nothing** about signature verification, key
  handling (e.g. the shared-key bug, FINDINGS Finding 5), forge data (who the
  author is, whether an approval is fresh or dismissed), or how
  `context.signers` and `context.approvals` were built. If Phase A puts a
  principal in `signers` that did not sign, every proof still "holds" and
  means nothing. **This is the blind spot.** The proofs move trust to the
  host; they do not remove it.
* **The schema is the model.** Inputs range over every well-typed request for
  the schema: any `Ref` with any `name` string, `signers` and `approvals`
  being sets of any size of any `User` entities, and `author` being any
  `User`. Nothing ties `author` to a signer or to a real commit author.
  Gittuf mode identifies users by key ID, so "alice" here means "the key ID
  alice".
* **`matchedPatterns` is unconstrained.** Gittuf-mode patterns that Cedar
  cannot express (`?`, `[!..]`) arrive as `context.matchedPatterns`, which the
  solver treats as an arbitrary set of strings unrelated to `resource.name`.
  The Proof 1 documents use only `*` patterns (`like`), so this did not arise.
  For documents that do use such patterns, "holds" results stay valid (they
  hold for all inputs, real ones included), but counterexamples may be
  impossible in reality: a pattern reported as matching a ref it does not match.
* **Specific policies, not the compiler.** Each proof is about the compiled
  output of the documents in `smt/docs/`, not about "all documents". That the
  compiler is correct is tested, not proven: differential tests, Python
  byte-compat, and the gittuf oracle (0 disagreements in gittuf mode).
* **gittuf mode, not gittuf.** Proof 1 is about the gittuf-mode Cedar
  policies. It transfers to gittuf itself only as far as the oracle comparison
  goes (FINDINGS.md); it is not a proof about gittuf's Go code.
* **Strict mode for Proof 2.**

## What the solver handled, and what was not tried

* Handled without workarounds: `like` patterns with `*`, `containsAll` and
  `contains` on entity sets of unbounded size, `forbid`/`permit`
  interaction, and default-allow permits.
* symcc rejects empty set literals (`compile_set`: "empty set literals are not
  supported"). The compiler never emits them; a hand-written `containsAll([])`
  would fail to compile symbolically.
* **Not tried:** extension types (the `datetime` policies of CAPABILITIES row 8),
  large expansions (all queries here have ≤ 5 policies; how the solver scales on,
  say, the 12,870-permit 8-of-16 expansion is unknown), and documents that use
  `matchedPatterns`.
