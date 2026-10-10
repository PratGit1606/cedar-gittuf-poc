# Cedar x gittuf POC

A working Python tool that tests whether Cedar can be the authorization engine for gittuf-style delegations, following the architecture from today's discussion:

1. Untrusted data is parsed and signatures are verified **on the host** (Cedar never verifies or hashes).
2. The verified facts are fed to Cedar as request context / entity attributes.
3. Cedar decides whether the policy is satisfied.
4. Policies are compiled from simple JSON delegations (Lucas's suggestion: JSON for common cases, Cedar underneath).

## Run it

```
pip install cedarpy cryptography
python3 demo.py                              # end-to-end example
python3 -m unittest discover -s tests -t .   # 24 tests, ~35 s
python3 bench.py                             # threshold expansion cost
```

## What is in it

| File | Purpose |
|---|---|
| `gcedar/compile.py` | JSON delegations to Cedar schema + policies. Expands k-of-n and nested roles into one `permit` per minimal approver set (Lucas's template suggestion). Refuses expansions over 200k candidates. |
| `gcedar/verify.py` | Two-phase verifier. Phase A: ed25519 verification, forge review interpretation. Phase B: Cedar. Only verifies keys named by rules matching the ref. |
| `gcedar/reference.py` | Independent pure-Python implementation of the same semantics, used as a test oracle. |
| `gcedar/fields.py` | Justin's use case: "field X must be signed by a key in set Y", with per-field thresholds. |
| `gcedar/analysis.py` | Bounded equivalence / subset / dead-policy checks by exhaustive evaluation (see caveats). |
| `tests/` | Differential, signature, forge-data, analysis and field tests. |

## Results

**Correctness.** 150 random delegation documents (nested roles, overlapping globs, thresholds, default allow/deny, approvals as a source, self-approval forbid) were evaluated by both Cedar and the reference verifier on every signer subset plus random mixed cases: 174,840 verdicts, 0 mismatches. Deliberately removing the first-match-wins clause from the compiler produces 2,384 mismatches on a smaller run, so the test does detect compiler bugs.

**Threshold expansion cost** (`bench.py`; one rule, one ref):

| Config | Permit rules | Cedar size | Per request |
|---|---:|---:|---:|
| flat 2-of-3 | 3 | 0.5 KB | 0.14 ms |
| flat 5-of-10 | 252 | 48 KB | 1.3 ms |
| flat 5-of-15 | 3,003 | 577 KB | 13 ms |
| flat 8-of-16 | 12,870 | 2.9 MB | 84 ms |
| 3-of-5 roles, each 3-of-5 | 10,000 | 2.5 MB | 70 ms |
| 3-of-5 roles, each 4-of-8 | 3.4M candidates | refused | n/a |

Flat expansion is exactly C(n,k). Per-request time grows roughly linearly with the number of permit rules (about 6.5 µs each). Typical gittuf thresholds (2-of-3, 2-of-5) are tiny; large groups with nested thresholds are not viable this way.

## Findings that matter for the design doc

1. **Expansion keeps thresholds visible to analysis and is exact**, unlike an `@threshold` annotation, but it is combinatorial. A practical cutoff is a few thousand rules; beyond that the fallback is counting outside Cedar, which hides the threshold from analysis.
2. **Cedar cannot filter or count over sets of records.** Fresh-vs-stale and dismissed review logic therefore lives in Phase A (`fresh_approvals`), and Cedar only sees a pre-filtered `approvals` set. Anything the host computes is outside what Cedar analysis can reason about. I tested stale approvals, dismissals, re-approval after dismissal, and a later "changes requested" review. I did not test CI check states or admin-bypass events.
3. **Self-approval is a `forbid`, which is stricter than gittuf's likely "ignore the author's approval".** Cedar can only deny the whole request when the author is in the approvals set. Excluding the author from the count would also have to happen in Phase A.
4. **First-match-wins rule ordering costs a negated clause for every earlier pattern** in each permit, so policy size grows with rule count squared. Rules stop being independent, which hurts the TUF-style "each delegator writes their own part" goal.
5. **Default-allow is an explicit catch-all permit** (`!(pattern1) && !(pattern2) ...`). It shows up in analysis like any other policy, which is a feature.
6. **Cedar reports which policies fired**, including `forbid` policies on denials, so the verifier can say exactly why something was allowed or denied.
7. **Signed fields work with default deny for free**: unknown fields are rejected, a signature copied from another field fails (the name is part of the signed bytes), and a changed value fails.

## Caveats

- **The analysis is not Cedar's SMT analysis.** `cedarpy` does not expose it. `analysis.py` enumerates every subset of principals over sampled refs, which is exhaustive for signer sets but only as good as the sampled refs. Real equivalence and subset proofs need Cedar's Rust analysis tooling, so that is a next step.
- **Delegation semantics are simplified, not gittuf's.** No terminating or propagating rules, no multi-role precedence, no real gittuf metadata, and the signed payload (`gittuf-rsl\nref\ncommit`) is my own, not gittuf's RSL entry encoding. This POC does not interoperate with a real gittuf repository.
- **Glob semantics are assumed:** `*` is the only wildcard and matches across `/`, which is how Cedar's `like` works. gittuf's actual pattern matching should be checked against this.
- **Lazy verification here is a prefilter** (only keys named by matching rules). The real mechanism Lucas described is typed partial evaluation, which would derive that from residual policies. `cedarpy` exposes `is_authorized_partial`, which I did not use.
- Forge data is trusted as given. Whether to trust it is the forge-trust question Patrick raised.
- Cedar here is the Rust engine via `cedarpy`, so the Go-port gap (no partial evaluation, no analysis) is not exercised.
