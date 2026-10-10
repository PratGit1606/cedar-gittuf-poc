# Findings: Cedar compiler vs real gittuf

## Oracle under test

| | |
|---|---|
| gittuf repository | https://github.com/gittuf/gittuf (fresh clone at `../gittuf`, unmodified) |
| gittuf commit | `0b0278ec1d484e59d2107c38f38c059908a33856` (2026-10-08, "Merge pull request #1645 from shreyaabaranwal/fix/root-metadata-bypassrsl") |
| Go | go1.27.1 linux/amd64 |
| cedar-go | v1.8.0 |

The harness (`oracle/`) drives gittuf through its public `experimental/gittuf`
API, which is the same code the CLI calls: `trust init`, `trust add-policy-key`,
`policy init`, `policy add-key`, `policy add-rule`, `policy stage` and `apply`,
`rsl record`, `attest authorize`, and `verify-ref --latest-only`. Principals that
need a tufv02 *person* (several IDs or keys) are added by running the gittuf
CLI, built from the same clone, because the public Go API needs internal
types to construct a person. Every repository, key and signature is real:
ed25519 SSH keys come from `ssh-keygen`, and RSL entries are SSH-signed Git
commits.

How a push is simulated (`World.Push`):
1. A new commit goes on a scratch feature branch, and the branch gets an RSL entry.
2. Each "attestor" signs a gittuf reference authorization (a DSSE attestation)
   for `ref`, covering the move from the current tip to that commit's tree.
3. `ref` is fast-forwarded and an RSL entry is recorded, signed by the
   "pusher" or left unsigned.
4. gittuf runs `VerifyRef(ref, WithLatestOnly())`. No error means allow.

On the Cedar side, `signers` = {pusher} ∪ attestors, restricted to principals in
the document.

## How gittuf actually decides (read from source at the commit above)

These facts determine what we must model. Every line reference is to that commit.

* **Every matching rule is an alternative; the order only decides which is tried first.**
  `findVerifiersForPathIfProtected` (`internal/policy/policy.go:489`) returns a
  verifier for every rule whose pattern matches. Then
  `verifyGitObjectAndAttestationsUsingVerifiers` (`internal/policy/verify.go:1308`)
  accepts if any one verifier meets its threshold. Our compiler uses first-match-wins,
  which is stricter. To be confirmed by randomized testing.
* **Terminating rules cut off later rules only when the matching rule has its own delegated rule file**
  (`policy.go`, the `break` sits inside `if s.HasTargetsRole(...)`).
* **Unprotected refs are allowed.** If no rule matches, the ref is unprotected
  (`verify.go:1110`). gittuf has no "default deny" (a catch-all `*`
  rule plays that role); the trailing `gittuf-allow-rule` is never turned into a verifier.
* **Patterns** use `fnmatch.Match(pattern, "git:"+ref, 0)`. With flags 0, `*`
  matches `/`, and `?` and `[...]` are also wildcards. Our compiler rejects `?` and `[]`.
* **Signers for a `git:` rule** are the signature on the **RSL entry** commit
  (at most one Git signature is counted) plus the DSSE signatures on the
  reference-authorization attestation for (ref, from-commit, to-tree), plus GitHub
  approvals mapped through `associatedIdentities`. The *commit's* own signature is
  **not** consulted for `git:` rules; commit signatures are only checked for
  `file:` rules.
* **Threshold counting** is per **principal ID**, and each **key** is credited at
  most once (`usedKeyIDs`, `internal/policy/signature.go:69`).

## Hand-written end-to-end case (`TestHandwritten2of3`, `TestHandwrittenCedarAgrees`)

Rule `protect-main`: 2-of-{alice, bob, carol} on `git:refs/heads/main`.

| RSL entry signed by | Attestation signed by | gittuf | Cedar |
|---|---|---|---|
| alice | bob | allow | allow |
| alice | (none) | deny | deny |
| mallory (not in policy) | alice, carol | allow | allow |
| mallory | alice | deny | deny |
| (unsigned) | bob, carol | allow | allow |
| alice | alice | deny | deny |

The gittuf debug trace (`ORACLE_DEBUG=1`) confirms that the denials are threshold
failures. In the first row alice is credited from the RSL entry's Git signature
and bob from the attestation. In the last row, alice's attestation signature is
skipped with "has already been counted towards the threshold".

## Finding 1: duplicate members in a rule (disagreement)

Repro: `TestProbeDuplicateMembers`.

| Rule | Signers | gittuf | Cedar |
|---|---|---|---|
| 2-of-[alice, alice] | alice | deny | **allow** |
| 2-of-[alice, alice] | alice, bob | deny | **allow** |
| 2-of-[alice, alice, bob] | alice | deny | **allow** |
| 2-of-[alice, alice, bob] | bob | deny | deny |
| 2-of-[alice, alice, bob] | alice, bob | allow | allow |

What gittuf does: `AddRule` (`internal/tuf/v02/targets.go:88`) checks
`len(authorizedPrincipalIDs) < threshold` on the **list**, then stores
`set.NewSetFromItems(...)`, which removes duplicates. Counting at verify time is
per distinct principal. So gittuf **accepts** `2-of-[alice, alice]` at write time,
and that rule can then never be satisfied. The CLI passes `--authorize` values
through unchanged (`internal/cmd/policy/addrule/addrule.go`), so this can be
reached from the CLI, e.g. `--authorize X --authorize X --threshold 2`, or the same
key given once through `--authorize-key` and once as an ID through `--authorize`.

What we do: `compile.py`, its Go port and `reference.py` count a duplicated
member once per occurrence, so alice alone meets 2-of-[alice, alice].

Classification:
* **(a) Our semantics model is wrong.** Thresholds count distinct principals.
  Our behaviour is also the less safe one: a duplicated member lowers the
  effective threshold.
* **(c) gittuf quirk.** The write-time check should use the length of the set. As
  written, gittuf will store a rule that can never be satisfied, which locks the
  namespace for everyone.

Not fixed yet, as requested.

## Finding 2: two principals sharing one key (disagreement, comes from Phase A)

Repro: `TestProbeSharedKey`. This uses two tufv02 persons, p1 and p2, with the
same SSH key; p3 has its own key.

| Rule | What was signed | gittuf | Our pipeline |
|---|---|---|---|
| 2-of-[p1, p2] | RSL entry by the shared key | deny | allow if Phase A reports {p1, p2} |
| 2-of-[p1, p2] | RSL entry + attestation by the shared key | deny | allow if Phase A reports {p1, p2} |
| 2-of-[p1, p2, p3] | RSL entry by the shared key | deny | allow if Phase A reports {p1, p2} |
| 2-of-[p1, p2, p3] | shared-key RSL entry + attestation by p3 | allow | allow |

What gittuf does: `policy add-person` accepts a second person with an existing
key, which is not rejected. At verify time `usedKeyIDs` credits that key to only
the first principal tried, so one key never counts twice.

What we do: Phase B (Cedar) has no notion of keys and only sees principal names,
so the outcome depends entirely on Phase A. I ran the real Python Phase A
(`gcedar/verify.py`) with p1 and p2 sharing a public key:

```
one signature, filed under p1 only       signers=['p1'] allowed=False
same signature filed under p1 and p2     signers=['p1', 'p2'] allowed=True
```

So whoever holds the shared key can meet 2-of-[p1, p2] by submitting the same
signature under both names.

Classification:
* **(d) A bug in our Phase A**, and a security-relevant one. The fix belongs on the
  host side: credit each verified key at most once, as gittuf does. It cannot
  be fixed in Cedar, which never sees keys. This is a concrete example of the
  Phase A/B boundary: "one key counts once" is a Phase A invariant that Cedar
  analysis cannot check.
* There is also a minor **(c) gittuf quirk**: the policy is allowed to contain
  two persons with the same key at all, and the credit goes to whichever
  principal is iterated first.

Not fixed yet, as requested.

## Status

* The hand-written case works end to end, and Cedar agrees on all 6 scenarios.
* Duplicate members and shared keys have been probed (above).
* Not yet done: randomized documents; targeted probes for rule order (first-match
  vs any-match), `*` vs `/`, `?`/`[]`, terminating rules, delegation to rule
  files (our "roles"), unprotected refs and default deny, RSL entry vs commit
  signatures.
