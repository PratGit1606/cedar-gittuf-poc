# Findings: Cedar compiler vs real gittuf

> **About "the prototype" below.** The project began as a prototype in another
> language. Its behaviour was ported to Go and checked byte for byte against
> it, and the prototype was then retired and archived outside this repository.
> Mentions of the prototype, its Phase A and its tests are history. The Go
> code is the reference implementation.

## Oracle under test

| | |
|---|---|
| gittuf repository | https://github.com/gittuf/gittuf (pinned, unmodified checkout created by `oracle/setup.sh` in `.gittuf-oracle/`) |
| gittuf commit | `0b0278ec1d484e59d2107c38f38c059908a33856` (2026-10-08, "Merge pull request #1645 from shreyaabaranwal/fix/root-metadata-bypassrsl") |
| Go | go1.27.1 linux/amd64 |
| cedar-go | v1.8.0 |

The harness (`oracle/`) drives gittuf through its public `experimental/gittuf`
API, which is the same code the CLI calls: `trust init`, `trust add-policy-key`,
`policy init`, `policy add-key`, `policy add-rule`, `policy sign`, `policy stage`
and `apply`, `rsl record`, `attest authorize`, and `verify-ref --latest-only`.
Principals that must be tufv02 *persons* (in our tests, two principals sharing
one key) are added with the gittuf CLI, built from the same clone, because the
public Go API needs internal types to construct a person. Every repository,
key and signature is real: ed25519 SSH keys come from `ssh-keygen`, RSL entries
are SSH-signed Git commits, and authorizations are DSSE envelopes.

How a push is simulated (`World.Push`):
1. A new commit goes on a scratch feature branch, and the branch gets an RSL entry.
2. Each "attestor" signs a gittuf reference authorization (a DSSE attestation)
   for `ref`, covering the move from the current tip to that commit's tree.
3. `ref` is fast-forwarded and an RSL entry is recorded, signed by the
   "pusher" or left unsigned.
4. gittuf runs `VerifyRef(ref, WithLatestOnly())`. No error means allow. Any
   error other than "gittuf policy verification failed" fails the test as a
   harness problem, so it is never counted as a deny.

On the Cedar side, Phase A is simulated for each mode: the set of principals,
or in gittuf mode the set of distinct key IDs, whose key signed the RSL entry
or the attestation.

Run with: `oracle/setup.sh`, then `cd oracle && go test -v .`. Set
`ORACLE_DOCS=300` for the large random run and `ORACLE_DEBUG=1` for gittuf's
own trace.

## Two compile modes

`go/gcedar` has two modes (`CompileMode`). Strict mode is the original
semantics. It was byte-identical to the prototype's compiler except for the
deliberate differences under "Go change 1" below.

| | `strict` (the original POC) | `gittuf` (mirrors the commit above) |
|---|---|---|
| Several rules match a ref | the first matching rule decides | any matching rule may satisfy |
| No rule matches | `default` (allow or deny) | always allowed (unprotected); an explicit `default: deny` is rejected |
| Principal identity in Cedar | name | **key ID**; principals that share a key collapse into one |
| Duplicate members | **rejected** (`DuplicateMemberError`), since Go change 1 below | **rejected**, since Go change 1 below; before that, counted once like gittuf |
| One signer reaching two members of one threshold (overlapping roles) | counts toward **one** member only, since Go change 1 below | n/a (no roles) |
| Two principals sharing a key | rejected by the Phase A verifier | collapse into one key-ID identity; a rule left with fewer distinct keys than its threshold gets no permits, as in gittuf |
| Patterns | `*` only (anything else is rejected) | `*` uses `like`; positive classes `[ab]` and `[0-9]` become a bounded OR of `like`; `?`, `[!..]` and escapes are matched in **Phase A** and passed as `context.matchedPatterns` |
| Roles, `approvals` source, forbid-self-approval | supported | rejected (no gittuf equivalent; see CAPABILITIES.md) |
| `except`, top-level `forbid`, `window`, `require` (README) | supported | rejected ("gittuf cannot express …") |

Gittuf mode's schema is `context: { signers: Set<User>, matchedPatterns: Set<String> }`.

## Summary of results

| Test | Verdicts | strict vs gittuf | gittuf mode vs gittuf |
|---|---:|---:|---:|
| Hand-written 2-of-3 | 6 | 0 differ | 0 differ |
| Rule-matching probe | 16 | **6 differ** | 0 differ |
| Pattern probe | 10 | 6 can't compile | 0 differ |
| Unprotected and default probe | 7 | **2 differ** | 2 can't compile (default deny, by design) |
| Duplicates and shared-key probe | 9 | **5 differ** | 0 differ |
| Roles expanded into gittuf rules vs strict-mode roles | 64 | 0 differ | n/a (roles rejected) |
| **Random documents** (300 docs, 8 pushes each) | 2,400 | 1,409 of 2,008 compared differ (1,392 can't compile, **17 semantic**); 392 not compared | **0 of 1,568 compared differ**; 832 not compared |

What the random documents contain: 41 have two principals sharing a key, 104
list a member twice, and 144 use a pattern that needs Phase A. Of the 2,400
pushes, gittuf allowed 1,270. "Not compared" means the document lists a
member twice and the Go compiler rejects it by design (Finding 4). The random
row comes from the run of 2026-10-12 (repo commit `52bb4af`, gittuf
`0b0278ec`, fresh `oracle/setup.sh` clone, `ORACLE_DOCS=300`, 13/13 oracle
tests passed in 666 s). An earlier version of this row compared all 2,400
strict-mode pushes, including those on documents that list a member twice,
and showed 1,575 differences (39 semantic).

**The oracle catches errors (mutation check).** I broke gittuf mode on purpose
and reran 100 random documents:
* Without key dedup, 13 of 800 verdicts disagreed with gittuf.
* With Phase A never reporting pattern matches, 43 of 800 disagreed.

Both mutations were reverted. Strict mode acts as a third mutant ("first match
wins"), and it disagrees too.

**What this does and does not show.** Gittuf mode agrees with gittuf's
`verify-ref --latest-only` on flat documents built from these features: `git:`
rules, SSH keys, one pattern per rule, a threshold, signatures from the RSL
entry and from reference authorizations, shared keys, and duplicate members.
It does not show agreement on anything listed under "Not modelled" below.

## How gittuf decides (from source, confirmed by the probes)

Line references are to the commit above.

* **Matching rules are alternatives.** `findVerifiersForPathIfProtected`
  (`internal/policy/policy.go:489`) returns one verifier per matching rule, and
  `verifyGitObjectAndAttestationsUsingVerifiers` (`internal/policy/verify.go:1308`)
  accepts if any one of them is met. Confirmed below.
* **Unprotected refs are allowed** (`verify.go:1110`). gittuf has no default
  deny. A catch-all `*` rule plays that role, and the built-in trailing
  `gittuf-allow-rule` is never turned into a verifier.
* **Patterns** are matched with `fnmatch.Match("git:"+pattern, "git:"+ref, 0)`.
  With flags 0, `*` matches `/`, and `?`, `[..]` and `[!..]` / `[^..]` are wildcards.
  Despite the comment "We validate pattern when it's added", no validation
  happens when a rule is added.
* **Which signatures count for `git:` rules:** the RSL entry's signature
  (at most one Git signature), the DSSE signatures on the reference
  authorization for (ref, from, to-tree), and GitHub approvals mapped through
  `associatedIdentities`. The commit's own signature does not count. Confirmed below.
* **Threshold counting** is over distinct principal IDs, and each key is
  credited at most once (`usedKeyIDs`, `internal/policy/signature.go:69`).
* **Terminating rules** cut off the remaining rules in a file only when the
  matching rule has its own delegated rule file. At this commit, though,
  `terminating` **cannot be set** for a user rule through the Go API or the CLI:
  `AddRule` hard-codes `false` (`internal/tuf/v02/targets.go:100`), and only the
  built-in allow rule is terminating. **Not probed:** it can only be reached by
  hand-editing and re-signing the metadata.

## Finding 1: matching rules are alternatives, not first-match (strict mode is wrong for gittuf)

Repro: `TestProbeRuleMatching`. Principals alice, bob and carol; every push is to `refs/heads/main`.

| Rules, in order | RSL entry | Attestation | gittuf | strict | gittuf mode |
|---|---|---|---|---|---|
| [main 2-of-{a,b}, main 1-of-{c}] | carol | | allow | **deny** | allow |
| [main 2-of-{a,b}, main 1-of-{c}] | bob | carol | allow | **deny** | allow |
| [main 1-of-{c}, main 2-of-{a,b}] | alice | bob | allow | **deny** | allow |
| [heads/* 1-of-{a}, main 2-of-{b,c}] | bob | carol | allow | **deny** | allow |
| [main 2-of-{b,c}, heads/* 1-of-{a}] | alice | | allow | **deny** | allow |
| [main 2-of-{b,c}, heads/* 1-of-{a}] | alice | bob | allow | **deny** | allow |

The other 10 pushes agree in all three. Classification: **(a) our semantics
model was wrong**. Gittuf mode covers it.

Consequence for the design: in gittuf a broad rule always weakens a narrower
one, whatever their order. Last row: `main` is "protected" by 2-of-{bob, carol},
but alice alone may push to it because `refs/heads/*` trusts her. Tightening
a sub-namespace takes a terminating rule that has its own delegated rule file
(see above), which the CLI cannot create at this commit. Strict mode shows
Cedar can express both behaviours. Which one gittuf wants is a gittuf design
question, not a Cedar limitation.

## Finding 2: patterns

Repro: `TestProbePatterns` (end to end), plus `go/gcedar/pattern_test.go`, which
evaluates Cedar's actual `like` with cedar-go and compares it with gittuf's own
fnmatch library.

| Pattern | Ref | Signer | gittuf | strict | gittuf mode (how it matches) |
|---|---|---|---|---|---|
| `refs/heads/*` | `refs/heads/feature/x` | bob | deny | deny | deny (`like`) |
| `refs/heads/*/main` | `refs/heads/a/b/main` | bob | deny | deny | deny (`like`) |
| `refs/heads/rel-?` | `refs/heads/rel-1` | bob | deny | can't compile | deny (Phase A) |
| `refs/heads/rel-?` | `refs/heads/rel-10` | bob | allow (unprotected) | can't compile | allow (Phase A) |
| `refs/heads/rel-[ab]` | `refs/heads/rel-a` | bob | deny | can't compile | deny (`like` OR) |
| `refs/heads/rel-[!a]*` | `refs/heads/rel-b1` | bob | deny | can't compile | deny (Phase A) |

Can Cedar's `like` express what gittuf accepts?
* **`*`-only patterns: yes, exactly.** In both, `*` matches across `/`.
  `TestStarPatternsAgreeWithFnmatch` checks 9 patterns against about 3,000 refs
  with cedar-go, and they agree with fnmatch on every one.
* **Positive classes (`[ab]`, `[a-c]`, `[0-9]`): yes, by rewriting.** Each class
  becomes an OR of `like` patterns (`TestBracketRewriteMatchesFnmatch` checks this
  is exact on the same corpus). The count is the product of the class sizes, so
  gittuf mode caps it at 64 alternatives and falls back to Phase A above that.
* **`?`, negated classes and escapes: no.** `like` has no single-character
  wildcard. `TestLikeCannotExpressQuestionMark` searches all 2.4M `like`
  patterns up to length 7 over the relevant alphabet and finds none that
  reproduces `rel-?` or `rel-[!1]`. The general argument for `rel-?`: rel-1 and
  rel-2 differ in their last character, so the pattern must put a `*` there.
  Whatever follows that `*` must be a common suffix of "1" and "2", which is
  empty, so the pattern also matches rel-10. In principle an OR over every
  possible character would work, but Cedar strings are Unicode, so that is not
  practical. **These patterns have to be matched in Phase A.** The host passes the
  matching patterns as `context.matchedPatterns`, and Cedar analysis then
  treats "does this pattern match this ref" as an unconstrained input.

Classification: **(b) Cedar limitation** for `?` and negated classes. **(a) Our
model was too narrow** for positive classes; gittuf mode handles them. One
fnmatch quirk: a class that starts with `]` (`[]a]`) is parsed as empty
instead of as a literal `]`. Phase A uses the same library, so gittuf mode
reproduces that quirk by construction.

## Finding 3: unprotected refs and default deny

Repro: `TestProbeUnprotected`. One rule: main 1-of-{alice}. Pushes to `refs/heads/other`.

| Document | Signer | gittuf | strict | gittuf mode |
|---|---|---|---|---|
| default allow | unsigned or mallory | allow | allow | allow |
| default deny | unsigned or mallory | allow | **deny** | can't compile (by design) |
| + catch-all `*` 1-of-{a,b,c} | unsigned or mallory | deny | deny | deny |
| + catch-all `*` 1-of-{a,b,c} | bob | allow | allow | allow |

gittuf has no notion of default deny. A catch-all rule is the gittuf way to
get it, and because rules are alternatives, the catch-all also acts as a floor
for every other namespace. Classification: **(a)**. Gittuf mode rejects
`default: deny` instead of silently ignoring it.

## Finding 4: duplicate members (gittuf lockout bug, and our model counted twice)

Repro: `TestProbeDuplicatesModes`, `TestProbeDuplicateMembers`, and the
standalone CLI script `repro/gittuf-duplicate-members-lockout.sh`.

| Rule | Signers | gittuf | strict | gittuf mode |
|---|---|---|---|---|
| 2-of-[alice, alice] | alice | deny | **allow** | deny |
| 2-of-[alice, alice] | alice, bob | deny | **allow** | deny |
| 2-of-[alice, alice, bob] | alice | deny | **allow** | deny |
| 2-of-[alice, alice, bob] | alice, bob | allow | allow | allow |

* **gittuf quirk (c), arguably a bug:** `AddRule` (`internal/tuf/v02/targets.go:88`)
  checks `len(authorizedPrincipalIDs) < threshold` on the list as given, then
  stores the deduplicated set. So it accepts a rule that can never be met and
  locks the namespace. The CLI passes `--authorize` through unchanged. Running
  `repro/gittuf-duplicate-members-lockout.sh` against this commit gives:
  ```
  == control: alice listed once, threshold 2 (expected: rejected)
  Error: insufficient keys to meet threshold
  == bug: alice listed twice, threshold 2 (accepted)
  Rule protect-main:
      Refs affected:
          git:refs/heads/main
      Authorized keys:
          SHA256:1HJaxYUJb0b6FzDryUlkDIW3JZwJZkyVe8d5NoYORZo
      Required valid signatures: 2
  == alice (the only authorized principal) pushes to main
  Error: verifying Git namespace policies failed, gittuf policy verification failed
  RESULT: verification failed: the rule stored as 2-of-{alice} can never be met; main is locked
  ```
  Script usage: run `oracle/setup.sh`, then `repro/gittuf-duplicate-members-lockout.sh` (builds gittuf from the pinned checkout), or `GITTUF_BIN=/path/to/gittuf repro/gittuf-duplicate-members-lockout.sh` with any gittuf CLI.
  It needs only `git`, `ssh-keygen`, and either Go (to build gittuf from the checkout) or a gittuf CLI.
* **(a) Our model was wrong in strict mode:** it counted a duplicated member once
  per listing, which quietly lowers the threshold.
* **Resolution (Go change 1):** the Go compiler **rejects** a member listed
  twice, in both modes, with `DuplicateMemberError`. This deliberately
  differs from the prototype (which counted twice) and from gittuf (which
  accepts the rule and locks the namespace). The oracle reports such
  documents as "not compared (rejected by design)". With this change, the
  300-document run compared 1,568 gittuf-mode verdicts with 0 disagreements,
  and 832 were not compared.

## Finding 5: principals sharing a key (bug in our Phase A)

Repro: `TestProbeSharedKey`, `TestProbeDuplicatesModes`. p1 and p2 are two
tufv02 persons with the same SSH key; p3 (carol) has a key of its own.

| Rule | What was signed | gittuf | strict (prototype-style Phase A) | gittuf mode |
|---|---|---|---|---|
| 2-of-[p1, p2, p3] | RSL entry by the shared key | deny | **allow** | deny |
| 2-of-[p1, p2, p3] | RSL entry and attestation by the shared key | deny | **allow** | deny |
| 2-of-[p1, p2, p3] | shared key + carol | allow | allow | allow |
| 2-of-[p1, p2] | RSL entry by the shared key | deny | **allow** | deny |

The prototype's Phase A (archived), run with p1 and p2 sharing a key:
```
one signature, filed under p1 only       signers=['p1'] allowed=False
same signature filed under p1 and p2     signers=['p1', 'p2'] allowed=True
```
* **(d) A bug in our Phase A**, and a security-relevant one: one key holder can
  meet 2-of-[p1, p2]. Cedar never sees keys, so the fix has to be on the host.
  Gittuf mode does it by making the key ID the Cedar identity. A Phase A
  invariant ("a key counts once") becomes structural, so Cedar analysis can rely
  on it, provided Phase A reports key IDs honestly.
* **(c) Minor gittuf quirk:** a policy may contain two persons with the same
  key, and the credit goes to whichever principal is iterated first.
* Known limit of gittuf mode: a person with *several* keys counts once in gittuf
  but would count once per key in gittuf mode. Our JSON has one key per
  principal, so this does not come up, but it would need Phase A to map keys
  to persons first.

## Finding 6: the commit's signature is irrelevant to `git:` rules

Repro: `TestProbeCommitVsRSLSignature`. Rule: main 1-of-{alice}.

| Commit signed by | RSL entry signed by | gittuf |
|---|---|---|
| alice | (unsigned) | deny |
| alice | mallory | deny |
| mallory | alice | allow |

This matches the source: for `git:` rules only the RSL entry's signature and
authorizations count, and commit signatures are only checked for `file:`
rules. Our model agrees by construction, because Phase A only collects RSL entry
and authorization signers. For the design doc: "who signed the commit" is a
different fact from "who authorized the ref update", and a Cedar context
should keep them separate (e.g. `context.commitSigners` vs `context.signers`).
Classification: none (agreement).

## Finding 7: delegated rule files are an OR across levels (our roles are not)

Repro: `TestProbeDelegatedRuleFile`. In `targets`, rule `team` is main
2-of-{alice, bob} and delegates to rule file `team` (signed by alice and bob),
which contains `team-main`, main 2-of-{carol, dave}. Separately, rule `other`
is refs/heads/other 1-of-{bob}.

| Push | gittuf |
|---|---|
| main: alice + bob (the delegating rule itself) | allow |
| main: carol + dave (the delegated rule alone) | allow |
| main: alice + carol (one from each level) | **deny**: signatures do not combine across levels |
| main: carol alone | deny |
| *with `team-anything: *` 1-of-{carol} added to the team file:* main, carol alone | **allow**: a delegated file can set a weaker rule than its delegator |
| ... other: carol | deny: delegated rules only apply where the delegating rule matches |
| ... other: bob | allow |

Our "roles" are nested thresholds (e.g. 2-of-[alice, @team]), which require
signatures from several levels together. gittuf delegation is the opposite
shape: each level is a complete alternative. Roles are not mapped onto
delegated rule files.

However, roles are **not** beyond gittuf's expressive power.
`TestRolesAsExpandedGittufRules` writes the compiler's expansion (one minimal
approver set per permit) as plain gittuf rules, one per set with threshold =
set size. Since rules are alternatives, gittuf then agrees with strict-mode
Cedar on all 64 signer subsets across two nested documents. Both systems reach
nested thresholds only by enumeration. CAPABILITIES.md records roles as
"compact notation plus analyzability on the Cedar side", not as Cedar-only
semantics.

## Minor

* The prototype's compiler crashed on `"rules": null` with a type error. It
  was never fixed; the prototype is archived. The Go compiler treats it as no
  rules.
* `TestRandomAgainstGittuf` takes about 30 s for 40 documents and about 4 min for
  300 (4 in parallel). One gittuf world takes about 0.3 to 1 s, or about 3 s
  with CLI-created persons.

## Classification summary

| # | Disagreement | Class | Status |
|---|---|---|---|
| 1 | First-match vs alternatives | (a) model | gittuf mode matches; strict mode kept as the Cedar-only variant |
| 2a | `?`, `[!..]` patterns | (b) Cedar limitation | Phase A matching (`context.matchedPatterns`) |
| 2b | `[ab]` patterns | (a) model too narrow | bounded `like` OR in gittuf mode |
| 3 | Default deny | (a) model | gittuf mode rejects it; use a catch-all rule |
| 4 | Duplicate members | (a) model + (c) gittuf lockout bug | gittuf mode matches; CLI reproducer written; both modes reject duplicates since Go change 1 |
| 5 | Shared keys | (d) our Phase A bug + (c) gittuf quirk | gittuf mode uses key IDs as identities; the Go Phase A refuses shared keys (Go change 1); the prototype's Phase A was never fixed (archived) |
| 6 | Commit vs RSL signature | agreement | none needed |
| 7 | Roles vs delegated rule files | different features (roles are expressible in gittuf by expansion) | CAPABILITIES.md; not forced |

## Not modelled (gittuf is richer than our JSON)

The JSON covers only what the probes needed. In gittuf mode a
principal's value is its key ID; the `key:<name>` form for shared keys exists
only in the test harness. Left out, and therefore not covered by the claim
above:
* rules with several patterns (`--rule-pattern` repeated); persons with several keys;
* GitHub app approvals (`associatedIdentities`), reference authorizations
  that cover a different from/to, and `verify-mergeable`'s threshold−1 relaxation;
* global rules (`threshold` and `block-force-pushes`), which are verified
  separately against all principals;
* `file:` rules (commit signatures, the changed-paths walk);
* tags (`verifyTagEntry` also requires a signed tag object);
* terminating rules (not settable, see above) and delegated rule files as
  compile targets;
* full-history verification (`VerifyRefFull`), policy changes partway through
  the history, RSL skip annotations and recovery;
* policy metadata thresholds (root and targets signatures) and expiry.

## Go change 1: each key counts once

Every path where one key could count twice toward a threshold, and how the Go
code closes it:

| Path | Before | Now | Test |
|---|---|---|---|
| Member listed twice in a rule or role (`["a","a"]`) | Prototype: counted twice | compile error `DuplicateMemberError` (strict and gittuf mode) | `TestDuplicateRuleMemberRejected`, `TestDuplicateRoleMemberRejected` |
| One signer satisfying two members of one threshold via overlapping roles (2-of-[@r1,@r2], a in both; or 2-of-[a,@r], a in @r) | Prototype and Go: a alone met it | each chosen member must be met by **disjoint** signers | `TestOverlappingMembersCountOnce`; differential test vs an independent search-based reference (a mutant without the rule gives 2,752 mismatches) |
| Same signer listed twice in Cedar context | already a set | unchanged (Cedar `Set`) | `TestRepeatedSignerInFactsCountsOnce` |
| Two principal names bound to one public key (one signature filed under both names) | Prototype Phase A: counted twice (Finding 5) | strict: the Go Phase A verifier refuses the document (hex is normalised, so `AB..` = `ab..`); gittuf mode: key ID is the identity | `TestSharedKeyRejected` (phasea_test.go), `TestGittufModeSharedKeyCountsOnce` |
| Field spec listing a key twice; two field keys with the same public key | Prototype: counted twice | compile error; field verifier refuses the document | fields_test.go |

The overlapping-roles row changes strict-mode meaning compared with the
prototype's compiler. While the prototype existed, the byte-compat test
against it skipped inputs with a duplicate member or an overlap; on its 403
inputs it reported 114 identical, 62 rejected by both, 0 different, 227
skipped. That test was removed together with the prototype.

## Notes on the Go implementation

**(a) The count-once rule changes strict-mode meaning compared with the prototype's compiler.**
In a threshold, each chosen member must be met by its own signers. One signer
cannot satisfy two members through overlapping roles: 2-of-[@r1, @r2] with
alice in both roles, or 2-of-[alice, @r] with alice in @r, need two different
signers. The prototype's compiler and reference let alice satisfy both.
With the rule removed from `ExpandThreshold`, the differential test
(Cedar vs the search-based Go reference, 171,644 verdicts) reports **2,752
mismatches**, so the rule is exercised. The byte-compat test against the
prototype (since removed) skipped the affected inputs on purpose (227 of 403).

**(b) The oracle pushes that are not compared.** In the 300-document
oracle run, **832 of 2,400 gittuf-mode pushes are not compared**. All of them
are on documents that list a member twice: gittuf accepts these (and the rule
can never be met), while the Go compiler rejects them with
`DuplicateMemberError`. Documents with **shared keys are still compared**:
gittuf mode does not reject them, it merges principals sharing a key into
one key-ID identity, as gittuf does. The remaining 1,568 gittuf-mode pushes
show 0 disagreements. So the "0 disagreements" claim covers documents without
duplicate members; for documents with them, we deliberately differ.

**(c) Field-signature encoding: the Go encoding is the specification.**
`Canonical` (`go/gcedar/fields.go`) defines the signed bytes of a field: the
JSON array `[name, value]` with no whitespace, object keys sorted by code
point, strings escaped to printable ASCII (`\uXXXX` for everything else),
integers in decimal, and floats in shortest round-trip form (`1.0`, `1e+16`).
**Known limit:** integers beyond 64 bits go through float64 and lose
precision. `123456789012345678901234` encodes as `1.2345678901234569e+23`. A
Go caller that builds values by hand must pass integers as `int`, `int64` or
`json.Number`, not `float64`. Field documents decoded from JSON already keep
integers exact: `TestFieldsIntegerValueFromJSON` fails if decoding falls back
to float64, which would encode `1` as `1.0`.

History: the format was chosen to match the prototype's JSON encoder with
sorted keys and no whitespace. Before the prototype was retired, a test
checked 13 values byte for byte against it,
including non-ASCII, control characters, DEL, `-0.0`, and floats at the
fixed/exponent boundaries. Edge cases checked by hand then: `1.50` gives `1.5`
and `1e2` gives `100.0`, the same in both. `1` gave `1` in both only after the
`json.Number` fix above. Integers beyond 64 bits were the one remaining
difference.
