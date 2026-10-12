# Capability matrix

One row per capability, one test per row. gittuf facts are checked against
gittuf `0b0278ec` (see FINDINGS.md), either by running gittuf in the oracle
(`oracle/`) or by reading its source; the "gittuf today" cell says which.

**Evidence labels** (for the Cedar approach):
- **oracle-verified**: compared against real gittuf in `oracle/`.
- **Go-tested**: a passing cedar-go test; no gittuf comparison.
- **Go-tested (compiler-emitted)**: the same, and the policies under test come
  from the JSON compiler (strict mode), not hand-written Cedar.
- **design-only**: argued, not run.
- **not possible**: cannot be expressed.

**The GitHub column is from GitHub's documentation and was not tested here.**
It covers branch protection, rulesets and CODEOWNERS as I understand them.
Treat it as a pointer, not evidence.

**Compiler output only.** Every row's test evaluates policies emitted by
`gcedar` (`Compile` / `CompileMode`), validated against the compiled schema
with cedar-go's experimental validator. Rows 4, 6, 8 and 9 use the
strict-mode fields `forbid`, `except`, `window` and `require` (README,
`go/gcedar/features.go`); gittuf mode rejects those fields with an error that
says gittuf cannot express them. Until this pass those four rows used
hand-written Cedar.

| # | Capability | gittuf today | GitHub metadata (docs, untested) | Cedar approach | Phase A fact the host must supply | Evidence | Test |
|---|---|---|---|---|---|---|---|
| 1 | **Nested roles** (k-of-[principals, @role]) | **Partly: no compact notation, but the meaning is expressible.** One plain rule per minimal approver set, threshold = set size. 0/64 disagreements on gittuf (oracle). gittuf's delegated rule files mean something else (an OR across levels) | No (teams and CODEOWNERS; no nested thresholds) | Compiler expands roles into one `permit` per minimal approver set (`containsAll`); each signer counts toward one member only | Verified signer set | oracle-verified | `TestCapNestedRoles`; `oracle/TestRolesAsExpandedGittufRules` |
| 2 | **Glob patterns** on refs | **Yes**: fnmatch, `*` crosses `/`, plus `?`, `[..]`, `[!..]` (oracle) | Yes (fnmatch-style branch and tag patterns) | `*` maps to `like`; positive classes `[ab]` to an OR of `like` patterns (≤ 64); `?` and `[!..]` are **not possible** in `like` | For `?` and `[!..]` only: `context.matchedPatterns` (which patterns match the ref, computed with gittuf's fnmatch) | oracle-verified | `TestCapGlobPatterns`; `oracle/TestProbePatterns`; `TestLikeCannotExpressQuestionMark` |
| 3 | **k-of-n thresholds** | **Yes** (oracle) | Partly: "N approvals required" counts anyone with write access, not k of a named set | One `permit` per k-subset (C(n,k) permits) | Verified signer set; in gittuf mode, distinct key IDs | oracle-verified | `TestCapThreshold`; `oracle/TestHandwritten2of3`, `oracle/TestRandomAgainstGittuf` |
| 4 | **Deny/forbid rules that override permits** | **Partly: two fixed kinds only.** A global `threshold` rule overrides a passing rule and also covers unprotected refs; `block-force-pushes` (oracle) | Partly (fixed restrictions: block force pushes, restrict deletions, restrict updates) | Top-level `"forbid": [{name, pattern, principals}]` compiles to `forbid … when { resource.name like P && context.signers.containsAny([…]) }`; Cedar's forbid wins over any permit, and the decision names the forbid. Not emitted: a gittuf-style k-of-N floor (`forbid … unless` with C(N,k) clauses, because Cedar has no set size); that variant is design-only now | The signer set (Phase A must verify the forbidden principals' signatures too; it does) | Go-tested (compiler-emitted); gittuf side oracle-verified | `TestCapForbidOverridesPermit`; `oracle/TestOracleGlobalRules` |
| 5 | **Self-approval ban** (author's approval cannot count) | **No.** `internal/policy` has no notion of the commit author (source) | Yes (a PR author cannot approve their own PR; "approval of most recent push" exists) | Compiler `forbid … when { context.approvals.contains(context.author) }`; Cedar reports the forbid | `context.author` mapped to a principal, plus the fresh approval set (forge data, trusted) | Go-tested | `TestForgeSelfApprovalForbidden` |
| 6 | **Rule exceptions** ("all of refs/heads/* except main") | **No.** Rules are alternatives, so a broad rule always also applies to main (oracle, FINDINGS Finding 1). Only character-level `[!..]`, and `terminating` cannot be set (source) | Yes (ruleset include/exclude patterns, bypass lists) | Ref exceptions: strict mode's first match. List main's rule first and the broad rule's permits carry `!(resource.name like "refs/heads/main")`. Principal exceptions: `"except": [p]` on a rule compiles to a `forbid` on the refs that rule decides (its pattern and no earlier rule's) when `context.signers.containsAny([p])` | None beyond the signer set | Go-tested (compiler-emitted) | `TestCapRuleExceptions` |
| 7 | **Field-level signing** (field X needs k-of keys Y; Justin's case) | **Partly**: `file:` rules protect file paths (commit signatures over changed paths), not fields inside a document (source) | No | One `Field` entity per field with a `signers` attribute; one `permit` per field per minimal key set; "all fields accepted and none missing" is a host loop | Per-field verified signer sets over `Canonical(name, value)`; the list of fields present | Go-tested | `TestFieldsAccept` (+ 12 more in `fields_test.go`) |
| 8 | **Time windows** (freeze periods, business hours) | **No.** No clock in verification (source) | No (not natively) | `"window": {not_before, not_after}` (RFC 3339, inclusive) adds `context.now >= datetime("…")` / `context.now <= datetime("…")` to the rule's permits; malformed timestamps are compile errors; no clock means deny with an error. Not emitted: recurring windows (business hours, `toTime()`/`duration`) and a freeze inside an otherwise open rule; those are design-only now | `context.now` from a **trusted** host clock (`Facts.Now`; the Verifier's `Clock`): not the commit's or RSL entry's own timestamp, which the signer controls. Which time to use when re-verifying history is open | Go-tested (compiler-emitted) | `TestCapTimeWindow` |
| 9 | **Attribute-based conditions** on ref and context (immutable tags, no force push, CI passed) | **Partly**: `block-force-pushes` is the only one (oracle). Tags also need a signed tag object (source) | Partly (required status checks, block force pushes, tag rules) | `"require": {"ci_passed": true}` adds `context.ci_passed == true` to the rule's permits; fact names match `[a-z_]+`, only `true` is accepted, and each fact is added to the schema as `Bool` only when used. Test: immutable tags (`refs/tags/*` requires `new_ref`), main requires `fast_forward` and `ci_passed`. Not emitted: entity attributes such as `resource.kind` | Each fact, as a boolean the host computes (`Facts.Host`): whether the ref is new, fast-forward (Git ancestry), CI status (forge, trusted). A missing fact is false | Go-tested (compiler-emitted) | `TestCapAttributeConditions` |
| 10 | **Explainable decisions** (which policy fired) | **Partly.** The CLI error is generic ("verifying Git namespace policies failed, gittuf policy verification failed", seen in the oracle); the satisfied rule is only in debug logs | Partly (the UI and API list the blocking rules) | Cedar diagnostics list every satisfied `permit` (rule + approver set) or the deciding `forbid`; a default deny lists nothing. Caveat: cedar-go assigns positional IDs (`policyN`) and ignores `@id`, so a side table (`Compiled.Meta`) maps them back | None | Go-tested | `TestCapExplainableDecisions` |
| 11 | **Schema validation of policies** | **No policy language to type-check**; rules are data. Further metadata validation not investigated | Partly (the API validates ruleset JSON) | cedar-go `x/exp/schema/validate` (strict) rejects unknown attributes and type errors; `NewEvaluator` runs it on all compiler output | None | Go-tested | `TestCapSchemaValidation` |
| 12 | **Rule-order independence** | **Yes**, except `terminating`, which cannot be set: matching rules are alternatives, and reversing their order never changed a verdict (oracle, Finding 1) | Yes (all applicable rulesets apply) | Cedar policy sets are unordered: 20 shuffles of the compiled policies never changed a verdict, in gittuf mode and in strict mode (strict mode writes its order into each permit as negated earlier patterns) | None | Go-tested (gittuf side oracle-verified) | `TestCapOrderIndependence`; `oracle/TestProbeRuleMatching` |

## How much of each row is Phase A

Rows 1–3, 6, 10, 11 and 12 need nothing beyond the verified signer set:
everything else is in Cedar and visible to analysis. The other rows rely on
host-computed facts that Cedar takes on trust:

| Row | What Cedar decides | What the host decides (Cedar cannot check it) |
|---|---|---|
| 2 (`?`, `[!..]` only) | the threshold | whether the pattern matches the ref |
| 4 | the override logic | nothing extra (the signer set, including the forbidden principals' signatures) |
| 5 | "author's approval must not count" | who the author is, which approvals are fresh (stale, dismissed and re-approved logic is all host-side, `FreshApprovals`) |
| 7 | the per-field threshold | which keys signed which field; the loop "all fields OK, none missing" |
| 8 | the window arithmetic | what time it is |
| 9 | the combination logic | each boolean fact (new ref, fast-forward, CI status) |

## Related source checks (not rows)

* **Dismissed approvals in gittuf:** `DismissedApprovers` is recorded in the
  GitHub approval attestation, but **never read during verification**:
  `internal/policy/verify.go` only reads `GetApprovers()`. Dismissal works
  because `DismissGitHubPullRequestApprover` rewrites the attestation without
  the dismissed approver (`experimental/gittuf/attestations.go`, around line 513).
  Source-verified, not oracle-tested (it needs a GitHub app).
* **Stale approvals in gittuf:** approvals and reference authorizations are
  indexed by (ref, from-commit, to-**tree**), so a new tree needs new approvals.
  Source-verified. The Cedar path's equivalent is `FreshApprovals` in Phase A
  (`TestForgeStaleApprovalAfterNewCommit`).

## Not covered in this pass

From the original Step 3 list: ref-deletion blocking, admin bypass, and a
scenario gittuf cannot do at all. These would be variations of rows 4, 6 and 9
(a forbid on `context.isDeletion`; a permit for an admin role with a forbid
carve-out; time windows, row 8, are already something gittuf cannot do).
They are **design-only** and untested, so they are not rows.

## Roles vs gittuf delegated rule files: where the meaning differs

(Unchanged from Step 2; this is the detail behind row 1.)

Our role `@team = 2-of-[carol, dave]` used inside `2-of-[alice, @team]` means:
alice signs **and** two of carol and dave sign.

A gittuf rule `team` (2-of-{alice, bob}) that delegates to a rule file `team`
containing `team-main` (2-of-{carol, dave}) means something different (oracle,
`TestProbeDelegatedRuleFile`):

1. **The levels are alternatives.** alice+bob is enough, and carol+dave is
   enough. Signatures never combine across levels: alice+carol is denied.
2. **The delegator's threshold protects the rule file, not the push.**
3. **The delegated file can be weaker than its delegator** (a `*` 1-of-{carol}
   rule in it lets carol push to main alone).
4. **The delegated file is confined to its delegator's namespace.**
5. **Order and `terminating` decide which files are consulted** (and
   `terminating` cannot currently be set).

Mapping in each direction:
- **gittuf to Cedar:** a delegation can be written as `1-of-[@delegator,
  @delegated-rule]`, with the delegated rule's pattern intersected with the
  delegator's. Point 2 is Phase A: the host checks the rule file's signatures
  before compiling it. **design-only** (not run against the oracle).
- **Cedar to gittuf:** yes for the meaning, by expansion: one plain gittuf rule
  per minimal approver set (oracle, 0/64 disagreements). So roles are notation
  plus analyzability on the Cedar side, not extra expressive power.
