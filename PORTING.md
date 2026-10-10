# Python → Go inventory

Every function and class in the Python POC and its tests, with its Go
equivalent. "Go" paths are relative to `go/`. analysis.py is deliberately not
ported: the SMT proofs (Step 4) replace it.

| Python | What it does | Go equivalent | Status |
|---|---|---|---|
| **gcedar/compile.py** | | | |
| `SCHEMA` | Cedar schema | `gcedar.Schema` | ported |
| `DelegationError` | error type | `gcedar.DelegationError` | ported |
| `_cedar_str` | quote a Cedar string | `cedarStr` | ported |
| `_like_pattern` | glob → `like` | `likePattern` | ported |
| `MAX_COMBINATIONS` | expansion guard | `MaxCombinations` | ported |
| `ExpansionTooLarge` | error type | `ExpansionTooLarge` | ported |
| `minimize` | drop strict supersets | `minimize` | ported |
| `count_choices`, `count_threshold` | candidate count bound | `countChoices`, `CountThreshold` | ported |
| `satisfying_sets`, `expand_threshold` | k-of-n / role expansion | `satisfyingSets`, `ExpandThreshold` | ported, **deliberate differences**: rejects duplicate members; overlapping members need disjoint signers |
| `Compiled` | output record | `Compiled` | ported (+ `Mode`, `Warnings`) |
| `compile_delegations` | doc → Cedar | `Compile` / `CompileMode(doc, ModeStrict)` | ported (byte-identical except the two differences above) |
| `__main__` | CLI | `cmd/gcedar compile` | ported |
| **gcedar/verify.py** | | | |
| `glob_to_re` | glob matcher | `GlobMatch` | ported |
| `rsl_payload` | signed bytes | `RSLPayload` | ported |
| `user` | Cedar entity JSON helper | `userSet` / `cedar.NewEntityUID` | ported (cedar-go types) |
| `Decision` | verdict + reasons | `Decision`, `Verdict` | ported |
| `verify_sig` | ed25519 verify | `VerifySig` | ported |
| `fresh_approvals` | stale / dismissed / re-approved / later CHANGES_REQUESTED | `FreshApprovals` | ported |
| `Verifier.__init__` | compile + validate | `NewVerifier` | ported (+ refuses shared public keys) |
| `Verifier.candidates` | lazy-verification prefilter | `Verifier.Candidates` | ported |
| `Verifier.phase_a` | signatures + forge data | `Verifier.PhaseA` | ported |
| `Verifier.entities`, `.request` | Cedar inputs | `Evaluator.Entities`, `Request` | ported |
| `Verifier.phase_b` | Cedar decision | `Evaluator.Decide` | ported |
| `Verifier.check` | both phases | `Verifier.Check` | ported |
| `Verifier.check_batch` | many requests, one ref | `Evaluator.DecideWith` (shared entity map) | ported |
| **gcedar/reference.py** | | | |
| `role_ok`, `reference_allows` | independent oracle for the compiler | `ReferenceAllows` (backtracking search) | ported, with the disjoint-signer rule |
| **gcedar/fields.py** | | | |
| `SCHEMA` | field schema | `FieldSchema` | ported |
| `canonical` | signed encoding of a field | `Canonical` | ported, byte-identical to Python (`TestCanonicalMatchesPython`) |
| `compile_fields` | fields → Cedar | `CompileFields` | ported, byte-identical (`TestCompileFieldsMatchesPython`); rejects a key listed twice |
| `FieldVerifier`, `.check` | two-phase field check | `NewFieldVerifier`, `FieldVerifier.Check` | ported (+ refuses shared public keys) |
| **gcedar/analysis.py** | | | |
| `sample_refs`, `subsets` | test universes | `sampleRefs`, `subsets` (test helpers) | ported as test helpers |
| `_cases`, `_uses_approvals`, `compare`, `_with`, `dead_policies` | bounded equivalence / subset / dead-policy checks | — | **not ported (by design)**: replaced by SMT proofs in Step 4 |
| **bench.py** | | | |
| `flat`, `nested` | benchmark documents | `flatDoc`, `nestedDoc` (test helpers) | ported |
| `latency_us`, main loop | expansion cost table | `BenchmarkExpansion` | ported (all 15 configs, C(n,k) check, refusal) |
| **demo.py** | | | |
| script, `change` | end-to-end example | `gcedar demo` (`cmd/gcedar/demo.go`) | ported; the final escalation check (uses analysis.py) is not ported |
| **tests/util.py** | | | |
| `keypair`, `make_world`, `sign` | test keys | `makeWorld`, `world.sign` | ported |
| `PATTERNS`, `random_doc` | random documents | `testPatterns`, `randomDoc` | ported |
| **tests/test_differential.py** | | | |
| `test_random_docs_exhaustive` | Cedar vs reference | `TestDifferential` | ported |
| **tests/test_verifier.py** (12 tests) | | | |
| `PhaseA.test_threshold_met_with_nested_role` | | `TestPhaseAThresholdMetWithNestedRole` | ported |
| `PhaseA.test_threshold_not_met` | | `TestPhaseAThresholdNotMet` | ported |
| `PhaseA.test_signature_over_other_commit_rejected` | | `TestPhaseASignatureOverOtherCommitRejected` | ported |
| `PhaseA.test_wrong_key_rejected` | | `TestPhaseAWrongKeyRejected` | ported |
| `PhaseA.test_garbage_signature_does_not_crash` | | `TestPhaseAGarbageSignatureDoesNotCrash` | ported |
| `PhaseA.test_lazy_verification_only_for_relevant_principals` | | `TestPhaseALazyVerificationOnlyForRelevantPrincipals` | ported |
| `ForgeData.test_two_fresh_approvals` | | `TestForgeTwoFreshApprovals` | ported |
| `ForgeData.test_stale_approval_after_new_commit` | | `TestForgeStaleApprovalAfterNewCommit` | ported |
| `ForgeData.test_dismissed_approval` | | `TestForgeDismissedApproval` | ported |
| `ForgeData.test_reapproval_after_dismissal_counts` | | `TestForgeReapprovalAfterDismissalCounts` | ported |
| `ForgeData.test_later_changes_requested_supersedes_approval` | | `TestForgeLaterChangesRequestedSupersedesApproval` | ported |
| `ForgeData.test_self_approval_forbidden` | | `TestForgeSelfApprovalForbidden` | ported |
| **tests/test_fields.py** (7 tests) | | | |
| `test_accept` … `test_signature_replayed_from_other_field` | | `TestFieldsAccept`, `…ValueChangedAfterSigning`, `…ThresholdOnField`, `…KeyNotAllowedForField`, `…UnknownFieldDeniedByDefault`, `…MissingRequiredField`, `…SignatureReplayedFromOtherField` | all 7 ported |
| **tests/test_analysis.py** (4 tests) | | | |
| `test_refactor_into_roles_is_equivalent`, `test_privilege_escalation_counterexample`, `test_dead_rule_shadowed_by_earlier_glob`, `test_default_allow_catchall_shows_up` | | — | **not ported (by design)**, with analysis.py |

Go-only additions (no Python counterpart): gittuf compile mode, pattern
analysis, count-once tests, Python byte-compat tests, and the gittuf oracle in
`oracle/`.
