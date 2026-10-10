# Capability matrix

Status: this is a partial draft from Step 2. It covers only the two rows that
Step 2's findings settled: roles (nested thresholds) and pattern syntax. The
full matrix, with one passing Cedar-path test per row, is Step 3.

Columns:
- **gittuf today**: verified against gittuf `0b0278ec`, in the source and with the oracle in `oracle/`.
- **Cedar natively**: expressible in policies with no host help.
- **Needs Phase A**: the host has to compute part of the decision.

| Scenario | gittuf today | Cedar natively | Needs Phase A | Test |
|---|---|---|---|---|
| Nested thresholds ("roles": k-of-[principals, @role]) | **No compact form.** Delegated rule files mean something else (an OR across levels, Finding 7). **But expressible by expansion**: one rule per minimal approver set, threshold = set size, verified on gittuf (`TestRolesAsExpandedGittufRules`, 0/64 disagreements) | **Yes**, by the same expansion (strict mode); cost grows with C(n,k) | No | `go/gcedar` `TestDifferential`, `TestExpansionSizes`; `oracle` `TestRolesAsExpandedGittufRules` |
| Ref patterns with `*` | Yes | Yes (`like`, `*` matches `/`) | No | `TestStarPatternsAgreeWithFnmatch` |
| Ref patterns with positive classes `[ab]` | Yes | Yes, as an OR of `like` patterns (capped at 64) | Only above the cap | `TestBracketRewriteMatchesFnmatch` |
| Ref patterns with `?`, `[!..]` | Yes | **No** | **Yes**: the host passes `context.matchedPatterns` | `TestLikeCannotExpressQuestionMark`, `TestProbePatterns` |

## Roles vs gittuf delegated rule files: where the meaning differs

Our role `@team = 2-of-[carol, dave]` used inside `2-of-[alice, @team]` means:
alice signs **and** two of carol and dave sign. Every satisfying set is a
combination across levels.

A gittuf rule `team` (2-of-{alice, bob}) that delegates to a rule file `team`
containing `team-main` (2-of-{carol, dave}) means something different (Finding 7):

1. **The levels are alternatives.** alice+bob is enough, and carol+dave is
   enough. Signatures never combine across levels: alice+carol is denied.
2. **The delegator's threshold protects the rule file, not the push.** alice
   and bob must sign the `team` rule file's metadata, but no push needs them.
3. **The delegated file can be weaker than its delegator.** A `*` 1-of-{carol}
   rule in the team file lets carol push to `main` alone.
4. **The delegated file is confined to its delegator's namespace.** Its rules
   are only consulted when the delegating rule's pattern matches the ref.
5. **Order and `terminating` decide which files are consulted.** No such
   concept exists for roles. `terminating` cannot currently be set by users.

Mapping in each direction:
- **gittuf to Cedar: yes (argued, not yet tested against the oracle).** A delegation is expressible with roles plus a
  pattern conjunction: `1-of-[@delegator, @delegated-rule]` for each delegated
  rule, with the delegated rule's pattern intersected with the delegator's
  pattern. Point 2, the metadata signatures, is Phase A: the host checks the
  rule file's signatures before compiling it, and Cedar is never asked.
- **Cedar to gittuf: yes for the meaning, not for the notation.** Because
  gittuf rules are alternatives, the compiler's own expansion can be written
  as plain gittuf rules: one rule per minimal approver set, with threshold
  equal to the set's size. `TestRolesAsExpandedGittufRules` runs two nested
  documents ("lead AND 2-of-team" and "2-of-[alice, 2-of-{bob,carol},
  1-of-{dave,erin}]") on real gittuf and on strict-mode Cedar, across all 32
  signer subsets each: 0 disagreements. It costs gittuf the same C(n,k)
  blow-up, as rule-file entries instead of Cedar permits.

**So, correcting the framing of this row:** roles are *not* more expressive
in Cedar than in gittuf. Both reach nested thresholds only by enumerating
minimal approver sets. What the Cedar path adds is (1) a compact source
notation that the compiler expands, and (2) the expanded policies sit where
Cedar's analysis can reason about them (Step 4). The real difference from gittuf's own
*delegation* feature is semantic (points 1–5 above), not expressive power.
