"""Bounded policy analysis by exhaustive evaluation.

This is NOT SMT analysis. Cedar's real analysis (equivalence, subset, dead code)
runs through an SMT solver and covers every possible input; cedarpy does not
expose it. Here we enumerate a finite universe (every subset of principals, and
sample refs derived from the rule patterns) and evaluate both policy sets in
Cedar. The answers are exact *for that universe*, which for these monotone,
set-based policies is the whole space of signer sets, but ref coverage is only
as good as the sampled refs. Treat results as strong evidence, not proof.
"""
from __future__ import annotations

import itertools

from .verify import Verifier


def sample_refs(*docs: dict) -> list[str]:
    refs = {"refs/other/zzz"}
    for d in docs:
        for r in d.get("rules", []):
            p = r["pattern"]
            refs.add(p.replace("*", "x"))
            refs.add(p.replace("*", "a/b"))
            refs.add(p.replace("*", ""))
    return sorted(refs)


def subsets(items: list[str]):
    for n in range(len(items) + 1):
        for c in itertools.combinations(items, n):
            yield list(c)


def _cases(principals: list[str], uses_approvals: bool):
    author = principals[0]
    for s in subsets(principals):
        yield (s, [], author)
    if uses_approvals:
        for a in subsets(principals):
            if a:
                yield ([], a, author)


def _uses_approvals(*docs) -> bool:
    return any(r.get("source") == "approvals" for d in docs for r in d.get("rules", [])) \
        or any(d.get("forbid_self_approval") for d in docs)


def compare(doc_a: dict, doc_b: dict, max_principals: int = 10) -> dict:
    """Compare two policy docs over the same universe.

    Returns {"equivalent", "a_subset_of_b", "b_subset_of_a",
             "only_a": [...], "only_b": [...], "universe": n}
    where only_a lists requests A allows and B denies (counterexamples to A ⊆ B).
    """
    principals = sorted(set(doc_a.get("principals", {})) | set(doc_b.get("principals", {})))
    if len(principals) > max_principals:
        raise ValueError(f"{len(principals)} principals is too many for brute force")
    va, vb = Verifier(_with(doc_a, principals)), Verifier(_with(doc_b, principals))
    uses = _uses_approvals(doc_a, doc_b)
    cases = list(_cases(principals, uses))
    only_a, only_b, total = [], [], 0
    for ref in sample_refs(doc_a, doc_b):
        ra, rb = va.check_batch(ref, cases), vb.check_batch(ref, cases)
        for (s, a, _), x, y in zip(cases, ra, rb):
            total += 1
            if x and not y:
                only_a.append({"ref": ref, "signers": s, "approvals": a})
            elif y and not x:
                only_b.append({"ref": ref, "signers": s, "approvals": a})
    return {"equivalent": not only_a and not only_b,
            "a_subset_of_b": not only_a, "b_subset_of_a": not only_b,
            "only_a": only_a, "only_b": only_b, "universe": total}


def _with(doc: dict, principals: list[str]) -> dict:
    """Same doc, but make every universe principal known (placeholder keys) so
    both sides share one entity set. Rules still only reference their own."""
    d = dict(doc)
    d["principals"] = {p: doc.get("principals", {}).get(p, "00" * 32) for p in principals}
    return d


def dead_policies(doc: dict) -> list[dict]:
    """Compiled policies that never fire anywhere in the universe."""
    principals = sorted(doc.get("principals", {}))
    v = Verifier(doc)
    cases = list(_cases(principals, _uses_approvals(doc)))
    from cedarpy import is_authorized_batch
    fired: set[int] = set()
    for ref in sample_refs(doc):
        reqs = [v.request(ref, principals[0], a, s, ap) for s, ap, a in cases]
        for r in is_authorized_batch(reqs, v.compiled.policies, v.entities(ref), v.compiled.schema):
            fired.update(int(x.removeprefix("policy")) for x in r.diagnostics.reasons)
    return [v.compiled.policy_meta[i] for i in range(len(v.compiled.policy_meta)) if i not in fired]
