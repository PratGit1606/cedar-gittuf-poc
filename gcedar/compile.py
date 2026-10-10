"""Compile gittuf-style JSON delegations into Cedar.
"""
from __future__ import annotations

import itertools
import json
from dataclasses import dataclass, field

SCHEMA = """\
entity User;
entity Ref { name: String };
action write appliesTo {
  principal: User,
  resource: Ref,
  context: { signers: Set<User>, approvals: Set<User>, author: User }
};
"""


class DelegationError(ValueError):
    pass


def _cedar_str(s: str) -> str:
    """Quote a string for a Cedar literal, rejecting anything exotic."""
    for ch in s:
        if ord(ch) < 0x20 or ch in '"\\':
            raise DelegationError(f"unsupported character {ch!r} in {s!r}")
    return '"' + s + '"'


def _like_pattern(p: str) -> str:
    """gittuf glob -> Cedar `like` pattern. `*` is the only wildcard in both."""
    for ch in p:
        if ord(ch) < 0x20 or ch in '"\\?[]':
            raise DelegationError(f"unsupported glob character {ch!r} in {p!r}")
    return '"' + p + '"'


MAX_COMBINATIONS = 200_000


class ExpansionTooLarge(DelegationError):
    pass


def minimize(sets: set[frozenset[str]]) -> set[frozenset[str]]:
    """Drop any set that is a strict superset of another (monotone policies).
    Equal-size sets can never be strict supersets, so only compare against
    strictly smaller kept sets."""
    kept: list[frozenset[str]] = []
    by_size: dict[int, list[frozenset[str]]] = {}
    for s in sorted(sets, key=len):
        smaller = [k for size, ks in by_size.items() if size < len(s) for k in ks]
        if not any(k <= s for k in smaller):
            kept.append(s)
            by_size.setdefault(len(s), []).append(s)
    return set(kept)


def count_choices(member: str, roles: dict, _stack: tuple = ()) -> int:
    """Upper bound on how many candidate sets expanding `member` generates
    (before dedupe and minimization). Cheap: nothing is materialized."""
    if not member.startswith("@"):
        return 1
    name = member[1:]
    if name in _stack:
        raise DelegationError(f"cyclic role reference: {' -> '.join(_stack + (name,))}")
    if name not in roles:
        raise DelegationError(f"unknown role @{name}")
    return count_threshold(roles[name]["members"], roles[name]["threshold"], roles, _stack + (name,))


def count_threshold(members: list[str], threshold: int, roles: dict, _stack: tuple = ()) -> int:
    per = [count_choices(m, roles, _stack) for m in members]
    # elementary symmetric polynomial e_k(per): sum over k-subsets of the product of their choice counts
    e = [1] + [0] * threshold
    for c in per:
        for j in range(threshold, 0, -1):
            e[j] += e[j - 1] * c
    return e[threshold]


def satisfying_sets(member: str, roles: dict, _stack: tuple = ()) -> set[frozenset[str]]:
    """Minimal principal sets satisfying one member (a principal or @role)."""
    if not member.startswith("@"):
        return {frozenset([member])}
    name = member[1:]
    if name in _stack:
        raise DelegationError(f"cyclic role reference: {' -> '.join(_stack + (name,))}")
    if name not in roles:
        raise DelegationError(f"unknown role @{name}")
    return expand_threshold(roles[name]["members"], roles[name]["threshold"],
                            roles, _stack + (name,))


def expand_threshold(members: list[str], threshold: int, roles: dict,
                     _stack: tuple = ()) -> set[frozenset[str]]:
    """All minimal principal sets that satisfy `threshold` of `members`."""
    if threshold < 1 or threshold > len(members):
        raise DelegationError(f"threshold {threshold} impossible with {len(members)} members")
    n = count_threshold(members, threshold, roles, _stack)
    if n > MAX_COMBINATIONS:
        raise ExpansionTooLarge(
            f"{threshold}-of-{len(members)} expands to up to {n:,} candidate sets "
            f"(limit {MAX_COMBINATIONS:,}); restructure the delegation or count outside Cedar")
    per_member = [satisfying_sets(m, roles, _stack) for m in members]
    out: set[frozenset[str]] = set()
    for chosen in itertools.combinations(range(len(members)), threshold):
        for pick in itertools.product(*(per_member[i] for i in chosen)):
            out.add(frozenset().union(*pick))
    return minimize(out)


@dataclass
class Compiled:
    schema: str
    policies: str
    policy_meta: list[dict] = field(default_factory=list)  # index == Cedar policyN id
    n_permit: int = 0
    n_forbid: int = 0


def compile_delegations(doc: dict) -> Compiled:
    principals = doc.get("principals", {})
    roles = doc.get("roles", {})
    rules = doc.get("rules", [])
    default = doc.get("default", "deny")
    if default not in ("allow", "deny"):
        raise DelegationError("default must be 'allow' or 'deny'")

    seen = set()
    for r in rules:
        if r["name"] in seen:
            raise DelegationError(f"duplicate rule name {r['name']}")
        seen.add(r["name"])

    blocks: list[str] = []
    meta: list[dict] = []
    n_permit = n_forbid = 0

    def emit(kind: str, body: str, info: dict):
        nonlocal n_permit, n_forbid
        blocks.append(f'{kind}(principal, action == Action::"write", resource) when {{ {body} }};')
        meta.append({"kind": kind, **info})
        if kind == "permit":
            n_permit += 1
        else:
            n_forbid += 1

    # Self-approval is a forbid so it overrides every permit (Cedar: forbid wins).
    if doc.get("forbid_self_approval"):
        emit("forbid", "context.approvals.contains(context.author)", {"rule": "<self-approval>"})

    for i, rule in enumerate(rules):
        for m in rule["members"]:
            if not m.startswith("@") and m not in principals:
                raise DelegationError(f"rule {rule['name']}: unknown principal {m}")
        source = rule.get("source", "signers")
        if source not in ("signers", "approvals"):
            raise DelegationError(f"rule {rule['name']}: bad source {source}")
        match = f"resource.name like {_like_pattern(rule['pattern'])}"
        earlier = "".join(f" && !(resource.name like {_like_pattern(rules[j]['pattern'])})"
                          for j in range(i))
        combos = expand_threshold(rule["members"], rule["threshold"], roles)
        for combo in sorted(combos, key=lambda s: sorted(s)):
            users = ", ".join(f"User::{_cedar_str(u)}" for u in sorted(combo))
            body = f"{match}{earlier} && context.{source}.containsAll([{users}])"
            emit("permit", body, {"rule": rule["name"], "combo": sorted(combo)})

    if default == "allow":
        none = " && ".join(f"!(resource.name like {_like_pattern(r['pattern'])})" for r in rules) or "true"
        emit("permit", none, {"rule": "<default-allow>"})

    return Compiled(SCHEMA, "\n".join(blocks) + "\n", meta, n_permit, n_forbid)


if __name__ == "__main__":
    import sys
    print(compile_delegations(json.load(open(sys.argv[1]))).policies)
