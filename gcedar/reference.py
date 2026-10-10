"""Independent reference implementation of the delegation semantics, written
directly from the spec in compile.py (no Cedar, no set expansion). Used as the
oracle for differential testing."""
from __future__ import annotations

from .verify import glob_to_re


def role_ok(member: str, roles: dict, have: set[str]) -> bool:
    if not member.startswith("@"):
        return member in have
    role = roles[member[1:]]
    return sum(role_ok(m, roles, have) for m in role["members"]) >= role["threshold"]


def reference_allows(doc: dict, ref: str, signers: set[str], approvals: set[str], author: str) -> bool:
    if doc.get("forbid_self_approval") and author in approvals:
        return False
    roles = doc.get("roles", {})
    for rule in doc.get("rules", []):
        if glob_to_re(rule["pattern"]).match(ref):
            have = signers if rule.get("source", "signers") == "signers" else approvals
            return sum(role_ok(m, roles, have) for m in rule["members"]) >= rule["threshold"]
    return doc.get("default", "deny") == "allow"
