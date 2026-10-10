"""Two-phase verifier.

Phase A (host, Python): everything Cedar must never do itself - parse untrusted
data, verify ed25519 signatures, interpret forge review data. Output is plain
facts: which principals verifiably signed, which approvals are fresh.

Phase B (Cedar): given those facts as request context, decide authorization.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import cedarpy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .compile import Compiled, compile_delegations


def glob_to_re(p: str) -> re.Pattern:
    return re.compile("".join(".*" if c == "*" else re.escape(c) for c in p) + r"\Z", re.S)


def rsl_payload(ref: str, commit: str) -> bytes:
    return f"gittuf-rsl\n{ref}\n{commit}".encode()


def user(id_: str) -> dict:
    return {"__entity": {"type": "User", "id": id_}}


@dataclass
class Decision:
    allowed: bool
    reasons: list[dict] = field(default_factory=list)  # which compiled policies fired
    signers: list[str] = field(default_factory=list)
    approvals: list[str] = field(default_factory=list)
    sig_checks: int = 0


def verify_sig(pubkey_hex: str, sig_hex: str, payload: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(
            bytes.fromhex(sig_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def fresh_approvals(forge: dict | None) -> list[str]:
    """Approvers whose latest review is an approval of the current head and was
    not dismissed afterwards. Cedar cannot filter or count over record sets,
    so this filtering has to happen here (see README: expressiveness finding)."""
    if not forge:
        return []
    head = forge.get("head")
    latest: dict[str, dict] = {}
    for rv in sorted(forge.get("reviews", []), key=lambda r: r["at"]):
        latest[rv["who"]] = rv
    dismissed_at: dict[str, int] = {}
    for d in forge.get("dismissals", []):
        dismissed_at[d["who"]] = max(dismissed_at.get(d["who"], -1), d["at"])
    out = []
    for who, rv in latest.items():
        if rv["state"] == "APPROVED" and rv["commit"] == head and dismissed_at.get(who, -1) < rv["at"]:
            out.append(who)
    return sorted(out)


class Verifier:
    def __init__(self, doc: dict, compiled: Compiled | None = None):
        self.doc = doc
        self.keys: dict[str, str] = doc.get("principals", {})
        self.compiled = compiled or compile_delegations(doc)
        res = cedarpy.validate_policies(self.compiled.policies, self.compiled.schema)
        if not res.validation_passed:
            raise RuntimeError(f"generated Cedar failed schema validation: {res}")
        self._pats = [(glob_to_re(r["pattern"]), r) for r in doc.get("rules", [])]
        self._principals = sorted(self.keys)

    # ---- Phase A -------------------------------------------------------
    def candidates(self, ref: str) -> set[str]:
        """Only principals named by rules whose pattern matches this ref."""
        out: set[str] = set()
        roles = self.doc.get("roles", {})

        def walk(member: str, seen=()):
            if member.startswith("@"):
                if member in seen:
                    return
                for m in roles[member[1:]]["members"]:
                    walk(m, seen + (member,))
            else:
                out.add(member)

        for rx, rule in self._pats:
            if rx.match(ref):
                for m in rule["members"]:
                    walk(m)
        return out

    def phase_a(self, change: dict) -> tuple[list[str], list[str], int]:
        payload = rsl_payload(change["ref"], change["commit"])
        checks = 0
        signers = []
        for p in sorted(self.candidates(change["ref"])):
            sig = change.get("signatures", {}).get(p)
            if sig is None:
                continue
            checks += 1
            if verify_sig(self.keys[p], sig, payload):
                signers.append(p)
        return signers, fresh_approvals(change.get("forge")), checks

    # ---- Phase B -------------------------------------------------------
    def entities(self, ref: str) -> list[dict]:
        ents = [{"uid": {"type": "User", "id": u}, "attrs": {}, "parents": []}
                for u in self._principals]
        ents.append({"uid": {"type": "Ref", "id": ref}, "attrs": {"name": ref}, "parents": []})
        return ents

    def request(self, ref: str, pusher: str, author: str, signers, approvals) -> dict:
        return {
            "principal": f'User::"{pusher}"',
            "action": 'Action::"write"',
            "resource": f'Ref::"{ref}"',
            "context": {"signers": [user(s) for s in signers],
                        "approvals": [user(a) for a in approvals],
                        "author": user(author)},
        }

    def phase_b(self, ref: str, pusher: str, author: str, signers, approvals) -> Decision:
        r = cedarpy.is_authorized(self.request(ref, pusher, author, signers, approvals),
                                  self.compiled.policies, self.entities(ref),
                                  self.compiled.schema)
        reasons = [self.compiled.policy_meta[int(x.removeprefix("policy"))]
                   for x in r.diagnostics.reasons]
        return Decision(r.decision == cedarpy.Decision.Allow, reasons,
                        list(signers), list(approvals))

    def check(self, change: dict) -> Decision:
        signers, approvals, checks = self.phase_a(change)
        d = self.phase_b(change["ref"], change["pusher"], change["author"], signers, approvals)
        d.sig_checks = checks
        return d

    def check_batch(self, ref: str, cases: list[tuple[list[str], list[str], str]]):
        """Phase B only, many (signers, approvals, author) cases for one ref, fast path
        for exhaustive testing. Returns list[bool]."""
        pusher = self._principals[0]
        reqs = [self.request(ref, pusher, author, s, a) for s, a, author in cases]
        out = cedarpy.is_authorized_batch(reqs, self.compiled.policies, self.entities(ref),
                                          self.compiled.schema)
        return [o.decision == cedarpy.Decision.Allow for o in out]
