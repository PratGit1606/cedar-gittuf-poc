"""A document is a set of fields, each carrying signatures. Phase A verifies the
signatures over a canonical encoding of (field name, value) and builds one Cedar
`Field` entity per field whose `signers` attribute holds only keys that
verified. Phase B asks Cedar whether each field is accepted. The document is
accepted iff every field is accepted and every field the policy requires is
present (the loop over fields is host-side; Cedar has no loops).

Policy document:
  {"keys": {"k1": "<pubkey hex>", ...},
   "fields": {"expires": {"threshold": 1, "keys": ["k1", "k2"]},
              "targets": {"threshold": 2, "keys": ["k1", "k2", "k3"]}}}
"""
from __future__ import annotations

import json

import cedarpy

from .compile import DelegationError, _cedar_str, expand_threshold
from .verify import verify_sig

SCHEMA = """\
entity Doc;
entity Key;
entity Field { name: String, signers: Set<Key> };
action accept appliesTo { principal: Doc, resource: Field, context: {} };
"""


def canonical(name: str, value) -> bytes:
    return json.dumps([name, value], sort_keys=True, separators=(",", ":")).encode()


def compile_fields(policy: dict) -> str:
    out = []
    for fname, spec in sorted(policy["fields"].items()):
        for k in spec["keys"]:
            if k not in policy["keys"]:
                raise DelegationError(f"field {fname}: unknown key {k}")
        for combo in sorted(expand_threshold(spec["keys"], spec["threshold"], {}),
                            key=lambda s: sorted(s)):
            ks = ", ".join(f"Key::{_cedar_str(k)}" for k in sorted(combo))
            out.append('permit(principal, action == Action::"accept", resource) when { '
                       f"resource.name == {_cedar_str(fname)} && resource.signers.containsAll([{ks}]) }};")
    return "\n".join(out) + "\n"


class FieldVerifier:
    def __init__(self, policy: dict):
        self.policy = policy
        self.policies = compile_fields(policy)
        res = cedarpy.validate_policies(self.policies, SCHEMA)
        if not res.validation_passed:
            raise RuntimeError(f"generated Cedar failed validation: {res}")

    def check(self, doc: dict) -> dict:
        """Returns {"accepted": bool, "fields": {name: bool}, "missing": [...], "sig_checks": n}."""
        keys = self.policy["keys"]
        ents = [{"uid": {"type": "Doc", "id": "d"}, "attrs": {}, "parents": []}]
        ents += [{"uid": {"type": "Key", "id": k}, "attrs": {}, "parents": []} for k in keys]
        checks = 0
        names = list(doc.get("fields", {}))
        for name in names:
            spec = self.policy["fields"].get(name)
            verified = []
            if spec:  # lazy: only check keys this field's rule names
                payload = canonical(name, doc["fields"][name]["value"])
                for k in spec["keys"]:
                    sig = doc["fields"][name].get("sigs", {}).get(k)
                    if sig is not None:
                        checks += 1
                        if verify_sig(keys[k], sig, payload):
                            verified.append(k)
            ents.append({"uid": {"type": "Field", "id": name},
                         "attrs": {"name": name,
                                   "signers": [{"__entity": {"type": "Key", "id": k}} for k in verified]},
                         "parents": []})
        reqs = [{"principal": 'Doc::"d"', "action": 'Action::"accept"',
                 "resource": f"Field::{json.dumps(n)}", "context": {}} for n in names]
        res = cedarpy.is_authorized_batch(reqs, self.policies, ents, SCHEMA) if reqs else []
        per = {n: r.decision == cedarpy.Decision.Allow for n, r in zip(names, res)}
        missing = sorted(set(self.policy["fields"]) - set(names))
        return {"accepted": bool(per) and all(per.values()) and not missing,
                "fields": per, "missing": missing, "sig_checks": checks}
