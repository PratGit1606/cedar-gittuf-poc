import unittest

from gcedar.fields import FieldVerifier, canonical
from tests.util import make_world

SKS, PKS = make_world(["k1", "k2", "k3"])
POLICY = {"keys": PKS, "fields": {"expires": {"threshold": 1, "keys": ["k1", "k2"]},
                                  "targets": {"threshold": 2, "keys": ["k1", "k2", "k3"]}}}


def field(name, value, signers, tamper=False):
    msg = canonical(name, value)
    return {"value": value, "sigs": {k: SKS[k].sign(b"x" + msg if tamper else msg).hex() for k in signers}}


class Fields(unittest.TestCase):
    def setUp(self):
        self.v = FieldVerifier(POLICY)

    def doc(self, **over):
        d = {"fields": {"expires": field("expires", "2027-01-01", ["k2"]),
                        "targets": field("targets", {"a": 1}, ["k1", "k3"])}}
        d["fields"].update(over)
        return d

    def test_accept(self):
        self.assertTrue(self.v.check(self.doc())["accepted"])

    def test_value_changed_after_signing(self):
        d = self.doc()
        d["fields"]["expires"]["value"] = "2099-01-01"
        r = self.v.check(d)
        self.assertFalse(r["accepted"])
        self.assertFalse(r["fields"]["expires"])

    def test_threshold_on_field(self):
        r = self.v.check(self.doc(targets=field("targets", {"a": 1}, ["k1"])))
        self.assertFalse(r["fields"]["targets"])

    def test_key_not_allowed_for_field(self):
        r = self.v.check(self.doc(expires=field("expires", "x", ["k3"])))  # k3 not in expires' key set
        self.assertFalse(r["fields"]["expires"])

    def test_unknown_field_denied_by_default(self):
        r = self.v.check(self.doc(extra=field("extra", 1, ["k1", "k2", "k3"])))
        self.assertFalse(r["fields"]["extra"])
        self.assertFalse(r["accepted"])

    def test_missing_required_field(self):
        d = self.doc()
        del d["fields"]["targets"]
        r = self.v.check(d)
        self.assertEqual(r["missing"], ["targets"])
        self.assertFalse(r["accepted"])

    def test_signature_replayed_from_other_field(self):
        d = self.doc()
        d["fields"]["expires"] = {"value": "2027-01-01", "sigs": d["fields"]["targets"]["sigs"]}
        self.assertFalse(self.v.check(d)["fields"]["expires"])
