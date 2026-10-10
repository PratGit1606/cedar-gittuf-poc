import unittest

from gcedar.verify import Verifier
from tests.util import make_world, sign

SKS, PKS = make_world(["alice", "bob", "carol", "dave", "erin"])
DOC = {
    "principals": PKS,
    "roles": {"release": {"threshold": 1, "members": ["dave", "erin"]}},
    "rules": [
        {"name": "main", "pattern": "refs/heads/main", "threshold": 2, "members": ["alice", "bob", "@release"]},
        {"name": "reviewed", "pattern": "refs/heads/feature/*", "threshold": 2,
         "members": ["alice", "bob", "carol"], "source": "approvals"},
    ],
    "default": "deny",
    "forbid_self_approval": True,
}
REF, C1, C2 = "refs/heads/main", "c" * 40, "d" * 40


def change(signers, commit=C1, ref=REF, sign_commit=None, **kw):
    return {"ref": ref, "commit": commit, "pusher": "alice", "author": "carol",
            "signatures": {p: sign(SKS[p], ref, sign_commit or commit) for p in signers}, **kw}


class PhaseA(unittest.TestCase):
    def setUp(self):
        self.v = Verifier(DOC)

    def test_threshold_met_with_nested_role(self):
        d = self.v.check(change(["alice", "dave"]))
        self.assertTrue(d.allowed)
        self.assertEqual(sorted(d.signers), ["alice", "dave"])

    def test_threshold_not_met(self):
        self.assertFalse(self.v.check(change(["alice"])).allowed)
        self.assertFalse(self.v.check(change(["dave", "erin"])).allowed)  # one role satisfaction only

    def test_signature_over_other_commit_rejected(self):
        d = self.v.check(change(["alice", "bob"], sign_commit=C2))
        self.assertFalse(d.allowed)
        self.assertEqual(d.signers, [])

    def test_wrong_key_rejected(self):
        c = change(["alice", "bob"])
        c["signatures"]["bob"] = sign(SKS["carol"], REF, C1)  # carol signs, claims to be bob
        d = self.v.check(c)
        self.assertEqual(d.signers, ["alice"])
        self.assertFalse(d.allowed)

    def test_garbage_signature_does_not_crash(self):
        c = change(["alice", "bob"])
        c["signatures"]["bob"] = "zz"
        self.assertFalse(self.v.check(c).allowed)

    def test_lazy_verification_only_for_relevant_principals(self):
        c = change(["alice", "bob", "carol", "dave", "erin"])
        self.assertEqual(self.v.check(c).sig_checks, 4)  # carol is not named by the main rule
        c = change(["alice", "bob", "carol"], ref="refs/other/x")
        self.assertEqual(self.v.check(c).sig_checks, 0)  # no rule matches, nothing verified


class ForgeData(unittest.TestCase):
    def setUp(self):
        self.v = Verifier(DOC)
        self.ref = "refs/heads/feature/x"

    def pr(self, reviews, dismissals=(), head=C1, author="carol"):
        return {"ref": self.ref, "commit": head, "pusher": "alice", "author": author, "signatures": {},
                "forge": {"head": head, "reviews": reviews, "dismissals": list(dismissals)}}

    def rv(self, who, state="APPROVED", commit=C1, at=1):
        return {"who": who, "state": state, "commit": commit, "at": at}

    def test_two_fresh_approvals(self):
        self.assertTrue(self.v.check(self.pr([self.rv("alice"), self.rv("bob")])).allowed)

    def test_stale_approval_after_new_commit(self):
        d = self.v.check(self.pr([self.rv("alice"), self.rv("bob", commit=C2)]))
        self.assertFalse(d.allowed)
        self.assertEqual(d.approvals, ["alice"])

    def test_dismissed_approval(self):
        d = self.v.check(self.pr([self.rv("alice", at=1), self.rv("bob", at=1)],
                                 dismissals=[{"who": "bob", "at": 2}]))
        self.assertFalse(d.allowed)

    def test_reapproval_after_dismissal_counts(self):
        d = self.v.check(self.pr([self.rv("alice", at=1), self.rv("bob", at=3)],
                                 dismissals=[{"who": "bob", "at": 2}]))
        self.assertTrue(d.allowed)

    def test_later_changes_requested_supersedes_approval(self):
        d = self.v.check(self.pr([self.rv("alice", at=1), self.rv("bob", at=1),
                                  self.rv("bob", "CHANGES_REQUESTED", at=2)]))
        self.assertFalse(d.allowed)

    def test_self_approval_forbidden(self):
        d = self.v.check(self.pr([self.rv("alice"), self.rv("bob"), self.rv("carol")], author="carol"))
        self.assertFalse(d.allowed)  # carol approved her own PR, forbid overrides the permit
        # Cedar reports the forbid that fired, so the denial is explainable
        self.assertEqual([(r["kind"], r["rule"]) for r in d.reasons], [("forbid", "<self-approval>")])
