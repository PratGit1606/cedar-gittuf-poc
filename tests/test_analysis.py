import copy
import unittest

from gcedar.analysis import compare, dead_policies
from tests.util import PATTERNS

P = {n: "00" * 32 for n in ["a", "b", "c", "d"]}


def doc(rules, roles=None, default="deny"):
    return {"principals": P, "roles": roles or {}, "rules": rules, "default": default}


def rule(members, threshold, pattern="refs/heads/main", name="r"):
    return {"name": name, "pattern": pattern, "threshold": threshold, "members": members}


class Analysis(unittest.TestCase):
    def test_refactor_into_roles_is_equivalent(self):
        flat = doc([rule(["a", "b", "c"], 2)])
        # same semantics, rewritten as nested roles
        nested = doc([rule(["@ab", "c"], 1)], roles={"ab": {"threshold": 2, "members": ["a", "b"]}})
        # NOT equivalent: nested lets {a,b} or {c}; flat needs two of three
        r = compare(flat, nested)
        self.assertFalse(r["equivalent"])
        self.assertTrue(any(x["signers"] == ["c"] for x in r["only_b"]))
        # a real refactor: 2-of-3 as 1-of-3 pairs
        pairs = doc([rule(["@ab", "@ac", "@bc"], 1)], roles={
            "ab": {"threshold": 2, "members": ["a", "b"]},
            "ac": {"threshold": 2, "members": ["a", "c"]},
            "bc": {"threshold": 2, "members": ["b", "c"]}})
        self.assertTrue(compare(flat, pairs)["equivalent"])

    def test_privilege_escalation_counterexample(self):
        old = doc([rule(["a", "b", "c"], 2)])
        new = doc([rule(["a", "b", "c"], 1)])  # someone lowered the threshold
        r = compare(new, old)
        self.assertFalse(r["a_subset_of_b"])
        self.assertTrue(all(len(x["signers"]) >= 1 for x in r["only_a"]))
        self.assertTrue(any(x["signers"] == ["a"] for x in r["only_a"]))
        self.assertTrue(compare(old, new)["a_subset_of_b"])  # tightening is safe

    def test_dead_rule_shadowed_by_earlier_glob(self):
        d = doc([rule(["a"], 1, "refs/heads/*", "broad"), rule(["b"], 1, "refs/heads/main", "main")])
        dead = dead_policies(d)
        self.assertEqual([x["rule"] for x in dead], ["main"])

    def test_default_allow_catchall_shows_up(self):
        d = doc([rule(["a"], 1)], default="allow")
        self.assertEqual(dead_policies(d), [])
        self.assertTrue(compare(d, doc([rule(["a"], 1)]))["b_subset_of_a"])
