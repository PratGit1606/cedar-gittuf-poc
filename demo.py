"""End-to-end demo: JSON delegations -> Cedar, signatures verified on the host."""
from gcedar.compile import compile_delegations
from gcedar.verify import Verifier
from gcedar.analysis import compare
from tests.util import make_world, sign

SKS, PKS = make_world(["alice", "bob", "carol", "dave", "erin"])
doc = {
    "principals": PKS,
    "roles": {"release": {"threshold": 1, "members": ["dave", "erin"]}},
    "rules": [{"name": "main", "pattern": "refs/heads/main", "threshold": 2,
               "members": ["alice", "bob", "@release"]}],
    "default": "deny",
}
print("== generated Cedar (2 of [alice, bob, @release(1 of dave,erin)]) ==")
print(compile_delegations(doc).policies)

v = Verifier(doc)
ref, commit = "refs/heads/main", "a" * 40
def change(who, sign_commit=commit):
    return {"ref": ref, "commit": commit, "pusher": "alice", "author": "carol",
            "signatures": {p: sign(SKS[p], ref, sign_commit) for p in who}}

for label, ch in [("alice + dave", change(["alice", "dave"])),
                  ("alice alone", change(["alice"])),
                  ("dave + erin (one role satisfied twice)", change(["dave", "erin"])),
                  ("alice + bob, signed a different commit", change(["alice", "bob"], "b" * 40))]:
    d = v.check(ch)
    why = [r.get("combo") for r in d.reasons]
    print(f"{label:42} -> {'ALLOW' if d.allowed else 'DENY '}  verified={d.signers} permits_fired={why}")

print("\n== privilege escalation check: did someone lower the threshold? ==")
weaker = {**doc, "rules": [{**doc["rules"][0], "threshold": 1}]}
r = compare(weaker, doc)
print("new policy allows nothing the old one denied:", r["a_subset_of_b"])
print("counterexample:", r["only_a"][0])
