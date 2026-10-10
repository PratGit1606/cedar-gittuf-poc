"""How badly does threshold expansion blow up, and what does it cost per request?"""
import math, time
from gcedar.compile import compile_delegations, count_threshold, ExpansionTooLarge
from gcedar.verify import Verifier


def flat(n, k):
    names = [f"p{i}" for i in range(n)]
    return {"principals": {x: "00" * 32 for x in names},
            "rules": [{"name": "r", "pattern": "refs/heads/main", "threshold": k, "members": names}]}


def nested(groups, per_group, outer_k, inner_k):
    roles, members, principals = {}, [], {}
    for g in range(groups):
        ms = [f"g{g}p{i}" for i in range(per_group)]
        principals.update({m: "00" * 32 for m in ms})
        roles[f"g{g}"] = {"threshold": inner_k, "members": ms}
        members.append(f"@g{g}")
    return {"principals": principals, "roles": roles,
            "rules": [{"name": "r", "pattern": "refs/heads/main", "threshold": outer_k, "members": members}]}


def latency_us(doc, reps=300):
    v = Verifier(doc)
    names = sorted(doc["principals"])
    cases = [(names[: i % len(names) + 1], [], names[0]) for i in range(reps)]
    t = time.perf_counter()
    v.check_batch("refs/heads/main", cases)
    return (time.perf_counter() - t) / reps * 1e6


configs = [(f"flat {k}-of-{n}", flat(n, k)) for n, k in
           [(3, 2), (5, 3), (7, 4), (10, 3), (10, 5), (12, 6), (15, 5), (16, 8), (20, 10)]]
configs += [(f"{ok}-of-{g} roles, each {ik}-of-{p}", nested(g, p, ok, ik)) for g, p, ok, ik in
            [(3, 3, 2, 2), (4, 4, 2, 2), (5, 5, 3, 3), (6, 6, 3, 3), (5, 8, 3, 4), (8, 8, 4, 4)]]

print(f"{'config':32} {'candidates':>14} {'permits':>10} {'KB':>9} {'compile ms':>11} {'us/req':>8}")
for label, doc in configs:
    r = doc["rules"][0]
    cand = count_threshold(r["members"], r["threshold"], doc.get("roles", {}))
    try:
        t = time.perf_counter(); c = compile_delegations(doc); ms = (time.perf_counter() - t) * 1000
    except ExpansionTooLarge:
        print(f"{label:32} {cand:>14,} {'REFUSED (over limit)':>43}")
        continue
    lat = latency_us(doc) if c.n_permit <= 20000 else float("nan")
    print(f"{label:32} {cand:>14,} {c.n_permit:>10,} {len(c.policies) / 1024:>9.1f} {ms:>11.1f} {lat:>8.0f}")
    if label.startswith("flat"):
        k, n = map(int, label.split()[1].split("-of-"))
        assert c.n_permit == math.comb(n, k)
print("flat rows equal C(n,k): ok")
