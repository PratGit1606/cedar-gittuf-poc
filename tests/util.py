import random
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from gcedar.verify import rsl_payload


def keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, pk.hex()


def make_world(names):
    sks, pks = {}, {}
    for n in names:
        sks[n], pks[n] = keypair()
    return sks, pks


def sign(sk, ref, commit):
    return sk.sign(rsl_payload(ref, commit)).hex()


PATTERNS = ["refs/heads/main", "refs/heads/*", "refs/heads/release/*", "refs/tags/*", "*"]


def random_doc(rng: random.Random, n_principals=6):
    names = [f"p{i}" for i in range(n_principals)]
    n_roles = rng.randint(0, 3)
    roles = {}
    for i in range(n_roles):
        pool = names + [f"@r{j}" for j in range(i + 1, n_roles)]
        members = rng.sample(pool, rng.randint(1, min(4, len(pool))))
        roles[f"r{i}"] = {"threshold": rng.randint(1, len(members)), "members": members}
    rules = []
    for i in range(rng.randint(1, 4)):
        pool = names + [f"@r{j}" for j in range(n_roles)]
        members = rng.sample(pool, rng.randint(1, min(5, len(pool))))
        rules.append({"name": f"rule{i}", "pattern": rng.choice(PATTERNS),
                      "threshold": rng.randint(1, len(members)), "members": members,
                      "source": rng.choice(["signers", "signers", "approvals"])})
    return {"principals": {n: "00" * 32 for n in names}, "roles": roles, "rules": rules,
            "default": rng.choice(["allow", "deny"]),
            "forbid_self_approval": rng.random() < 0.3}
