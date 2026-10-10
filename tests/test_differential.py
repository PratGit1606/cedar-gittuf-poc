"""Cedar-compiled verdicts must equal the reference verifier on every input."""
import itertools
import random
import unittest

from gcedar.analysis import sample_refs, subsets
from gcedar.reference import reference_allows
from gcedar.verify import Verifier
from tests.util import random_doc


class Differential(unittest.TestCase):
    def test_random_docs_exhaustive(self):
        rng = random.Random(1609)
        total = mismatches = docs = 0
        for _ in range(150):
            doc = random_doc(rng)
            names = sorted(doc["principals"])
            v = Verifier(doc)
            cases = []
            for s in subsets(names):
                cases.append((s, [], names[0]))
            for _ in range(60):  # mixed signers/approvals/author
                cases.append((rng.sample(names, rng.randint(0, 6)), rng.sample(names, rng.randint(0, 6)),
                              rng.choice(names)))
            for a in subsets(names):
                cases.append(([], a, names[0]))
            for ref in sample_refs(doc):
                got = []
                # check_batch takes (signers, approvals, author)
                got = v.check_batch(ref, [(s, a, au) for s, a, au in cases])
                for (s, a, au), g in zip(cases, got):
                    want = reference_allows(doc, ref, set(s), set(a), au)
                    total += 1
                    if g != want:
                        mismatches += 1
                        if mismatches <= 5:
                            print("MISMATCH", ref, s, a, au, "cedar", g, "ref", want, doc)
            docs += 1
        print(f"differential: {docs} docs, {total} verdicts compared, {mismatches} mismatches")
        self.assertEqual(mismatches, 0)
        self.assertGreater(total, 100000)


if __name__ == "__main__":
    unittest.main()
