"""The validation condition from ADR-0001, as a test.

    "Validated the day apatea, running only from its own repository against an
     adapter, independently rediscovers issue #3 in a checkout of aletheia
     predating the boundary policy. Until then this is a design, not an
     instrument."

`targets/vulnerable_reference.py` is that predating state, held still, so the
claim is checkable without a second repository. If this file ever passes
trivially — or if apatea reports the vulnerable target clean — apatea is broken,
not fixed.
"""
from __future__ import annotations

import unittest

from apatea.search import run
from targets.fixed_reference import TARGET as FIXED
from targets.vulnerable_reference import TARGET as VULNERABLE


class RediscoversTheKnownFinding(unittest.TestCase):
    def setUp(self):
        self.r = run(VULNERABLE)

    def test_it_finds_violations_at_all(self):
        self.assertTrue(self.r.findings, "found nothing in a known-vulnerable target")

    def test_it_finds_the_unicode_adjacency_class(self):
        hits = [v for v in self.r.findings if v.transformation == "unicode_adjacency"]
        self.assertTrue(hits, "did not rediscover issue #3")

    def test_it_finds_the_sharp_form_total_suppression(self):
        """Not merely a lower score — every factor silenced. That was the bug."""
        blinded = [v for v in self.r.findings
                   if v.severity == "blinded" and v.transformation == "unicode_adjacency"]
        self.assertTrue(blinded, "found a dip, not the blindness")
        self.assertTrue(any(v.atom == "critical" for v in blinded),
                        "did not reproduce the canonical `criticalé` case")

    def test_it_finds_the_class_across_scripts(self):
        """Latin-1 only would mean fixed-for-French, not fixed."""
        scripts = {v.variant_id.split("-")[-1] for v in self.r.findings
                   if v.transformation == "unicode_adjacency"}
        self.assertGreaterEqual(len(scripts), 4, f"only saw {scripts}")


class DoesNotCryWolf(unittest.TestCase):
    """A search that flags everything is not discriminating, it is noisy.

    Noise is how a security tool gets switched off, which is the failure mode
    that matters most for something nobody is paid to read.
    """

    def test_the_fixed_reference_is_clean(self):
        r = run(FIXED)
        self.assertEqual(
            [v.as_dict() for v in r.findings], [],
            "flagged the target that has the fix — apatea is over-reporting",
        )

    def test_the_control_was_actually_searched(self):
        """Clean must mean 'searched and held', never 'searched nothing'."""
        r = run(FIXED)
        self.assertGreater(r.variants, 500)
        self.assertGreater(sum(r.held.values()), 500)
        self.assertGreaterEqual(len(r.tried), 4)


if __name__ == "__main__":
    unittest.main()
