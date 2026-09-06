"""The catalogue, checked directly rather than through a search."""
from __future__ import annotations

import unittest

from apatea.invariants import determinism, extent_stability
from apatea.search import run
from apatea.target import Assessment, CallableTarget
from apatea.transform import ALGEBRA, variants


def _static(score, extracted=()):
    return lambda c, o: Assessment(score, ("x",), tuple(extracted))


class ExtentStability(unittest.TestCase):
    def test_flags_a_parameter_not_present_verbatim(self):
        t = CallableTarget("liar", _static(0.5, ["not-in-the-input"]))
        v = extent_stability(t, "some content", "web_search")
        self.assertIsNotNone(v)
        self.assertEqual(v.invariant, "extent_stability")

    def test_accepts_a_parameter_that_is_present(self):
        t = CallableTarget("honest", _static(0.5, ["content"]))
        self.assertIsNone(extent_stability(t, "some content", "web_search"))


class Determinism(unittest.TestCase):
    def test_flags_an_unstable_target(self):
        seq = iter([0.1, 0.9])
        t = CallableTarget("flaky", lambda c, o: Assessment(next(seq)))
        self.assertIsNotNone(determinism(t, "x", "web_search"))


class Monotonicity(unittest.TestCase):
    def test_a_target_that_ignores_content_is_clean(self):
        """Vacuously monotone — and the perimeter is what exposes that."""
        r = run(CallableTarget("constant", _static(0.5)))
        self.assertEqual(r.findings, [])
        self.assertGreater(r.variants, 0)


class Algebra(unittest.TestCase):
    def test_every_transformation_declares_meaning_preservation(self):
        for t in ALGEBRA:
            self.assertIsInstance(t.meaning_preserving, bool, t.name)

    def test_reshape_refuses_already_structured_input(self):
        """The guard apatea's own first run taught it."""
        out = [v for v in variants('{"a": "b"}') if v.transformation == "form_reshape"]
        self.assertEqual(out, [], "double-encoding is not a meaning-preserving reshape")

    def test_case_refuses_identifiers(self):
        for ident in ("export API_KEY=xyz", '"runtimeExecutable": "npm"', "foo@1.2.3"):
            out = [v for v in variants(ident) if v.transformation == "case"]
            self.assertEqual(out, [], f"case is not meaning-preserving for {ident!r}")

    def test_case_still_applies_to_prose(self):
        out = [v for v in variants("critical") if v.transformation == "case"]
        self.assertTrue(out)


if __name__ == "__main__":
    unittest.main()
