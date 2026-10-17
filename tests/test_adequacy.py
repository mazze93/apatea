"""The search instrument must reject vacuous and malformed evidence."""
import unittest
from apatea.cli import main
from apatea.search import run
from apatea.target import Assessment, CallableTarget
from targets.fixed_reference import TARGET

class Adequacy(unittest.TestCase):
    def test_empty_search_is_not_a_pass(self):
        for kwargs in ({"atoms": ()}, {"only": ("typo",)}, {"only": ()},
                       {"atoms": ("123",), "only": ("case",)}):
            with self.assertRaises(ValueError):
                run(TARGET, **kwargs)

    def test_malformed_assessments_are_rejected(self):
        for value in (None, Assessment(float("nan")), Assessment(float("inf")),
                      Assessment(-1), Assessment(2), Assessment(True),
                      Assessment(0.5, extracted=(123,))):
            target = CallableTarget("malformed", lambda c, o: value,
                                    controls=(("critical",), ("ordinary",)))
            with self.assertRaises(ValueError):
                run(target)

    def test_target_errors_are_distinct_from_findings(self):
        self.assertEqual(main(["--target", "fixed", "--only", "typo", "--quiet"]), 2)

    def test_target_must_declare_both_controls(self):
        with self.assertRaises(ValueError):
            run(CallableTarget("unspecified", lambda c, o: Assessment(0)))

    def test_control_preserves_ascii_edges_under_ignorecase(self):
        for ch in ("K", "ſ", "İ", "ı"):
            self.assertGreater(TARGET.assess("critical" + ch, "web_search").score, 0)
