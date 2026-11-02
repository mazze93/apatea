"""Register transformation + aletheia malicious-eval seed loading."""
from __future__ import annotations

import unittest
from pathlib import Path

from apatea.seed import (
    BUILTIN_ATOMS,
    atoms,
    atoms_from_documents,
    load_malicious_documents,
)
from apatea.transform import variants

ALETHEIA = Path.home() / "Projects" / "tools" / "aletheia"


@unittest.skipUnless(
    (ALETHEIA / "evals" / "malicious" / "register-poem-ballad.txt").is_file(),
    "aletheia register-gap corpus not checked out",
)
class RegisterSeedCorpus(unittest.TestCase):
    def test_loads_register_documents(self):
        docs = load_malicious_documents(ALETHEIA)
        names_hint = " ".join(docs)
        self.assertIn("esbuild@0.28.1", names_hint)
        self.assertTrue(any("\u200b" in d for d in docs), "ZWSP poem missing")

    def test_atoms_include_founding_payload_and_documents(self):
        a = atoms(ALETHEIA)
        self.assertIn("esbuild@0.28.1", a)
        self.assertGreater(len(a), len(BUILTIN_ATOMS))
        # Full soft-register bodies are seeds, not only extracted atoms.
        self.assertTrue(any("small key" in s for s in a))

    def test_extracted_atoms_from_docs(self):
        docs = load_malicious_documents(ALETHEIA)
        extracted = atoms_from_documents(docs)
        self.assertIn("esbuild@0.28.1", extracted)
        self.assertIn("0.28.1", extracted)


class RegisterTransformation(unittest.TestCase):
    def test_wraps_compact_atom(self):
        out = [v for v in variants("esbuild@0.28.1") if v.transformation == "register"]
        ids = {v.variant_id for v in out}
        self.assertEqual(
            ids, {"quiet-prose", "poem-minimal", "poem-ballad", "poem-zwsp"}
        )
        zwsp = next(v for v in out if v.variant_id == "poem-zwsp")
        self.assertIn("\u200b", zwsp.content)
        self.assertIn("esbuild@0.28.1", zwsp.content)
        self.assertIn("crit\u200bical", zwsp.content)

    def test_skips_multiline_documents(self):
        poem = "esbuild@0.28.1 —\na small key\nfor a small door.\n"
        out = [v for v in variants(poem) if v.transformation == "register"]
        self.assertEqual(out, [])

    def test_skips_empty_atom(self):
        self.assertEqual(
            [v for v in variants("") if v.transformation == "register"], []
        )
        self.assertEqual(
            [v for v in variants("   ") if v.transformation == "register"], []
        )


if __name__ == "__main__":
    unittest.main()
