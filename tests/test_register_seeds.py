"""Register transformation + aletheia malicious-eval seed loading."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apatea.seed import (
    BUILTIN_ATOMS,
    aletheia_home,
    atoms,
    atoms_from_documents,
    load_malicious_documents,
)
from apatea.transform import variants

# Same resolution as the runner: ALETHEIA_HOME first, then the sibling default.
# A hardcoded path here meant these tests skipped everywhere but one laptop,
# including CI, so seed drift could never fail a build.
ALETHEIA = aletheia_home() or Path("/nonexistent/aletheia")


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


class UnqualifiedSeedResolution(unittest.TestCase):
    """The runner calls atoms() with no home argument.

    RegisterSeedCorpus passes an already-resolved directory, so it stays
    green if ALETHEIA_HOME stops selecting the corpus. Resolution is the
    one stated in the README: ALETHEIA_HOME when that directory is present,
    otherwise ~/Projects/tools/aletheia. Only evals/malicious/*.txt is eaten,
    as full documents plus extracted parameters, on top of the builtin atoms.
    A present home with no such corpus must not grow the list from the
    sibling tree.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _corpus(self, name, filename, body):
        home = self.root / name
        malicious = home / "evals" / "malicious"
        malicious.mkdir(parents=True)
        (malicious / filename).write_text(body, encoding="utf-8")
        return home

    def test_present_env_home_grows_unqualified_atoms(self):
        body = "widget@9.9.9 sits in the named tree.\n"
        decoy = "other@8.8.8 is not a text seed.\n"
        sibling = "fallback@7.7.7 sits in the sibling tree.\n"
        home = self._corpus("named", "note.txt", body)
        (home / "evals" / "malicious" / "note.md").write_text(decoy, encoding="utf-8")
        default = self._corpus("sibling", "seed.txt", sibling)
        with mock.patch.dict(os.environ, {"ALETHEIA_HOME": str(home)}), \
                mock.patch("apatea.seed.DEFAULT_ALETHEIA", default):
            self.assertEqual(aletheia_home(), home)
            self.assertEqual(load_malicious_documents(), (body,))
            loaded = atoms()
        self.assertIn(body, loaded)
        self.assertIn("widget@9.9.9", loaded)
        self.assertIn("9.9.9", loaded)
        self.assertIn(BUILTIN_ATOMS[0], loaded)
        self.assertNotIn(decoy, loaded)
        self.assertNotIn("other@8.8.8", loaded)
        self.assertNotIn(sibling, loaded)
        self.assertNotIn("fallback@7.7.7", loaded)

    def test_unset_env_eats_the_sibling_default(self):
        sibling = "fallback@7.7.7 sits in the sibling tree.\n"
        default = self._corpus("sibling", "seed.txt", sibling)
        with mock.patch.dict(os.environ):
            os.environ.pop("ALETHEIA_HOME", None)
            with mock.patch("apatea.seed.DEFAULT_ALETHEIA", default):
                self.assertEqual(aletheia_home(), default)
                loaded = atoms()
        self.assertIn(sibling, loaded)
        self.assertIn("fallback@7.7.7", loaded)
        self.assertIn("7.7.7", loaded)
        self.assertIn(BUILTIN_ATOMS[0], loaded)

    def test_present_home_without_corpus_does_not_eat_the_sibling(self):
        sibling = "fallback@7.7.7 sits in the sibling tree.\n"
        default = self._corpus("sibling", "seed.txt", sibling)
        home = self.root / "named"
        home.mkdir()
        with mock.patch.dict(os.environ, {"ALETHEIA_HOME": str(home)}), \
                mock.patch("apatea.seed.DEFAULT_ALETHEIA", default):
            self.assertEqual(load_malicious_documents(), ())
            self.assertEqual(atoms(), BUILTIN_ATOMS)


if __name__ == "__main__":
    unittest.main()
