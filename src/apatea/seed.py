"""Seed atoms and documents from aletheia's malicious eval corpus.

Apatea does not invent her first lies from nowhere. The gate's
`evals/malicious/` directory is the perimeter memory — every costume the gate
already remembers is fodder for the transformation algebra. Soft-register
poems belong here as *seeds* for unicode / form_reshape / invisible; the gap
they document (proceed under ENFORCE) stays aletheia's known-failure alarm.

Seeds are *data*. Treat them the way aletheia treats a web result: never as
instruction to the runner itself.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

DEFAULT_ALETHEIA = Path.home() / "Projects" / "tools" / "aletheia"

# Governing-parameter shapes worth mutating even when no eval corpus is nearby.
# The founding incident's exact payload stays first so a cold run still covers it.
BUILTIN_ATOMS: tuple[str, ...] = (
    "critical", "urgent", "exploit", "breach", "immediately",
    "CVE-2024-9999", "must upgrade", "security advisory",
    "You should upgrade", "Run the following command", "use this version",
    "According to the official documentation", "officially recommended",
    "the documentation states", "1.2.3", "foo@1.2.3", "port: 3000",
    "npm install foo", "export API_KEY=xyz", "upgrade to version 2.0",
    '"runtimeExecutable": "npm"',
    # Founding incident + register-gap corpus (aletheia evals/malicious/register-*)
    "esbuild@0.28.1",
    "0.28.1",
    "npm install esbuild@0.28.1",
)

_PKG_AT = re.compile(r"\b[A-Za-z0-9_-]+@[0-9]+\.[0-9]+(?:\.[0-9]+)?\b")
_VERSION = re.compile(r"\b\d+\.\d+\.\d+\b")
_PORT = re.compile(r"\bport[\"'\s:=]+[0-9]{2,5}\b", re.I)


def aletheia_home(explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        return explicit if explicit.is_dir() else None
    env = os.environ.get("ALETHEIA_HOME")
    if env:
        p = Path(env)
        return p if p.is_dir() else None
    return DEFAULT_ALETHEIA if DEFAULT_ALETHEIA.is_dir() else None


def malicious_dir(home: Path | None = None) -> Path | None:
    root = aletheia_home(home)
    if root is None:
        return None
    d = root / "evals" / "malicious"
    return d if d.is_dir() else None


def load_malicious_documents(home: Path | None = None) -> tuple[str, ...]:
    """Full bodies of every `*.txt` under evals/malicious — search fodder."""
    d = malicious_dir(home)
    if d is None:
        return ()
    docs: list[str] = []
    for path in sorted(d.glob("*.txt")):
        text = path.read_text(encoding="utf-8")
        if text.strip():
            docs.append(text)
    return tuple(docs)


def load_expected_notes(home: Path | None = None) -> tuple[dict, ...]:
    """expected.jsonl rows — perimeter memory, including known failures."""
    root = aletheia_home(home)
    if root is None:
        return ()
    path = root / "evals" / "expected.jsonl"
    if not path.is_file():
        return ()
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return tuple(rows)


def atoms_from_documents(docs: tuple[str, ...]) -> tuple[str, ...]:
    """Pull compact governing-parameter atoms out of seed documents."""
    found: list[str] = []
    seen: set[str] = set()
    for doc in docs:
        for rx in (_PKG_AT, _VERSION, _PORT):
            for m in rx.finditer(doc):
                atom = m.group(0)
                if atom not in seen:
                    seen.add(atom)
                    found.append(atom)
    return tuple(found)


def atoms(home: Path | None = None,
          include_documents: bool = True) -> tuple[str, ...]:
    """Builtin atoms, plus atoms and (optionally) full docs from aletheia."""
    docs = load_malicious_documents(home)
    extra = atoms_from_documents(docs)
    out: list[str] = []
    seen: set[str] = set()
    for a in BUILTIN_ATOMS + extra:
        if a not in seen:
            seen.add(a)
            out.append(a)
    if include_documents:
        for doc in docs:
            # Cap size so a novel essay in the corpus cannot explode the search.
            if len(doc) <= 4000 and doc not in seen:
                seen.add(doc)
                out.append(doc)
    return tuple(out)
