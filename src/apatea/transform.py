"""The transformation algebra.

Apatea does not carry a list of attacks. Lists go stale, and they only ever
contain attacks somebody already thought of — U+FEFF was found precisely
because nobody had. Instead it carries *transformations*: functions from one
string to many, each with a claim about whether it preserves meaning.

That claim is what makes an invariant checkable. `criticalé` still reads as
"critical" to a human, so a detector that stops seeing it has lost something. A
transformation that genuinely changes meaning would make the same test
nonsense, so those are marked and excluded from monotonicity.
"""
from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterator

# Non-ASCII letters across scripts. A detector that survives é but not Ж has
# been fixed for Latin-1, not fixed.
LETTER_EDGES = ["é", "ü", "α", "Ж", "א", "م", "क", "中"]

# Format and mark characters. Historically these did NOT produce divergence,
# which is exactly why they are kept: a control that starts failing is
# information.
INVISIBLE_EDGES = [
    "́",  # combining acute
    "​",  # zero-width space
    "‌",  # ZWNJ
    "‍",  # ZWJ
    "‮",  # RTL override
    "﻿",  # BOM / zero-width no-break space
]


@dataclass(frozen=True)
class Variant:
    transformation: str
    variant_id: str
    content: str


@dataclass(frozen=True)
class Transformation:
    name: str
    fn: Callable[[str], Iterator[Variant]]
    meaning_preserving: bool
    note: str = ""

    def __call__(self, text: str) -> list[Variant]:
        return list(self.fn(text))


def _unicode_adjacency(text: str) -> Iterator[Variant]:
    """A non-ASCII letter at either boundary. This is issue #3."""
    for edge in LETTER_EDGES:
        cp = f"U+{ord(edge):04X}"
        yield Variant("unicode_adjacency", f"prefix-{cp}", edge + text)
        yield Variant("unicode_adjacency", f"suffix-{cp}", text + edge)


def _invisible(text: str) -> Iterator[Variant]:
    """Zero-width and combining characters at the boundaries."""
    for edge in INVISIBLE_EDGES:
        cp = f"U+{ord(edge):04X}"
        yield Variant("invisible", f"prefix-{cp}", edge + text)
        yield Variant("invisible", f"suffix-{cp}", text + edge)


def _normalization(text: str) -> Iterator[Variant]:
    for form in ("NFC", "NFD", "NFKC", "NFKD"):
        out = unicodedata.normalize(form, text)
        if out != text:
            yield Variant("normalization", form.lower(), out)


# Syntax that makes a string an identifier rather than prose. Env var names,
# package names, JSON keys, CVE ids and shell commands are all case-sensitive
# to their real consumers, so changing their case changes their meaning.
_IDENTIFIERISH = ('=', '@', '"', '{', '/', '\\', '_')


def _case(text: str) -> Iterator[Variant]:
    """Case folding — meaning-preserving for prose, and only for prose.

    Second guard learned from apatea's own output. Run against live aletheia,
    the unguarded version produced nine 'findings', eight of which were this
    mistake: `export API_KEY=xyz` uppercased is not the same command, and
    `"runtimeExecutable"` title-cased is not the same key. The detector was
    right to stop matching; the transformation was wrong to claim equivalence.

    An adversary that cries wolf on identifiers would train its reader to
    ignore it, which costs more than the findings are worth.
    """
    if any(ch in text for ch in _IDENTIFIERISH) or any(c.isdigit() for c in text):
        return
    for name, out in (("upper", text.upper()), ("title", text.title())):
        if out != text:
            yield Variant("case", name, out)


def _form_reshape(text: str) -> Iterator[Variant]:
    """Prose to structured form.

    The transformation that would have found issue #1 with no human insight
    involved: the detector recognised `port: 3000` and missed `"port": 3000`.
    Same governing parameter, different costume.
    """
    # Guard, learned from apatea's own first run against the fixed reference:
    # reshaping text that is ALREADY structured double-encodes its quotes, and
    # a double-encoded string is not the same claim in a different costume — it
    # is a different string. The transformation would then report a monotonicity
    # violation that says nothing about the target, only about the mangling.
    #
    # A transformation's meaning_preserving flag is a claim, and claims need
    # guards. False positives are how a security tool gets switched off.
    if '"' in text or "{" in text:
        return

    yield Variant("form_reshape", "json-value", json.dumps({"command": text}))
    yield Variant("form_reshape", "json-nested",
                  json.dumps({"config": {"servers": [{"exec": text}]}}))
    if ":" in text:
        key, _, val = text.partition(":")
        yield Variant("form_reshape", "json-keyed",
                      json.dumps({key.strip(): val.strip()}))
    yield Variant("form_reshape", "yamlish", f"config:\n  value: {text}\n")

    # Value SHAPE, not just structure. Aletheia's issue #7: the detector had
    # learned that a governing parameter can wear prose or JSON, but each
    # pattern still hard-coded one value shape — a quoted string for
    # executables, a bare number for ports — so each was blind to the other's
    # form. An array-valued command is the canonical shape in docker-compose,
    # Kubernetes and launch.json, and it was the one that got through.
    #
    # Found by hand while writing that issue up, which is the wrong way round.
    # These variants exist so the next one is found by the search.
    yield Variant("form_reshape", "json-array", json.dumps({"command": [text]}))
    yield Variant("form_reshape", "json-args", json.dumps({"args": [text, "-c"]}))
    if text.isdigit():
        yield Variant("form_reshape", "json-number-bare", '{"port": %s}' % text)
        yield Variant("form_reshape", "json-number-quoted", '{"port": "%s"}' % text)


ALGEBRA: tuple[Transformation, ...] = (
    Transformation("unicode_adjacency", _unicode_adjacency, True,
                   "found issue #3 in aletheia"),
    Transformation("invisible", _invisible, True,
                   "found the U+FEFF extent split"),
    Transformation("normalization", _normalization, True),
    Transformation("case", _case, True),
    Transformation("form_reshape", _form_reshape, True,
                   "the shape of issue #1"),
)


def variants(text: str, only: tuple[str, ...] | None = None) -> list[Variant]:
    out: list[Variant] = []
    for t in ALGEBRA:
        if only and t.name not in only:
            continue
        out.extend(t(text))
    return out
