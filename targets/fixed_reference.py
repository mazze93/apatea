"""The same assessor with the boundary policy applied.

Identical weights, identical patterns, one difference: `\b` is replaced by an
explicit rule about ASCII identifiers, stated rather than inherited from a
runtime default.

    Match a security keyword unless it is embedded inside a larger ASCII
    identifier. Unicode letters adjacent to it do not suppress a detection.

Its job in this repository is to be the control. A search that flags the
vulnerable target and also flags this one is not discriminating — it is just
noisy, and noise is how a security tool gets switched off.
"""
from __future__ import annotations

import re

from apatea.target import Assessment

from .vulnerable_reference import (AUTHORITY, KEYWORDS, PRESCRIPTIVE, TRUST,
                                   WEIGHTS)

ASCII_IDENT = "[A-Za-z0-9_]"
LEFT, RIGHT = f"(?<!{ASCII_IDENT})", f"(?!{ASCII_IDENT})"


def bounded(p: str) -> str:
    return f"{LEFT}(?:{p}){RIGHT}"


PATTERNS = {
    "urgency": re.compile(bounded(KEYWORDS), re.I),
    "prescriptive": re.compile(bounded(PRESCRIPTIVE), re.I),
    "authority": re.compile(bounded(AUTHORITY), re.I),
    "governing_parameter": re.compile(
        bounded(r"\d+\.\d+\.\d+") + r"|" + bounded(r"[a-z][\w-]*@\d+[\d.]*")
        + r"|" + bounded(r"(?:port|PORT)\s*[=:]\s*\d{2,5}")
        + r"|" + LEFT + r"(?:npm|pip|yarn)\s+(?:install|add)\s+[^\s﻿]+"
        + r"|" + LEFT + r"(?:export|set)\s+[A-Z_]{2,}=[^\s﻿]+"
        # Structured form. Aletheia's issue #1: the same governing parameter
        # wearing a different costume. Apatea found this gap in THIS file,
        # unprompted, before these three alternatives were added — the
        # form_reshape transformation reduced `port: 3000` to a score of 0.0.
        + r'|"(?:runtimeExecutable|command|cmd|exec|entrypoint|program|shell|interpreter)"\s*:\s*"[^"]{1,200}"'
        + r'|"(?:runtimeArgs|args|argv)"\s*:\s*\['
        + r'|"(?:port|PORT)"\s*:\s*"?\d{2,5}"?', re.I),
}


def assess(content: str, origin: str = "web_search") -> Assessment:
    factors, extracted = [], []
    for name, rx in PATTERNS.items():
        hits = [m.group(0) for m in rx.finditer(content)]
        if hits:
            factors.append(name)
            if name == "governing_parameter":
                extracted.extend(dict.fromkeys(hits))
    risk = sum(WEIGHTS[f] for f in factors)
    if "governing_parameter" in factors and "prescriptive" in factors:
        risk += 0.25
    if "urgency" in factors:
        risk *= 1.3
    risk = min(1.0, risk)
    trust = TRUST.get(origin, 0.3)
    score = min(1.0, risk * (0.4 + 0.6 * (1 - trust)))
    return Assessment(round(score, 4), tuple(factors), tuple(extracted))


class _T:
    name = "fixed_reference"
    assess = staticmethod(assess)


TARGET = _T()
