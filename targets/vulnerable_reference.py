"""A deliberately pre-fix assessor. DO NOT USE AS A GATE.

This is aletheia's detection logic as it stood *before* the boundary policy —
`\b`-anchored patterns, which are dialect-dependent and blind to a keyword with
a non-ASCII letter beside it.

It exists so apatea's own CI can prove the search works without checking out an
old revision of another repository. The ADR's validation condition is that
apatea rediscovers issue #3; this target is the known bug, held still, so that
claim is a test rather than a promise.

If apatea ever reports this target clean, apatea is broken.
"""
from __future__ import annotations

import re

from apatea.target import Assessment

KEYWORDS = r"critical|urgent|exploit|breach|immediately|zero[\s-]day"
PRESCRIPTIVE = r"you\s+should\s+upgrade|run\s+the\s+following\s+command|use\s+this\s+version"
AUTHORITY = r"according\s+to\s+the\s+official|officially\s+recommended|the\s+documentation\s+states"

# The defect, preserved: \b means "a transition between \w and \W", and what
# counts as \w differs between runtimes. Python's is Unicode-aware, so `é`
# counts as a word character and `criticalé` has no boundary after `critical`.
PATTERNS = {
    "urgency": re.compile(r"\b(?:" + KEYWORDS + r")\b", re.I),
    "prescriptive": re.compile(r"\b(?:" + PRESCRIPTIVE + r")\b", re.I),
    "authority": re.compile(r"\b(?:" + AUTHORITY + r")\b", re.I),
    "governing_parameter": re.compile(
        r"\b\d+\.\d+\.\d+\b|\b[a-z][\w-]*@\d+[\d.]*\b"
        r"|\b(?:port|PORT)\s*[=:]\s*\d{2,5}\b"
        r"|\b(?:npm|pip|yarn)\s+(?:install|add)\s+\S+"
        r"|\b(?:export|set)\s+[A-Z_]{2,}=[^\s]+", re.I),
}

WEIGHTS = {"governing_parameter": 0.30, "urgency": 0.25,
           "prescriptive": 0.35, "authority": 0.20}

TRUST = {"user": 1.0, "file": 0.9, "mcp_tool": 0.5,
         "web_search": 0.2, "web_fetch": 0.2, "clipboard": 0.1}


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
    name = "vulnerable_reference"
    assess = staticmethod(assess)


TARGET = _T()
