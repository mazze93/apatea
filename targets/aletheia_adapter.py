"""Adapter for the live gate.

Set ALETHEIA_HOME, or leave it and the default sibling path is tried. The
adapter is intentionally trivial: apatea should never need to understand
aletheia's internals, only her answer.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from apatea.target import Assessment

DEFAULT = Path.home() / "Projects" / "tools" / "aletheia"


def _load():
    home = Path(os.environ.get("ALETHEIA_HOME", DEFAULT))
    src = home / "src"
    if not (src / "aletheia").is_dir():
        raise ImportError(f"aletheia not found at {home} (set ALETHEIA_HOME)")
    sys.path.insert(0, str(src))
    from aletheia.assess import assess as _assess  # noqa: PLC0415
    return _assess


def assess(content: str, origin: str = "web_search") -> Assessment:
    fn = _load()
    a = fn(content, origin)
    return Assessment(
        score=float(a.injection_risk_score),
        factors=tuple(f["category"] for f in a.risk_factors),
        extracted=tuple(a.governing_parameters),
    )


class _T:
    name = "aletheia"
    assess = staticmethod(assess)


TARGET = _T()
