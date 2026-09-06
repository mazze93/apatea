"""Findings, and the half that is easy to skip: what held.

A run reporting nothing is indistinguishable from a run that searched nothing,
unless it says what it tried. The perimeter is not a courtesy — it is the only
thing that makes "no findings" mean anything, and it is the first thing to get
dropped under time pressure, so it is required here rather than optional.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .invariants import Violation


def content_hash(text: str) -> str:
    return "blake2s:" + hashlib.blake2s(text.encode("utf-8"), digest_size=16).hexdigest()


@dataclass
class Run:
    target: str
    origin: str
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    atoms: int = 0
    variants: int = 0
    checks: int = 0
    findings: list[Violation] = field(default_factory=list)
    tried: dict[str, int] = field(default_factory=dict)   # transformation -> variants
    held: dict[str, int] = field(default_factory=dict)    # invariant -> checks passed

    @property
    def clean(self) -> bool:
        return not self.findings

    def summary(self) -> dict:
        return {
            "ts": self.started,
            "target": self.target,
            "origin": self.origin,
            "atoms": self.atoms,
            "variants": self.variants,
            "checks": self.checks,
            "findings": len(self.findings),
            "perimeter": {"tried": self.tried, "held": self.held},
        }

    def to_jsonl(self, path: Path) -> None:
        """Append-only, hashed rather than storing payloads verbatim.

        Apatea's own output is, by construction, text engineered to look like an
        attack. Writing it verbatim into a shared log makes the log a delivery
        mechanism, so the payload is hashed and the reproducing input is left to
        the deterministic seed instead.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"kind": "run", **self.summary()}, ensure_ascii=False) + "\n")
            for v in self.findings:
                rec = {"kind": "finding", "ts": self.started, "target": self.target}
                rec.update(v.as_dict())
                rec["content_hash"] = content_hash(v.content)
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def render(self) -> str:
        lines = [f"apatea · target={self.target} · origin={self.origin}",
                 f"  {self.atoms} atoms → {self.variants} variants → {self.checks} checks"]
        if self.findings:
            lines.append(f"  {len(self.findings)} VIOLATION(S)")
            for v in self.findings[:40]:
                mark = "!!" if v.severity == "blinded" else " ·"
                lines.append(f"  {mark} [{v.invariant}] {v.atom!r} + {v.transformation}/{v.variant_id}")
                lines.append(f"       {v.detail}")
            if len(self.findings) > 40:
                lines.append(f"  … and {len(self.findings) - 40} more")
        else:
            lines.append("  no violations")
        lines.append("  perimeter — tried: " + ", ".join(f"{k}×{v}" for k, v in sorted(self.tried.items())))
        lines.append("  perimeter — held:  " + ", ".join(f"{k}×{v}" for k, v in sorted(self.held.items())))
        return "\n".join(lines)
