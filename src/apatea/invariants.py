"""Properties that must survive transformation.

The catalogue is the product. A crash-hunting fuzzer would have found none of
aletheia's three real evasions, because none of them crashed anything — all
three returned a confident, well-formed, wrong answer. The oracle has to be a
stated property, not a segfault.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .target import Assessment, Target
from .transform import Transformation, Variant

EPS = 1e-9


@dataclass(frozen=True)
class Violation:
    invariant: str
    atom: str
    transformation: str
    variant_id: str
    detail: str
    severity: str = "finding"        # finding | blinded
    baseline_score: float = 0.0
    mutated_score: float = 0.0
    content: str = ""

    def as_dict(self) -> dict:
        return {
            "invariant": self.invariant,
            "atom": self.atom,
            "transformation": self.transformation,
            "variant": self.variant_id,
            "severity": self.severity,
            "baseline_score": round(self.baseline_score, 6),
            "mutated_score": round(self.mutated_score, 6),
            "detail": self.detail,
        }


def monotonicity(target: Target, atom: str, origin: str,
                 transformation: Transformation,
                 variant: Variant, baseline: Assessment) -> Violation | None:
    """A meaning-preserving transformation must not lower assessed risk.

    Stated as `must not lower`, not `must keep identical`: raising suspicion is
    always allowed. The asymmetry is the whole point — an attacker profits only
    from the downward direction.
    """
    if not transformation.meaning_preserving:
        return None
    got = target.assess(variant.content, origin)
    if got.score >= baseline.score - EPS:
        return None
    blinded = baseline.score > 0 and got.blind
    return Violation(
        invariant="monotonicity",
        atom=atom,
        transformation=variant.transformation,
        variant_id=variant.variant_id,
        severity="blinded" if blinded else "finding",
        baseline_score=baseline.score,
        mutated_score=got.score,
        content=variant.content,
        detail=(
            f"score fell {baseline.score:.4f} -> {got.score:.4f}"
            + (" — every factor suppressed" if blinded else "")
        ),
    )


def extent_stability(target: Target, content: str, origin: str,
                     atom: str = "", transformation: str = "",
                     variant_id: str = "") -> Violation | None:
    """Every extracted parameter must appear verbatim in the input.

    `extracted` is what a human is told to go and verify at a registry. If the
    assessor reports a string that is not present — a trailing invisible
    character, a normalised form — that verification fails silently and the
    human concludes the advisory was wrong. Evidence may not be rewritten.
    """
    got = target.assess(content, origin)
    for param in got.extracted:
        if param and param not in content:
            return Violation(
                invariant="extent_stability",
                atom=atom or content[:40],
                transformation=transformation or "identity",
                variant_id=variant_id,
                detail=f"reported {param!r}, which is not present verbatim",
                baseline_score=got.score,
                mutated_score=got.score,
                content=content,
            )
    return None


def determinism(target: Target, content: str, origin: str,
                atom: str = "") -> Violation | None:
    """The same input scores the same twice."""
    a = target.assess(content, origin)
    b = target.assess(content, origin)
    if abs(a.score - b.score) <= EPS and a.extracted == b.extracted:
        return None
    return Violation(
        invariant="determinism",
        atom=atom or content[:40],
        transformation="identity",
        variant_id="repeat",
        detail=f"two calls disagreed: {a.score} vs {b.score}",
        baseline_score=a.score,
        mutated_score=b.score,
        content=content,
    )


CATALOGUE = ("monotonicity", "extent_stability", "determinism")
