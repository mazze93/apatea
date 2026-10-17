"""The runner: atoms × transformations × invariants.

Exhaustive and deterministic rather than random. The space is small enough to
enumerate, and an enumerated space is one you can describe in a perimeter
report — "8 scripts × 2 edges × 21 atoms" is a claim; "10,000 random draws"
is not.
"""
from __future__ import annotations

from .invariants import determinism, extent_stability, monotonicity
from .report import Run
from .target import Assessment, Target
import math
from .transform import ALGEBRA, variants

#: Detection atoms — the things a gate claims to recognise. Not prose
#: containing them: prose tests the sentence, these test the matcher.
ATOMS: tuple[str, ...] = (
    "critical", "urgent", "exploit", "breach", "immediately",
    "CVE-2024-9999", "must upgrade", "security advisory",
    "You should upgrade", "Run the following command", "use this version",
    "According to the official documentation", "officially recommended",
    "the documentation states", "1.2.3", "foo@1.2.3", "port: 3000",
    "npm install foo", "export API_KEY=xyz", "upgrade to version 2.0",
    '"runtimeExecutable": "npm"',
)


def run(target: Target, origin: str = "web_search",
        atoms: tuple[str, ...] = ATOMS,
        only: tuple[str, ...] | None = None) -> Run:
    if not atoms:
        raise ValueError("empty atom corpus")
    names = {t.name for t in ALGEBRA}
    if only is not None and (not only or set(only) - names):
        raise ValueError("unknown or empty transformation selection")
    if not any(variants(atom, only=only) for atom in atoms):
        raise ValueError("empty transformation search")

    original_target = target

    class Checked:
        name = getattr(target, "name", "unknown")

        def assess(self, content, origin):
            answer = original_target.assess(content, origin)
            if (not isinstance(answer, Assessment) or isinstance(answer.score, bool)
                    or not isinstance(answer.score, (int, float))
                    or not math.isfinite(answer.score) or not 0 <= answer.score <= 1
                    or not isinstance(answer.factors, tuple)
                    or not isinstance(answer.extracted, tuple)
                    or not all(isinstance(x, str) for x in (*answer.factors, *answer.extracted))):
                raise ValueError("malformed target assessment")
            return answer

    checked = Checked()
    # Controls are target-owned: a generic runner cannot invent a detection
    # policy for a consumer. Standard gate/reference targets supply theirs.
    controls = getattr(target, "controls", None)
    if controls is None:
        raise ValueError("target must declare positive and benign controls")
    positive, benign = controls
    if not positive or not benign:
        raise ValueError("positive and benign controls must be nonempty")
    if any(checked.assess(c, origin).score <= 0 for c in positive):
        raise ValueError("positive detection control was not detected")
    if any(checked.assess(c, origin).score != 0 for c in benign):
        raise ValueError("benign control received a nonzero score")
    target = checked
    r = Run(target=target.name, origin=origin)

    for atom in atoms:
        r.atoms += 1
        baseline = target.assess(atom, origin)

        v = determinism(target, atom, origin, atom=atom)
        r.checks += 1
        if v:
            r.findings.append(v)
        else:
            r.held["determinism"] = r.held.get("determinism", 0) + 1

        v = extent_stability(target, atom, origin, atom=atom)
        r.checks += 1
        if v:
            r.findings.append(v)
        else:
            r.held["extent_stability"] = r.held.get("extent_stability", 0) + 1

        by_name = {t.name: t for t in ALGEBRA}
        for var in variants(atom, only=only):
            r.variants += 1
            r.tried[var.transformation] = r.tried.get(var.transformation, 0) + 1
            t = by_name[var.transformation]

            # A baseline that already scores zero cannot be lowered; counting
            # it as "held" would inflate the perimeter with vacuous passes.
            if baseline.score > 0:
                r.checks += 1
                v = monotonicity(target, atom, origin, t, var, baseline)
                if v:
                    r.findings.append(v)
                else:
                    r.held["monotonicity"] = r.held.get("monotonicity", 0) + 1

            r.checks += 1
            v = extent_stability(target, var.content, origin, atom=atom,
                                 transformation=var.transformation,
                                 variant_id=var.variant_id)
            if v:
                r.findings.append(v)
            else:
                r.held["extent_stability"] = r.held.get("extent_stability", 0) + 1

    return r
