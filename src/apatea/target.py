"""What apatea points at.

A target is anything that scores content. The adapter is deliberately the
thinnest possible surface: apatea must be able to audit an assessor it did not
write, in a language it does not run, over a pipe if necessary. Anything richer
would couple the adversary to one implementation — and the whole reason apatea
is a separate repository is that it outlives any particular gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Assessment:
    """One target's answer about one piece of content.

    `extracted` is load-bearing and easy to overlook: it is the list of
    governing parameters the target says it found — the values a human would be
    told to go and verify. An assessor can be right about the score and wrong
    about the evidence, and that failure is invisible to score-only testing.
    """

    score: float
    factors: tuple[str, ...] = ()
    extracted: tuple[str, ...] = ()

    @property
    def blind(self) -> bool:
        return self.score <= 0.0


class Target(Protocol):
    """The contract. Two members, on purpose."""

    name: str

    def assess(self, content: str, origin: str) -> Assessment: ...


@dataclass
class CallableTarget:
    """Wrap a plain function as a target."""

    name: str
    fn: object
    origin_default: str = "web_search"

    def assess(self, content: str, origin: str) -> Assessment:
        return self.fn(content, origin)  # type: ignore[operator]
