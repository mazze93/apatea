"""apatea — ἀπάτη, deceit. The adversary kept as an instrument.

Complement to aletheia. Where she is a gate — synchronous, fast, fails open —
this is a runner: asynchronous, unbounded, fails loud. It does not hunt
crashes. It holds properties that must survive transformation and searches for
inputs that break them.

    target      the thin adapter contract; anything that scores content
    transform   the transformation algebra (not a list of attacks)
    invariants  the catalogue of properties
    search      atoms × transformations × invariants
    report      findings, and the perimeter of what held
"""

__version__ = "0.1.0"

from .invariants import Violation  # noqa: F401
from .report import Run  # noqa: F401
from .search import ATOMS, run  # noqa: F401
from .target import Assessment, CallableTarget, Target  # noqa: F401
