"""apatea — run the adversary against a target.

    apatea --target vulnerable          # the pre-fix reference: finds issue #3
    apatea --target fixed               # the boundary policy: should be clean
    apatea --target aletheia            # the live gate (needs ALETHEIA_HOME)
    apatea --target fixed --log run.jsonl

Exit codes are the interface: 0 clean, 1 violations found, 2 could not run.
Apatea FAILS LOUD — the opposite of aletheia, which fails open because she sits
in a request path and must never break the agent. Nothing here is in a request
path, so silence on error would only hide a search that did not happen.
"""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

from .search import run
from .target import Target

BUILTIN = {
    "vulnerable": ("targets.vulnerable_reference", "TARGET"),
    "fixed": ("targets.fixed_reference", "TARGET"),
    "aletheia": ("targets.aletheia_adapter", "TARGET"),
}


def load(name: str) -> Target:
    if name in BUILTIN:
        mod, attr = BUILTIN[name]
    elif ":" in name:
        mod, attr = name.split(":", 1)
    else:
        raise SystemExit(f"unknown target {name!r}; try: {', '.join(BUILTIN)}")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    return getattr(importlib.import_module(mod), attr)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="apatea", description=__doc__)
    p.add_argument("--target", default="fixed")
    p.add_argument("--origin", default="web_search")
    p.add_argument("--only", default=None,
                   help="comma-separated transformation names")
    p.add_argument("--log", default=None, help="append JSONL here")
    p.add_argument("--quiet", action="store_true")
    a = p.parse_args(argv)

    try:
        target = load(a.target)
    except Exception as exc:                      # noqa: BLE001
        print(f"apatea: cannot load target {a.target!r}: {exc}", file=sys.stderr)
        return 2

    only = tuple(x.strip() for x in a.only.split(",")) if a.only else None
    r = run(target, origin=a.origin, only=only)

    if not a.quiet:
        print(r.render())
    if a.log:
        r.to_jsonl(Path(a.log))
    return 0 if r.clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
