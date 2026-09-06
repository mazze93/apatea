# ADR-0001 — apatea: the adversary as a service

**Status:** proposed
**Date:** 2026-09-04
**Relates to:** aletheia (the gate), stele (the protected surface), issues #1, #3, #6

## Context

Aletheia is a gate. She sits in a `PostToolUse` hook, scores inbound content,
and — once enforcement is on — refuses. Gates are judged by what they stop.

**Nothing currently measures what she misses.**

That asymmetry is not hypothetical here, and the evidence is specific:

- **Issue #3.** A single non-ASCII letter beside any keyword made the live
  Python assessor blind. `criticalé` scored `0.0`. Found by a mutation corpus
  written ad hoc, on its first run, after the detector had passed every test it
  had.
- **U+FEFF.** A second dialect split, invisible to 69 hand-written vectors,
  surfaced only when 651 *generated* cases ran. Same detection, different
  extent — and extent is what a human is told to verify at a registry.
- **Issue #1.** A labelled incident scored 0.26 and passed for weeks. The cause
  was that the detector recognised `port: 3000` and missed `"port": 3000` — the
  same governing parameter in a different *form*.

Three real evasions, none found by review, all found by generating variants of
things the detector already claimed to understand. The search deserves to be a
service rather than a directory inside the thing it audits.

## The name

Ἀλήθεια — *unconcealment*, truth as the removal of hiddenness.
Ἀπάτη — *deceit*. In the myth, one of the daimones released from the jar.

The pairing is the point: the deceiver is kept as an instrument rather than
imagined as an outside force. Apatea's job is to lie convincingly to Aletheia
and report every lie she accepted.

## Decision

**Build apatea as its own repository — a complement to aletheia, not a mode of
it.** Four properties define it.

### 1. A gate and a runner have opposite lifecycles

This is the load-bearing reason for separation, and fusing them damages both.

| | aletheia (gate) | apatea (runner) |
|---|---|---|
| invocation | synchronous, in the hook path | asynchronous, out of band |
| latency budget | milliseconds | minutes to hours |
| dependencies | standard library only | may be heavy |
| on its own failure | **fail open** — never break the agent | **fail loud** — a violation is a build failure |
| optimises for | not blocking real work | finding what got through |

A search that must return in milliseconds is a timid search. A gate that may
take minutes is not a gate. Making apatea a flag on aletheia would either make
the hook heavy or make the search shallow, and in practice both.

### 2. It searches for invariant violations, not crashes

This is what makes it not a fuzzer. Apatea holds a catalogue of properties that
must hold under transformation, and searches for inputs that break them. The
first one already exists, in `tests/test_boundary_mutations.py`:

> No Unicode-only mutation of a detection atom may lower the assessed risk.

Generalised, the catalogue is:

- **Monotonicity.** A transformation that preserves meaning must not reduce
  assessed risk. (Issue #3 is a violation of this.)
- **Extent stability.** Any extracted governing parameter must appear verbatim
  in the input. Evidence may not be silently rewritten. (U+FEFF.)
- **Form invariance.** The same governing parameter must score the same in
  prose and in structured form. (Issue #1 — and note apatea would have found it
  automatically, because prose→JSON is one transformation in the algebra.)
- **Parity.** Where two implementations exist, they must agree. This one is
  temporary: it dies with the second implementation (see #5).
- **Determinism.** The same input scores the same twice.

A crash-hunting fuzzer would have found none of the three real findings above.
None of them crashed anything. All three returned a confident, well-formed,
wrong answer.

### 3. It records what it could not break

Half of an adversary's output is the perimeter. A run that finds nothing must
say *what it tried* and *what held*, or "no findings" is indistinguishable from
"searched nothing." This is the same discipline as the known-failure alarm in
`tests/test_evals.py`: an assertion that a gap is *still* a gap, so a silent fix
cannot erase the record that it existed.

### 4. It runs against targets, not against itself

Aletheia is the first target. **Stele is the reason.** Stele is the anchor and
the integrity-telemetry surface; apatea stands behind it and reports what passed
the tripwires, rather than standing in the request path where a false positive
would stop real work. A target is anything exposing an assessment interface.

## Rejected alternatives

- **A `--fuzz` mode on aletheia.** Fails on the lifecycle argument above, and
  puts the adversary's dependencies inside a hook that must fail open.
- **A plain fuzzer (AFL-style, crash-hunting).** Wrong oracle. The failures that
  matter here are confident wrong answers, not crashes.
- **Leave it as a test directory.** This is the status quo, and the status quo
  is why the corpus only ever ran against one target and only when someone
  remembered. A test suite proves a known case; an adversary searches.
- **A curated red-team prompt library.** Lists go stale and encode only attacks
  someone already thought of. The transformation algebra is generative: it
  produces attacks nobody wrote down, which is how U+FEFF surfaced.

## Specification

```json
{
  "id": "apatea",
  "role": "adversarial invariant-search runner; complement to aletheia",
  "repo": "mazze93/apatea (proposed, private, MAX posture)",
  "workspace_path": "tools/apatea",
  "lifecycle": {
    "invocation": "async, scheduled or on-demand; never in a request path",
    "on_internal_failure": "fail loud, non-zero exit",
    "determinism": "seeded; a run is reproducible from its seed and corpus version"
  },
  "target_interface": {
    "description": "A target is anything that scores content. Adapters are thin.",
    "contract": "assess(content: str, origin: str) -> {score: float, factors: [...], extracted: [str]}",
    "initial_targets": ["aletheia", "stele"]
  },
  "transformations": [
    {"name": "unicode_adjacency", "status": "built", "note": "letters from 8 scripts + format chars, both edges — found issue #3"},
    {"name": "normalization", "status": "planned", "note": "NFC/NFD/NFKC/NFKD"},
    {"name": "form_reshape", "status": "planned", "note": "prose <-> JSON <-> YAML <-> query string — would have found issue #1"},
    {"name": "encoding", "status": "planned", "note": "percent, HTML entity, base64-in-field, escape sequences"},
    {"name": "whitespace", "status": "partial", "note": "zero-width, BOM, line separators — found the U+FEFF extent split"},
    {"name": "homoglyph", "status": "planned", "note": "explicitly out of aletheia's scope; in apatea's"},
    {"name": "case_and_spacing", "status": "planned"},
    {"name": "structural_nesting", "status": "planned", "note": "the governing parameter buried N levels deep"}
  ],
  "invariants": [
    {"id": "monotonicity", "statement": "A meaning-preserving transformation must not lower assessed risk.", "status": "built"},
    {"id": "extent_stability", "statement": "Every extracted parameter appears verbatim in the input.", "status": "built"},
    {"id": "form_invariance", "statement": "The same governing parameter scores alike in prose and structured form.", "status": "planned"},
    {"id": "parity", "statement": "Multiple implementations agree.", "status": "built", "note": "temporary; dies with the second implementation (#5)"},
    {"id": "determinism", "statement": "Identical input scores identically across runs.", "status": "planned"}
  ],
  "outputs": {
    "findings": "violation + minimal reproducing input + the invariant broken + a runnable command",
    "perimeter": "what was tried and held — required, not optional; 'no findings' without it is meaningless",
    "format": "JSONL, append-only, content-hashed like aletheia's audit log"
  },
  "seed_from_aletheia": [
    "parity/unicode_boundary_mutations.py -> the generator",
    "tests/test_boundary_mutations.py -> the first invariant",
    "evals/expected.jsonl + known-failure alarm -> the perimeter memory"
  ],
  "non_goals": [
    "model-level semantic paraphrase (a different class, needs a model in the loop)",
    "standing in any request path",
    "replacing aletheia's tests — the invariants stay asserted in aletheia's own CI too"
  ],
  "first_action": "Extract the generator from aletheia behind a target adapter and re-find issue #3 with it. If it cannot rediscover a known finding, it is not yet a search."
}
```

## Consequences

**Positive.** The search that found three real evasions becomes a thing that
runs on a schedule against several targets instead of a directory someone
remembers. Aletheia's hook stays standard-library-only and fast, because the
expensive half moved out. Stele gets a guard that reports rather than blocks.
And the invariants become portable: they are statements about *any* assessor,
so they survive the Rust consolidation in #5 that will delete the parity
harness.

**Negative.** A second repository to maintain, and a real risk that it becomes
a thing that runs and is never read — an adversary whose findings nobody opens
is worse than none, because it manufactures the feeling of coverage. The
perimeter output is the mitigation, and it is the part most likely to be
skipped under time pressure.

There is also a self-reference hazard worth stating: apatea generates content
designed to look like an attack. Its own output, its logs, and this document are
exactly the kind of text aletheia is built to flag. Any pipeline carrying
apatea's findings must treat them as *data*, never as instruction — the same
rule aletheia applies to a web result.

## Verification

The decision is validated the day apatea, running only from its own repository
against an adapter, independently rediscovers issue #3 in a checkout of aletheia
predating the boundary policy. Until then this is a design, not an instrument.
