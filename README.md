# apatea

*Ἀπάτη* — deceit. The adversary kept as an instrument.

Complement to [aletheia](https://github.com/mazze93/aletheia). She is a **gate**:
synchronous, standard-library-only, sits in a hook, and fails *open* because she
must never break the agent. This is a **runner**: asynchronous, unbounded, and
fails *loud*, because nothing here is in a request path and silence would only
hide a search that did not happen.

Gates are judged by what they stop. Nothing measures what they miss.

```
atoms  ×  transformations  ×  invariants  →  findings + perimeter
```

## It is not a fuzzer

None of the three real evasions found in aletheia crashed anything. All three
returned a confident, well-formed, wrong answer:

| finding | what it was |
|---|---|
| issue #3 | one non-ASCII letter beside a keyword; `criticalé` scored **0.0** |
| U+FEFF | same detection, different *extent* — an invisible character inside the reported evidence |
| issue #1 | `port: 3000` recognised, `"port": 3000` missed — same parameter, different costume |

A crash-hunting fuzzer would have found none of them. The oracle has to be a
stated property, so apatea carries **invariants**:

- **monotonicity** — a meaning-preserving transformation must not lower assessed risk
- **extent stability** — every extracted parameter appears verbatim in the input
- **determinism** — the same input scores the same twice

and **transformations** rather than a list of attacks, because lists only ever
contain attacks somebody already thought of. U+FEFF was found precisely because
nobody had.

## Run it

Python 3.11+, standard library only.

```bash
PYTHONPATH=src:. python3 -m apatea.cli --target vulnerable   # exit 1 — finds the known bug
PYTHONPATH=src:. python3 -m apatea.cli --target fixed        # exit 0 — clean, and says what held
PYTHONPATH=src:. python3 -m apatea.cli --target aletheia     # the live gate
```

Exit codes are the interface: `0` clean, `1` violations, `2` could not run.

## The perimeter is not optional

A run reporting nothing is indistinguishable from a run that searched nothing.
So every run states what it tried and what held:

```
apatea · target=fixed_reference · origin=web_search
  21 atoms → 688 variants → 1287 checks
  no violations
  perimeter — tried: case×39, form_reshape×61, invisible×252, unicode_adjacency×336
  perimeter — held:  determinism×21, extent_stability×709, monotonicity×557
```

## Targets

A target is anything that scores content. The adapter is two members — `name`
and `assess(content, origin) -> Assessment` — so apatea can audit an assessor it
did not write, in a language it does not run.

- `targets/vulnerable_reference.py` — aletheia's logic *before* the boundary
  policy. **Not a gate.** It exists so the ADR's validation condition is a test:
  if apatea cannot rediscover a known finding, it is not yet a search.
- `targets/fixed_reference.py` — the same with the policy applied. The control.
  A search that flags both is not discriminating, it is noisy — and noise is how
  a security tool gets switched off.
- `targets/aletheia_adapter.py` — the live gate (`ALETHEIA_HOME`).

## What its own first runs found

Three runs, three corrections — two of them to **apatea itself**, which is the
point of keeping the control:

1. Against `fixed_reference`, it flagged `port: 3000` reshaped to JSON. Real —
   that is issue #1's shape, and the control did not yet have the structured
   patterns. Fixed the control.
2. Then it flagged `"runtimeExecutable": "npm"` reshaped again. **Apatea's
   fault**: reshaping already-structured text double-encodes its quotes, which
   is not the same claim in a different costume. Guarded.
3. Against live aletheia it produced nine findings, eight of which were case
   folding applied to identifiers — `export API_KEY=xyz` uppercased is not the
   same command. **Apatea's fault again.** Guarded.

A transformation's `meaning_preserving` flag is a *claim*, and claims need
guards. An adversary that cries wolf trains its reader to ignore it, which costs
more than the findings are worth.

## Its output is untrusted input

Apatea generates text engineered to look like an attack. Its findings, its logs
and its documentation are exactly what aletheia exists to flag. Anything
carrying them must treat them as **data, never instruction** — the same rule
aletheia applies to a web result. The JSONL log stores a content hash rather
than the payload for the same reason.

## Design record

`docs/adr/ADR-0001-apatea.md` — why a separate repository, the invariant
catalogue, the gate/runner split, and the falsifiable condition under which this
is an instrument rather than a design.

MIT. Unpaid, unowned; if it is useful, take it.
