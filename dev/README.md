# dev/

Two harnesses that are **not part of the tool**. Nothing here ships to a box,
nothing here is imported by `faultone.py`, and deleting this directory changes
nothing about what the tool does. They exist because two questions come up
before every release and neither is answerable by the test suite.

Both are stdlib-only and offline, like everything else here.

## `deep_e2e.py` — does the whole pipeline hold, for every finding?

```bash
python3 dev/deep_e2e.py
```

The suite asserts each finding *fires*. This asks the rest: does the verdict
name it, does the exit code match its severity, does the stage strip agree,
does it survive JSON and HTML, and is any of it order-dependent. It also runs
the compound cases where two faults are present and the cause has to win, and
re-runs the whole registry across three hash seeds in subprocesses.

Deliberately outside the suite: it is slow, and it *reports* rather than
asserts, so it can surface something nobody thought to write an assertion for.

## `equivalence.py` — did a change stay inert where it was meant to?

```bash
python3 dev/equivalence.py v1.5.0
```

Runs every scenario against the working tree and against the tool at a git
ref, and diffs the answers — findings, headline, owner, confidence,
corroboration, unrelated, every stage. Exits non-zero if any differ.

**The point is the silence.** "All the tests still pass" does not prove a
change was contained: the tests assert what each scenario *should* say, so a
change that quietly alters some other scenario in a way nobody wrote an
assertion for goes unnoticed. This compares every answer to itself.

That is how the direction model shipped with confidence — 110 scenarios, zero
differences, so a box with nothing connected to it behaves exactly as it did
the version before, by construction rather than by hope.

Both runs use **today's** test file against the older tool, so the scenarios
are identical and only the tool differs. That is what makes the comparison mean
anything, and it also means this reaches back only as far as the current
fixtures still drive the old tool — a few versions, in practice. Past that it
says so and stops rather than comparing two different questions.
