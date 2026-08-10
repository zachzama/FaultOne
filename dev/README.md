# dev/

Five harnesses that are **not part of the tool**. Nothing here ships to a box,
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

## `about.py` — does the GitHub About box still say what we think?

```bash
python3 dev/about.py          # compare, exit 1 if they differ
python3 dev/about.py --fix    # set it from REFERENCE.md
```

`release.py --push` runs the `--fix` form for you, so this is the manual door
for when something went out without it.

The About box lives on someone else's server, so the test suite cannot read it.
It sat quoting a finding count eighteen out of date while every number inside
the repository stayed green — the drift the guards exist to catch, in the one
place they cannot look. The canonical text lives in REFERENCE.md under **The
repository description**, where the suite does pin it; this compares that block
against the live box.

Needs the network and an authenticated `gh`, which is why it is here and not in
the suite. Run it when you tag.

## `release.py` — cut a release without forgetting half of it

```bash
python3 dev/release.py 1.7.0 --notes-file notes.md            # bump, test, commit, tag
python3 dev/release.py 1.7.0 --notes-file notes.md --push     # ...and ship it
python3 dev/release.py 1.7.0 --notes-file notes.md --dry-run  # print the plan
```

`git push --follow-tags` creates a tag and nothing else. A GitHub Release is a
separate object built on top of one, and it is what drives the "Latest" badge
and notifies watchers. Nine tags shipped without a Release before anyone
noticed, so the Releases page went on showing a version eight releases behind
while every tag was correct.

It bumps the version in **both** places that carry it, runs the suite **before**
committing — and reverts the bump if the suite fails, so a release that cannot
pass its own tests never reaches a tag — then commits, tags, and with `--push`
pushes and publishes the Release together. Publishing together is the point:
doing the second half separately is what got forgotten nine times.

With `--push` it also sets the GitHub About box from `REFERENCE.md`, because
that number drifted on three releases running and was caught every time by a
check that only ever reported it. There is no version of this where the two
should disagree, so the release sets it rather than asking. That step is
deliberately not fatal: by the time it runs the release is published, and a
description that could not be set is worth saying loudly without making a
successful release look like a failed one.

It never pushes without `--push`. That decision is the user's and this file
should not be able to make it by accident.

## `audit.py` — do the rules between findings hold, one fault or six?

```bash
python3 dev/audit.py            # every scenario, then 500 random combinations
python3 dev/audit.py 5000       # more combinations
python3 dev/audit.py --seed 7   # a different draw, reproducibly
```

`deep_e2e.py` walks each finding through the pipeline and checks four
hand-written compound cases. This asks a different question: do the
*relationships between* findings hold — exactly one cause, a consequence never
also unrelated, nothing explained by a fault facing the other way, no
consequence sitting below its own cause, the hardware marking matching its set
— and do they still hold when several faults are present at once?

That last part is the point. **Every scenario in the suite is single-fault by
construction**: a fixture is written to make one thing go wrong. So the rules
that only exist *between* findings are the least exercised logic in the tool,
and since the report now draws those relationships on screen, they are also the
most visible.

Combinations are drawn from the real findings each scenario emits, so every
input is one the tool actually produces. They are stripped of the `relation` and
`kind` their own report gave them first — the corpus has to be inert, or every
draw inherits six findings that were each the cause of their own single-fault
report.

Its checks were verified by breaking each rule in turn and confirming it
noticed: a consequence facing the wrong way, a finding in both the explained and
unrelated lists, a cause explaining something below it, and the hardware marking
drifting from its set.
