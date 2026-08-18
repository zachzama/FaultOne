# dev/

Seven harnesses that are **not part of the tool**. Nothing here ships to a box,
nothing here is imported by `faultone.py`, and deleting this directory changes
nothing about what the tool does. They exist because the questions that come up
before a release are not the ones a test suite answers: it checks that each
thing still does what it was written to do, not whether a change leaked into
something nobody thought to assert about.

All seven are stdlib-only and offline, like everything else here.

`HANDOVER.md` sits alongside them and is not one of them: it records what
is unfinished and what was tried and rejected, since a commit says what was
done rather than what was ruled out.

## `deep_e2e.py`: does the whole pipeline hold, for every finding?

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

## `equivalence.py`: did a change stay inert where it was meant to?

```bash
python3 dev/equivalence.py v1.5.0
```

Runs every scenario against the working tree and against the tool at a git
ref, and diffs the answers: findings, headline, owner, confidence,
corroboration, unrelated, every stage. Exits non-zero if any differ.

**The point is the silence.** "All the tests still pass" does not prove a
change was contained: the tests assert what each scenario *should* say, so a
change that quietly alters some other scenario in a way nobody wrote an
assertion for goes unnoticed. This compares every answer to itself.

That is how the direction model shipped with confidence: 110 scenarios, zero
differences, so a box with nothing connected to it behaves exactly as it did
the version before, by construction rather than by hope.

Both runs use **today's** test file against the older tool, so the scenarios
are identical and only the tool differs. That is what makes the comparison mean
anything, and it also means this reaches back only as far as the current
fixtures still drive the old tool: a few versions, in practice. Past that it
says so and stops rather than comparing two different questions.

## `about.py`: does the GitHub About box still say what we think?

```bash
python3 dev/about.py          # compare, exit 1 if they differ
python3 dev/about.py --fix    # set it from REFERENCE.md
```

`release.py --push` runs the `--fix` form for you, so this is the manual door
for when something went out without it.

The About box lives on someone else's server, so the test suite cannot read it.
It sat quoting a finding count eighteen out of date while every number inside
the repository stayed green: the drift the guards exist to catch, in the one
place they cannot look. The canonical text lives in REFERENCE.md under **The
repository description**, where the suite does pin it; this compares that block
against the live box.

Needs the network and an authenticated `gh`, which is why it is here and not in
the suite. Run it when you tag.

## `release.py`: cut a release without forgetting half of it

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
committing, and reverts the bump if the suite fails, so a release that cannot
pass its own tests never reaches a tag, then commits, tags, and with `--push`
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

Cutting and shipping are separable, and finishing a cut works: run it once to
bump, test, commit and tag, then again with `--push` to send it. That second
run is the command the first one prints, and for a while it could not be
followed. By then the bump had happened, so the version matched and the guard
at the top rejected the very command above it. It now re-runs the suite as a
last gate, skips the bump and the tag it already made, and pushes. A version
that matches with no tag behind it is still refused, because that is a
half-finished cut or a hand edit and guessing between them is worse than
stopping.

## `hero.py`: draw the report for the README

```bash
python3 dev/hero.py          # writes docs/hero-dark.svg and docs/hero-light.svg
```

The image at the top of the README is the tool's own output, rendered through
the tool. A screenshot is a claim about the output that stops being true the
moment the output changes, and nothing would notice; the suite regenerates both
images and requires the committed bytes, so a stale one fails rather than sits
there being believed.

Two things it is careful about. The report comes from a **test scenario, never
a live run**. A report is a map of the network it was taken on, so a hero
taken from a real machine would publish the addressing of whoever built it. And
the output is **byte-identical every time**: the banner's timestamp, OS and
interpreter are pinned, so regenerating produces no diff unless the report
itself changed.

Every glyph carries its own `x` rather than one position per run. `textLength`
would be shorter, and is honoured by browsers and ignored by some preview
renderers, which draws a line wider than the panel it sits in, on exactly the
machines nobody tested.

## `slowest.py`: where does the suite spend its time?

```bash
python3 dev/slowest.py          # the whole suite, then the slowest 20
python3 dev/slowest.py 40       # ...the slowest 40
```

Exits with the suite's own status, so it is a gate and not a report. CI runs
this rather than the plain command and gets the timings for nothing.

A slow suite is only ever fixed with a list. One test was **eighty-four per
cent** of the runtime and nobody knew: `--export` to an unwritable path, with
no `--quick`, so every run did a full traceroute and waited out its sixty
second timeout to test that a *write* fails. One flag took the suite from
seventy-two seconds to thirteen.

The reason it runs in CI too is that the slow machine has to be the one that
reports. Windows takes eight times longer than Linux, and no run on a laptop
can show why.

## `branch_sweep.py`: which branches of the viewer does nothing exercise?

```bash
python3 dev/branch_sweep.py false   # then-sides: is the markup ever drawn?
python3 dev/branch_sweep.py true    # else-sides: is the fallback ever taken?
```

A test that asserts a string appears in `VIEWER_TEMPLATE` passes against code
wired to a constant, because the dead branch still contains the string. That has
been wrong three times here. Counting those assertions was the first attempt at
sizing the problem and it sized the wrong thing - it measures how a test is
written, not whether the behaviour is covered. Fifty-four of them looked like a
hole; forcing all fifty-four branches found **no** uncovered then-side.

Run both directions. The else-sides are not the lesser half: `setFavicon` had
two fallbacks on one line, and deleting the first changed no test's answer
because a fixture had given both the same colour.

Half an hour, one full suite run per site, so this is a thing to run when the
viewer's branching changes rather than part of the suite. It reads ternaries
only - the `&&` guards in that template have never been forced either way.

## `audit.py`: do the rules between findings hold, one fault or six?

```bash
python3 dev/audit.py            # every scenario, then 500 random combinations
python3 dev/audit.py 5000       # more combinations
python3 dev/audit.py --seed 7   # a different draw, reproducibly
```

`deep_e2e.py` walks each finding through the pipeline and checks four
hand-written compound cases. This asks a different question: do the
*relationships between* findings hold: exactly one cause, a consequence never
also unrelated, nothing explained by a fault facing the other way, no
consequence sitting below its own cause, the hardware marking matching its set
, and do they still hold when several faults are present at once?

That last part is the point. **Every scenario in the suite is single-fault by
construction**: a fixture is written to make one thing go wrong. So the rules
that only exist *between* findings are the least exercised logic in the tool,
and since the report now draws those relationships on screen, they are also the
most visible.

Combinations are drawn from the real findings each scenario emits, so every
input is one the tool actually produces. They are stripped of the `relation` and
`kind` their own report gave them first: the corpus has to be inert, or every
draw inherits six findings that were each the cause of their own single-fault
report.

Its checks were verified by breaking each rule in turn and confirming it
noticed: a consequence facing the wrong way, a finding in both the explained and
unrelated lists, a cause explaining something below it, and the hardware marking
drifting from its set.

## mutate.py

Breaks a rule on purpose and reports whether the suite objects. A green
test proves nothing until breaking the thing it tests makes it fail, and
that was being done by hand - a throwaway script per change, written from
memory each time. One of those copied four files instead of the tree, so
sixteen documentation tests failed on every mutant and on the control
alike, which read as three rules being well covered when nothing had been
proved.

Two things are therefore not left to the caller. The whole tree is copied,
because tests read the README, the reference, the viewer and `dev/`. And an
unchanged control runs first with no flag to skip it, because a suite that
fails before anything is mutated makes every result behind it noise.

```bash
python3 dev/mutate.py mutations.json    # a set, as JSON
python3 dev/mutate.py --self-test       # two mutations with known answers
```

An anchor that does not appear exactly once is reported as a bad mutation
rather than run: one that edits nothing survives every time and reads as a
hole in the tests.

## counts.py

Puts the numbers the documents quote back in line with the code: findings,
of which faults, ranked causes, tests, and three file sizes, across README.md,
REFERENCE.md and the sizes pinned in the suite. `TestDocsMatchReality` fails
when they drift, which is right and is half the job - the other half was being
done by hand on nearly every commit, and a red suite became the normal way to
find out a release was one finding further along.

```bash
python3 dev/counts.py            # rewrite them
python3 dev/counts.py --check    # say what is stale, change nothing
python3 dev/counts.py --self-test
```

It rewrites the pins inside `test_faultone.py` as well as the prose, because
moving one without the other leaves the red suite this exists to prevent. That
makes it the one harness here that edits the thing which would otherwise catch
it, so it self-tests: `--check` must write nothing against a document that is
genuinely stale, and a rewrite must settle in one pass.

### dev/mutations

The sets, kept beside the rules they check rather than written from memory
each time - which is how this harness came to be needed. One file per group
of related rules: verdict severity, corroboration, the log leg, the broker
leg, latency causation, the two sides, and the hop list.

```bash
python3 dev/mutate.py --anchors                     # do they still apply
python3 dev/mutate.py dev/mutations/both-sides.json # one group
python3 dev/mutate.py dev/mutations                 # all of them, ~1h
```

`--anchors` is the one to run after touching anything they point at. A set
whose anchor has drifted reports every mutation in it as bad, which is correct
and slow to discover: an hour of suite runs to be told a line moved.
