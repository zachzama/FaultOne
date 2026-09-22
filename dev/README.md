# dev/

Harnesses and release tools that are **not part of the tool**. Nothing here
ships to a box, nothing here is imported by `faultone.py`, and deleting this
directory changes nothing about what the tool does. They exist because the
questions that come up before a release are not the ones a test suite answers:
it checks that each thing still does what it was written to do, not whether a
change leaked into something nobody thought to assert about.

Stdlib-only and offline, like everything else here, with two stated
exceptions: `release.py` and `about.py` talk to GitHub, which is the point of
them, and `shot.py` drives Chrome because photographing a page needs a browser.

No count in that first line any more. It said "seven harnesses" while the
directory held sixteen files, which is the same way every other number here
went stale before `counts.py` started deriving them - and this one is not
worth deriving.

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

## `vacuous.py`: find tests that pass without asserting anything

```bash
python3 dev/vacuous.py             # check every test in the suite
python3 dev/vacuous.py --self-test # check this file works
```

`mutate.py` asks the expensive question - would this test notice if the rule it
covers broke - one hand-written mutation at a time. There are 73 of those
against 1,780 tests, so most of the suite has never been asked anything.

This asks the cheap question of all of them at once, by wrapping the assertion
methods and watching what each test actually reaches: did it execute an
assertion, and did that assertion have anything in it. Wrapped rather than
parsed, because the source says which assertions a test *contains* and only
running it says which ones a test *reached* - an assertion inside a loop that
never runs is the case worth finding, and no amount of reading the file shows
it.

It found the thing it was built for on its first run. `path_admin_prohibited`
has a numeric form, `!13`, and a test written specifically for it - which
asserted `if said:` and so passed for as long as the rule did not fire. It
never fired: `TRACE_PROHIBITED` held the letter forms only, and which one a box
prints depends on its traceroute rather than on what the router said.

Two lists, and they mean different things. A test that executed no assertion
and is not named for asserting-by-not-raising is broken; that list is empty and
the exit code says so. A test whose every assertion compared one empty thing to
another is a list to *read*: asserting that a list is empty is how this suite
says a rule stayed quiet, and what this cannot show from outside is whether the
fixture arranged the situation at all.

The instrument has a control, and needed it. The first version could not see a
test with zero assertions at all - such a test never reaches the wrapper, so it
had no row and never appeared - and it reported a clean tree. That is exactly
the failure it exists to catch, and only the planted tests in `--self-test`
caught it.

## `release.py`: cut a release without forgetting half of it

```bash
python3 dev/release.py 1.7.0 --notes-file notes.md            # bump, test, commit, tag
python3 dev/release.py 1.7.0 --notes-file notes.md --push     # ...and ship it
python3 dev/release.py 1.7.0 --notes-file notes.md --dry-run  # print the plan
python3 dev/release.py --self-test                            # check the CI gate
```

`git push --follow-tags` creates a tag and nothing else. A GitHub Release is a
separate object built on top of one, and it is what drives the "Latest" badge
and notifies watchers. Nine tags shipped without a Release before anyone
noticed, so the Releases page went on showing a version eight releases behind
while every tag was correct.

It bumps the version in **both** places that carry it, runs the checks
**before** committing, and reverts the bump if any of them fails, so a release
that cannot pass its own tests never reaches a tag, then commits, tags, and with
`--push` pushes and publishes the Release together.

The checks are the suite **and** `deep_e2e.py`, `audit.py` and `counts.py
--check`, because the suite is not all of them. The audit holds every finding
and five hundred combinations of them to the rules that only exist *between*
findings, and nothing in the suite checks those - so it went red and stayed red
through three releases, each of which this gate waved past after asking the
suite alone. They cost under two seconds together.

Then it asks GitHub whether the commit being released *from* is green, and
refuses to cut if it is not. Everything above runs here, on one machine, on one
Python, and none of the four jobs CI runs is this one: "it passed locally" is a
statement about a Mac. A commit CI has never seen is not a pass either, which is
the case a cut from unpushed work lands in. `--no-ci-check` is there for working
offline and is meant to be mentioned in the notes when it is used. Publishing together is the point:
doing the second half separately is what got forgotten nine times.

With `--push` it also sets the GitHub About box from `REFERENCE.md`, because
that number drifted on three releases running and was caught every time by a
check that only ever reported it. There is no version of this where the two
should disagree, so the release sets it rather than asking. That step is
deliberately not fatal: by the time it runs the release is published, and a
description that could not be set is worth saying loudly without making a
successful release look like a failed one.

Two things ride along with a bump because both carry the version and both
would otherwise be stale the moment it moves: the README **hero** is redrawn
and the export **screenshot** is recaptured, each reverting the bump if it
fails. `dev/shot.py --check` is in the gate as well, which is the only thing
that would notice a cut being *finished* by a later run against a
hand-edited version.

The **example pages publish themselves**: `.github/workflows/pages.yml` runs
on any `v*` tag, so the push this does is what republishes them. Nothing here
uploads a site, and no generated HTML is committed.

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

## `demos.py`: the example reports, and the site they become

```bash
python3 dev/demos.py                 # nine pages and an index, to ~/Desktop
python3 dev/demos.py site            # or somewhere else
```

Nine reports, each a different fault, plus an index that lists them with the
tool's own headline and the three side states beside it. This is what
`.github/workflows/pages.yml` publishes on every tag, so it is the version of
the output a reader meets first.

**Built from the test corpus, never from a live run** - same argument as
`hero.py`: a demo taken from a real machine publishes the addressing of
whoever made it. The banner is pinned to Linux for the same reason.

It checks itself twice, and both checks came from something that shipped
wrong. **A page's verdict has to name the fault its filename claims**, or this
exits non-zero - two pages once passed by saying "No fault found" while their
`based_on[0]` still matched the scenario name. And **a page has to show what
the tool learned**: the AS numbers shipped tested and invisible on forty pages
for a week, because nothing asked whether a reading reached the page.

The index is written last and only when every page has passed, so a directory
with an index in it is a directory that built cleanly. Its colours are mapped
from all four side states explicitly and there is no default - the first
version mapped two and sent the rest to the fault colour, which printed
`PASS` in red on seven of the nine cards while the build stayed green.

## `shot.py`: photograph the HTML export for the README

```bash
python3 dev/shot.py            # writes docs/export.png and docs/export.json
python3 dev/shot.py --check    # is the committed one stale?
```

The hero above is a drawing of the *terminal* report. This is the HTML export,
the thing `--export` writes, and a reader evaluating the tool would otherwise
see only half of what it makes. It drives `demos.py` and photographs demo 1 -
the page whose whole argument is visible without scrolling.

A photograph can fall out of step with what it depicts, which is the standing
objection to committing one. So this writes down what it captured: the
`VIEWER_TEMPLATE` hash and the version that was in the banner, in
`docs/export.json`. The suite fails when either moves without a recapture, and
the comparison lives in `shot.py` so `--check` and the test cannot drift apart
by both being written carefully. `release.py` recaptures on a bump for the same
reason it redraws the hero.

Needs Chrome, which is why it is here and not in a harness: the tool has no
dependencies and the suite has none either.

## `live.py`: is the published site still being served?

```bash
python3 dev/live.py                # check the published site
python3 dev/live.py --base URL     # or somewhere else
```

Everything else here checks the site is **correct when built**. This asks
whether it is **still there**, which fails in ways a build cannot see: a
setting changed, Pages switched off, a rename that left the index pointing at
files that are gone. Run weekly from `.github/workflows/live.yml`.

This is the gap the resume card sat in for nine releases - a claim about the
world that nothing re-read.

**It follows the index rather than a list**, because a list written here would
be a list of the pages that existed the day it was written, and those two
disagreeing is the failure worth catching.

Two markers, because there are two ways to serve something that is not a
report. One says the response is the viewer at all rather than a Pages 404.
The other tells a report apart from the **empty viewer** - `static/index.html`
is the same template with nothing in its island, and serving that by accident
answers 200 and looks right. Both were checked against a known-different case
rather than assumed: `headline` is in the empty viewer *twice* because the
rendering code mentions it, and the verdict label is lowercase in the file
because the capitals come from `text-transform`. Matching what the screenshot
showed found nothing on all nine pages.

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
python3 dev/counts.py --card     # does the live resume still agree?
python3 dev/counts.py --card --card-url=URL    # ...or a copy of it
python3 dev/counts.py --self-test
python3 dev/counts.py --kinds    # the X.733 coverage table
python3 dev/counts.py --kinds --deep    # ...and how many can be the answer
```

`--card` is the only part of this that reaches outside the repository, and it
exists because `--check` cannot. The resume's FaultOne card quotes the
collector count, findings, tests, mutations and the Python floor, and it lives
in `zachzama/zachzama.github.io`. That put it beyond every guard here: it fell
**nine releases** behind once, and then drifted again inside a single
afternoon - pushed saying 1,999 tests and made wrong an hour later by a test
that took the total to 2,000.

It is **read-only**, because the card is not here to fix. It can only say the
card is wrong, which is the part nobody was doing. The floor is compared
against what this README promises rather than derived a second way, and
`--card-url` points it at a copy so a resume edit can be checked before it is
pushed - and so this check can be aimed at a deliberately wrong page, which is
the only way to know it fails when it should. Run weekly from
`.github/workflows/live.yml` beside `live.py`: both are claims about the world
that nothing re-read.

`--kinds` answers the question the finding list cannot: **what have we not
got.** Every ranked rule carries an ITU-T X.733 event type and probable cause,
which is a vocabulary this project does not control, so the causes with no
finding behind them are visible instead of being defined out of existence by a
list drawn around what already exists. The first run of it returned CPU
saturation - `cpuCyclesLimitExceeded`, which this box reads the load average
for on every run and has never named.

`--deep` adds how many rules of each kind can *be* the answer rather than only
a symptom of one, and it costs a run of the scenario corpus because there is no
static list of which findings are symptoms - it is measured by raising each one
and asking whether the verdict names it. Do not shorten that with `--quick`:
the sampling windows are skipped, findings that need one report as symptoms,
and the table grows a coverage hole that is not there. That mistake was made
while writing this and briefly showed nine.

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
