# Open threads

Not a harness and not documentation. What is unfinished, and what is finished
but easy to undo by accident, written down because the reasoning behind them is
not in the code and would otherwise have to be rediscovered.

Everything here is checkable from the repository. Where a number is quoted,
the command that produces it is next to it.

## Start here (as of v1.24.0 plus the 2026-08-19 batches)

Suite green at **1,831**, tree clean, `dev/counts.py --check` says nothing is
stale, nothing pushed since v1.24.0. No release cut on top of it - the work
since is tests and four behaviour fixes, one of which changes what a report
says on a live box, so tag it whenever you like.

The work in flight is one long thread: **asking whether the suite's tests do
anything**, and it has produced five patterns that make the rest of it fast.
Read them before picking any of it up - every real gap so far has fitted one.

1. **A guard whose test exercises a neighbouring path.** Never a missing test -
   a test with an accurate name that never reaches the line.
2. **An early guard subsumed by a later one.** Equivalent, and deleting it is
   usually wrong: the subsumption rests on conventions rather than guarantees.
3. **A test that asserts a phrase appears** checks neither the values in it nor
   that it stays away when it should.
4. **A multi-condition guard where the tests drive one condition.** The
   coverage on the front of the expression makes the back of it look tested.
5. **A fixture that short-circuits before the condition under test.** Its tell
   is a guard whose *earlier* conditions are well covered.

And one rule that has mattered more than any of them: **a survivor is not a
defect.** Across this work, sixteen were real, thirteen were equivalent
mutants, one was dead code, and nine had a single benign cause. Sort before
acting; the obvious response to a batch of survivors has been wrong three
times.

**Next, in the order I would take it:**

- **The empty-only sweep, continued.** Batches ten to twenty-one: **72
  mutations, 26 holes, 5 equivalent mutants**, in `negatives-batch-ten`
  through `-twentyone.json`. Sixty-eight tests moved from unexamined to
  known-real. Still the best rate of anything open, and
  `python3 dev/vacuous.py` lists the 150 left.

  **Two predictors now, and the second is easier to search for.** Every hole
  has been a guard the corpus never exercised *because no scenario produces the
  input combination* - a one-row source matrix, a `/128` beside only a
  link-local, two findings from one family, a port range, a router worse on one
  side than the other. That beats "empty-only" as a selector. But batch
  seventeen found three of its four by reading **a comment that claims the code
  handles N shapes where the fixtures build one**, which is greppable in a way
  that "imagine an input nobody built" is not, and batch eighteen found a
  live defect the same way within one grep. **That seam is now worked out** -
  batch nineteen swept the rest of the enumerating prose and every claim had
  fixtures behind it. The productive form of the rule is the sharper one
  batch nineteen ended on: **look for the input every real box has that no
  fixture builds.** Loopback was the example; the fixtures are tidier than
  any machine this runs on, and each way they are tidy is a guard nothing
  tests.

  **And a third ending for a survivor**, which batch fourteen added to the two
  already here. A guard subsumed *inside its own function* is untestable and
  gets a comment. A guard subsumed by a *convention elsewhere* gets a comment
  too. A guard subsumed by its **caller** is only untested through the path
  everything else uses - a direct call closes it, and that is strictly better
  than excusing the line. Reach for it before writing one off.
- **19 message-value mutations** left, all of them helpers, renderers or second
  sentences - deliberately stopped there, since none is a number a verdict
  rests on.
- **Phase A's last 14** conversions, each needing a judgement rather than a
  rewrite. Hygiene, not a fix - do not let it look urgent.
- **Phase C** (explicit ranking) then **B** (a contract for `raw`).
- The résumé card, which the user has deprioritised repeatedly.

## Settled: the clauses a report can say and no scenario produced

A finding whose message contains an `if` has more than one thing to say, and
the corpus keeps one scenario per finding - which asks whether a finding fires
and cannot ask whether it fires both ways. Sweeping every conditional clause
and matching its longest run of fixed words against what the corpus renders
found 15 of 36 never produced.

**Seven are now driven by tests** and hold under mutation: more than one
firewall rule, a second unreachable proxy, the listener holding a datagram
queue, a second queued listener, the session a quiet box was run over, the
handshake share of a slow answer, and the collisions that turn a duplex
mismatch from a warning into a critical. That last one is the only one where
the unrendered clause marked a change of severity, and it was the finding
already exempted in `COARSER_ON_THE_STRIP` on exactly that reasoning.

**Two were attempted and removed.** `ephemeral_ports_low` needs the port range
read off the box before it can judge pressure against it, and
`inet_unreachable`'s backend clause needs a run aimed at a backend that is also
unreachable - two fixtures rather than one. Both were first written as "assert
if it fired", which passed while producing nothing. A test that proves nothing
looks exactly like coverage, so they are out rather than green.

**All fifteen are driven now.** The last six needed hand-built traces: a hop
with two responders for the fan-out clauses on `double_nat` and `latency_wall`,
a wall at hop 1, a walk with two translations, and a route answer that says
on-link while the trace went through a router.

One of those exposed the worst defect this harness has had. `dev/mutate.py`
reported two of them as SURVIVED when the mutation had broken the syntax: the
module never imported, no line beginning FAIL: or ERROR: was printed, and zero
failures reads as "nothing tests this rule" about a rule that is perfectly well
tested. It sends somebody to write tests that already exist. Mutants are now
checked for being importable before their result is believed - which is the
same check `branch_sweep.py` has made with `node --check` since it was written,
and the lesson did not travel.

**Getting the sweep right took three attempts and that is the transferable
part.** Stripping the placeholders out of a clause glues the fragments either
side together into a string that appears nowhere, so it reported clauses as
missing that are plainly in the message - `proxy_backend_down` was a false
positive twice. The unit that works is the longest run of fixed words between
placeholders.

## Settled: what a mutation being caught by one test does and does not mean

The whole set ran on 2026-08-18: **33 mutations, 0 survived, control clean.**
The first time it has gone through in one pass.

Ten of the 33 are held by exactly one test each. All ten were checked and all
ten are behavioural - they call the tool and assert on what comes back, not the
"a string appears in VIEWER_TEMPLATE" shape this project has been wrong about
three times. A single assertion is not a weak assertion.

**One real gap came out of asking a different question.** Not "is the test
strong" but "does the rule reach the reader". Replacing `annotation_means(f)`
with the raw flag was caught only by `nothing_is_defined_and_never_used` - a
structural test that fired because the function became unused, and would not
have fired had anything else still called it. Nothing asserted that a report
says "administratively prohibited" rather than "!X". It does now, on the
message rather than on the function.

**And a measurement that is not a defect.** 21 of 24 vocabulary phrases never
appear in any scenario's message. That is inherent to a lookup table:
`TRACE_ANNOTATIONS` has nine entries and only the three in `TRACE_PROHIBITED`
are ever rendered in words, and `CHECK_MEANS` surfaces one status per run. A
scenario per enum member would be corpus bloat for no signal. Recorded so
nobody reads the same number later as twenty-one holes.

The rule worth carrying: **a vocabulary being complete, and a vocabulary
reaching the page, are two different tests.** The AS numbers shipped correct
and invisible on forty pages for a week for the same reason.

## Settled: the two long functions, split along seams that were already there

`diagnose` was 451 lines and `_check_path` 388, and every ordering mistake this
week has been inside one of them. Both are down: `diagnose` 361,
`_check_path` 163.

Four blocks came out, each answering a different question from the code around
it. `_survey_this_box` is everything read before a target is chosen, which is a
group because aiming at the backend a box depends on most means reading its
socket table first. `_check_against_the_last_visit` is the only part asking what
is true now *and was not last time*. `_findings_from_the_walk` reads a path that
is already a fact, where everything above it is still obtaining one and may
retry three ways. `_check_path_mtu` is a separate question with separate probes
that sat in the middle only because it shares a target.

**The check that means something for a refactor is `dev/equivalence.py`, not the
suite.** 190 scenarios against HEAD, 0 differ, run after each extraction rather
than once at the end - either could have been the one that moved something, and
a single check would not say which. The suite asserts what each scenario should
say, so a change that quietly alters a scenario nobody wrote an assertion for
goes straight through it.

**Two things worth keeping from doing it.** Threading four values out of the
baseline block took four NameErrors, which is the argument for the extraction
rather than against it: a block reading four names out of four hundred lines of
context is one nobody can check in place. And the `_read_` prefix is
load-bearing - the harness stubs every `cmd_*` and `_read_*` name to seal the
process, so an orchestrator called `_read_...` was replaced wholesale and the
socket table never arrived. Name a collector `_read_`, name anything that only
calls collectors something else.

Still over 120 lines, in order: `render_text_report` 295, `_check_flows` 252,
`_check_ports` 217, `analyze_tcp_flows` 205, `build_verdict` 195.

## The 142 tests that assert only on empty things

`dev/vacuous.py` flags them; this is what reading them found.

**They are two populations and conflating them is why the list reads as a
wall.** 21 assert an empty *violation* set - the structural guards, whose
healthy state is nothing to report, and several of which caught real defects
this week. Those are working as designed. The other 121 run something and
assert a rule stayed quiet, and for those the question is whether the fixture
arranged the situation at all. Only a mutation answers that.

**Six were mutated as a spread across different rules. Five were caught and one
was a real hole**, in `dev/mutations/negatives-that-stay-quiet.json`:

`_check_bonds` skips a bond with `if not down or len(down) >= len(members)`.
Delete `not down` and every healthy bond reports as degraded - and all 1,780
tests pass. The only test named for it,
`test_a_healthy_bond_reports_nothing_down`, asserts that
`_bond_members_linux` found nothing down. That is the **parser**, not the
finding, and the whole of `TestBondMembers` was about the parser. The finding
had no test of any kind.

That is the shape to look for in the remaining 115: a test whose name describes
a conclusion and whose body checks the layer underneath it. Three tests now
cover `_check_bonds` itself, including the positive case so the negative one
cannot pass by the finding being unreachable.

**Batch two: six more, five caught, one survivor that is not a hole.** In
`dev/mutations/negatives-batch-two.json`. The survivor is worth writing down
because it is a category, not a defect.

`_serves_traffic` opens with `if not sock.get("ok"): return None`. Deleting it
survives and always will: a failed collector returns its own error shape with
none of the parsed keys, so the port test two lines down already returns None
for every failure the corpus can produce.

**That is not the same as the line being dead**, and the distinction decides
what to do about it. The group-size guard in `_check_idle_endpoint` came out
when a mutation proved it dead - it was subsumed by the next line for *any*
input. This one is subsumed only while "a failed collector carries no data"
holds, which is a convention here rather than a guarantee: a partial read that
kept some rows and reported not-ok would reach the test below with real ports.
So the line stays, with a comment saying it is untestable and why, and the
mutation is out of the set - a mutation that can never be caught makes the set
permanently red and teaches nothing.

**Batch ten: five mutations across three rules, one survivor, and the survivor
was a gap.** In `dev/mutations/negatives-batch-ten.json`.

`_check_source_reachability` opened with `if len(rows) < 2: return` and the
bind-failure check sat *below* it. Widening the gate to `< 1` survived, which
said nothing tested the boundary - and reading why found the reason. A bind
failure is not a comparison: one address the kernel will not send from is a
fact about this box and needs no second address to be held against. Behind the
gate it was silent on a box with a single global address, and
`source_address_not_held` does not cover that either, because it answers
`--source <address>` and not `--source all`. So a box with one address it
cannot use was reported by nothing.

The bind check moved above the gate, and the gate then had nothing left to do -
one address is either reached or failed, and the check below returns on an
empty half either way, for any input. That is the `_check_idle_endpoint` case
rather than the `_serves_traffic` one: subsumed for every input rather than
while a convention holds, so it came out. Three tests cover what it used to
hold, pinned on the behaviour rather than on the line.

**Two notes on running these.** The mutation that found it had to be deleted
afterwards - its anchor no longer exists - and replaced with two on what the
move actually decided. And the control earned its keep: the first re-run
refused to start because three new tests had made the pinned count stale, which
would otherwise have read as five rules being well covered when nothing had
been proved.

**Batches eleven and twelve: eleven mutations across five rules, all caught,
no holes.** In `negatives-batch-eleven.json` and `negatives-batch-twelve.json`.
The relay-volume pair and its unreadable-kernel case, four guards in
`udp_window` (drained, bound mid-window, no buffer, and the share floor), the
firewall counter reset, both halves of `_where_that_is`, and the missing
inbound count in `_check_asymmetric_path`.

Written down because a batch that finds nothing is still a result: those eleven
tests are known real rather than unexamined, and re-running them is a second
each. Sixteen mutations across the three batches, one hole - which is the rate
this list was estimated at, so the estimate is holding.

One thing to watch in the reading. Two of the eleven were caught partly by
`nothing_is_defined_and_never_used`, because the mutation left a threshold
constant unreferenced. That is the dead-name guard firing, not a behavioural
test, and on its own it would prove nothing about the rule - both had a real
test beside it in the caught list. Check *which* tests caught a mutation before
counting it as covered.

**Batch thirteen: six mutations, three survivors, one hole and two equivalent -
which is the sort ratio this list keeps producing.** In
`negatives-batch-thirteen.json`, now four after the two equivalent ones came out.

The hole is in `service_addresses`. It calls a `/32` or `/128` a service
address when another address on the same interface has a wider prefix, and the
scope filter at the top is the only thing stopping a **link-local** counting as
that second address. Delete the filter and every `/128` on the box reads as a
service address, because every IPv6 interface carries a link-local - the common
case, not an edge one - and no test in 1,809 noticed. Two tests now, the second
being the positive case so the first cannot pass by the shape never being
recognised.

The two equivalent ones are worth knowing as a pair, because both are subsumed
by a **guarantee** rather than by a convention, which is the `_serves_traffic`
handling rather than the `_check_idle_endpoint` one:

- `o is not entry` in the same `any()`. The `continue` above guarantees this
  entry's prefix *is* the host route, so it can never satisfy the wider-prefix
  test. Kept, because an edit to that guard would otherwise make it silently
  wrong.
- `if not servers: return` in `_check_proxy_backends`, subsumed by `if not
  down` two lines below for every input.

Both lines carry a comment saying they are untestable and why, and both
mutations are out of the set - one that can never be caught makes the set
permanently red and teaches nothing.

**Batch fourteen: six mutations, one survivor, and a third way to close one.**
In `negatives-batch-fourteen.json`. Four guards in `name_the_addresses` and two
scoping conditions in `mark_fanout`.

The survivor was the IPv4 filter on what gets a reverse lookup, and it survives
through the report *by construction*: `addresses_on_the_page` already filters to
IPv4 before handing the set over, so nothing arriving that way can reach it.
That reads like the `_serves_traffic` case - keep the line, comment it as
untestable, drop the mutation - but there was a better move here, because the
function is directly callable. **A test that calls it directly catches the
mutation**, so the line is covered rather than excused.

That is worth having as a third option beside the other two. A guard subsumed
by its *caller* is not untestable, only untested through the path everything
else uses. Reach for a direct call before writing it off, and only fall back to
a comment when the subsumption is inside the same function.

Worth catching, too: a hostname with three dots in it splits into four parts, so
`dns_ptr`'s own length guard lets it through and the box sends a reverse query
for something that was never an address.

**Batch fifteen: five mutations on the baseline comparison, all caught.** In
`negatives-batch-fifteen.json`. Context findings excluded from the diff, the
comparison not diffing its own summary, an unchanged severity not reported as a
change, the direction on a fault that cleared, and the local-only filter when
the target moved. That feature is well covered; nothing to do there.

**Batch sixteen: six on the cause-and-consequence rules, one hole and one
equivalent.** In `negatives-batch-sixteen.json`, now five.

The hole is the family filter in `build_verdict`. Four port results are four
instances of one check and two optical readings are two views of one module, and
that filter is the only thing stopping a sibling being reported as a *separate
problem*. Delete it and `optics_warning` arrives as unrelated underneath
`optics_rx_low` - the report sending somebody to look at a second thing that is
the first thing. `test_a_symptom_of_the_cause_is_not_called_unrelated` is named
for exactly this and does not reach it; no scenario in the corpus produces two
findings from one family. Two tests now, the second being a genuinely separate
check so the first cannot pass by nothing ever being called unrelated.

The equivalent one is `f.get("code") != code` in the same expression: a finding
is always in its own family, so the family test already excludes the cause. The
line stays - it says the obvious thing directly, and the family test is a
judgement that could be narrowed later - with a comment, and the mutation is out
of the set.

**Batch seventeen: six mutations, four survivors, four holes and one of them a
live defect.** In `negatives-batch-seventeen.json`. Two on the port a firewall
rule names, two on which shared router gets described, and two controls that
were caught first time and are kept for the same reason a control is.

The defect is in `_ports_named_by`. A rule can name a range, and the ends were
being read into a set and intersected with what this box listens on - which
matches a service on 1000 or on 2000 and says nothing about the thousand ports
between them. A box serving 1500 behind `--dport 1000:2000 -j DROP` was
reported by nothing, and that is the exact silence the check exists to break.
It now asks the question the other way round: a range is a bound to test
against, and the ports to test are the handful this box actually serves, so the
sentence also names the reader's own port rather than the rule's bounds.

The other three were correct code that nothing reached. The multiport list
already worked; the two in `_check_shared_hop` are a shared hop picked on state
before delay, and a hop described from the side it is worse on. Both of those
are single expressions whose two halves moved together in every fixture: every
trace pair here is identical on both sides, so the side that decides the
severity was never the side that had a different answer.

**A second selector, and it found three of the four.** The empty-only list did
not lead here. `_RULE_DPORT` carries a comment saying it reads "both the single
and the multiport forms", and the entire suite builds one dport shape,
`--dport 443` - so the comment claims two forms and the corpus builds one. That
generalises: **a comment that says the code handles N shapes, where the fixtures
build one**, is as sharp as the input-combination rule and much easier to grep
for. The same reading found the two in `_check_shared_hop`, where the docstring
describes one router seen from two directions and every fixture makes the two
views identical.

Worth knowing about the regex while anyone is in there: `[\d,\s:-]+` reaches
over the separator into the flag after the port, so `--dport 443 -j DROP`
captures `443 -` and the last piece of nearly every rule is empty. The
`isdigit` filter is what drops it, and it looks like defensive noise until you
know that.

**Batch eighteen: seven mutations, and the new selector paid for itself
twice.** In `negatives-batch-eighteen.json`. `TRACE_PROHIBITED` holds six
spellings of three refusals - the comment says so - and the suite built two of
the six. Reading the table against traceroute(8) rather than against memory
found two faults in one character.

**"!T" was in the set and is not a refusal.** It is "for this type of service
the destination host is unreachable": a path that does not carry this traffic,
no policy behind it, nobody to ask. It was firing `path_admin_prohibited`,
which is critical and says in as many words that somebody configured this and
there is a person to go and talk to - so the report sent a reader hunting for a
rule that was never written. **And "!Z" was in neither table**, which is the
spelling a BSD traceroute prints for code 10. The refusal this set exists to
catch was read as an unexplained silent path on exactly the boxes the letters
were added for. `!A` also carried the generic phrase where it is specifically
the *network* refusal, and four more letters traceroute defines - `!U`, `!W`,
`!I`, `!Q` - were absent and printed as their own tokens.

**The first version of the test that covers this was vacuous, and the shape is
worth carrying.** It looped over `nd.TRACE_PROHIBITED` asking whether each
member reaches the finding. Delete a member and the loop shrinks with it, so
it went green against the exact edit it was written to catch - two mutations
survived that should not have. **A test that iterates the constant it is
checking cannot check the constant.** The six are named in the test now and
the tuple is compared against them.

**A false catch, and where it came from.** The first run of this batch reported
a mutation caught by `TestOwnTlsListener.test_reading_the_fields_leaves_no_file
_behind` - a TLS test with no connection to a traceroute constant. It was
globbing the shared temp directory, so a second mutant suite's certificate
landed in its window: six failures in ten under a competing writer. Fixed in
its own commit. **Read which test caught a mutation, every time.** A mutation
run cannot tell a real catch from a test failing for its own reasons, and the
false one says "covered" about something nothing covers.

**A gotcha that cost twenty minutes here.** `dev/counts.py` rewriting 1055 to
1056 leaves the file the same length, and macOS caches bytecode by size and
mtime under `~/Library/Caches/com.apple.python/` rather than in `__pycache__`.
The suite then runs the old code against the new documents and fails on a
number that is plainly correct in both files. Delete the cached `.pyc` there,
not just `__pycache__`.

**Batch nineteen: the prose selector swept to exhaustion, six mutations, two
holes and one equivalent.** In `negatives-batch-nineteen.json`, now five.

**Most of what the selector points at turns out to be covered, and that is the
headline.** Every claim of the form "N shapes, N spellings, N notations" was
checked: the three interface headers `ip`/`ifconfig`/`ipconfig` write, mtr's
`-b` "name (address)" form, the ping source flag riding both command forms, the
three ways a proxy row arrives with no status, the three netmask notations, and
BSD's singular-and-plural counter lines. All six have fixtures. The vocabulary
tables were where this selector paid, and they are done - so treat the grep as
finished rather than as a seam to keep mining.

**The two holes came from somewhere else, and they sharpen the input rule.**
`_check_every_interface` builds its set of active interfaces with
`i.get("packets") and not i["name"].startswith("lo")`, and the fixture builds
interfaces that are all named `eth*` and all carrying traffic. So neither
condition was tested - and both are load-bearing on **every real box**. Counted
as an interface, loopback never reports a cable fault, so "the same fault on
all of them" can never be true and the finding stops firing anywhere. Same for
a spare NIC passing nothing. Delete either guard and the rule is silently dead
in production while the whole suite stays green.

That is worth stating as its own rule, because it is not quite the one above:
**the input shape no fixture builds is sometimes the shape every real box
has.** A corpus of tidy fixtures - three NICs, all named alike, all busy - is
missing the loopback that is on literally every Linux box. Those gaps produce
false negatives that appear only in the field, which is the expensive kind.
Three tests now, the third being a clean fourth NIC that still has to stop the
finding, so the two positives cannot pass by the skip being unconditional.

**The equivalent one is the scope test in the same loop.** A finding with no
scope carries None or "", and the intersection with `active` two lines below
drops both for every interface list a collector can produce. It is
distinguishable only on a box with an interface whose name is the empty string,
which nothing parses. The line stays with a comment and the mutation is out of
the set.

**And a prediction that was wrong, which is why the rule is to read the catch.**
`asn_with_name` matches `shown == net or shown.endswith("." + net)`, and the
unit tests beside it only ever pass a name equal to the network - so the second
half looked like a certain gap. It is caught, by a scenario fixture three
thousand lines away that traces `core-rtr-07.corp.internal` inside
`corp.internal` and asserts the estate is not printed twice. Checking which
test caught a mutation is not only for spotting false catches; it is also how
you find that a guard is covered from somewhere you would never have looked.

**Batch twenty: eight mutations, eight survivors, one cause - and the answer
was one test rather than eight.** In `negatives-batch-twenty.json`.

Batch nineteen ended on "look for the input every real box has that no fixture
builds", and the obvious next question was how far the loopback gap went. Ten
places skip loopback before judging an interface. A mutation deleting the skip
survived at **every one of them**, because the corpus builds interface lists
that are all named `eth`-something and all busy - a machine that does not
exist. The busiest interface on a proxy is routinely `lo`.

**Adding a loopback to the shared fixture was not the fix, and that is worth
knowing before someone tries it.** `counters()` now builds one, because a
corpus that omits what every box has is wrong on its own terms - but the suite
went green unchanged and **all eight mutations still survived**. A real
loopback is clean: no errors, no carrier flaps, no optics, no negotiated speed.
The guards are not protecting against a *faulty* loopback, they are protecting
against loopback being *counted*, and no assertion in the corpus looked at the
count. A realistic fixture is not the same thing as a test.

**So it is a contract test**, the same shape as the nine `ok` guards: eight
fixtures would have been eight ways of saying one thing, several of them
describing a loopback that reports CRC errors and optical power, which is not a
machine either. `TestLoopbackIsNotOneOfTheCables` walks the file and requires
every function that reads `link_stats` interfaces to skip loopback, with five
named exceptions that are right not to - the collector that builds the list,
the delta arithmetic, the route lookup, the emptiness check, and the set of
names that exist. A second test holds that list to being exceptions, so a name
left there after a function changes cannot quietly become a hole. Same
reasoning as the finding-side fallback: a decision somebody made rather than
one nobody noticed.

**With one behavioural anchor underneath it, on purpose.** A contract test
proves a filter is written, not that it works - renaming `lo` to `lop` would
satisfy it. So the printed link table is asserted directly against a report
carrying a loopback moving 40 Gbps, which is the reader-visible end and the
row that would sit at the top of the table. Every structural test in here
wants one of those beside it.

**Batch twenty-one: the other half of the same expressions, six mutations, six
survivors.** In `negatives-batch-twentyone.json`. The guards that skip an
interface carrying no traffic are as untested as the loopback ones and for the
identical reason - every interface in the corpus is busy. The comment above one
of them has said "every box has a pile of idle virtual interfaces" the whole
time. Same answer: the contract test now covers both halves, with two named
exceptions that are right not to skip the idle - `_check_link_flaps`, because a
port with a loose cable flaps without ever passing a packet and that *is* the
finding, and `_qualify_upstream_verdict`, because the value it reads is only
ever written for an interface that moved something.

**And the batch found a defect in the contract test itself, which is the part
to carry.** The first version asked whether the function body contained
`["packets"]`. `_check_counters` says "packets" several times over for other
reasons, so deleting its guard left the word behind and the mutation survived a
test written that hour to catch it. **A structural test that matches on
vocabulary rather than on the construct is the weak kind** - the same family as
a test asserting a phrase appears. It matches the shape of the guard now
(`not x["packets"]`, or `x["packets"] and`), and the mutation is caught.

**How to work through the rest:** take a handful at a time, find the guard that
keeps the rule quiet, and write a mutation that forces it open. A caught
mutation means the test is real. Two things learned from eleven so far:

- **Do not trust the name of the test.** The one real hole had an accurate name
  pointing at the wrong layer - `test_a_healthy_bond_reports_nothing_down`
  tests the parser, not the finding.
- **Sort survivors into holes and equivalent mutants before acting.** Of three
  survivors across both batches, one was a missing test and two were mutants
  that could not change an answer. Deleting a guard because a mutation survived
  is the wrong lesson from the right signal.

**Batch three: six more, two survivors, both closed.** In
`dev/mutations/negatives-batch-three.json`, both in `first_hop_from_route`.

- Its `ok` guard was never doing the work.
  `test_a_box_that_cannot_even_read_its_route_says_nothing` hands it a failure
  with **no stdout**, so the empty parse two lines down returns the same answer
  and the guard could be deleted unnoticed. A command that exits non-zero and
  still prints is the case it exists for, and that is the fixture now.
- Its `valid_target(via)` guard had nothing driving it at all. `via` is
  whatever follows the word - the pattern is `\bvia (\S+)` - so that call is
  the only thing between a malformed route line and a host in the report, which
  is then rendered, exported and handed to a reverse lookup.

The second one is also a lesson about writing the test. The first draft
asserted that `via unreachable` would be rejected, and it failed: `valid_target`
checks *syntax*, and a bare word is a valid hostname. The claim had to be
narrowed to the one that is true - text that could not be a host never becomes
one - and that is worth more than the version that would have passed by
accident.

**Batch four: six, all caught.** The firewall window, the baseline comparison
and the call score are all genuinely covered.

**Batch five: five, one real gap.** `count_the_hops_in` skips a peer that is
not an IPv4 address, and nothing drove it - every fixture has IPv4 peers, so
deleting the guard sends a ping per side to an address the tool had already
decided not to ask. Asserted on *what was pinged* rather than on the answer,
which is the technique `test_quick_mode_pings_no_peer_for_a_distance` already
uses and says why.

Two more mutations came out of that batch rather than being fixed, and the
reasons are different:

- **`if inbound:` in the same function is an equivalent mutant.** Setting
  `hops_in` to None and leaving the key absent read the same through `.get()`,
  and nothing distinguishes them anywhere.
- **`if quick:` is not a unique anchor** - it appears five times. A mutation
  whose anchor matches more than once is reported as bad rather than run, which
  is the harness working; anchor on the function's own line instead.

**Batch six: six, three survivors, one real.** `_check_discard_route` reads the
routing table without checking that reading it worked - the same shape as
`first_hop_from_route` two batches earlier, and it matters more here, because
naming a discard route is the most decisive finding the tool has and it would
be drawn from output the run had decided not to trust. Every fixture fails the
read with no output, so the empty parse below returned the same answer.

The other two were equivalent, and both for the same reason as several before
them - **an early guard subsumed by a later one**:

- `discards_the_target` checks `not target_ip`, and the `try/except ValueError`
  four lines down catches `ip_address(None)` anyway.
- `_check_relay_volume` checks `not client or not backend`, and both are
  `by_side.get(...) or {}`, so an empty side reaches the `volume_readable` test
  and returns there.

**Thirty-four of the 121 examined, nine survivors: four real gaps, five
equivalent mutants.** Roughly 87 still unexamined, at about six mutations per
two-minute run.

**Two patterns now hold across six batches, and both are worth reading before
the next one.**

*Every real gap has been a guard whose test exercises a neighbouring path* -
never a missing test. The bond test checked the parser instead of the finding;
three separate `ok` guards were handed a failure with no output, so the empty
parse below them gave the same answer; the TTL guard had no non-IPv4 fixture.
Each had a test with an accurate name that never reached the line.

*Every equivalent mutant has been an early guard subsumed by a later one.* That
is worth knowing because the tempting response - delete the redundant guard -
is usually wrong: they are cheap, they state intent, and the subsumption
depends on conventions rather than guarantees. Only delete when the later line
subsumes the earlier one for **any** input, which is what happened to the
group-size guard in `_check_idle_endpoint` and has not happened since.

## Batches seven and eight

**Seven: six mutations on the verdict reasoning, all caught.** `_sides_can_agree`,
`_same_scope`, the `WEAK_EVIDENCE` filter and the `derived_from` filter are
genuinely covered in both directions. Worth as much as a finding: that is the
most consequential code in the file.

**Eight: six on the per-source matrix and the zone strip. Four survived, three
were real** - and all three came from one test asserting a phrase *appears* and
nothing else.

`_which_question_answered` builds the sentence explaining that an address
answered TCP and not ping, which on these boxes is the ordinary case rather
than a fault. Its only test checked that the phrase was present. So nothing
noticed when the sentence named addresses it is not about (one that answered
both, one that answered neither), and nothing noticed when the guard keeping it
out entirely was deleted - which writes the sentence with an empty list of
addresses in front of it on every report where anything failed.

`_reaches_tint` grades an address the box does not hold as a warning rather
than a fault - it failed in the kernel before a packet left, so it is an
instance that is not there rather than a path that is not working. Untested.

The fourth survivor is equivalent and now says so in a comment: a row is only
in the `reached` list if it pinged **or** answered TCP, so "did not ping"
already means "answered TCP" inside that function. The invariant comes from the
caller's split, not from the line.

**Batch nine: six on the path MTU, certificate expiry, LLDP and the ipv4 flag.
One real.** `_check_path_mtu` opens on three conditions and only two were
driven - not quick, and loss below 100%. The third is the one its own comment
names: a path MTU measured toward a destination that answered no probe at all
is a measurement of nothing, and without the guard it produces
`pmtu_unmeasurable`, which reads as a gap in coverage on a run whose target was
simply unreachable.

*A shape worth looking for:* **a guard with several conditions where the tests
drive one of them.** The quick-mode half of that same line was well covered,
which is what made it look tested.

## The multi-condition guards: swept, and awaiting triage

The fourth pattern was hunted directly, the way the `ok` guards were. Every
`if A and B and C:` inside a `_check_*` function, one mutation per condition
with the rest of the guard intact: **42 conditions across 17 guards**, of which
17 could be written as a unique anchor and run. **10 survived.**

**Those ten are survivors, not gaps.** This session's record is three to one
against: most survivors have been equivalent mutants or a shared contract.
Triage each before writing anything, using the rule that has held throughout -
does the mutation change an answer the tool can actually produce.

One has been triaged and was real. `_check_gateway` decides whether one
unanswered probe is a rate or an artefact of the sample with
`sent < MIN_PROBES_FOR_LOSS`. Twenty probes and one lost is a rate, and without
the condition it reads as unmeasurable. **The internet side asserts exactly
this; the gateway side did not** - the two share a shape, which is how a
boundary ends up covered on one side only, and is worth checking for wherever a
rule exists in both directions.

**Triaged and closed. Three were real, six were equivalent, one was dead
code.**

*Real, and all three the same shape - a fixture that short-circuits before
reaching the condition:*

- `_check_link_modes` guards `100 < speed < capacity` with `speed is not None`.
  The test named for unknown speed has **no capacity**, so it stops one
  condition earlier. `ethtool` prints `Speed: Unknown!` with the supported modes
  on a port that is down, so capacity-known-and-speed-unknown is ordinary - and
  without the guard that is `100 < None` on an unplugged port.
- The same function notes a tunnel's MTU only when it differs from the
  standard. Every fixture used a smaller tunnel, so nothing drove
  `mtu != STANDARD_MTU`, and without it every tunnel on every box gets a note.
- The `not quick` half of `_check_path_mtu`.

*Equivalent, six of them, and five for one reason:* **the gate is a count and
the condition beside it is a rate derived from that same count.** `live_drops`
with `live_ppm`, `collisions` with `coll_ppm`, `errors` with `err_ppm`, and two
`_check_path` gates on `lossy` - `final_loss >= 5` cannot be true unless the
final hop is lossy. `_check_call_quality` guards `avg` and `floor` separately
when `parse_ping_stats` sets both or neither. All six are out of the set: a
mutation that can never be caught makes it permanently red.

*Dead code, one.* `_check_path` had a second `if` computing whether the stall
reached the last hop, whose body was `pass`. It read as the guard making that
decision while the decision was made by the next `if`, and its comment was the
only part doing any work. Removed, comment kept where the work happens. **My
triage called this one a likely real gap and it was not** - a mutation on dead
code survives exactly like a mutation on an untested one, and only reading the
body tells them apart.

The set is `dev/mutations/multi-condition.json`; regenerate after edits, because
the anchors are whole guard expressions and move easily.

**Seventy-eight of the 121 examined. Twelve real gaps, thirteen equivalent
mutants, one piece of dead code, nine explained by one contract.** Forty-three
left.

*A fifth pattern, from this triage:* **a fixture that short-circuits before the
condition under test.** Both real gaps here had a test named for exactly the
input in question, which stopped one condition short of driving it. The tell is
a guard where the earlier conditions are well covered.

*A third pattern, from batch eight:* **a test that asserts a phrase appears
tests almost nothing.** It does not check which values the phrase names, and it
does not check that the phrase stays away when it should. Three mutations lived
in that one gap. Grep the suite for `assertIn` on a message and ask what else
would still pass.

## Open, and the largest thing found so far: the numbers in messages

The third pattern was swept the way the `ok` guards were, and it is much
worse than the family that prompted it.

**Method.** Every finding message built from an f-string, every numeric
placeholder in one - `{expr:.0f}` - replaced by a literal `0`. Type-safe, and
it leaves every word of the sentence exactly as it was. A test that asserts the
phrase still passes; only a test that asserts the *value* fails.

**Result: 21 of 24 survived.** There are 62 such placeholders in the file and
177 messages built this way. A finding can say `0ms` where it means `580ms`,
`0%` where it means `90%`, and the suite is silent.

That matters more than the guard gaps above it. The numbers are the evidence
somebody acts on - "hop 3 adds 57ms of the delay that varies" sends an engineer
to hop 3, and the same sentence with a wrong number sends them nowhere. 205
assertions in the suite check message text; almost all of them check words.

**Run against all 62: 53 survived.** Nine were already covered.

**Now 19 survive**, down from 53, across twenty-two test edits. Everything a
verdict is built on is covered: the latency family, the queue at a hop, path
loss, the throughput split, gateway and internet loss on both the measured and
the unmeasurable sides, the TLS handshake comparison, the conntrack and accept
queue rates, syn cookies, link flaps, CPU load, the shared hop, the resolver
timing, live interface drops, and the latency wall's own headline.

**What is left is deliberately left.** Six are helpers and renderers -
`_fmt_bytes`, the progress line, the load-average context sentence, and the
service/link tables in the text report. The rest are second sentences inside
findings whose primary figures are now pinned. None of them is a number a
verdict rests on, which was the boundary drawn when this was picked up again.

**The remaining set was mischaracterised once and it is worth not repeating.**
It was called "renderers and a thin tail"; measuring it said 17 of 30 were
still finding messages, including `_check_gateway` and `_check_internet`, which
fire on every run. Sort the survivors by the function that owns them before
deciding anything about their value.

Four of the first five were **this week's own work** - tests I wrote that assert
the sentence while the figures the finding turns on went unchecked. The pattern
is not confined to old code.

**Two shapes keep recurring in the fixes, and both are reusable:**

- *A test that serves a real request cannot assert a number.* The port timing
  breakdown had no assertion on any of its three phases for exactly that
  reason. Build the result instead of measuring one, and the numbers become
  knowable.
- *Where the message prints a split, assert it adds up.* `throughput_limited_by`
  names a leader and then lists three shares; the added test checks the leader
  is the largest of the three it goes on to print, which no single-value
  assertion would catch.

**Quote the run, not the arithmetic.** An intermediate count of 42 did not
reconcile with the mutations closed since, and the discrepancy was not chased.
The figure to trust is whatever a freshly regenerated set reports against the
current tree; the lines below come from that run:

```
1245 3332 4110 4559 9479 11122 11517 12829 13065 13572 13573 13808 14811
15704 15779 15782 15914 15993 16026 17023 17033 17422 17432 20118 20175
20176 20359 20411 20412 20414
```

Regenerate the set after any edit - the line numbers move. The generator is a
regex over `faultone.py` for `{expr:.0f}` inside an f-string, one mutation per
line, replacing the expression with `0`.

**How to work through the rest.** Regenerate the set - the generator is six
lines of regex over `faultone.py` and is described above - run it, and for each
survivor add the value to whichever test already asserts that message's words.
Most survivors already have a test; it asserts the sentence and not the number,
so the fix is usually one line in an existing test rather than a new one.

Three messages had no assertion on their content at all and are the place to
start: the port timing breakdown (`connect / TLS / waiting`, which is the whole
value of that finding), the clock skew, and the jitter-against-RTT pair.

## The `ok` guards: a family, and the contract underneath them

The first pattern above turned out to be predictive, so the family was hunted
directly rather than one batch at a time: **31 early returns guard on a
collector's `ok` flag.** A mutation was generated for each consumer and run in
one go. **Nine survived.**

Nine survivors is not nine bugs, and the reason is one fact about `run`:

> `run` sets `ok` True whenever the process *ran*, whatever it exited with. Its
> three failures are command-not-found, timeout and an exception, and **none of
> them carries output.**

A ping exiting 1 on total loss keeps its summary, which is the point of reading
the flag that way. But it also means every consumer's empty parse returns the
same answer its `ok` guard would, for every result `run` can produce - so those
mutations survive by construction and always will.

So the guards defend a **contract**, not a reachable state, and the contract is
what is worth checking. `test_a_result_marked_not_ok_never_carries_data` asks
the source: three literals build a not-ok result with a payload key, and all
three set it to an empty list. A collector that hand-builds a not-ok result
*with* rows would break all thirty-one guards at once, silently, and that test
is what notices.

**Do not write nine fixtures for this.** They would assert behaviour on a state
`run` cannot produce, which is why the generated set was deleted rather than
kept: a mutation that can never be caught makes the harness permanently red.
The two `ok` guards that *did* get fixtures - `first_hop_from_route` and
`_check_discard_route` - are worth keeping anyway: they pin the intent of the
two most decisive readings in the tool, and they would catch a hand-built
result long before the static check explained why.

## Open: phase A, `findings` from out-parameter to return value

81 functions take `findings`; 66 mutate it in place. That is the dominant
coupling in the file: ordering is implicit, any check can see another's output,
and no check can be exercised without building the shared list first.

**Measured, and the number that matters is not 66.** Classified by whether a
function only appends or actually reads what is already there:

| | count | what to do |
|---|---|---|
| appends only | **53** | return a list; caller does `findings += ...` |
| reads the list as well | **12** | keep taking it - the dependency is real and now visible |
| takes it, never appends | 15 | already read-only; leave alone |

The twelve that genuinely read are `_all_clear`, `_check_addressing`,
`_check_against_the_last_visit`, `_check_cpu_load`, `_check_every_interface`,
`_check_flows`, `_check_internet`, `_check_path`, `_check_ports`,
`_check_saturation_bursts`, `_check_utilization` and `_own_service_findings`.
Those are the ones that reason about other findings - `_check_cpu_load` explains
existing ones, `_all_clear` fires when nothing else did - and after this
refactor that is a declared input rather than an accident of a shared list.

**The transform is not mechanical, and two categories prove it.** Of the 53:

- **27 contain a bare `return`.** Converted naively they return `None`, and
  `findings += None` raises. Every bare return has to become `return found`.
  This bit on the first function converted, which is the right place for it to
  bite.
- **10 already return something** - `_check_arp` returns the neighbour entries,
  `_check_dns` its own result. Those need a tuple, or the finding list moved to
  a second call, and each is a judgement rather than a rewrite.
- 16 are the straightforward case.

**Done so far: 44 of 53** - `_check_bonds`, then the 16 with no `return`
statement at all, which are the straightforward category. `dev/equivalence.py`
reports 195 scenarios with none differing after each batch, which is the bar
for a refactor here rather than a green suite.

Two things the batch taught, both worth having before the next one:

- **Rewrite the signature before the call site.** The definition line contains
  the call's own text as a substring, so replacing the call first clobbers the
  `def`. A syntax error was the only reason that was noticed, and it would not
  have been noticed at all if the clobbered function had still parsed.
- **Fourteen tests call these directly**, which is worth knowing before
  assuming the corpus is the only caller: `_check_asymmetric_path`,
  `_check_idle_endpoint` and `_check_server_limits` all have unit tests that
  passed a list in. That is a good sign about coverage and it means the call
  sites in `test_faultone.py` move with each batch.

The 27 with a bare `return` are done too, in two batches with
`dev/equivalence.py` between them. Three more things they taught:

- **A bare return can carry a trailing comment**, and several do. The AST has
  already said the value is None, so the line only has to *start* with the
  keyword - requiring it to be exactly `return` stopped a batch dead on
  `return    # not a box with two sides to compare`.
- **The caller's list is not always called `findings`.** `_check_clock` appends
  into `late`, a second list the report merges further down, so the call site
  becomes `late += _check_clock(raw)`. Take the accumulator's name from the
  call rather than assuming.
- **A test pins the call's source text.**
  `test_the_cache_check_runs_after_the_resolvers_are_probed` asserts that
  `_check_dns_cache` is called after `_check_dns`, by string. Its own comment
  warns that the `def` line contains the call as a substring - the same hazard,
  written down by whoever hit it first.

**What is left: 14, and they are all judgement rather than rewrite.** Each
already returns something - `_check_arp` its neighbour entries, `_check_dns`
whether resolution failed, `_choose_target` the target and its kind - so each
needs a tuple, a second call, or a small object, and the right answer differs
per function. `_check_path` and `_check_ports` are large enough that they
should probably be split first.

The remaining fourteen: `_check_addressing`, `_check_arp`, `_check_call_quality`,
`_check_dns`, `_check_flow_delay`, `_check_link_modes`,
`_check_neighbours_and_optics`, `_check_path`, `_check_ports`,
`_check_returns_that_stopped`, `_check_shared_hop`,
`_check_source_reachability`, `_choose_target`, `_own_service_findings`.

The transformer used for the first 44 is in the session scratchpad as
`phaseA.py`. It rewrites the signature before the call site, converts bare
returns, and takes the accumulator's name from the call - the three things that
went wrong when it did not.

Run `dev/equivalence.py` after every batch, not at the end. It compares against
the previous release, so a batch that changes an answer is found while the
batch is small enough to read.

## Collectors are a registry now, not a naming convention

`@collector` registers every function that reaches outside the process into
`COLLECTORS`, and the harness stubs what is in there. It used to derive that
list from the `cmd_` and `_read_` prefixes, which is a naming convention doing
an interface's job - and the job went undone the moment somebody wrote a reader
without thinking about the name. That is exactly what `_sysfs_names` was.

Three things worth knowing before touching it.

**The guard covers commands as well as files now.** It looked for `os.listdir`
and `open("/proc...")` only, so it covered thirteen of fifty-six collectors and
a mutation removing the decorator from `cmd_kernel_log` survived a whole run.
It also checks calls to `run`, `run_first_understood`, `run_first_usable`,
`create_connection`, `getaddrinfo` and `gethostbyaddr`.

**Four functions are plumbing, not collectors**, and are listed as such in the
guard: `run`, the two `run_first_*` wrappers, and `connect_from`. A collector is
a question about the box; these are what carries one. Stubbing them would hide
the collector bugs the registry exists to surface. The list lives in the test
rather than in the tool, because the tool never reads it and `TestNoSecondCopy`
correctly rejects a constant nothing reads.

**Registering `_link_stats_bsd`, `_link_modes_bsd` and `_tcp_counters_bsd`
changed no observable behaviour**, and that is honest rather than a gap:
`fresh()` pins `OS_NAME` to Linux, so their branch never runs in the corpus.
They are defence for a platform the scenarios do not describe. Two mutations
against them survived until they were rewritten to remove the compatibility
fallback as well - equivalent mutants, not holes.

The fallback: `fresh()` and `DiagnoseHarness.collectors()` fall back to the
prefix scan when the module has no `COLLECTORS`. That path exists only for
`dev/equivalence.py`, which runs the current tests against a previous
`faultone.py` to prove a refactor changed no answer - and that copy predates
the registry.

## A severity leaks through every place that recomputes it

Worth knowing before touching a verdict again, because it cost four passes.

`target_alone_unreachable` is a warning when the tool picked the target itself:
grading its own default choice as a critical network fault is the tool
manufacturing its own headline. Setting that severity fixed nothing on its own.
The report still said critical, because three other places derive their own
state from the raw findings rather than from the verdict, and a critical
`path_loss` measured toward the dead target came through every one of them:

1. `_verdict_severity` lifts the verdict to match the worst thing it explains.
2. `build_stages` fails a stage on a critical finding sitting in its warn set.
3. `build_sides` lights a zone from any critical finding facing it.

Each was found only by rendering the page after fixing the one before it, and
the last one - `connects out to FAULT` - is the first thing a reader sees. None
of them would have shown up in a test asserting the verdict.

So: after changing what a severity means, render the report and read it as a
stranger. The suite covers what the tool concludes and very little about what
the page says, and these three are the places a conclusion gets recomputed
behind its back.

## Settled: the suite no longer reads the machine it runs on

CI was red on every push from 2026-08-16 to 2026-08-18 - all four jobs, for
three different reasons - while the suite passed here every time. It was never
checked, which is the first lesson: **local green is not green.** All three are
fixed and the run is green; one part is left open and is described below.

Two of the three were the same shape: a test asking the host operating system a
question instead of the code under test. The third was `dev/audit.py`, which is
in the "dev harnesses" job and is not the suite - so a rule that only that
harness checks can break without a single test failing, which is the point of
it. `test_a_closed_port_says_nothing` bound a socket, closed it, connected to
the port it had just released and required the refusal to be "refused"; the
Windows runner answered with a timeout. Which refusal an operating system gives
is not this tool's to assert. That the two are told apart is.

`_sysfs_names` walked /sys/class/net without the `_read_`
prefix, so nothing stubbed it and the seal reported it on every Linux job;
there is no /sys on a Mac, so the branch never ran here. Four more host readers
had the same naming problem and are renamed. A static guard now asks the
*source* which functions reach the host without a collector's name, so it
answers the same on every platform.

`cmd_udp_sockets` was left live inside `fresh()`, so the `no_clients_connected`
scenario found whatever the build box had bound - datagram findings on Windows,
none here. Stubbed.

**This is closed, and not by stubbing the last four.** They were not reading
the host. They were being driven through readers the scenarios stub, and the
one host input left in them was the platform.

`OS_NAME = platform.system()` is the largest host input the tool has. Nearly
every collector branches on it, so the same scenario walked a different path on
each of the three platforms CI builds on - which is most of why a suite green
on a Mac was red on Ubuntu and red in a third way on Windows. `fresh()` pins it
to Linux, because that is what the corpus describes; 25 tests already set it by
hand and the ones that mean something else say so after the line. Nothing else
had to change.

The evidence is the suite run three times with `platform.system()` lying -
Windows, Darwin, Linux - all identical. Keep that trick; it is two lines and it
answers a question no amount of reading can:

```python
import platform; platform.system = lambda: "Windows"
```

The guard is static, because the failure cannot be reproduced here:
`platform.system()` must be called exactly once, nothing may read `sys.platform`
or `os.name` sideways, and `fresh().OS_NAME` must be Linux whatever this machine
is. A second call, a sideways read, and an unpinned `fresh()` were each checked
to fail it.

**Two earlier numbers here were wrong, and both the same way: each counted
something the scenario configures as something the scenario reads.** The claim
that blanket-stubbing stops forty-four scenarios firing came from a blank
returning `None` where almost every `_read_*` returns `{}` and its callers do
`.get()` - those scenarios were raising, not losing a finding. The claim that
`cmd_kernel_drops` had 28 scenarios leaning on the machine came from blanking
the collector on top of the `_read_kernel_drops` fixture those scenarios set
for it. To measure this properly: blank one collector at a time, with the shape
it really returns, only where the scenario left it live, and remember that a
scenario driving a real collector through a stubbed reader is the corpus
working rather than a leak.

`fresh()` keeps `AS_WRITTEN`, every collector as the module wrote it, captured
before anything replaces one. A test of a collector's *own* behaviour needs the
real function bound to the copy whose `open` and `OS_NAME` it patched, and
stubbing the collector takes that away - which it did to fifteen tests at once.
Each of them names the collector it is testing now, which is an improvement on
receiving it by accident.

Four collectors are still the module's own inside `fresh()` - `cmd_kernel_drops`,
`cmd_link_stats`, `cmd_kernel_log`, `cmd_tcp_health` - and that is correct.
Every input they have is stubbed, so they are the code under test rather than a
hole. The snippet below counts them; four is the expected answer, not a debt.

```bash
python3 - <<'EOF'
import os, sys; sys.path.insert(0, "."); sys.argv = ["x"]
os.environ.pop("SSH_CONNECTION", None)
import test_faultone as T
m = T.fresh()
live = [n for n in dir(m)
        if (n.startswith("cmd_") or n.startswith("_read_")) and callable(getattr(m, n))
        and os.path.basename(getattr(getattr(m, n), "__code__", None).co_filename)
            == "faultone.py"]
print(len(live), "collectors still read the machine"); print("\n".join(live))
EOF
```

Two things that cost time finding this, both worth not repeating. `"test_faultone.py".endswith("faultone.py")` is true, so the first version of that check reported all fifty-three as live. And the two readers that answer with a pair need different blanks - `_read_link_stats` gives `({}, source)` and `_read_load_average` gives `(None, None)` - so one shared stub fails at the unpack or at the arithmetic.

## Settled: four vocabularies borrowed, and the rule that found them

All four are done, 2026-08-18. What is worth keeping is the rule the survey
produced, not the four: **borrow a vocabulary when it is a closed set of
facts; keep the hand-written list when it encodes a decision.** X.733 probable
causes are facts. "Ports worth probing" is a decision, and deriving
`SERVING_PORTS` from IANA would make it worse - 3000 is not registered for HTTP
and is one of the commonest ports a service actually listens on.

`MULTI_LABEL_TLDS` had the live bug and is the one to understand. Seven
hand-picked labels standing in for the Public Suffix List, which is **not
vendored on purpose**: ~230KB against a tool that has to stay one small
stdlib-only file, and it would be the largest thing here by several times. So
it stays manual and stays incomplete - the question is only whether it is
incomplete where it matters. It was: `ne.jp` is *the* ISP suffix in Japan, so
every Japanese provider on a path collapsed into one network called "ne.jp",
which is the exact failure the comment above that list has always claimed to
prevent. `nhs.uk` and `sch.uk` did it to two of the larger British networks.
Now ~40 entries grouped by country so a gap is visible.

`CHECK_MEANS` gained `INI`, `UNK` and `SOCKERR` - what a check reports *before
it has run*, so a freshly reloaded proxy no longer shows a status the report
cannot explain, at the moment somebody is most likely to be looking at it.
Plus `L6OK` and `L7OKC`.

`DNS_RCODES` is the IANA registry: 0-11 and 16-23, with 12-15 deliberately
absent because they are unassigned and claiming them would be worse than
printing the number.

`TRACE_ANNOTATIONS` gained `!V`, and the numeric `!<N>` form now goes through
`annotation_means()` rather than falling through raw. An unreachable nobody
can name is still a router refusing on purpose, and the number is what
somebody looks up.

Six mutations in `dev/mutations/borrowed-vocabularies.json`, none survived.

**Still unlabelled and still fine:** `TCP_STATES` is RFC 9293's eleven states
exactly, `LAYERS` is OSI, `TUNNEL_OVERHEAD` is RFC-derived header sizes. Each
now wants a comment naming its source so nobody improves them.

## Open: where the laptop stopped, 2026-08-17 evening

Picked up after pulling v1.21.0, so this continues the desktop session below
rather than replacing it. Everything is committed and pushed, the suite is
green at **1,689**, the tree is clean and `dev/counts.py --check` says nothing
is stale. Nothing is half-applied.

**Two things landed.** Every ranked finding now carries an ITU-T X.733 event
type and probable cause - `dev/counts.py --kinds`, and `--deep` for how many of
each can be the answer rather than only a symptom. And the audit that made
possible immediately returned one gap, which is now built: `cpu_saturated`
names this box's own run queue as the cause of a timing that had none.

**The next work is the four vocabularies above.** They are independent, small,
and each has a source to copy from rather than a judgement to make.

**One thing to know before touching `cpu_saturated`.** It is gated on some
other finding already describing something slow, because a test older than it
says a busy box is not a network fault and that rule is right - a proxy at
capacity doing what it was bought for must not be reported as broken. The gate
reads the X.733 class rather than a list of codes, so a latency finding written
later is covered the day it is classified. Do not remove the gate to "make it
fire more".

### The older stopping point, from the desktop

The suite was green at 1,671 there, the tree clean, and all three demo sets
regenerated.

**The branch sweep is done and does not need re-running.** Both directions ran
clean over all 88 sites on 2026-08-16 - 0 survivors, 0 edits that broke the
syntax, every forced branch noticed by at least two tests. The regex that found
54 of them was replaced: conditions are forced by *inserting* `|| true` or
`&& false` before the operator rather than by finding where the condition
begins, which needs no extent and cannot cross a template boundary. Re-run it
only when the viewer's branching changes.

**The one sweep never yet run as a whole:** `python3 dev/mutate.py
dev/mutations` - 25 mutations across seven files, about an hour. Each set has
been run on its own as it was written and every one came back clean, but the
whole thing has not gone through in a single pass. Run `--anchors` first; it
takes a second and tells you whether any of them still apply.

**Three things worth knowing before trusting any mutation run.** Copy the whole
tree, not the two Python files - sixteen documentation tests error for want of
a README and an error counts the same as a failure. Run a control first, always;
a suite that fails before anything is mutated makes every result behind it
noise, which happened and was not noticed for three runs. And nothing in `dev/`
is covered by the suite, so a mutation there correctly survives - which is why
`counts.py` and `mutate.py` self-test, and why `demos.py` checks its own pages.

**The one place a reading can still be invisible.** The suite proves a finding
fires; `test_every_ranked_finding_can_be_the_answer_somewhere` proves it can
headline, so a page can exist for it. Neither proves a *detail inside* a finding
ever renders - the AS numbers shipped tested and unseen on forty pages for a
week for exactly that reason. `dev/demos.py` now fails if no hop on a page
carries an AS, which closes that one case and not the general one.

## Closed: the flaky test, and the half of it the first fix missed

`DiagnoseHarness.test_healthy_device` failed roughly one run in six. It passed
300 times in isolation, which is the signature of something leaking in from
outside rather than something wrong in the test.

The first round found the harness naming seventeen collectors in a tuple while
the tool had grown to thirty-eight, so twenty-two ran for real - including
`cmd_tls_check`, a live TLS handshake, from a suite that promises it sends no
packets. Deriving the list off the module fixed those, and the failure did not
recur in nine full runs. That was recorded here as evidence and not proof, and
it was right not to call it proof, because it was not the whole cause.

Stubbing collectors was never going to be enough. A collector is where a read
is *supposed* to happen, and the leak does not have to use one. Walking the
call graph out of `diagnose()` and stopping at every stub found **eleven
functions still reaching the host**, and three of them ran on every single
call: `dns_ptr` sent a real DNS PTR query twice, `trace_constant_flow` opened a
real socket, and `kernel_source_address` asked the kernel about this machine.
Ten of the twelve tests in the class were reaching the network.

A longer list of names is the fix that went stale the first time, so the
boundary is closed at the boundary instead. `setUp` now seals the process -
`socket`, `subprocess`, and reads under `/proc`, `/sys` and `/etc` - so
anything crossing it fails the way it fails on a box where nothing is
available, which is a state the tool handles and the same state on every
machine. The attempt is recorded and `tearDown` names the door. Five doors were
re-opened one at a time to confirm the seal catches each; all five were caught,
and the class now runs in 0.1s.

Two scenarios came out of it. `source_address_is_held` survived its mutation at
first, which said no test passed `--source`, so the case
`_check_source_address` calls the one that outranks the whole run - a backup
node holding its own address and reporting a healthy box that serves nothing -
had no end-to-end coverage at all. It has two now.

**If a flake appears anywhere else, the mechanism to reach for is the call
graph, not the name prefix.** `dev/` has no script for it; it was a throwaway
AST walk from `diagnose()` treating `cmd_*`, `_read_*` and `which` as stops.

## Open: four things that are waiting on the repo being public

Not decisions - all four are settled and simply cannot be done yet, because
each depends on something that only exists for a public repository. Kept
together so going public is one pass rather than four rediscoveries.

1. **Private vulnerability reporting.** `SECURITY.md` tells a reporter to use
   Security -> Report a vulnerability. That feature is public-only, and the
   API refuses to enable it while private, so the policy currently names a
   route that does not exist yet. It is a toggle in Settings -> Security. No
   address is published on purpose: an inbox in a public file is a decision
   that cannot be taken back.
2. **The badge row**, below.
3. **macOS in the test matrix.** Left out because it costs ten times Linux
   while minutes are metered, and it is the machine the suite already runs on
   daily. Free once public, and then it is one `include:` line.
4. **CodeQL.** Free for public repositories and worth having here rather than
   as decoration: the tool shells out with a target and a port list that come
   from the user, which is the shape its Python queries are for.

### The badge row


Three badges were designed for the top of the README and are not there,
because every one of them 404s against a private repo. Both badge services
read through the public API, so this is not a matter of getting the URLs
right - there is nothing to read.

```markdown
[![tests](https://github.com/zachzama/FaultOne/actions/workflows/tests.yml/badge.svg)](https://github.com/zachzama/FaultOne/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/release/zachzama/FaultOne?color=2E7D32)](https://github.com/zachzama/FaultOne/releases)
[![Licence](https://img.shields.io/github/license/zachzama/FaultOne?color=555)](LICENSE)
```

Check whether it is time, without opening a browser - each of these prints
what the badge would say:

```bash
curl -s https://img.shields.io/github/v/release/zachzama/FaultOne | grep -o 'aria-label="[^"]*"'
curl -s https://img.shields.io/github/license/zachzama/FaultOne  | grep -o 'aria-label="[^"]*"'
curl -s -o /dev/null -w '%{http_code}\n' \
  https://github.com/zachzama/FaultOne/actions/workflows/tests.yml/badge.svg
```

While private they answer `repo not found`, `no releases or repo not found`,
and `404`. When they answer with a version, a licence and `200`, the block
above can go in under the first line of the README.

Deliberately three, and deliberately these three. The repo this idea came from
carries eleven, covering coverage, three OpenSSF checks, a build tool and a
linter - none of which run here. A badge for a service this project does not
use is the same stale number the suite spends 1079 tests preventing, moved to
the first thing anyone reads.

A test-count badge was considered and rejected: it would be a number in a URL,
and the guard that pins every other count in the docs reads prose, not a
shields path. It would be the one count in the repository free to drift.

## Settled: every address asks for itself, and the table is drawn on request

`--source all` asks each global-scope address whether it can reach the target.
Link-local and loopback are left out - neither can reach off the segment, so a
failure from them is only what they are - and one address is the ordinary run.

**The constraint was never the traceroute.** `SOURCE_ADDRESS` is a global read
in nineteen places, and probes cannot run together while each has to assign it
in turn. `_source_flag` and `cmd_ping` take the source as an argument now,
defaulting to the global, so the other seventeen sites are untouched and a test
pins that the run-wide setting is never written. Only the probe repeats:
everything read about the box is a property of the box, and the trace stays out
because tracing twelve identical paths to learn what one already said is how a
run of seconds becomes one of minutes. Twelve addresses cost about what one
does.

**The drawing decision, which went the other way from the last three.** The
plane tag, the fan-out mark and the instances table all stay quiet unless they
change a reading. This one is drawn whenever the run was asked to ask, because
the flag is the gate: somebody typed it, and three agreeing rows are the answer
to what they typed. Silence is the one reply that cannot be told apart from the
flag having done nothing - a different failure from being quietly noisy. Four
shapes were drawn before choosing; the rejected ones are worth knowing about.
Only-on-disagreement makes healthy indistinguishable from ignored, and the
finding already fires there. A column on the instances table conflates one row
per listener with one row per address, and a box can hold an address it serves
nothing on.

Both renderers end in a sentence rather than three rows of "yes", because a
table of agreements is a measurement and not yet a reading.

**Not built, and each its own decision:** ports per source - the original shape
said "reachable, loss, latency and port", and only ping is probed - and the
re-trace from an address that failed.

## Open: the ranking decisions nobody has reviewed

The verdict picks the first match walking `VERDICT_RULES` in order, so where two
findings share a layer the answer is decided purely by which line was written
first. That surface is large and most of it has never been looked at. This
prints its size:

```bash
python3 -c '
import os, sys, collections; sys.argv=["x"]
os.environ.pop("SSH_CONNECTION", None)
import faultone as nd, test_faultone as T
layer = {}
for code, (setup, kw) in T.S.items():
    m = T.fresh(); setup(m)
    try: r = m.diagnose(quick=True, **T.scenario_kwargs(kw))
    except Exception: continue
    for f in r["findings"]:
        if f["code"] == code: layer[code] = f.get("layer")
by = collections.defaultdict(list)
for c, *_ in nd.VERDICT_RULES:
    if c in layer: by[layer[c]].append(c)
print(sum(len(v) * (len(v) - 1) // 2 for v in by.values()), "same-layer pairs")'
```

It answers 823, and a sample of eighty found about 70% of them can occur
together, so roughly 576 reachable decisions. `deep_e2e.py` pins twenty-seven
pairs against a declared winner, of which twenty-three are drawn from the
scenario corpus and four are hand-injected; not all of them are same-layer, so
the covered share of that 576 is smaller still.

**The cheap yield is spent, and that is the useful part of this note.** The
first ten pairs examined found a real inversion: two addressing faults ranked
below the gateway loss they explain. The next twenty found nothing. Three of
those twenty disagreed with the expectation and all three were the expectation
being wrong rather than the tool, and eleven could not be composed at all,
because two scenarios on one box often produce only one finding. Expect roughly
one bug per fifty pairs at several minutes of thought each, and do not treat the
remaining 576 as a backlog to burn down.

## Settled: the fan-out is drawn where it explains a hedge, and nowhere else

`balanced_hops` finds the hops where more than one router answered, three
findings soften themselves on it, and the page drew none of it - so a reader
met the hedge with nothing on the hop list to account for it.

It was a drawing question, as the note that opened this said, and the answer
turned on scope rather than on treatment. **Marking every fanned hop is
truthful and useless**: a backbone that load-balances at half its hops carries
a mark on half the list, and a mark that common stops being read. So the mark
is made where a conclusion actually rested on it - `mark_fanout` is called by
`loop`, `double_nat` and `latency_wall` with the span each already computed
through `balanced_between`, and a fan-out nobody hedged on stays undrawn. That
is a true fact about the trace rather than an explanation of anything.

The treatment is a `.hwhy` sub-line, which is the mechanism already printing
*no reply*, *32% loss* and *enters example-isp.net*. It reads `3 routers
answered here - the path fans out`, and it takes the dim colour rather than
warn or crit: the other sub-lines say what is wrong with a hop, and this one
says what the trace could not tell about it. The other routers' names go in the
row's `title`, where the list's own footnote already lives - they are detail,
and the line is the meaning.

Three alternatives were drawn and rejected. A count appended to the host cell
(`+2`) says nothing a reader can act on. A glyph with a tooltip fails the rule
this file already keeps - *every marked hop says why, in words* - and vanishes
into a ticket paste or a screen reader. Listing the other routers as sub-rows
spends the vertical space the hop list was thinned to protect, ten rows on a
path that balances five times, and still never names the concept.

The whole data change was one key on the viewer's row: `also` was in the report
and the row builder had never carried it.

## Settled: the outbound column on a broker is not where the traffic goes

`analyze_tcp_flows` splits connections into ones that arrived and ones this box
opened. That is a true statement about TCP and the right split for a proxy:
clients one side, backends the other, two networks with two owners.

A box that brokers through tunnels breaks it in a way the split cannot see. The
traffic it exists to carry goes *inside* the tunnels, so it never appears as a
connection at all, and what is left in the outbound column is whatever the box
opens for itself - its control plane. The report labelled that "what this box
connects out to", which reads as where the users' traffic goes. It was the one
place the picture was not merely incomplete but pointed the wrong way.

**The split was not changed, and should not be.** It is right about direction,
and every loss figure and stalled return on that side is a real reading about a
real thing. What changed is the label, on a box recognised as brokering:
datagram tunnels arriving and a handful of outbound sessions rather than a
population. There the column reads "what this box connects out to for itself",
and a context finding says the far side of the forwarded traffic is not on the
report at all.

**What was considered and not built:** splitting the inbound population into
client connectors and app connectors. Both dial in, both land on the same port,
and the socket table records nothing that separates them. Peer address scope is
the obvious proxy and it is a guess dressed as a measurement - it happens to
work on one deployment shape and quietly mislabels another. The honest position
is that the box sees one inbound population and the report says so.

## Settled: which plane the numbers describe, said only where there are two

Every per-connection reading here is TCP: the client table is `ss -tan` and the
statistics are `ss -tin`. On a box whose control plane is TCP and whose user
traffic is datagrams, direction, stalled returns, relay volume, queuing delay,
TIME_WAIT pressure and ephemeral ports all describe the control plane, under
headings that read as how users are being served.

The choice was framed as a word in every heading against a line under the
panel. Both are worse than the third option: **say it only where there is
another plane to confuse it with.** On a box with no datagram listeners "TCP"
on every heading is a word repeated on every report to rule out a possibility
nobody had. `other_plane()` returns nothing on such a box and the page draws
nothing at all.

That is the same rule the fan-out mark follows - drawn only on the hops a
hedge was computed on - and it is worth naming because it keeps coming up. Say
it where it changes the reading.

`planeTag` and `planeNote` are named functions rather than expressions inside
the render, so a test can execute them in node instead of asserting that the
template contains the words. That distinction is not academic here: a badge
wired to a constant passed a contains-the-field test earlier in this file's
history.

## Settled: the datagram queue is a level, and levels need a different instrument

`Recv-Q` on a datagram listener is bytes the kernel took delivery of that the
process has not read - the counterpart to an accept queue, for a plane that has
no accept. Two things about it shaped the design and are worth keeping:

**It is a level, not a counter.** The delta every other sampled reading here
uses is the wrong instrument: a queue that went 8000 to 0 to 8000 has a delta
of nothing and never emptied. What two readings support is narrower - over the
bar at both ends and no lower at the end - and the message says outright that
two samples cannot separate one standing backlog from two bursts.

**A byte count cannot say whether a queue is large.** The first version used a
fixed floor of 4096 and the scenario corpus rejected it inside one run: a
listener sitting flat at exactly that turned the context finding about not
being able to count clients into a warning about a backlog. Four kilobytes is a
serious backlog on a small socket and one datagram on a large one. The bar is a
share of the socket's own receive buffer now, read from `skmem` via `ss -m`,
with a byte floor underneath so a tiny buffer cannot reach a quarter of itself
on one datagram.

Where the buffer cannot be read - `netstat`, or an `ss` that rejects `-m` -
this says nothing rather than falling back to a byte count. There is no honest
fallback: the fallback is the thing that was wrong.

**Still unanswerable, and deliberately unanswered:** how many peers a listener
serves, and whether datagrams were lost in flight. The kernel records neither
for an unconnected socket. Both would need the listener's own counters, and
`clients_may_be_on_the_datagram_plane` already refuses the first - a
neighbouring finding implying an answer would undercut it.

## Open: the resume card quotes numbers that moved again

`zachzama/zachzama.github.io` carries a FaultOne project card with the finding
and test counts on it. As of 2026-08-17 the tool has **188 findings and 1,671
tests**; the card still says 153 and 965. Nothing checks it, and every release
makes it staler - it has now been wrong across eight of them. Either update it
with the release or stop quoting the numbers, and the second is the one that
stops this recurring. `python3 dev/counts.py` prints the current figures.

## Settled: every parser was read, and one mistake accounted for most of them

All ~40 parsers were reviewed on 2026-08-16. Nine defects, all reproduced before
being fixed and all with a test that fails against the code it describes.

**Four of the nine were one mistake**: a value matched by a branch written for a
*different* value. It is worth naming because it is invisible in review - every
one of these reads correctly line by line.

- `ethtool -m` prints a module's limits beside its readings and every limit
  repeats the name of the reading it bounds, so `Laser output power high alarm
  threshold` was read as the transmit power - and being last in the dump, it
  won. The flags collide the same way: `Module temperature high alarm` starts
  with the name of the temperature reading, so the alarm was stored as the
  temperature and dropped.
- nft prints a rule's comment inline, and the verdict was read off the whole
  line, so a rule that accepts under `comment "do not reject this"` was recorded
  as rejecting.
- The local port decides whether a connection is outbound; the remote one was
  tested, so every client of a server counted as a place the box had been.
- `ifconfig` says `inactive` for a link that is down, and `"active" in` that is
  true, so a dead link read as up.

**The sweep that follows from it.** Four shapes were searched for across the
file: prefix-swallowing branch chains, decisive tokens matched inside free text,
first-match where most-specific decides, and reading one end of a pair where the
other decides. Only the instances above turned up - the negation-as-substring
search returned exactly one hit, which was the `ifconfig` one. **A sweep that
finds nothing is still a result**, so: those four seams are clean as of this
date, and re-running them costs minutes.

**The other repeated shape was Windows.** Five readers ran a Windows command
and then handed the output to a reader that could not parse it, so the branch
cost a process and returned nothing - which reads as a quiet box rather than an
unread one. Ping counts and ping timings, the socket table (`LISTENING` is not
`LISTEN`, and there are no queue columns to skip), datagram rows (three fields
where ss gives five), and `arp -a` (hyphens, no `dev`, no `at`). Everything on
that platform failed silently and in the safe direction, which is why none of it
had ever been noticed.

**One fix introduced a second bug, caught by re-running the reproduction rather
than by the suite.** Making `default` readable in `discards_the_target` made the
choice among matching routes load-bearing for the first time, and it returned
the first match where routing is longest-prefix. Re-run the original
reproduction after a fix, not just the tests.

## Settled: three of the last four capability gaps were never gaps

Worth recording because the mistake repeated and the shape of it is
transferable.

Four tools were reviewed against this one on 2026-08-14: Paris and Dublin
traceroute for multipath and NAT, scamper and ZMap/Zgrab2 for active probing.
The review concluded that Paris, Dublin and sting-style directional loss were
**structurally out of reach**, because this tool runs unprivileged.

That premise was wrong. The box this is aimed at is reached through a jump
server and arrives privileged, and more to the point the privilege question was
never checked before being used as an argument. Three of the four
recommendations rested on it.

What the corrected review found, in the order the cost actually falls:

- **`tc -s qdisc` needs no privilege at all.** It was filed under "what root
  buys" and is a read-only netlink dump. Nothing was ever in the way.
- **Paris needs privilege only on the receive side.** A UDP socket with a fixed
  destination port and `IP_TTL` stepped is already a constant flow; only the
  raw ICMP socket that hears the replies is privileged. About 130 lines, not
  the 200+ estimated.
- **Dublin is nearly free once the walk exists.** The quoted header is in the
  ICMP message the walk already parses to match probes.
- **The firewall counters could not name a rule by reading the ruleset**, which
  is what the first review promised. Simulating a vendor ruleset would be wrong
  quietly. Reading the counters either side of the probes and reporting what
  moved is the design that works, and it reuses the sampling window that was
  already there.

**The rule: check whether a limit is real before building an argument on it.**
Twice in one session a conclusion rested on an unchecked premise about what
could not be measured, and both times the answer was in the code or one command
away.

## Settled: adding a collection is five files, and two of them are counts

Every new collector this release tripped the same guards in the same order, so
here is the list. `cmd_socket_owners`, `cmd_qdisc` and `cmd_firewall_counters`
all needed:

1. an entry in the raw registry in `faultone.py` (label, layer, desc),
2. an entry in `RAW_STAGE` saying which stage of the strip it answers,
3. `COLLECTOR_IS_DOCUMENTED_AS` in the suite, whose phrase must appear verbatim
   in the REFERENCE list,
4. the numbered list in REFERENCE.md, renumbered from the insertion point,
5. the count in three places: the REFERENCE table, the REFERENCE heading, and
   the README sentence, plus the pinned number in the suite.

The counts are pinned rather than derived on purpose - "a thing inspected" is a
human grouping, not a function - so the suite tells you every time and the fix
is manual each time.

**One capability read twice is one collection.** The firewall counters were
carried as `firewall_before` and `firewall_after` at first, which made a box
that cannot read rules count as two checks that could not run and marked the
confidence of every verdict down twice for one gap. `equivalence.py` caught it
on two unrelated scenarios. A pair of reads belongs behind one raw key with the
difference already taken.

## Settled: the socket guard watches every way out, on every scenario

The guard that was supposed to protect "this suite reaches nothing" did not
exist. The note here described one that booby-traps `connect`, `connect_ex` and
name resolution; that was a check run by hand from a scratchpad once and never
committed. What the suite actually had was a single datagram check, on one
scenario.

It now watches socket *creation*, `connect`, `connect_ex`, `sendto` and name
resolution, across the whole scenario corpus. Creation is in there because two
of the things that got past never connected: a raw ICMP socket, and a
unix-domain one to a service that may or may not exist on the machine running
the suite. Loopback is allowed and a numeric address is not treated as a
resolution, because neither can depend on the network the suite runs from.

**It found a fifth on its first run, and the interesting part is why that one
looked safe.** `kernel_source_address` opens a UDP socket and connects it to a
documentation address. Its docstring is right that this sends no packet -
`connect` on a datagram socket fixes a destination rather than transmitting -
and that is why it read as harmless. But the answer it returns is *this
machine's routing table*, so the `interfaces_unreadable` scenario produced one
message on a laptop with a default route and a different one on a build box
without. No packet, same defect. It is pinned in `fresh()` to the address the
interface fixture already hands out, so the two agree.

The five hand-stubs are enforced rather than remembered now: delete any one
from `fresh()` and the guard names it. That was the whole complaint here -
hand-stubbing worked and did not generalise, so the next one would have been
found by a test behaving differently on somebody else's machine.

## Settled: the hop list is run by its tests, not read by them

A test asserting that a string appears in `VIEWER_TEMPLATE` passes against code
wired to a constant, because the dead branch still contains the string. That
had happened three times - the privilege badge, the plane tag, the quiet lane -
and the hop list was the largest fragment still tested that way.

`hopWhy` and `hopList` were const arrows declared inside `renderDiagnosis`, so
nothing could call them and three tests reached them by slicing the template on
`const hopWhy`. They are top-level functions now. `hopList` takes the
reverse-DNS map as an argument rather than closing over it, because that map
belongs to the report and not to the fragment.

`run_viewer_fn` in the suite is the shared way to do this: it lifts named
functions and the template's own uppercase constants into node, runs one, and
returns what it built. It skips where node is missing rather than passing,
because a check that could not run is not a check that succeeded. The three
tests that sliced the source now call the function; eleven more cover branches
nothing reached at all - the site edge, the resolved name, the reason a hop is
marked, the counts back and their asymmetric case, the baseline line, and both
escaping paths.

**The mutation that proves the point, and the one to reach for next time this
comes up.** Change `escapeHtml(names[h.host])` to `escapeHtml(h.host)`: the
condition `names[h.host] ?` and the class `hname` both survive untouched, so
every substring test still passes, and the list draws the address where the
name should be. Running the fragment catches it. Nine cruder mutations were
caught too, including the site edge wired to a constant.

The three that were left went the same way in the pass after: `findingTags`
with `layerBadge` under it, `zoneCard`, and the two section headings as
`pathSection` and `whereSection`. Headings are worth naming for a reason of
their own - a heading is a promise that something follows it, and the failure
to guard is a title standing over an empty section, which is exactly the case a
substring search cannot see because the words are in the template either way.

Two mutations from that pass were recorded here as the ones to reach for,
because both were said to leave every substring assertion passing: draw the
hint chip from `f.code` instead of `f.hint`, and drop `&& f.severity !== 'ok'`
from the lowest-layer mark so an ok finding is marked as the lowest broken
layer.

**Both are caught now** - checked on 2026-08-16 by applying each to a copy and
running the suite. `test_a_hint_appears_only_when_the_finding_has_one` and
`test_the_lowest_broken_layer_is_marked_and_an_ok_one_is_not` each name their
case and run the fragment, so the coverage arrived after this note was written
and the note outlived it. They are still the right *shape* of mutation to reach
for; they are no longer examples of anything missing.

One warning from re-running them, which cost a wrong answer the first time. A
scratch copy holding only `faultone.py` and `test_faultone.py` makes about
sixteen documentation tests error for want of a README, and those errors read
as mutation coverage - the first run of this reported nineteen tests catching a
mutation that two tests catch. Copy the docs into the scratch tree, or count
only the failures you can name.

**That last claim used to read "what is left is CSS and lookup tables", and it
is not true.** Counted on 2026-08-16: 54 positive `assertIn`s against
`VIEWER_TEMPLATE`, across 29 test methods that never run node, are on
executable text rather than CSS - JS conditions (`f.hint ?`, `st.because &&`,
`h.site_edge ?`), calls (`verdictRow(data.verdict)`,
`getPropertyValue(FAVICON_VAR[state]`), and markup attributes (`role="button"`,
`aria-expanded="true"`).

The count overstates the exposure and is still the wrong shape: several of
those fragments are executed by a *different* test, so the assertion is a
second, weaker check rather than the only one. What is not covered anywhere is
narrower and worth naming - `setFavicon`, `addPanel` and `renderResult` are
never mentioned by the suite at all, by name or otherwise.

Left as a backlog rather than burned down, because the pattern to convert them
is settled and only the work remains. Reproduce the count with:

```bash
python3 - <<'PY'
import ast, re
lines = open("test_faultone.py", encoding="utf-8").read().splitlines()
tree = ast.parse("\n".join(lines))
n = 0
for cls in [x for x in ast.walk(tree) if isinstance(x, ast.ClassDef)]:
    for fn in [x for x in cls.body if isinstance(x, ast.FunctionDef)]:
        body = "\n".join(lines[fn.lineno - 1: fn.end_lineno])
        if not re.search(r"(nd|m)\.VIEWER_TEMPLATE", body): continue
        if "subprocess.run([node" in body or "_writes(" in body: continue
        n += len([m for m in re.findall(r"assertIn\(\s*(['\"])(.+?)\1", body)
                  if not re.match(r"^[.@#-]", m[1])])
print(n, "substring assertions on template text")
PY
```

A count with no name attached is the thing this file warns about elsewhere, so
treat it as a direction of travel: it should only go down, and the three
unmentioned functions should go first.

**And then that count was measured properly, and it was measuring the wrong
thing.** The three unmentioned functions were covered first - `setFavicon`,
`addPanel` and `renderResult` now run against a DOM stub through
`run_viewer_dom`. Then every conditional in the template was forced, one at a
time, and the suite run against each: **54 sites, 0 survivors.** There is no
branch in that template whose "then" side can be switched off without a test
noticing.

So the 54 substring assertions are not a coverage hole. They are a second and
weaker check sitting beside a real one, which is worth tidying and is not worth
treating as risk. **The count was a proxy, the mutation is the measurement, and
the two disagreed.** Reach for the sweep rather than the count:

```bash
# forces each `cond ?` in VIEWER_TEMPLATE to `false`, one at a time, and runs
# the suite against each. A site nothing complains about is an untested branch.
python3 dev/branch_sweep.py false     # then-sides: 0 survivors on 2026-08-16
python3 dev/branch_sweep.py true      # else-sides
```

Two things that direction does not cover, and one of them found a real bug the
same day. Forcing false only tests the *then* side; the `setFavicon` fallback
that no test noticed was an *else*. And the sweep reads ternaries only - the
thirteen `&&` guards in that template have never been forced either way.

## Settled: a product's interface is readable where it is documented and chosen

`cmd_haproxy_stats` stays. It is the only reading here the kernel cannot
produce: a socket table says what is connected, never which of those a service
has decided to stop using, which check failed, or how many times it has
flapped.

The question was never the code - 132 lines, a scenario, twenty-one tests - it
was whether this tool may know the name of a product. The rule that decides it,
so no future one is argued from scratch:

**Read a product's interface where it is documented, read-only, enabled by the
operator on purpose, and the data has no substitute.**

That admits the stats socket: it is a published interface someone chose to
expose, and nothing else on the box carries what it says. It excludes the
vendor's state directories declined on 2026-08-12, which are undocumented
internals whose layout says more about who runs this box than the name does.
It excludes nginx's `stub_status`, already declined on value - seven numbers,
where the socket table and `ListenOverflows` say more, closer to the source.

The distinction that matters is not "is it a product name" but **what the name
reveals**. A vendor's private directory layout is a statement about the author's
employer. HAProxy is infrastructure half the internet runs; a tool that reads it
says nothing about who wrote the tool. That is why `haproxy` is not on the
withheld list the suite guards, and the guard is what keeps that judgement
honest rather than a habit.

**What was actually missing, and is now fixed.** The code was tested and the
collector was in the inspected list, but the finding had no prose anywhere -
not in REFERENCE, not in the README. A capability a reader cannot find is one
that gets rebuilt. It is written up now, including what it cannot say: it is
conditional on someone having enabled the socket, so its silence means nothing.

## Settled: the baseline diffs findings, not ten scalars

Surfaced independently by two comparisons - SuzieQ's differentialReachability
and then Kentik, PRTG and LogicMonitor all treating change over time as first
class. That repetition was the signal: it is the weakest part of this tool
relative to everything in its space.

`compare_reports` diffed about ten hand-picked scalars and the verdict
sentence. Measured before touching it: a box going from `all_clear` to a
critical loss finding produced **one line** - the headline text is different.
True, and useless, on the one feature whose whole job is saying what changed.

Findings were the right unit because they are already the unit everything else
is expressed in: a stable code, a severity that moves in a known direction, and
a headline written to be read. Nothing new is measured and no finding was added.

Three things it has to get right, all of them found by building it:

- **Only faults.** Context findings arriving and leaving is mostly the box
  being read slightly differently, and a list of those buries the two lines
  that matter.
- **Never itself.** A baseline report carries its own `regression_since_baseline`,
  so diffing it reports last visit's summary of *its* baseline as a fault that
  has since cleared, on every third visit.
- **Not across a change of target.** The pre-existing guard caught this: two
  visits to different destinations did not measure the same thing, and
  `--target auto` moves on its own the first time a box gains a client. Only
  findings that were never about the target survive it.

The verdict line is dropped when a listed fault already carries that sentence,
because the verdict headline *is* a finding's headline and both lines would
read as two changes. It is also dropped when the verdict is itself about the
comparison, which is the section describing itself above the list it describes.

## Settled: two gaps found by checking against somebody else's fault table

Batfish parses configurations, simulates convergence and computes a data plane
without touching the network. Opposite instrument to this one: it answers what
*would* happen for every flow, and cannot see a full queue or an unplugged
cable. What it has that is worth borrowing is a **closed vocabulary** - its flow
dispositions name every way a packet can end, which is exactly the shape a
findings table can be audited against.

Eight of the ten had a finding here. Two did not, and both were observable from
data already collected:

- **`DENIED_IN`** - the firewall reader was wired to one caller, `egress_blocked`,
  and nothing looked at inbound drops. On a box whose job is accepting
  connections that is the more important direction.
- **`NULL_ROUTED`** - blackhole, unreachable and prohibit routes were never
  parsed, and the routing table was read only to find the default gateway.

**The one that was deliberately not built** is `filterLineReachability`: ACL
lines that can never match because a broader line shadows them. Batfish proves
it from the rule structure. The observed version would be "this rule's counter
is zero", which on any real ruleset is true of most rules and would be a noise
generator. A proof and an observation are not the same finding, and the weaker
one is not worth having.

The audit is worth repeating against other tools' vocabularies. It found more in
an afternoon than reading feature lists did, because a closed enum of outcomes
is checkable and a feature list is not.

## Settled: the trace is checked against the route, and only the first hop

Compared against SuzieQ, which computes a path from collected forwarding state
instead of probing for it, and therefore has no load-balancing artefacts to
work around at all. That is not reachable from one box - it needs every
device's tables - but one piece of it is.

The routing table was read to find the default gateway and for nothing else.
Nothing asked whether the path being measured is the path the traffic takes.

**Not by comparing against the default gateway.** That answers the question
wrongly and in the direction that produces false alarms: a more specific route,
a second table, a tunnel holding a prefix are all ordinary and all make the
first hop something other than the default next hop. `ip route get` answers the
exact question for one destination, and `route -n get` does on BSD.

**Only the first hop, and that is not a limitation to fix.** It is the only hop
this box decides. Everything past it belongs to another device's forwarding
table and is not knowable from here, which is the entire reason a trace gets
sent rather than computed.

Context, never a fault. Policy routing and a split tunnel are configurations,
not breaks. What it earns is being said *before* the hop list: everything below
it - loss, the latency wall, the site edge, a NAT - was measured on a route the
traffic does not take, and all of it reads as fact.

## Settled: a box with no firewall is not a box that failed a check

`collection_coverage` excludes checks that cannot apply here, which is why a
cloud instance is not marked down for having no fibre optics. The firewall
reader now follows the same rule: no `nft` and no `iptables` means
`applicable: False`, not a failed read. A tool that is present and refuses is
still a failure, because that is a thing that could have been read and was not.

The distinction is worth keeping in mind for anything added next. It is the
difference between "there is nothing here to look at" and "I could not look".

## Settled: the picture had its own bugs, and the suite could not see them

Four contradictions between the ranked verdict and what the page drew, all
found by reading reports rather than by any test, and all fixed:

1. The clients box read "skipped" while the strip below said the clients stage
   was warning or failing. Twenty-four scenarios, seven of them hiding a
   critical. The box is skipped when nothing is connected, on the grounds that
   green would claim something was checked; the strip never applied that gate.
2. Traffic in was drawn *inside* the block headed "The path out, hop by hop",
   so a box losing packets from its clients showed a red inbound node beneath a
   title about the other direction and above a path that was entirely green.
3. A hop the report had already decided was cosmetic - loss at a router that
   rate-limits its own replies, which clears by the destination - was drawn
   critical under a verdict reading "no fault found".
4. The boundary arrows were single-headed, drawing a box that relays as a
   one-way chain.

**A fifth, found the same way and fixed later.** Only the *page's* arrows were
repaired. The terminal kept a single `->`, always green whatever the leg was
doing, so one report drew a proxy one way in the browser and both ways over
SSH - and the README's own hero image showed a green arrow pointing at a
failing side. It carries `<-->` coloured by the leg now, `-->x` where the
return has stalled, and `<==>` where the way out is confirmed delivered. The
split shape has to survive losing its colour: that line gets pasted into
tickets, and two heads told apart only by an escape sequence become one arrow
the moment it does.

**And the guard that could not have caught any of it.** The rule about what may
split the heads was held by searching `VIEWER_TEMPLATE` for the field the code
was supposed to read. That pins how the code is written, not what it draws -
the same shape of test as the `innerHTML` one below, which held a defect in
place. The arrow is `boundaryArrow()` now: a named function returning a string,
called directly by tests that read what comes back. Eleven cases, and five
mutations including the heads drawn the wrong way round.

**Why 1,000 tests did not catch any of them.** The suite tests the data: which
findings fire, what the verdict names, which stage moves, what survives the
export. Whether a heading matches the thing under it is a question about the
rendered page, and almost nothing asked one. `equivalence.py` had the same
blind spot - it compared findings, verdict and stages across versions but never
the three boxes, so a panel that moves without a stage moving was invisible to
it. It compares them now.

The test that came closest to catching the second one asserted the literal
string `innerHTML = inboundHtml +`, which pinned the defective construction in
place rather than catching it. A test written against how the code is, rather
than what it should do, is worse than no test there.

**What the same audit confirmed is not wrong**, so nobody re-opens it: thirteen
scenarios show a red verdict over a green hop chain, and every one is correct.
A DNS failure, an expired certificate or a path MTU blackhole leaves the path
genuinely fine, and colouring it would be inventing a fault. Three findings
whose stage reads "fail" while their own severity is a warning
(`duplex_mismatch`, `port_host_unreachable`, `tls_handshake_failed`) are the
documented design: the strip records whether a stage passed, the severity
records how bad it is. Left alone deliberately.

## Settled: the return path is measurable after all, for TCP

The tool used to say the return path could not be measured. That was inherited
from the technique rather than decided: a traceroute is one-way, and a
retransmit ratio is a single number that cannot say whether the data or the
acknowledgement went missing.

`ss -ti` was already being run and its whole line already parsed into key and
value pairs. Seven fields were lifted out and the rest dropped, and among the
dropped ones were `lastsnd` and `lastrcv`. Sending twenty milliseconds ago and
having heard nothing for nine seconds is not an inference - it is two counters
disagreeing. `dsack_dups` is kept for the same reason: the far end saying it
already had a segment is proof the data arrived.

Each side of a proxy now carries `silent_return` out of `connections`, plus
`direction_readable` so a silence of zero can be told from a question never
asked.

**Each head of the boundary arrow reads its own counter, and a head with none
keeps the leg's colour.** The first version hardcoded the outbound head to pass
whenever the return stalled, which drew "the way out is fine" on no measurement
at all - the exact thing the return head is careful not to do. Silence carries
the way back; a DSACK carries the way out, and `delivered_anyway` was being
computed for every side and read by nothing until it did. An unmeasured
direction is not a healthy direction.

**Counting connections alone had a hole in it.** A side was called stalled only
once most of it had gone quiet, and a box holding one long-lived session beside
forty short ones is an ordinary shape - on it the session that matters is a
minority of one, so when it died the arrow drew nothing. `side_return_stalled`
now fires on a majority by count *or* by share of the side's traffic
(`DIR_SILENT_SHARE`), and both renderers say which of the two applied, because
"1 of 40" without the share reads as an over-reaction to one bad connection.

The decision is taken once, where the counters are read, and travels in the
report as `return_stalled`. It was about to be written in Python and again in
the page's JavaScript, which is two copies of a threshold and two chances to
disagree about the same report. Reports written before that field exists still
carry the counts, so both renderers keep the older rule as a fallback.

**The trap this is built around.** An idle connection has a large `lastrcv` for
the plainest reason there is: nothing is happening on it. Reading that as a
stalled return would fire on every quiet socket on a healthy box. So the box
has to be sending, recently, and enough to be owed an answer, before its
silence means anything - `DIR_SENDING_MS`, `DIR_SILENT_MS`,
`DIR_SILENCE_RATIO`, `DIR_MIN_BYTES`, all in the threshold table.

**The second trap, found later.** `lastrcv` counts data, and an application
with nothing to say sends none while its kernel goes on acknowledging
everything that arrives. On `lastsnd` and `lastrcv` alone these two are the
same reading:

    a database taking nine seconds over a query    lastsnd:10 lastrcv:9000 lastack:10
    a return path that has stopped carrying        lastsnd:10 lastrcv:9000 lastack:9000

One of them is not a network fault at all, and the first drew a broken return
leg with a note saying nothing was coming back - which sends somebody after a
carrier over a slow query. `lastack` was already being parsed and then read by
nothing. Unlike a reply, an acknowledgement is not the far end's to withhold,
so it separates them: still arriving means the path back is carrying and the
far end is holding the request. A kernel that does not report it now claims
neither direction, because without it the two rows above are genuinely
indistinguishable and naming one would be a coin toss drawn as a measurement.

The acknowledged-but-unanswered case is counted per side as `unanswered` and
said in words, deliberately without touching the arrow: an acknowledgement is
proof that network is carrying, so reddening the return leg would point at a
carrier for something sitting above it.

**It was an arrowhead with no finding underneath it.** For two releases the
counters coloured the boundary arrow and the ranked verdict knew nothing about
them, so a report could draw a broken return leg beside "No fault found - this
device looks healthy from here". Because the corpus is keyed one scenario per
finding code, there was also no scenario, and none of the three harnesses ever
ran the rule - `equivalence` reported "0 differ" on a change that rewrote it.
Every test that existed was a negative guard that the arrow *does not* split.

`tcp_return_stalled_backends` and `tcp_return_stalled_clients` close it. They
rank **below** the two sided loss findings, because a side losing traffic is
the nearer cause of a side gone quiet and the percentage is the more useful
sentence, and **above** the service findings, because a return path carrying
nothing is a network fault and those are not. Both are critical, which moves
their stage to `fail` through the escalation in `build_stages` rather than
through the fail set.

What is still not measurable: traceroute loss cannot be attributed to a
direction, because the trace is one-way by construction, and a direction with
no traffic on it cannot be judged at all. Distinguishing "the acknowledgement
was lost" from "the far end was slow to send it" needs TCP timestamps and is
not attempted.

## Settled: two readings that are recorded and deliberately not graded

Both are easy to "finish" by adding a finding, and both would then fire on
healthy boxes. The reasons are here because a reader who sees a number in a
report and no finding attached to it will assume the finding is missing.

**`app_limited`.** The kernel prints a bare word - no key, no value - saying
the sending was paced by whatever feeds the socket rather than by the network.
On a box that inspects traffic that sounds like the most useful thing there is:
the network is fine and the software is the bottleneck. It is not gradeable.
Its two siblings, `tcp_flow_receiver_limited` and `tcp_flow_sendbuf_limited`,
each fire on a *share of active time*, and that share is precisely what keeps
them quiet on a healthy box. This flag has no such number behind it and is set
on any connection not filling its window, which is most of them. A finding
would have nothing holding it back.

**`relay_volume_lopsided`** is a finding, but severity `ok` and never a fault,
which is the same bargain `no_upstream_sessions` makes. A box that inspects
traffic is supposed to stop some of it, so a policy refusing requests and a box
that has quietly stopped forwarding are the same shape in a socket table.
Nothing available here separates them, so it names both readings and judges
neither. Its ratio is an order of magnitude rather than a percentage:
inspection rewrites what it forwards and TLS termination re-frames it, so the
two sides never match closely and a tight ratio fires on every healthy box.

A test pins the first decision rather than the code, so adding a finding there
means arguing with something that states why there is not one.

## Settled: the suite opens no sockets, and that is a property to keep

Three port-check tests reached a live host to work out which address family
gets dialled. One asserted the IPv4 fallback, which only happens where IPv6 is
broken - so it passed on machines without IPv6 and failed on machines with it,
reading a property of whatever network the suite was run from rather than
anything about the code. It had been green on one machine and red on another
for as long as both existed.

All three are stubbed against documentation addresses now, and two gained the
assertion they were missing. Checked by running the whole suite with `connect`,
`connect_ex` and name resolution booby-trapped: nothing reaches past loopback.

The reason to keep it that way is not tidiness. A test that touches the network
is a test whose result depends on where it ran, and this suite is the thing
that decides whether a release goes out.

**The blind spot this described is closed** - see "the socket guard watches
every way out" above, which supersedes the paragraph that used to sit here. The
trap now covers socket creation, `connect`, `connect_ex`, `sendto` and name
resolution across the whole corpus.

Checked rather than assumed, on 2026-08-16: each of the five vectors was
exercised deliberately against the live guard and each was recorded, and a
loopback connect was not. A guard nobody has tried to get past is a guard whose
green run means nothing, which is the same rule as [[a green test is not a
tested rule]] applied to the harness instead of the code.

## Settled: a green test is not a tested rule

Three tests written on 2026-08-12 passed against code with the rule they were
named for deleted. Each fixture was set up the obvious way, satisfied one
condition, and was refused by a different one - so the test passed for a reason
other than the one in its name, which is invisible from a green run.

`flow_direction` has four conditions and two tests named its idle-connection
guard while the ratio clause was doing the refusing. `side_return_stalled` has
two independent rules and one test per rule, each satisfied by the other. A
group-size guard in `_check_idle_endpoint` survived every mutation and was
right to: a group of one cannot hold both a serving and an idle member, so the
line was dead and came out.

**Copy the two files to a scratch directory, break one clause, run the new test
class there.** A rule with two independent conditions needs a fixture that
holds one out of the way while testing the other. A mutation that survives is
information either way: the test does not isolate what it names, or the code is
dead, and it is worth finding out which.

## Settled: the demo pages are generated, not kept

`dev/demos.py` writes five report pages to the Desktop. They are not committed
and should not be: they are build output, and a stale one is a report claiming
something the tool no longer says.

Every page comes from the test corpus. A report is a map of the network it was
taken on, so a demo made from a live run would publish the addressing of
whoever made it, and the banner is pinned to Linux for the reason the README's
hero image is.

The script asserts each page's verdict names the fault its filename claims, and
exits non-zero otherwise. That is not defensive: the first version shipped a
port-exhaustion page whose headline read "no fault found", because it stubbed
the collector that finding reads its numbers from.

## Settled: three formal ways to separate cause from symptom, and why none are built

Time-order validation, topological distance and counterfactual invalidation are
the standard answers to the question this tool exists to answer. All three were
weighed against what this program actually is.

**Time-order** exists in a coarse form and the finer version is prototyped.
Eight findings end `_live` and six `_historical`, and the twenty codes in
`LATENT` are barred from headlining over something actively failing, which is
what keeps a table near its limit from outranking live retransmits.
`dev/proto_sequence.py` is onset ordering proper and is deliberately not wired
in. Two reasons, and the second is the harder one. A default run is a snapshot,
and `--soak` samples only per-interface throughput, so the cascade the prototype
is written around has a series for one of its three counters: wiring it in means
building a new sampler, not connecting an existing one. And where onset ordering
would help most, separating a latent condition from one that just started, the
prototype refuses to answer on purpose.

**Topological distance** needs a dependency graph, and this tool measures one
box. What stands in for a graph is layer for depth, `_sides_can_agree` for
direction, and `_same_scope` so that two interfaces are two problems. Blast
radius in the sense meant by cluster tooling needs cluster telemetry.

**Counterfactual invalidation** is absent, and the inversion found this cycle is
what it would have caught for nothing. The substitute for a single-box snapshot
is to do the counterfactual once, by hand, and encode it: the paired cases in
`deep_e2e.py` are exactly that. `--baseline` is the one runtime mechanism that
approximates it, being a counterfactual with the answer supplied rather than
computed.

Three public benchmarks for this were evaluated and none can be run against.
They consume time-series telemetry from clusters and answer which service is at
fault; this consumes commands on one box and answers whether the fault is here,
inbound or outbound. An adapter would have to fabricate socket tables out of
metrics, and would then be testing the fabrication.

## Settled: three rules that are enforced rather than remembered

Each of these was learned once, applied at one call site, and rediscovered
somewhere else later. They are now tests that read the source, so a collector or
a counter written next year is held to them without anyone remembering:

- no collector chooses a command on existence alone, without also asking whether
  it answered
- every probe that sends off the box names its source when one was given
- a box with only administrative sessions on it reaches the same findings as a
  box with none

The third is the one most easily undone, because the counters it protects look
like ordinary counters. Being logged in used to invent a fault and suppress a
true one at the same time.

## Settled: what was done to the README's design, and what was not

Four options were drawn up and rendered on a branch before any were applied.
Two shipped: the report as a generated hero image, and two native GitHub
alerts. The badges are above. The fourth was a nav row of anchor links under
the title, declined because the README is one page with eight headings and
GitHub already renders a table of contents from the heading icon on every
file - it would have been a row of links above content that fits on two
screens.

## Settled: the hint table is incomplete on purpose

Each finding card can carry a one-word chip for the thing to go and touch -
`cable`, `DNS`, `ISP`, `switch port` - from a closed vocabulary of seventeen
words. `owner` already answers who owns a finding, but it is prose: 106 distinct
phrases across 137 ranked findings, very nearly one each. The chip is the part
you can read without reading.

**Ninety-nine of the 137 are classified. The other 38 are deliberately blank and
are not a backlog.** They are the ones where no single noun is right -
`latency_wall`, `regression_since_baseline`, `retrans_spurious`, and the
`unclear - the check couldn't run` family, where the honest hint would be a
shrug. A missing chip reads as "not classified"; a wrong one reads as an answer,
and a single word carries more authority than the paragraph under it.

So the rule is: **add one only when the noun is obvious, and never to make the
table look finished.** `test_a_finding_with_no_hint_gets_no_chip` fails if the
table is ever completed, which is the tripwire for exactly that impulse.

Two entries exist to contradict the obvious reading and must not be "corrected":

- `duplex_mismatch` and `collisions` point at the **switch port**, not the
  cable. Climbing error counters look like a cable, and on a full-duplex link
  they are the port disagreeing about duplex, which no cable will fix. This is
  the case the README uses to explain why the ranking is the point.
- `tls_not_yet_valid` points at the **clock**, not the certificate. It is not
  expired; the device's clock is wrong.

A third guard holds the direction: no hint may face the opposite way from the
finding it labels, so `the client path` cannot appear on a fault about the way
out. The vocabulary also gates the way out rather than only the table, so a word
added without being agreed on renders as nothing rather than as a new word.

## Settled: why the path view looks the way it does

Thirteen ideas were tried on the path view. Five shipped. The rest are recorded
here because a commit says what was done, not what was tried and dropped, and
several of these are the first thing anyone would suggest.

Shipped: the ribbon; hop boxes sized by time; the last visit drawn beneath;
a severity word on the marked hop and on the dominant segment; a dashed
connector to a destination nothing answered from.

Rejected, with the reason:

- **Grouping consecutive hops in one carrier into a single node.** The largest
  of the options, and the only one that changes which nodes exist rather than
  how they are drawn, so it needs rules about what must never be folded away,
  and each of those is somewhere a bug can live. Its benefit could not be
  shown: every trace in the corpus is two to four hops, so it saved nine nodes
  across a hundred and fifty-two paths. The case for it rested on a synthetic
  path.
- **Moving the per-hop delay onto the connector.** Correct in principle (the
  delay belongs to the link, not the router at the far end), and it did not
  earn its place beside the two that shipped.
- **Cascading a wrapped row**, in four forms: a margin per box, a relative
  offset per box, explicit rows each indented, and fixed columns. All four
  tried to make a wrapped row read as continuous. The ribbon does not wrap,
  which is why it worked where they did not. `margin-top` in particular grows
  the flex line, so a step between boxes becomes a gulf between rows.
- **A gantt-style waterfall**, each bar starting where the last ended. It is
  the right shape for phases of one request and the wrong one here: it leaves
  gaps, and gaps read as time nothing accounted for.
- **Scaling rows to a fixed millisecond budget.** No path in the corpus reaches
  1000ms (the median is 20ms), so a fixed row never fills and never wraps, and
  the mechanic cannot fire on real data.
- **Chevron-shaped boxes.** Direction becomes part of the shape, which survives
  a wrap. The clip-path cuts off the left border that carries severity, so the
  colour is lost; fixable by moving severity into the fill, not attempted.
- **Marking the site edge on the ribbon, and labelling the dominant segment
  directly.** Both good technique, both declined as more than the picture
  needed.

Two measurements worth keeping, because they decide these arguments:

```bash
# every path in the corpus, and what share one hop takes
python3 - <<'PY'
import sys, statistics; sys.argv=["x"]
import test_faultone as T
tot, shares = [], []
for code, (setup, kw) in sorted(T.S.items()):
    m = T.fresh(); setup(m)
    try: r = m.diagnose(quick=False, **T.scenario_kwargs(kw))
    except Exception: continue
    hops = [h for h in (r.get("hops") or []) if h.get("avg_ms") is not None]
    if len(hops) < 2: continue
    end = max(h["avg_ms"] for h in hops); tot.append(end)
    ds = [h.get("delta_ms") or 0 for h in hops]
    if end: shares.append(100 * max(ds) / end)
print("path total ms: median %.0f max %.0f" % (statistics.median(tot), max(tot)))
print("biggest hop as a share: median %.0f%%" % statistics.median(shares))
PY
```

The second number is why the ribbon is nearly binary in practice: one long
segment and a row of slivers. That is what a traceroute looks like.

And a gap in the corpus that hid a real bug: every scenario names its hops
identically, so nothing exercised long or short PTR names. Real ones run from
one character to forty-two, and box width was being driven by the name rather
than by the time until a path with realistic naming was drawn. If a layout
change touches hop width, test it against names of both extremes.
