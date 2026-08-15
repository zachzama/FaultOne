# Open threads

Not a harness and not documentation. What is unfinished, and what is finished
but easy to undo by accident, written down because the reasoning behind them is
not in the code and would otherwise have to be rediscovered.

Everything here is checkable from the repository. Where a number is quoted,
the command that produces it is next to it.

## Open: a flaky test, diagnosed by mechanism rather than caught

`DiagnoseHarness.test_healthy_device` failed roughly one run in six. It passed
300 times in isolation, which is the signature of something leaking between
tests rather than something wrong in the test.

The harness claimed in its own docstring that every collector was stubbed. It
named seventeen in a tuple; the tool had grown to thirty-eight. Twenty-two ran
for real, including `cmd_tls_check`, which opens a live TLS handshake, from a
suite that promises it sends no packets. Others read the host: socket states,
server limits, orphan counts. `test_healthy_device` asserts the only finding is
`all_clear`, so anything the machine happened to be doing could add one.

The list is derived from the module now and the failure has not recurred: nine
consecutive full runs, where about one and a half failures would have been
expected. That is good evidence and not proof: at a one-in-six rate there is
roughly a nineteen per cent chance of nine clean runs by luck.

**If it comes back, capture which finding joined `all_clear`.** That names the
collector immediately. The failing assertion was never captured the first time,
so the diagnosis above is inference from mechanism and rate, and a second round
of inference would not be worth much.

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

## Open: --source measures one address, not every address

`--source ADDR` binds the probes to one of the addresses a box holds. A box
holding several has one path per address, and there is no way to ask for all of
them in one run.

The shape it wants: iterate the global-scope addresses only, since link-local
and loopback are noise; run the box-reading checks once rather than per address;
report a matrix of source against reachable, loss, latency and port. The
constraint that decides whether it is worth building is the traceroute. Measured
on one machine, a quick run is about 7s and a full one about 64s, and nearly all
of that difference is the trace. Taken per source, twelve addresses is thirteen
minutes. Taken once from the primary, and again only for a source that actually
failed, it is about two. The second shape is also the better diagnosis, because
it traces the path that broke rather than twelve identical ones.

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

## Open: the resume card quotes numbers that moved again

`zachzama/zachzama.github.io` carries a FaultOne project card with the finding
and test counts on it. They are now **165 findings and 1,334 tests** as of
v1.16.0, and nothing checks the card against the tool. Every release makes it
staler. Either update it with the release or stop quoting the numbers.

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

**The booby-trap has a known blind spot, and it has now been walked into
twice.** It watches `connect`, `connect_ex` and name resolution. It does not
watch `sendto`, and it does not watch socket *creation*. `dns_ptr` went through
that hole with a UDP datagram; `trace_constant_flow` would have gone through it
with a raw socket and a `sendto`. Both are stubbed in `fresh()` by hand, which
works and does not generalise.

Anything added that sends without connecting has to be stubbed deliberately,
because nothing will tell you. Widening the trap to cover `socket.socket` for
`SOCK_RAW` and `sendto` would close it properly and has not been done.

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
