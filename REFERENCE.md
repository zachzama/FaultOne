# FaultOne 1.5 reference

Everything the tool checks, and how it decides which of those checks is the
answer. For getting started see the
[README](README.md).

## Why the ranking is the point

Every tool in this category collects more than this one does. What none of them
does is decide, from the same counters, which fault is the cause and which are
its consequences — and that decision is where the wrong answer usually comes
from, because the obvious reading of the evidence is often wrong.

Four cases where a competent engineer, looking at exactly the same numbers,
reaches the wrong conclusion:

| The evidence says | The obvious answer | What the ordering says |
|---|---|---|
| CRC errors climbing on the interface | replace the cable | collisions on a **full-duplex** link mean the switch port disagrees about duplex — no cable will fix that |
| Every destination is losing traffic | your link is bad | the box's own receive backlog is overflowing — it is too busy, not broken, and the signature is identical |
| Retransmissions are high | the path is dropping packets | the far end acknowledged data it already had, so the packets arrived — reordering, not loss |
| The certificate won't validate | renew the certificate | it has not started being valid yet, which is almost always this device's clock |

In each, the tool reports the same underlying findings a checklist would. The
difference is which one it puts at the top, and that is the whole product: 122
findings exist and exactly one reaches you as the answer.

The rule is a single sentence. **A broken layer makes every layer above it look
broken, so the lowest layer with a live fault is the cause and the rest are
symptoms.** The word doing the work there is *live*. Bottom-up ordering has one
well-known failure — taken alone it will chase the lowest layer whether or not
anything there is actually broken — so a finding that describes a risk rather
than a failure (an optic with margin left, a link that flapped yesterday, a
table filling but refusing nothing) is never the headline while something is
actively failing. It is still reported, and it is still the answer when nothing
else is wrong, which is exactly when you want to hear about it. Everything else is bookkeeping: which findings count as
corroboration, which are too weak to be evidence, which are consequences of the
one already named.

It is worth being precise about what this does and does not claim. It applies
one plausible ordering, consistently, every time — it does not know your
network. It still says *likely*. It reports how much of itself managed to run,
names faults it cannot explain, and declines to call something loss when the
sample cannot support it. The value is that the reasoning is the same on every
run and you can read it: `VERDICT_RULES` is an ordered list in the source, not
a model, and every verdict cites the findings it came from.

## A box with no inbound ports at all

A third shape, and the one every check here is quietest about: a connector that
opens no listening ports by design, holds a few long-lived links outward, and
carries traffic over them. Nothing connects *to* it, so every inbound check
stays silent correctly — and that silence used to be the whole report.

**A box with no listeners can still have dependencies.** Backend detection was
gated on serving, which is right for a laptop — the busiest peer there is
whatever application is open — but wrong for a connector, whose handful of
links to an edge is the one thing it needs. The gate is now *serving, or
holding a concentrated handful* (`CONNECTOR_DESTINATIONS`), so a connector's
edge becomes what the run aims at while a laptop browsing thirty sites still
gets nothing.

**A box doing nothing reports nothing wrong, which is why this was invisible.**
No listeners, no connections, every check passing — because a box with no
traffic has no faults in its traffic. It read *"no fault found, this device
looks healthy"*, identically to the same box with its links up.
`no_traffic_at_all` fires when there are no listening ports and no connections
anywhere except the session the tool was run over. That exclusion matters: we
arrived over it, so counting it would mean the check could never fire from the
place it is run.

It distinguishes **"no peers listed" from "the peer list was never produced"**.
Only the first is evidence; a socket table this tool could not read is a gap,
not an idle box, and reading one as the other made it fire on thirty scenarios
at once.

## A box that forwards, rather than one that depends

Some boxes open connections *on behalf of other people*: a forwarding proxy, a
gateway, anything brokering user traffic outward. Two of this tool's
assumptions are wrong on one, and both were wrong in the same direction — they
treat every outbound connection as this box's own business.

**Ephemeral pressure is per destination, not global.** A source port only has
to be unique within the four-tuple, so the same one serves any number of
different destinations at once. `ephemeral_ports_low` counted every outbound
socket against the range, which reports exhaustion on a box holding 26,000
connections spread over 250 destinations — about a hundred per destination, and
nowhere near a limit. It now measures the busiest single destination, names it,
and says how many places the rest are spread across:

| | old reading | correct reading |
|---|---|---|
| 26,000 conns over 250 destinations | 92% — fires | ~104 to the worst — quiet |
| 26,000 conns to one destination | 92% — fires | 92% — fires |

**Its outbound peers are not its dependencies.** `--target auto` picks the
most-connected outbound peer, which on a forwarding box is whichever
destination happens to be popular this minute — diagnosing the path to it says
nothing about the box. A dependency now has to hold `BACKEND_MIN_SHARE` of the
outbound connections as well as clearing the minimum count: a handful of real
backends each hold a large slice, one destination out of hundreds holds almost
none.

When no peer qualifies and there are more than `FORWARDER_DESTINATIONS` of
them, that shape is itself reported (`target_is_forwarded`) and the run falls
back to the default target rather than inventing a dependency. The finding says
what to pass instead — the service this box reports to, or a destination its
users are complaining about.

## Two failures that make every other check pass

**Nothing is reaching this box.** Being taken out of a load balancer's pool is
invisible from the box it happened to: the service is up, the port is open, the
certificate is fine, and no traffic arrives. Every check here passes. It is the
most common way a proxy is "down" and the least visible from inside it.

`no_clients_connected` fires when this box is listening on a port whose purpose
is answering clients and fewer than `SERVING_INBOUND_MIN` connections are open
inbound — naming the peer when there is one, since a single connection from one
address at that volume is a health check rather than traffic.

Gated to `SERVING_PORTS` deliberately. Almost every machine listens on
*something* — sshd, a metrics endpoint, a database bound to the LAN — and
"listening with nobody connected" is only interesting when the thing listening
exists to be connected to. Without that gate it fired on any box running sshd,
which is all of them; it fired on the machine this was written on.

It stays a **warning**: a genuinely quiet period looks the same from here, and
the message says so.

**The answers came from a cache on this box.** `dns_local_cache` reports when a
configured resolver is on loopback — `127.0.0.53` (systemd-resolved),
`127.0.1.1` (dnsmasq or a NetworkManager stub), or any other loopback address.

It is context, never a fault, and it changes what every DNS result below it
means: a stale or poisoned entry in a cache *here* is invisible from anywhere
else, will not reproduce from the next machine somebody tries, and outlives the
upstream being fixed. That is the shape of "it works for me", and it is worth
knowing before a resolver result is read as the network's answer.

## Redundancy: what a neighbour table can and cannot show

A gateway that is a **virtual address** belongs to a redundancy pair, and that
reframes every finding about it — "the gateway is down" on a pair more often
means a failover that did not complete than a router that stopped. The protocol
and group are readable straight off the MAC the neighbour table already gave
us:

| | |
|---|---|
| `00:00:5e:00:01:XX` | VRRP, or CARP — they share this range, which is exactly why a CARP `vhid` and a VRRP `vrid` collide on one segment |
| `00:00:5e:00:02:XX` | VRRP for IPv6 |
| `00:00:0c:07:ac:XX` | HSRPv1 |
| `00:00:0c:9f:fX:XX` | HSRPv2 |
| `00:07:b4:00:XX:YY` | GLBP |

`gateway_is_virtual` reports which, as context. `virtual_router_conflict` fires
when **two different groups** answer for one address — two virtual routers
configured onto the same IP, traffic landing on whichever the switch learned
last, symptoms moving with no pattern.

**What this cannot see, and says so.** A same-group split brain — two masters,
one VRID — is invisible here, because both use the *same* virtual MAC. That is
what VRRP is for. The neighbour table shows one entry and there is nothing to
detect, and a check that implied otherwise would be worse than no check. A
first draft of this had a branch for it that could never execute.

The signal that *is* available is the address **changing hands between
visits**: same IP, different hardware behind it. `--baseline` reports it,
neutrally rather than as a regression — a pair failing over is the pair doing
its job, and only the reader knows whether it should have. One virtual MAC and
one real one stays an ordinary `duplicate_ip`, because one of each is not two
virtual routers and claiming so would outrun the evidence.

## Boxes outside the country the defaults were chosen in

Three assumptions that held on a domestic appliance and do not hold on a fleet.

**IPv6-only is a working configuration, not a fault.** `has_ip_address` looked
for IPv4 and nothing else, so a box on a mobile carrier or in a datacentre that
never handed out IPv4 was reported *critical, exit 2, "this device never got
onto the network"* while holding a global IPv6 address and serving traffic. It
now counts a routable IPv6 address — but not link-local, since every interface
gets an `fe80::` whether or not anything configured it, and accepting that
would make the check unfailable.

The knock-on matters more. Every reachability check here is IPv4-shaped: the
gateway comes from `default via <IPv4>`, the default target is an IPv4 literal.
On an IPv6-only box those aren't failing, they're **unmeasurable** — so they
report `gw_unmeasurable_v4` and `inet_unmeasurable_v4` and conclude nothing,
the same way an absent tool does. The all-clear stops claiming "the gateway and
the internet are reachable" when neither was reached, which is the exact
overclaim that sentence exists to avoid.

This is a contained fix, not IPv6 parity. The tool still diagnoses the IPv4
path; on an IPv6-only box it now says so instead of inventing an outage. Point
`--target` at an IPv6 address or a name with an AAAA record to diagnose the
path that box actually uses.

**Names are not all ASCII.** `--target` accepts an internationalised hostname
and converts it to the punycode form the DNS actually carries, once, at entry —
so every command run and socket opened downstream sees ASCII, and the report
records what was *reached* rather than what was typed. A box in Tokyo or Munich
has backends named in its own script, and rejecting them as "invalid" made the
tool unusable exactly where nobody can paste an alternative.

**The defaults point at hosts some jurisdictions filter.** `8.8.8.8` and the
`google.com` DNS probe are blocked or poisoned in several countries. The
reachability confirmation covers part of this — nothing is called unreachable
on ICMP alone — but on a filtered network the honest move is to point
`--target` at something the box is actually supposed to reach. With
`--target auto` on a box serving traffic that already happens: it aims at a
backend it holds connections to, which is by definition reachable.

## Which way a fault faces

The ordering rule — *the lowest layer with a live fault is the cause* — is
right, and it is right **within a direction**. Direction and layer are
orthogonal axes, and the chain collapsed them into one, built for a device that
only talks outward. On a box that answers requests there are two directions:

| | |
|---|---|
| **local** | This box and its own link. Sits in both paths, so it explains symptoms in either — which is the original rule, unchanged. |
| **downstream** | Toward whoever connects to this box: the load balancer, the edge, the accept path. Broken here and clients cannot get in. |
| **upstream** | Toward whatever this box depends on: backends, DNS, the path out. Broken here and this box cannot answer them. |

The two resource ceilings show why this is not cosmetic. `fd_pressure` and
`ephemeral_ports_low` are both "this box ran out of something", and they break
**opposite directions** — descriptors stop it accepting, ports stop it opening.
Before this they were indistinguishable.

### Reading it without knowing what a layer is

"Which of the three is it" comes before "which layer", and it can be answered
by someone who has never heard of layers. The report leads with three boxes and
an arrow:

```
  clients in (10.20.0.7) FAULT  ->  this box ok  ->  depends on (10.60.9.30) degraded
```

- The state is a **word as well as a colour** — colour alone is not readable to
  everyone, and does not survive a printout or a screenshot pasted into a
  ticket.
- Each zone carries **the sentence that put it there**, not just a lamp. A
  colour says there is a problem; the sentence says what it is.
- The **load balancer is named** when one address carries most of the inbound
  traffic (at least 60%, minimum three connections). That is the difference
  between "something on the way in" and an address someone can go and look at.
  A spread of public addresses is the public, and naming the busiest of them
  would be noise dressed as a finding. This box cannot see past the balancer to
  the real clients and does not pretend to.
- The **upstream zone names what the run aimed at**, which with `--target auto`
  is the backend.
- On a box with nothing connected the inbound zone reads **none connected** and
  greys out — not green, which would claim something had been examined, and not
  an alarm, because the socket table *was* read and there was nothing coming
  in. That is an answer, not a gap.

```
  clients in none connected  ->  this box FAULT  ->  depends on ok
```

The panel is shown on **every** box, including one that only talks outward. It
was hidden there at first, on the grounds that two boxes and an arrow restate a
seven-stage strip that says the same thing more precisely. That reasoning
optimises for a reader who can already read the strip — and boxes that only
talk outward are the common case, so hiding it there meant the panel written
for someone who *cannot* read the strip was the one they would almost never be
shown.

What it changes:

- **A fault facing the other way is surfaced as `also, unrelated`, whatever its
  layer.** Client-side loss and loss on the path to a backend are both layer 3,
  so the layer rule named one and presented the other as its consequence, and
  said nothing about the second. Fixing the first left the second exactly where
  it was — the failure `also, unrelated` exists to prevent.
- **A fault facing the other way is not corroboration.** Two problems is not
  one problem confirmed twice.

`FINDING_SIDE` is exhaustive rather than defaulting, so every code is a
decision someone made and a new one cannot join by accident. On a box with no
inbound service every finding is local or upstream, nothing here can fire, and
the output is **identical** — verified across all 110 scenarios, comparing
findings, headline, owner, confidence, corroboration, unrelated and every stage.

## The verdict

The top of every report names one likely root cause, who owns it, and what to
do next — so you don't read eight findings to work out which one is the cause
and which are consequences:

```
========================================================================
LIKELY ROOT CAUSE: The gateway does not answer at all - the local link is down
  owner: the site network   confidence: medium
  next: Check the switch port, cabling, and whether the gateway itself is up.
  This device is configured but has nothing to talk to.
========================================================================
```

**This is ordering, not intelligence, and deliberately so.** A broken layer
makes every layer above it look broken, so the rule is: the lowest layer with a
*live* fault is the root cause, and each rule names the owner — this device,
the site network, the provider, or the destination. A dead gateway with failing
DNS on top reports the gateway, not DNS.

Confidence is a three-way label, not a percentage. A percentage would imply a
probability calibrated against outcomes — *"of boxes that looked like this, 73%
had this cause"* — and nothing ever tells the tool whether reseating the cable
fixed it, so that number would be a formula's output wearing a decimal point.
What the verdict shows instead is the countable evidence behind the label:

```
owner: this device or its cable   confidence: medium (16 of 18 checks ran)
```

Coverage feeds the label as well as being shown. Below 70% of collections
returning data a verdict cannot be called well-supported, and below 40% it is
low confidence however well corroborated — a conclusion drawn from a third of
the checks is not the same as one drawn from all of them.

The verdict also names a fault it *cannot* explain. The layer rule assumes a
causal chain, which is what makes it useful; where there is no chain — a
flapping link and an expired certificate have nothing to do with each other —
it would otherwise discard the second one, and fixing the first leaves it
exactly where it was:

```
also, unrelated: The certificate on 8.8.8.8:443 expired 40 day(s) ago
```

Confidence counts corroboration only from a *different check* at the same layer
or below. Four closed ports are four results from one check, not four
independent signals - counting them as agreement once let a speculative sweep of
a DNS server read as a high-confidence root cause on a healthy device.

Corroboration is also only counted from the same layer or below:
downstream failures are consequences, not evidence. A duplex mismatch confirmed
by collisions reads `high`; a lone historical error count reads `low`.

A third rule: findings too weak to be a verdict are too weak to be evidence for
one. An error count that stopped climbing, an MTU that's merely unusual, and a
router that declines to answer traceroute all read as `low` confidence when
they're the answer — so none of them can raise someone else's. Without that, an
unrelated non-standard MTU sitting in the report turned a `medium` call into a
`high` one purely by being present.

No model is involved. When you're explaining a conclusion you have to be able
to say *why* the
tool concluded what it did, so every verdict cites the finding codes it was
built from (`based_on` in the JSON), and the rules are a readable list in
`VERDICT_RULES` — you can check its work, and it can't invent a cause that
isn't in the data.

## How the diagnosis works

It's a short rule-based pass, not a model — deliberately, so you can
read and trust exactly why it says what it says. Roughly:

1. Does any interface have an IPv4 address? If not → local
   link/DHCP issue.
2. Is there a default gateway in the routing table? If not → device is
   stuck on its local subnet.
3. Can it ping the gateway? 100% loss → local link/AP/switch problem.
   Partial loss → flaky cabling/Wi-Fi.
4. Can it ping `8.8.8.8`? Gateway OK but this fails → router's uplink or
   an upstream/ISP issue.
5. Does DNS resolve `google.com`? IP connectivity works but this fails →
   DNS server misconfigured or unreachable.
6. Traceroute to the target — if every probe times out for the last
   few hops with no success afterward, the break is likely at or just
   past that hop.

## What "a check" means here, and how many there are

These are the inputs the ranking works from. They matter as evidence for the
verdict rather than as a score: a tool with twice as many checks and no
ordering would hand you twice as much to read and no answer.

Three different numbers get quoted, and conflating them would be misleading, so
they're spelled out:

| | Count | What it is |
|---|---|---|
| **Data collections** | **26** | Distinct things it inspects on the device or the path — the routing table, the error counters, a TLS handshake, and so on. Some run more than once (two pings, one per checked port). |
| **Findings** | **122** | Distinct conclusions it can reach and state in plain language. 105 are faults; 17 are context, like which switch port you're on. |
| **Ranked causes** | **105** | Findings the verdict knows how to rank and assign an owner to. |
| **Automated tests** | **531** | 618 tests of this program's own code. A developer number, not a measure of what it checks for you. |

**The 122 findings are the useful figure** if you want to know what the tool can
tell you. Every one has a scenario in the test suite that triggers it end to
end.

### The 26 things it inspects

**On the device**
1. Interfaces and addresses
2. Routing table and default gateway
3. Interface error, drop, CRC and collision counters
4. Carrier transitions — how often the link has dropped and returned
5. Kernel log — link transitions and NIC resets, with the times attached (Linux)
6. Packets this device drops itself — receive backlog and accept queues (Linux)
7. Connection tracking table — how full it is, and whether it has refused (Linux)
8. Link speed, duplex and MTU
9. Optical module power and alarms (fibre)
10. LLDP/CDP neighbour — which switch and port
11. ARP / neighbour table
12. TCP socket states
13. TCP retransmission counters
14. Per-connection TCP statistics — loss and stalls broken down by destination (Linux)
15. Clock synchronisation and offset, where a time daemon can be asked
16. Listening ports
17. Neighbour inventory (with `--inventory`)

**Off the device**
18. Gateway reachability and loss
19. Target reachability and loss
20. Hop-by-hop path (traceroute, or mtr where installed)
21. TCP-probe path, when the standard one is filtered
22. Path MTU
23. DNS resolution
24. Each configured DNS resolver, individually
25. TCP reachability of specific ports
26. TLS handshake and certificate on ports that should have one

**Derived from the above, not separately collected:** call quality (MOS), the
site edge and network handoffs, latency deltas and jitter per hop, link
utilization, and the comparison against a `--baseline`.

## Every flag

```
--report                 print the findings to this terminal and exit
--inventory              list neighbours already known to this device (passive)
--quiet                  hide the progress line while the checks run
--version                print the version and exit
--quick                  skip the traceroute and path MTU (~2s instead of ~7s)
--soak SECONDS           sample over a window instead of taking a snapshot
--uplink-mbps MBPS       the site's WAN line rate, so utilisation is measured
                         against the link that actually fills rather than the
                         NIC's own speed. Needs --soak
--baseline FILE          compare against a previous report from this site
--target HOST            what to ping/trace (default 8.8.8.8)
--check-ports 53,443     TCP reachability for specific ports (max 32),
                         or 'common' for 22, 53, 80, 443, 8080.
                         Preset results are informational: naming a port asserts
                         you expect it open, a preset asserts nothing
--export FILE            write a report; a .html name gives a single
                         self-contained page, any other name gives JSON.
                         Use - for stdout
--emit-viewer [FILE]     write the standalone viewer (default static/index.html)
```

Exit status follows the monitoring-plugin convention, so it drops into a
scheduled check without anything parsing its output:

| | |
|---|---|
| `0` | nothing wrong |
| `1` | at least one warning |
| `2` | at least one critical finding |
| `3` | the check couldn't run, or couldn't deliver — too old a Python, a bad `--target`, an unreadable `--baseline`, a report that couldn't be written, or a crash |

**This changed in 1.3.** It used to be `1` for a critical and `0` for
everything else, which meant a run reporting a degraded link, a flapping
resolver or 7% path loss exited `0` — so a wrapper saw success while the tool
was saying something was wrong. If you script against it, `!= 0` now means
"something to look at" rather than "catastrophe only".

A failed `--export` prints the report to stdout rather than losing it — the
run has already happened — says what went wrong on stderr, and exits `3`.

While the checks run, a single line on **stderr** shows what's happening and
how long it's taken:

```
  [ 0.4s] probing gateway and 8.8.8.8, tracing the path
```

It overwrites itself, and clears before the report prints. Under `--soak` it
counts the remaining window down each second, so a two-minute sample doesn't
look like a hang. It's on stderr rather than stdout so `--export -` still emits
nothing but JSON, it turns itself off when stderr is redirected — a log full of
half-finished lines helps nobody — and `--quiet` disables it entirely.


## Python versions

**Minimum: Python 3.7** — that's where `subprocess.run`'s `capture_output` and
`text` arguments arrived. Nothing newer is used, and nothing outside the
standard library, so there is no dependency to break when the box is patched.

Two tests keep that honest rather than aspirational: one parses the source at
the stated floor (so newer syntax can't slip in and fail months later on an
appliance instead of here), and one asserts every import is standard library.

If the interpreter is older, the tool prints the version it needs and exits
`2` — before running any command, so you get a sentence instead of a
`TypeError` from the first ping.

**After a Python upgrade on the box**, the check is the tool itself:

```bash
python3 faultone.py --version      # runs, so the floor is satisfied
python3 test_faultone.py           # 618 tests, a few seconds, no dependencies
```

The suite runs on the appliance as happily as anywhere else, which is the point
of having no dependencies — you can validate the tool in the environment that
matters rather than hoping your laptop resembles it.

Every report records the interpreter alongside the tool version:

```
FaultOne 1.0.0 - Linux - python 3.11.2 - 2026-08-06T15:16:44-07:00
```

so a `--baseline` taken before an upgrade reports "python: 3.9.6 -> 3.11.2"
rather than leaving you to wonder why a measurement moved.

## Versioning

`python3 faultone.py --version` prints what's on the box, and every report
carries the version that produced it — in the JSON, at the top of the terminal
output, and in the badge of a self-contained page:

```
FaultOne 1.0.0 - Linux - 2026-08-06T14:58:06-07:00
```

That matters most for `--baseline`: comparing this visit against one taken by a
different version, the comparison says so, because a difference in what the
tool measures isn't a difference in the network.

## The numbers behind the judgements

Every finding here is a threshold someone chose. They're listed so you can
disagree with one - and so that when a provider pushes back on a report, you
can say what the bar was rather than "the tool said so".

| Constant | Value | What it decides |
|---|---|---|
| `ERR_PPM_WARN` | **100** | interface errors, per million packets, before they're worth reporting |
| `COLL_PPM_WARN` | **10** | collisions, per million packets — lower, because full duplex shouldn't have any |
| `LINK_FLAP_PER_DAY` | **2** | carrier transitions per day of uptime before a link counts as flapping |
| `KLOG_RECENT_SECONDS` | **3600** | how far back a kernel-log event still counts as happening now |
| `KLOG_FLAPS_RECENT` | **4** | carrier transitions logged within that hour before the link is called unstable. Two is one clean down/up |
| `SOFTNET_DROP_PPM` | **10** | receive-backlog drops per million packets processed |
| `CONNTRACK_WARN_PCT` | **80** | how full the connection tracking table gets before it's mentioned |
| `CONNTRACK_REFUSAL_PER_DAY` | **10** | conntrack refusals per day of uptime for a historical count |
| `ACCEPT_OVERFLOW_PER_DAY` | **10** | accept-queue overflows per day of uptime for a historical count |
| `QUEUE_RTT_MULTIPLE` | **2.0** | how far a connection's smoothed round trip must sit above its own lowest-ever before the excess counts as queue rather than distance |
| `QUEUE_DELAY_MS` | **30.0** | and how many milliseconds of excess. Both are needed: the multiple alone fires on a LAN where 0.2ms becomes 2.2ms, the absolute alone fires on a satellite hop whose 45ms of variance is weather |
| `FLOW_LOSSY_PCT` | **2.0** | retransmit ratio at which one connection is called lossy |
| `SYN_RETRANS_PCT` | **5** | share of connection attempts needing their SYN resent before setup is called the problem |
| `ATTEMPT_FAIL_PCT` | **10** | share of connection attempts that never establish at all |
| `CSUM_ERR_PPM` | **1** | segments per million arriving with a bad TCP checksum — should be zero |
| `SPURIOUS_RETRANS_PCT` | **30** | share of retransmissions the far end says were unnecessary before reordering, not loss, is the story |
| `MIN_PACKETS_FOR_RATE` | **20000** | packets an interface must have carried before an error or collision *rate* is quoted about it. One error on a nearly idle NIC divides out to twenty times the threshold - the same reasoning `MIN_PROBES_FOR_LOSS` applies to ping, which had never been applied here |
| `MIN_PROBES_FOR_LOSS` | **10** | probes needed before a single unanswered one is allowed to be called a loss rate |
| `LATENCY_WALL_MS` | **100** | milliseconds a single hop must add before it is worth naming as a wall. The first hop counts its own latency: the path starts there, so everything before it is zero, and a satellite or VPN first hop carrying the whole delay is a wall like any other |
| `LATENCY_WALL_SHARE` | **0.5** | and the share of the end-to-end delay it must be. The finding says a single hop adds *most* of the round trip, so "most" is what it measures - without this a uniformly graded path fired it and named a hop no worse than its neighbours |
| `BURST_UTIL_PCT` | **25** | utilisation below which a queue overflowing has to be explained by bursts rather than volume |
| `UPLINK_FULL_PCT` | **70** | share of the `--uplink-mbps` rate this device has to be using before the site's own line is called full. Lower than the NIC threshold: CPE queues are small and the line is shared, so loss starts well before the last few percent |
| `SERIES_MAX_SAMPLES` | **900** | most samples a rate series holds. At or below this the interval is one second; a longer soak stretches the interval rather than storing more |
| `EPHEMERAL_PRESSURE_PCT` | **80** | share of `ip_local_port_range` in use before outbound connections are at risk |
| `FD_PRESSURE_PCT` | **80** | share of the system-wide file descriptor ceiling in use before a serving box is in danger of not accepting |
| `ABORT_TIMEOUT_PCT` | **2.0** | share of connections handled that ended with the peer having stopped answering before it stops looking like people leaving and starts looking like a path |
| `SYN_RECV_HIGH` | **256** | half-open connections before the backlog is worth reporting. A busy server always has some |
| `OWN_TLS_MAX_PORTS` | **3** | TLS listeners of our own tested per run. Each costs a handshake against a service that is probably logging connections |
| `BACKEND_MIN_CONNECTIONS` | **2** | connections to one peer before `--target auto` treats it as a dependency rather than a passing conversation |
| `BACKEND_MIN_SHARE` | **0.15** | and the share of outbound connections it must hold. A count alone cannot tell a dependency from a busy destination |
| `FORWARDER_DESTINATIONS` | **50** | distinct outbound destinations above which a box is forwarding traffic rather than consuming a few services |
| `CONNECTOR_DESTINATIONS` | **6** | at or below this, a box with no listening ports is holding a deliberate handful of connections rather than browsing |
| `SERVING_INBOUND_MIN` | **3** | live inbound connections before a box counts as serving traffic. One is a health check or your own SSH session; a handful is clients |
| `UPLINK_UNKNOWN_FLOOR_MBPS` | **5** | traffic below which an upstream verdict needs no "rule out your own line first" caveat - too little to fill any line a site would be sold |
| `COVERAGE_GOOD_PCT` | **70** | share of checks that must return data before a verdict can be called well-supported |
| `COVERAGE_THIN_PCT` | **40** | below this, any verdict is low confidence however well corroborated |
| `FLOW_LIMITED_PCT` | **20.0** | share of a connection's active time blocked before the blocker is named |
| `SYN_SENT_WARN` | **3** | half-open outbound connections before it's a backlog |
| `CLOSE_WAIT_WARN` | **20** | sockets the application never closed before it's a backlog |
| `DNS_SLOW_MS` | **500** | a resolver's answer time before it's called slow |
| `MOS_WARN` | **4.0** | call quality below this is degraded |
| `MOS_BAD` | **3.6** | call quality below this is unusable |
| `CERT_EXPIRY_WARN_DAYS` | **21** | days left on a certificate before it's flagged |
| `CLOCK_SKEW_WARN_MS` | **5,000** | clock offset past which logs from this box stop lining up with anything else |
| `CLOCK_SKEW_BAD_MS` | **300,000** | …and past which Kerberos stops authenticating |
| `TLS_HANDSHAKE_RATIO` | **4** | handshake time as a multiple of the connect before the server is blamed |
| `TLS_HANDSHAKE_FLOOR_MS` | **250** | …and the floor below which that ratio is noise on a fast link |
| `OPTIC_RX_WARN_DBM` | **None** | optical receive power below which a fibre link has little margin left |
| `OPTIC_RX_CRIT_DBM` | **None** | …and below which the receiver can no longer work reliably |
| `STANDARD_MTU` | **1500** | the MTU an interface is expected to have; anything else is called out |

And the limits that bound a run rather than judging anything:

| Constant | Value | What it bounds |
|---|---|---|
| `FLOW_MIN_BYTES` | **50,000** | bytes a connection must have moved before a loss ratio means anything |
| `FLOW_MIN_SEGS` | **40** | the same bar on kernels too old for byte counters |
| `LINK_FLAP_BASELINE` | **2** | transitions a healthy link accumulates just by coming up at boot |
| `MIN_COUNTER_WINDOW` | **2** | seconds the counter window runs for, even on a fast run |
| `MAX_SOAK_SECONDS` | **3600** | longest --soak accepted |
| `MAX_CHECK_PORTS` | **32** | most ports --check-ports will try |
| `PORT_CHECK_WORKERS` | **8** | concurrent port connects — bounded so it doesn't resemble a scan |
| `BANNER_TIMEOUT` | **0.5** | seconds spent waiting for a service to announce itself |
| `FLOW_MAX` | **20000** | connections read from ss before the sample is declared partial |
| `FLOW_READ_BYTES` | **12000000** | how much socket-table output is read before analysing it. None of it is stored - the table is replaced by a digest before the report is written |
| `FLOW_PEERS_SHOWN` | **10** | peer addresses a report will name |
| `MAX_OUTPUT_BYTES` | **64,000** | bytes of any one command's output the report will carry |
| `PTR_WORKERS` | **8** | concurrent reverse lookups during --inventory |
| `PTR_DEADLINE_SECONDS` | **2.0** | seconds --inventory spends on reverse lookups in total |

They're plain module constants at the top of `faultone.py`, so changing one is
an edit, not a configuration format. There is deliberately no config file: a
tool you pipe over SSH shouldn't need a second file to behave predictably.

## The stage strip

Under the verdict, the whole chain at a glance — the way a handheld tester
shows it:

```
  link PASS   address PASS   gateway PASS   internet PASS   dns FAIL   mtu -   ports -
```

A stage that wasn't measured reads `-`, never `PASS`. Claiming a check passed
when it never ran is the one thing a summary like this must not do.

## What layer each check is testing

Every check and every finding carries an OSI layer tag, shown as a badge
in the UI and as a `layer` field in the exported JSON:

| Layer | Checks | What a failure here means |
|---|---|---|
| **L1 · Physical** | interface has an IPv4 address, error counters, link speed/duplex | cable unseated, Wi-Fi not associated, port down, DHCP never completed, corrupted frames on the wire |
| **L2 · Data link** | ARP/neighbour table, gateway ping, interface MTU, LLDP switch port | local segment problem — switch/AP port, bad cabling, interference |
| **L3 · Network** | routing table, default gateway, internet ping, traceroute, path MTU | addressing or routing — no gateway, upstream/ISP break |
| **L4 · Transport** | listening ports, TCP port checks | firewall rule or the service isn't listening |
| **L7 · Application** | DNS lookup | name resolution — wrong or unreachable DNS server |

A check is tagged with the **lowest layer it can implicate**, not the
layer of the protocol it speaks. Pinging your gateway is an L3 (ICMP)
operation, but 100% loss to your own gateway is really evidence about
the local link, so that finding is tagged L2.

The point is ordering: a broken layer makes every layer above it look
broken too, so the lowest failing layer is the one worth fixing first.
The report exposes that directly as `lowest_broken_layer`, the UI
highlights that badge and prints a "start here" note under the findings,
and `--export` prints the same line to your terminal:

```
Lowest layer showing a problem: L2 - Data link (switch/AP, ARP, MAC,
local segment) - start there, higher layers may just be downstream symptoms.
```

Every finding is shown with severity (`ok` / `warning` / `critical`),
and the raw command output that produced it is right below, so you can
verify the reasoning yourself. The path diagram renders each traceroute
hop as a node (green = healthy, amber = partial reply loss, red =
timeout) between "this device" and the target.

## What the path diagram tells you

Each hop carries a bit of insight beyond "hop 3 answered in 24ms", all derived
from the trace already taken — no extra packets:

- **lan / wan** — whether the hop is inside this site (RFC1918, CGNAT,
  link-local) or out on the provider's network. The first public hop is marked
  **site edge**, and that boundary is the demarcation between the site's
  network and their ISP — usually the first thing you want to establish.
- **+Nms** — latency this hop *added* over the previous one. An accumulating
  total tells you little; the jump tells you where the delay is introduced.
  The largest jump is called out, along with which side of the edge it's on.
- **jitter** — spread between the three probes to that hop (shown at 5ms and
  above). A wide spread means congestion or an unstable link even when the
  average looks healthy.
- **gateway / target** — which hop is this device's default gateway, and
  whether the path actually reached what you aimed at.

- **network handoffs** — where the PTR domain changes, so you can see the path
  pass from one operator into the next (`example-isp.net → dns.google`). The
  summary lists every network crossed.
- **cgnat** — a hop in `100.64.0.0/10` means the provider is NAT-ing this site.
  There's no public address on the connection, so nothing reaches it from
  outside regardless of local configuration — worth knowing before chasing an
  inbound-access problem on the device.

Three structural faults are detected from the same data:

- **Double NAT** — two different private subnets before the site edge means at
  least two routers in series. It usually still works, but it breaks inbound
  connections and port forwarding, and makes intermittent faults hard to place.
- **Routing loop** — the same address answering at two hop numbers. Traffic is
  circling and will die when the TTL runs out; that's an upstream routing
  misconfiguration, not a fault on the device.
- **Latency wall** — a single-hop jump over 100ms, attributed to the correct
  side of the demarcation (site, carrier-NAT layer, or provider network).
  Everything past it inherits the delay, so the later hops looking slow is a
  symptom rather than a separate problem.

```
    1 lan 192.168.1.1        1.5 ms   gateway
       ----- site edge: past here is the provider's network -----
    2 wan 198.51.100.13      15.3 ms   +13.8ms, jitter 5.0ms
  -> biggest latency jump: +13.8ms at hop 2, on the provider's side
```

## When the trace stops but the target answers

Plenty of networks drop the probes classic traceroute uses while forwarding
ordinary traffic perfectly. The path looks broken and isn't.

If the trace stops short while the target still answers ping, FaultOne retries
with TCP SYN probes to port 443 (`tcptraceroute`, `traceroute -T`, or
`mtr --tcp`, whichever exists). If that reaches the target, the report says so:

> The standard trace stopped at hop 4, but a TCP probe to port 443 reached
> 8.8.8.8 — so the path is fine and something along it simply doesn't answer
> traceroute probes.

That's the difference between escalating a broken path and knowing the probes
were being filtered. TCP probes need raw sockets, so this is skipped when
running unprivileged — like every other optional step here.

## Interface error counters

Every other check here measures *reachability* — it tells you something is
broken, not whose fault it is. The error counters the NIC keeps are different:
they're evidence that the damage is happening on this device's own link.

- **CRC / frame errors** — bits arriving corrupted: bad cable, dying SFP,
  dirty fiber, or a duplex mismatch. Physical, and on this device's link.
- **Carrier losses** — the link is flapping up and down.
- **Collisions** — on a full-duplex port (nearly all modern ones) these
  shouldn't happen at all; a steady rate is the classic duplex-mismatch
  fingerprint, so they get a lower threshold than generic errors.
- **Drops / overruns** — frames arrived but the box couldn't keep up. That's
  device-side: CPU, ring buffer, or driver — *not* the network.

Counters are cumulative since boot, so a bare number means little — 47 errors
over 200 days of uptime is noise. Three things are reported instead:

1. the raw count per interface,
2. the **rate** (errors per million packets), which separates background
   noise from a real problem, and
3. whether the counters are **climbing right now** — outside `--quick` the
   counters are sampled twice, 2s apart. "1,200 errors, +14 in the last 2s"
   is a live fault; "1,200 errors, steady" is history.

Only interfaces that have actually passed traffic are considered, so the pile
of idle virtual interfaces on a typical box stays out of the way. When
everything is clean, the all-clear says so explicitly — "the physical link
into this device is clean" is exactly the sentence you need when the question
is whether the box is at fault.

Read on Linux from `/sys/class/net/*/statistics` (no output parsing at all)
and on macOS/BSD from `netstat -i -b -n`.

## Speed, duplex, and MTU

**Speed and duplex** are what this interface and the upstream switch port
negotiated with each other, so a problem there is unambiguously about that
cable and those two ports:

- **Half duplex** on a switched link is almost always a failed negotiation or
  a hard-coded mismatch — one side forced, the other auto-negotiating.
  Throughput collapses under load while pings stay perfect, which is why it
  gets misdiagnosed as "the network is slow". Reported critical when
  collisions are also present, since that confirms it.
- **A link at 100 Mbps** on gigabit-capable hardware usually means a damaged
  cable: gigabit needs all four pairs, 100 Mbps needs two, so one broken pair
  silently drops you a tier instead of failing outright.

Collisions are read in light of the negotiated duplex — on a half-duplex link
they're expected, so only the duplex finding is reported rather than both.

**Interface MTU** below 1500 usually means a tunnel (VPN/PPPoE) or a manual
override; above 1500 (jumbo) only works if every device in the path agrees.

**Path MTU** is the more valuable half, and it's the one thing here that
catches a failure invisible to everything else. The interface can say 1500
while something along the path silently drops full-size packets — so pings
and SSH work fine while large transfers, file copies, TLS handshakes and VPN
traffic stall. FaultOne sends do-not-fragment pings at descending sizes
(interface MTU, then 1492/1400/1280/1000 — the common tunnel sizes) and
reports the largest that gets through:

```
PATH MTU TO 8.8.8.8
   1500 bytes   blocked
   1492 bytes   blocked
   1400 bytes   passes
  -> largest that gets through: 1400  (interface is set to 1500)
```

That gap is a PMTU blackhole and is reported critical. Skipped under
`--quick`, since it costs a few extra pings.

## Fibre links: optical power

Where the interface is fibre and `ethtool` can read the module, receive and
transmit power are reported along with the module's own alarm thresholds:

```
OPTICAL MODULES
  eth0        rx  -36.90 dBm  tx   -2.33 dBm   FINISAR CORP. FTLX8571D3BCL
```

A degrading fibre link — dirty connector, tight bend, dying laser — stays
**up** and passes every reachability check while quietly corrupting frames. The
error counters see the damage; only this says why. Below about -25 dBm most
receivers can't work reliably (reported critical); below -20 dBm the link works
with little margin (warning). Where the module raises its own alarm flags those
win, since the vendor's thresholds beat any generic number.

## Which switch port am I on? (LLDP/CDP)

Switches advertise their identity and the port you're plugged into. When
`lldpd` is installed, FaultOne reads those advertisements and reports:

```
SWITCH PORT (LLDP/CDP)
  eth0 -> SW-CLOSET-2 port Gi1/0/12 vlan 30 (10.0.0.2)
```

Every L1/L2 finding here used to end with "check the switch port" and leave you
to find it. Now the verdict names it:

```
next: Reseat or replace the cable and try a different switch port; if the errors
follow the device, it's the NIC or its transceiver. This device is connected to
SW-CLOSET-2 port Gi1/0/12.
```

Entirely passive — nothing is sent and nothing is captured; `lldpd` has already
collected the frames. Needs `lldpd` present and LLDP or CDP enabled on the
switch; skipped silently otherwise, like every optional tool here.

## DNS, resolver by resolver

"Does google.com resolve" hides the DNS failures that actually bite. Each
configured resolver is queried individually:

```
DNS RESOLVERS (probe: google.com)
  192.168.1.1           NOERROR       5.8 ms
  192.168.1.2           no reply     2000 ms
```

- **One of two resolvers dead** — the nastiest DNS fault, because lookups work
  or hang depending on which one the stub picks. It reads as "the network is
  intermittently slow", and a single lookup usually passes.
- **A slow resolver** — every new connection waits on it, so the whole site
  feels broken while every connectivity check succeeds.
- **NXDOMAIN hijacking** — a name in the reserved `.invalid` domain is queried;
  it cannot exist, so an answer means a captive portal or ISP redirect service
  is inventing replies.
- **Disagreement** between resolvers — a stale cache, or a middlebox answering
  selectively.

Queries are built and parsed here in ~60 lines of standard library rather than
shelled out to `dig`, which minimal appliances often don't ship — and which
would make the timings include process startup.

## Call quality (MOS)

Latency, jitter and loss are three numbers most people can't act on. MOS is the
one they're actually complaining about:

```
CALL QUALITY (estimated, to 8.8.8.8)
  MOS 4.39 (excellent)   latency 24ms · jitter 2ms · loss 0%
```

Scored from the measurements already taken — no extra packets — using the
E-model arithmetic PingPlotter uses: effective latency is `avg + jitter×2 + 10`,
because variation hurts a call more than steady delay does, then loss costs
~2.5 R-points per percent. The scale is 4.3+ excellent, 4.0–4.3 good, 3.6–4.0
fair, below 3.6 most people call the line unusable. 4.4 is the ceiling for
G.711, so a perfect LAN scores 4.4, not 5.

With `mtr` installed, each hop gets its own MOS, so you can see *where* call
quality starts to fall apart rather than only that it did.

## Link utilization

Under `--soak`, byte counters are sampled across the window and compared to the
negotiated link speed:

```
en0    122,124,366    0    0    0.0   steady over 60s   94.1/3.2 Mbps rx/tx (94% of link)
```

A full link behaves exactly like a broken one from the application's side —
latency climbs, transfers stall — but nothing is faulty. Above 80% this is
reported, and the verdict names it "capacity, not a fault" so nobody replaces
hardware that's working.

### The denominator is usually the wrong one: `--uplink-mbps`

That 94% is against the **NIC's** negotiated speed, which is the only rate this
box can read. On the appliances this tool is built for it is also the wrong
one. A branch box has a gigabit port in front of a 50 Mbps line, so a site
filling that line completely shows as 5% busy — and every symptom it produces
(loss to every destination, latency climbing under load, calls breaking up)
gets read as the carrier dropping traffic. That verdict came out at high
confidence, and it sends someone to open a ticket against a circuit that is
working exactly as sold.

Measuring the line from here would mean generating load on a customer's
connection, which this tool won't do. So it takes the number as an input
instead — it's on the ticket:

```bash
python3 faultone.py --report --soak 60 --uplink-mbps 50
```

With that, utilisation is computed against the line as well as the NIC, and at
`UPLINK_FULL_PCT` (70%) or above one of two findings comes out — and which one
depends on whether anything was actually failing at the time:

| | |
|---|---|
| `uplink_saturated` | Full, **and** something broke while it was: dropped packets, or probes that went unanswered. Ranked above every loss, latency and retransmit verdict it explains, and owned by "the site's own capacity, not the carrier". |
| `uplink_busy` | Full, nothing failing. A backup, a sync, a large transfer — a line being used, which is not a line that is broken. Reported, and `LATENT`, so it can't headline over a live fault but is still the answer when nothing else is wrong. |

`link_saturated` and `link_busy` split the same way against the NIC's speed.

That split came out of building the burst work: the candidate-rule test put a
nightly backup at 96% of the line with nobody complaining, and the single
`uplink_saturated` finding took the headline as root cause over everything
else in the report.

Without the flag, the tool doesn't pretend. When the verdict blames the path or
the provider on evidence a full line produces just as well, and this device was
itself moving more than `UPLINK_UNKNOWN_FLOOR_MBPS` (5 Mbps) during the window,
it says so and drops to medium confidence:

```
  owner: the provider   confidence: medium (16 of 18 checks ran)
  next: Loss starts upstream of this site. Escalate with the hop where it
  begins. First, rule out the site's own line: this device was moving 48.0
  Mbps during the check, and a full uplink produces exactly this pattern.
  Re-run with --uplink-mbps <the site's rate> to settle it before escalating.
```

The findings this applies to are in `CONGESTION_MASQUERADE`: a dead gateway
isn't what a full uplink looks like, so it gets no caveat.

## ICMP is one protocol, and the one most often blocked

Ping is how almost every tool in this category decides whether something is
reachable, and on a server it is the least reliable signal available. Blocking
outbound ICMP is ordinary hardening; blocking it entirely is routine inside a
cloud VPC. Before this was handled, a box serving traffic all day reported:

```
LIKELY ROOT CAUSE: The gateway answers but nothing beyond it does - the
site's uplink is down
  owner: the provider   confidence: medium
```

Critical, exit 2, on every scheduled run. So nothing is called unreachable on
ICMP alone any more:

| | how reachability is confirmed instead |
|---|---|
| the target | A TCP connect to 443, 80 then 53 — the host the operator named, not a scan. **A refusal proves it as well as an accept does:** an RST is a completed round trip, so the packets got there and the reply got back. Only a timeout is inconclusive. Reports `inet_icmp_filtered`. |
| the gateway | Its entry in the neighbour table. ARP does not cross a dead cable or a down switch port, so an entry with a hardware address means the link is up whatever ICMP says. An entry with no MAC, or in `FAILED`/`INCOMPLETE`, is the kernel asking rather than the gateway replying, and does not count. Reports `gw_icmp_filtered`. |

Both findings read as `ok` — they exist to stop something else being misread,
and neither is ever a fault. When ICMP *and* the confirming probe both get
nothing, `gw_unreachable` and `inet_unreachable` still fire exactly as before,
still critical, still exit 2. The point was never to stop reporting outages.

## Running this on a server rather than a branch box

Most of this tool assumes a device that *initiates* traffic — the question is
whether it can get out. A box serving inbound traffic inverts that, and two
things follow from it.

**Clients connected right now are proof the network works.** `ss` output is
split into what arrived and what left: a listener on a non-loopback address is
a service, and an established connection whose local port matches one is a
client. `SERVING_INBOUND_MIN` (3) is the bar, because one inbound connection is
your own SSH session or a load-balancer health check.

So when nothing outbound reaches the target — no ICMP, no TCP — but clients are
connected inbound, that is `egress_blocked` (warning, owner *"this box's egress
policy, probably by design"*) rather than `inet_unreachable` (critical, owner
*the provider*). A server with no outbound internet is usually a server that
was built that way. On a box with no clients connected, the critical still
fires exactly as before.

**A check that cannot apply here is not a check that failed.** A cloud instance
has no fibre optics, no switch neighbour, no `ethtool` and no carrier
transitions to count. Those were counted as failed collections, so coverage
read low and *every* verdict on that box was marked down in confidence for
running on the hardware it runs on. Platform-gated collectors now return
`applicable: False` and drop out of the denominator entirely — the figure is
meant to say how much of what *could* have run did. On a Mac this moved a
routine run from `11 of 15 checks ran` to `11 of 12`.

What is still branch-shaped and simply won't fire on a server: LLDP, optics,
duplex and speed negotiation, carrier flaps, CGNAT detection, `--inventory`.
None of it does harm; it now costs nothing in confidence either.

### The ceilings that look like network faults

Five findings for limits that live on this box and are invisible to every
other check here — which is the point, because from a client's side and from
the wire they are indistinguishable from the path being broken:

| | reads | what it means |
|---|---|---|
| `syncookies_live` | `TcpExt SyncookiesSent` | The kernel saying, in words, that a listen queue overflowed. Connections arrived faster than the service accepted them. The clearest single statement available that a backlog is too small or something is flooding it. |
| `syncookies_historical` | same, since boot | It has overflowed before but not during this run. `LATENT`, so it can't headline over a live fault. |
| `ephemeral_ports_low` | `ip_local_port_range` vs outbound sockets | A proxy talking to backends runs out of source ports long before anything else breaks, and the failure looks exactly like the far end refusing the connection. `TIME_WAIT` is named in the finding because it is usually what is holding them. |
| `fd_pressure` | `/proc/sys/fs/file-nr` | At the ceiling the service stops accepting. Nothing on the wire is wrong. |
| `syn_recv_backlog` | `SYN_RECV` count vs `somaxconn` | Half-open connections piling up — either the accept queue isn't draining or something opens connections and abandons them. The syncookie counter is what tells those apart, which is why both are reported. |

All five are ranked above the path and loss verdicts, because each one makes
this box refuse or fail to open connections, and bottom-up ordering would
otherwise hand the answer to whatever symptom that produced further out.

### What the run aims at: `--target auto`

`8.8.8.8` answers "can this box reach the internet". That is the whole question
on a branch appliance and close to irrelevant on a box whose job is answering
requests — what matters there is whether it can reach the things it *depends
on*. Those are visible in `ss`: the connections it opened itself.

`--target` now defaults to `auto`. On a box that accepts connections it picks
the peer with the most outbound connections; on anything else it falls back to
`8.8.8.8`. Rules that keep it honest:

- **Listening is not serving.** Almost every machine has something bound to a
  port, so "has a listener and talks to things" describes a laptop as well as a
  proxy. The bar is clients actually connected (`SERVING_INBOUND_MIN`), the same
  one `egress_blocked` uses. Found on a real laptop, which had picked whichever
  application server was open as its "backend".
- **Counted by connections, not bytes.** A pool of twenty to a database is a
  harder dependency than one long transfer to object storage, and pools are
  what proxies keep.
- **A client is never a backend**, however many connections it holds. A single
  load balancer in front of you outnumbers every backend you have, and aiming
  at it would point the tool at what sends traffic rather than what the service
  needs.
- `BACKEND_MIN_CONNECTIONS` (2) — one connection somewhere is a DNS lookup or
  a webhook.
- **Ties break by address**, so the choice is the same on every run. A target
  that moves makes two reports impossible to compare.
- Your own SSH session is excluded, as it is everywhere else here.
- The choice is **always** reported (`target_is_a_backend`), and asking for
  `auto` where there is no backend says so (`target_auto_failed`) rather than
  silently leaving you reading a report about `8.8.8.8` believing it is about
  your database.

A dependency on a **public** address — a managed database, an external API — is
still worth aiming at, and is reported as `dependency` rather than `backend`.
The path to it genuinely leaves the site, so it aims there without claiming the
readings are about an internal segment.

**The attribution changes with it.** "The provider" is right for `8.8.8.8` and
flatly wrong for a database on the other side of a rack, so
`BACKEND_TARGET_VERDICTS` re-owns the five verdicts about reaching the target —
`inet_unreachable`, `inet_partial_loss`, `trace_stalls`, `loop`,
`egress_blocked` — to the internal segment. One rule per fault, with only the
attribution overridden, rather than a parallel set of near-duplicate codes. The
`--uplink-mbps` caveat also switches off: "rule out the site's own line" is
about the WAN, which an internal segment does not go near.

### The path only goes one way, and says so

A traceroute is outbound. This box can send probes toward a client, but nothing
here can observe the route a client's packets took to *arrive* — that is a
property of IP, not a gap in the tool. So there is no inbound path diagram, and
inventing one would be worse than leaving it out.

What there is instead is better evidence than a probe: the kernel's own
measurement of every connection a client actually has open, which `ss -tin`
carries. On a box that serves traffic the report shows both directions:

```
CLIENTS IN (measured on their own connections, not probed)
  6 connection(s) via 10.20.0.7   rtt 12.4ms   loss 7.33%
  -> this box cannot see past 10.20.0.7 to the client, so a clean reading here
     means clean as far as 10.20.0.7 - not clean to whoever is complaining.

PATH OUT TO 10.60.9.30 - what this box depends on
    1 lan gw.dc1                            0.3 ms
    2 lan xc.dc1-dc2                        8.4 ms   +8.1ms
    3 lan db01.dc2                          9.1 ms   +0.7ms, target
```

- The outbound panel is **named as a direction** rather than as "the path",
  which it stopped being the moment there were two.
- Latency is the **median**, not the worst: one stalled connection should not
  stand in for how a whole side is being served.
- The caveat is in the panel, not the documentation. A clean reading to the
  balancer is not a clean reading to the user, and a panel that does not say
  so invites exactly that reading.
- When connections arrive from many addresses there is no balancer to name, and
  it says that instead — the spread *is* the answer.
- On a box nothing connects to there is no inbound direction, so the panel is
  absent and the outbound one keeps its original title. Drawing an empty
  inbound leg would be inventing a measurement.

### Queue, or distance

`ss` reports two round-trip figures per connection and this tool used one of
them. `rtt` is the smoothed average; `minrtt` is the lowest that same socket has
ever seen. The difference between them is time spent **waiting**, and it is the
one number that separates *this path is long* from *something on it is
buffering* — two faults with different owners and different fixes, which every
other latency reading here is blind to. A ping and a per-hop delta can say how
long the trip took; neither can say how much of it was queue.

```
1 connection(s) between this box and what it depends on are waiting in a queue
rather than travelling: the worst is 10.0.0.90 at 96.0ms against its own best
of 8.0ms, so 88.0ms of every round trip is spent buffered.
```

Reported per side (`queuing_delay_clients`, `queuing_delay_backends`, or plain
`queuing_delay` on a box with no listeners), because a queue in front of the
clients and a queue in front of the backends are two different pieces of
equipment.

**Both tests are needed, and each rejects what the other lets through:**

| | `QUEUE_RTT_MULTIPLE` alone | `QUEUE_DELAY_MS` alone | both |
|---|---|---|---|
| LAN backend, 0.2ms → 2.2ms | fires — 11× | quiet | quiet ✓ |
| satellite hop, 575ms → 620ms | quiet | fires — 45ms | quiet ✓ |
| backend behind a full interconnect, 8ms → 96ms | fires | fires | fires ✓ |

Chosen by running candidate rules against twelve paths that should and should
not fire; this pair was the only one that got all twelve right.

A connection's own minimum is the honest floor for it — the same socket has
been that fast, so anything above is waiting somewhere. Kernels too old to
report `minrtt` leave it absent, and absent is skipped rather than read as
zero: zero would make every connection look infinitely queued.

### Which side of the proxy the loss is on

`ss` gives the local port of every connection, and this box already knows which
ports it listens on. A connection whose local port is one of them is a
**client's**; anything else is one this box **opened to a backend**. Those are
two different networks with two different owners, and averaging them produced a
wrong answer confidently:

```
a proxy with clean clients and a lossy database on 10.0.0.90

  verdict: Some destinations are losing traffic while others stay clean
  owner  : the provider or upstream
  next   : the drops are out on the path
```

A carrier ticket for the inside of your own rack. Now:

| | |
|---|---|
| `tcp_flow_loss_backends` | Clients clean, backends lossy. Owner: *the segment between this box and what it depends on*. The service and the path to your users are fine. |
| `tcp_flow_loss_clients` | Backends clean, clients lossy. Owner: *the path between this box and the people using it*. The service itself is healthy. |

Both rank above every direction-blind loss verdict, because the direction
answers "who owns this" and the shape only answers "how many destinations".
When **both** sides are lossy the direction says nothing useful and the
existing every-destination reading is the better answer, so it falls through.
On a box with no listening ports every flow is outbound by definition, `side`
stays `None`, and nothing about this changes — inventing a side there would be
a claim the data cannot support.

### The certificate this box serves

Every other TLS check here points outward, at something this device connects
to. A box terminating HTTPS is the opposite case, and its own certificate is
the one that takes the site down when it expires — and nothing was looking at
it. A proxy could be two days from an outage and the report read healthy.

On every full run, for each TLS port this box is **already listening on** (at
most `OWN_TLS_MAX_PORTS`, and only ports conventionally used for TLS, so this
never becomes a probe):

| | |
|---|---|
| `own_tls_expired` | Browsers are refusing it now. Ranked above everything about the path: when this is wrong the path is irrelevant. |
| `own_tls_expiring` | Within `CERT_EXPIRY_WARN_DAYS`. `LATENT` — real, dated, and not yet refusing anyone. |
| `own_tls_untrusted` | Usually an incomplete chain. Works from any machine that already trusts the issuer, which is why it works for you and not for customers. |
| `own_tls_handshake_failed` | TCP connects and the handshake doesn't. Every client is getting exactly this. |

Two details that decide whether this is useful or just noisy:

- **It connects to the address the service is bound to**, not blindly to
  loopback, and a service that simply isn't on the address we can reach
  reports *nothing at all*. A proxy bound to one public interface is healthy;
  calling that a broken listener would fire on every box that binds to one
  address. "No TCP" and "TCP but no TLS" mean opposite things and do not share
  a code path.
- **It verifies against the name on the certificate**, read from the
  certificate itself, while connecting to this box. The public name often
  resolves to a load balancer in front of you, so dialling it would test the
  wrong machine — and a chain that only completes because of *this* machine's
  trust store is exactly the failure that reaches customers and not you.

A certificate that doesn't verify never reaches Python's parsed dates, and a
private CA is most of what a proxy serves internally. ASN.1 encodes times as
printable ASCII, so `der_validity` takes them from the same string scan
`der_strings` already does — no hand-written X.509 parsing, which this file
deliberately avoids.

### Resets, and why the count of them is not a finding

A proxy sends a lot of TCP resets, and most of them are housekeeping.
[HAProxy closes backend connections with RST on purpose](https://gitlab.com/gitlab-com/gl-infra/production-engineering/-/issues/10589),
via `SO_LINGER`, to conserve ports and memory. So `OutRsts` is recorded in the
report and **never becomes a finding** — the same number is normal on one box
and alarming on another, and a tool whose job is deciding which fault matters
has no business guessing.

What is diagnostic is *why* a connection was aborted, which the kernel counts
separately:

| | |
|---|---|
| `aborts_on_memory` | `TCPAbortOnMemory` moving. The box ran out of socket memory and killed established connections to cope. Unambiguous, and never normal. |
| `reqq_full_drops` | `TCPReqQFullDrop` moving. SYNs dropped before reaching a queue. The client sees a connection that never opens and retries — indistinguishable from packet loss, and there is none. |
| `aborts_on_timeout` | `TCPAbortOnTimeout` as a **share** of connections handled (`PassiveOpens` + `ActiveOpens`), above `ABORT_TIMEOUT_PCT`. A count alone means nothing: some of this is ordinary on any public service, because people close laptops. Needs at least 100 connections in the window before a percentage is allowed to exist at all. |

### Per-flow analysis at proxy scale

`ss -tin` is about 430 bytes per connection. Command output is capped at
`MAX_OUTPUT_BYTES` (64 KB) so that a report stays a size you can paste, which
on a box holding tens of thousands of connections meant the per-flow analysis
ran on an arbitrary first ~150 sockets — 0.3% of them — and "worst peer" was
picked out of that sample.

The socket table is never stored: it names every peer this box talks to and is
replaced by a digest before the report is written. So the cap that mattered was
never the report's. `FLOW_READ_BYTES` (12 MB) is how much is *read* and
`FLOW_MAX` (20,000) how many connections are analysed; 40,000 sockets parse in
about 125 ms and analyse in about 20 ms. A sample that hits either limit still
reports `tcp_flow_sample_partial`, exactly as before — the aim was to make the
sample representative, not to stop admitting when it isn't.

## Duplicate IP and TCP retransmits (Wireshark findings, without a capture)

Two of Wireshark's most useful signals are available without capturing any
traffic — which matters on someone else's network, where capture is a consent
question, not a technical one:

- **Duplicate IP** — Wireshark flags an address claimed by two MACs. The same
  conflict is visible in the ARP/neighbour table this box already keeps. The
  reverse (one MAC, many IPs) is a router answering proxy ARP and is *not*
  reported. A duplicate address makes symptoms move around with no pattern,
  which is why it wastes so much time.
- **TCP retransmits** — read from `/proc/net/snmp` on Linux (`netstat -s` on
  BSD). This is loss measured on the box's **real traffic**, not probe traffic,
  so it catches drops that ICMP tests miss. Under `--soak` it's a live rate;
  otherwise a lifetime figure, and the report says which.

### Which destination the retransmits belong to

The counter above gives one number for the whole box. It can tell you traffic
is being dropped; it cannot tell you whether that's one sick destination or all
of them — and those have different owners. On Linux, `ss -tin` reports the
kernel's own per-connection statistics, so the split is available without
capturing anything or reading any payload.

| What the connections show | Reading | Owner |
|---|---|---|
| Every network lossy | Loss that follows every destination equally isn't out in the network | this device or its segment |
| Some networks lossy, others clean | The link carries the clean traffic fine, so the drops are further out | the provider or upstream |
| Only one destination measured | Nothing to compare against — stated as the weaker finding it is | that path, or that host |

It also reports what a loss figure can't: a connection blocked on the **far
end's receive window** is waiting on the remote application, not the network,
and a connection blocked on **this box's own send buffer** is a local socket or
memory limit. Both are common causes of "the network is slow" that no amount of
bandwidth fixes.

Some details that decide whether the answer is trustworthy:

- Peers are grouped by network (`/24`, or `/64` for IPv6) before the
  every-destination call, so two addresses reached over one upstream path don't
  read as two independent faults.
- Kernels before ~4.15 have no per-socket byte counters. The segment counts are
  used instead, and the report says which basis it used — without that fallback
  a genuinely lossy box on an older kernel reads as perfectly clean.
- Loopback peers are excluded (retransmits on `127.0.0.1` are memory pressure,
  never a path), as is the SSH session this tool is probably running over, which
  on a quiet box would otherwise be the only sample and become the verdict.
- Connections that haven't moved enough data for a ratio to mean anything are
  not counted, and the report says "not enough traffic to judge" rather than
  implying health.
- This is one check, not two: the per-destination findings and the host-wide
  rate are the same drops seen twice, so they can't corroborate each other into
  false confidence.
- On a box with more connections than one report can carry, only a prefix is
  read — and `ss` prints in kernel table order, so a prefix can easily be one
  busy application's connections. "No destination is clean" is a claim about
  what *isn't* there, so it needs the whole sample and is withheld; the loss is
  still reported, with the owner left open rather than guessed. "This one is
  lossy, that one is clean" is a claim about what *is* there, and still holds.
- The report stores a digest, never the socket table — that table names every
  peer this box has spoken to and runs to tens of kilobytes.

`ss` is Linux-only. Elsewhere the check reports that it can't run, which is not
the same as reporting that nothing is wrong.

## Neighbours: `--inventory`

The kernel's neighbour table already lists every device this box has exchanged
traffic with. `--inventory` formats it, with reverse-DNS names where the
configured resolvers answer:

```
NEIGHBOURS (33 known to this device, nothing was probed)
  192.168.1.1     gateway.local                   54:07:7d:bf:2d:34
  192.168.1.50    printer.local                   00:e0:4c:b0:03:fd
```

**It is not a scan.** Nothing is probed, pinged or connected to — every entry
is a device that was already talking to this one. That distinction is the
reason it can run on a network nobody gave you permission to sweep, and it
costs nothing because the table was already collected for the duplicate-address
check.

What it deliberately excludes: incomplete entries (a lookup that failed is not
a device), broadcast and multicast addresses. Including them turned 36 real
neighbours into 257 phantom ones the first time this ran.

The trade is honest: this shows what this device *has talked to*, not what
*exists* on the segment. A host that has never exchanged a frame with it won't
appear. If you need real discovery, use a scanner built for it — that job wants
a different tool, and sweeping someone else's network is a consent question
rather than a technical one.

Name lookups run in parallel against the resolvers already configured, and are
abandoned after a couple of seconds: an inventory is not worth stalling a
diagnosis for.

## Socket states

What this device's own TCP sockets are doing right now, read from `ss`/`netstat`
— the same signal Zeek derives from the wire, without a capture:

```
SOCKETS (this device)
  established 31   listen 17   time_wait 8
```

Two states carry a diagnosis:

- **SYN_SENT piling up** — this device is trying and nothing is answering. That
  is traffic being filtered, not a slow network, and the finding names the
  address it's failing to reach. From the application's side a dropped SYN and
  a slow server look identical.
- **CLOSE_WAIT piling up** — the far end hung up and the local application never
  closed its socket. That is an application bug, not a network fault, and it is
  the clearest "stop blaming the network" evidence available from here. It ends
  with the process running out of file descriptors.

## TLS and certificates

A port check proves something accepts connections. It says nothing about
whether the service works. For ports that should speak TLS (443, 8443, 993 and
friends) the handshake is completed and the certificate read:

```
PORT CHECKS
  github.com:22            open   SSH-2.0-c2e5186
  github.com:443           open   TLSv1.2, issued by Sectigo Limited, 55d left
```

Which surfaces four faults nothing else here can see:

- **The port opens but TLS doesn't complete** — something is listening and it
  isn't the service you wanted. A port check alone calls this healthy.
- **An expired certificate** — clients refuse outright while the network is
  perfect. Reported critical, with days remaining.
- **A certificate close to expiry** — cheaper to fix now than during the outage
  it becomes.
- **Interception** — if the issuer is a known inspection product rather than a
  public CA, traffic is being re-signed in the path.
  Anything that pins or verifies certificates fails while ping and port checks
  look perfect.

Verification failures aren't fatal to the check: the handshake is retried
without verification purely to read the certificate, because a bad certificate
is exactly what needs describing.

**Banners.** Ports that aren't TLS get a short read after connecting — SSH and
SMTP announce themselves immediately. A quiet port costs 0.5s and nothing else.

## Listening ports

What this device has bound, and on which interface rather than just loopback.
It pairs with the port checks below: those ask whether something answers from
outside, this shows whether anything is listening here at all — the difference
between "the firewall is blocking it" and "the service isn't running".

## Port checking

Check if specific ports are reachable on the target (uses plain TCP connect, no root required):

```bash
python3 faultone.py --report --target 8.8.8.8 --check-ports 53,443,8080
```

Results show per-port reachability and any failures are flagged in the findings.

Ports are checked concurrently (up to 8 at a time), so a list of unreachable
ports costs one timeout rather than one per port. The cap keeps the burst small
enough to look like a diagnostic rather than a port scan to whatever is
watching the site's network.

## Catching intermittent faults: `--soak`

A normal run is a snapshot. The faults that are hardest to place — a marginal
cable, a hop dropping 3%, a link that flaps — are invisible in one pass and
obvious over a minute. `--soak SECONDS` samples over a window instead:

```bash
python3 faultone.py --report --soak 120
```

- **Error counters** are watched for the whole window, not 2 seconds, so
  "+14 errors in 120s" is a rate you can trust rather than a coin flip. The
  window runs alongside everything else rather than as a dedicated pause, so a
  normal run reports the error rate over its full duration (~7s) at no extra
  cost, and `--soak 60` takes about 60 seconds rather than 60 plus the run.
- **Per-hop loss** comes from `mtr` when it's installed — hundreds of probes per
  hop instead of traceroute's three.
- **Pings** run for longer, so partial loss shows up as a percentage.
- **Throughput** is sampled every second through the window, not just at its
  two ends — see below.

Sixty to 120 seconds is the sweet spot. Longer rarely tells you more, and
you're usually on a call.

### Why the average is the wrong number: bursts

The byte counters used to be read once at each end of the window and divided.
That gives a mean, and a mean is precisely the wrong statistic for the fault
`--soak` exists to find. On a 50 Mbps line:

| pattern | mean | peak | seconds full | reported before |
|---|---|---|---|---|
| steady third of the line | 33% | 33% | 0 | nothing ✓ |
| **full 20s of every 60, calls breaking** | **46%** | **100%** | **40** | **nothing ✗** |
| **a 5s flood a minute** | **63%** | **100%** | **10** | **nothing ✗** |

The middle row is the point: 46% is indistinguishable from a healthy site
running at 46%, and the line is completely full for a third of the window.
Longer soaks made it worse, not better — more window to average the burst away.

The progress line already ticked once a second through the wait. It now reads
the counters on the same tick, which costs about 2.4 ms per read: 0.29 s of
work across a `--soak 120`. Each interface carries `peak_mbps` and the series
itself, and `SERIES_MAX_SAMPLES` bounds what a long soak stores — at or below
900 seconds the interval is one second, above it the interval stretches, so an
hour-long window costs the same to carry as a two-minute one and every sample
stays a real measurement over a real interval rather than a decimated guess.

The series covers the part of the window still left to wait when the other
checks finish, not the whole of it. The counter window deliberately runs
alongside everything else, and under `--soak` the probes stretch too, so about
40 s of the window goes to the rest of the run. Measured on a real box:

| | sampler gets | samples |
|---|---|---|
| `--soak 20` | nothing — the run outlasts the window | 0 |
| `--soak 60` | 21 s | 21 |
| `--soak 120` | 83 s | 82 |

**So bursts need `--soak 60` at the least, and 120 is where it works properly** —
which is the same window this section already recommends for everything else.
Each interface records `series_seconds` next to the series so the sampled span
is never confused with the nominal one, and the peak and the mean are both
taken from those same samples, so they are always comparing like with like.
Interfaces that moved nothing carry no series at all.

Two details that are easy to get wrong and are tested:

- The rate divides by the **measured** interval, not the one that was asked
  for. A tick that lands at 1.4 s and is divided by 1.0 reads 40% high.
- A counter that resets mid-window drops the tick rather than recording zero. A
  zero is a claim that the interface was idle for that second, which drags the
  mean down and hides exactly the burst this is here to find.

#### When a burst is a fault, and when it is just a line being used

A line going to 100% in bursts is normal — that is a line doing its job. Firing
on the shape alone cries wolf on every site with a backup window. So
`saturation_bursts` requires **harm in the same window**: packets this device
dropped, or probes to the target that went unanswered. Neither is inferred from
the throughput itself, which would make the test circular.

That rule was picked by testing candidates against patterns that should fire
and patterns that should not. It was the only one that got all seven right —
`peak >= 70%`, `p95 >= 70%` and a duty-cycle threshold each raised false alarms
on an ordinary download or backup window.

### The window you didn't have to wait for: the kernel log (Linux)

A soak catches a fault while you're watching. The kernel has been watching
since boot, and every carrier transition and adapter reset went into its log
with a timestamp — the one thing a counter doesn't carry.

This matters because every lifetime counter in this tool is divided by uptime
to get a rate, and that division destroys exactly the information you need. A
box up for ninety days that lost carrier eighty times in the last ten minutes
averages to 0.89 transitions a day: under `LINK_FLAP_PER_DAY`, no finding, and
the run reports **no fault found** on a link that is falling over right now.
That was the tool's answer before this check existed.

With the log read, the same run says:

```
LIKELY ROOT CAUSE: The link has been dropping and coming back - the kernel
logged each time
  owner: this device or its cable
  next: The port is up now, which is why everything else here reads clean.
  This is physical: reseat the cable, try a different switch port, and
  compare the times below against the port's own log at the other end.
  This device is connected to SW-CLOSET-2 port Gi1/0/24.

  eth0 lost and regained carrier 80 time(s) in the last 10 minutes, most
  recently 47s ago - the kernel logged each one.
```

Two findings come from it:

| | |
|---|---|
| `link_flapping_logged` | `KLOG_FLAPS_RECENT` (4) or more carrier transitions inside the last hour. Supersedes the lifetime rate for that interface, so one cable is one finding, not two at different urgencies. |
| `nic_reset_logged` | The driver reset the adapter — "Detected Hardware Unit Hang", a transmit queue timeout, a firmware crash. Every connection drops each time and **no interface counter records that it happened**, so the log is the only place this is visible at all. |

How it reads the log, and why in that order:

- `dmesg` first, with its default `[  1234.567]` seconds-since-boot stamps.
  Subtracting from `/proc/uptime` gives an exact age, and unlike `dmesg -T`
  it cannot be broken by a locale.
- `journalctl -k -o short-unix` when dmesg is restricted — `dmesg_restrict=1`
  is the default on Debian and Ubuntu — which gives epoch stamps.
- If neither can be read, the check reports itself **unavailable**, which
  lowers coverage. It never reports "nothing was logged": a check that reads a
  refusal as good news is worse than no check.
- A kernel built with `printk.time=0` stamps nothing. The events are still
  reported, with an unknown age, and an unknown age is never counted as recent.
- Boot-time link-up messages are ordinary; the one-hour window
  (`KLOG_RECENT_SECONDS`) is what keeps them from firing this on every healthy
  host.
- The ring buffer is capped from the **tail**. It is megabytes of boot messages
  followed by the lines that matter, so keeping the first N bytes would store
  precisely the wrong half.

## What changed since last visit: `--baseline`

**A comparison is only a comparison if both visits measured the same thing.**
Since `--target auto` picks a backend off this box's own connections, the
target can change between visits with nobody touching a flag — no clients on
the first visit, clients on the second. Everything measured *to the target*
(call quality, hop count, where the site edge falls) is therefore only compared
when both runs went to the same place; the change of target is reported on its
own, neutrally, so a shorter diff is never mistaken for a quieter network.

Without that, comparing call quality to `8.8.8.8` against call quality to a
database two racks away reported *"something changed since the last visit, and
not for the better"* on a network where nothing had changed at all.

A field tool can't keep history — but you keep the reports, so "what changed"
is a diff of two JSON files with no service, no storage and no network:

```bash
python3 faultone.py --export site-a-jan.json          # this visit
python3 faultone.py --report --baseline site-a-jan.json   # next visit
```

```
CHANGES SINCE BASELINE
  ! en0 switch port: Gi1/0/12 -> Gi1/0/24
  ! en0 VLAN: 20 -> 30
  ! en0 link speed: 1000 -> 100
  ! en0 duplex: full -> half
  ! en0 errors since baseline: 0 -> 4200  (+4200)
  ! call quality (MOS): 4.39 -> 3.7
```

That's a device that got re-patched into a different port, negotiated badly,
and has been collecting errors since — a story no single reading tells. Changes
that got *worse* also become a finding, so they can't be scrolled past, and the
verdict will name the change rather than the symptom.

Two things it deliberately won't do: report a difference when either side is
missing the data (a `--quick` baseline, or a tool that wasn't installed last
time, would otherwise manufacture regressions), and report negative error
counts when the box has rebooted — a counter that went backwards is reported as
a reboot instead.

## Export / import workflow (no server, no open port)

There is no server mode: the tool never listens on anything. Run the diagnosis
once and write it to a file instead:

```bash
sudo python3 faultone.py --export report.json
sudo python3 faultone.py --export report.json --target 1.1.1.1   # trace/ping a different target
sudo python3 faultone.py --export report.json --target 8.8.8.8 --check-ports 53,443
```

This runs the same collection + heuristics as the live UI, but opens
no port at all. Copy `report.json` to your laptop (`scp`, USB, email,
whatever), then open `static/index.html` **directly in a browser** —
no server needed for this part — and use **Load exported report** in
the sidebar. You get the same findings, LED panel, and visual hop-by-hop
path diagram (source → gateway → each traceroute hop, colored by
timeout/latency → target) as the live view, built entirely client-side
from the JSON file.

`static/index.html` only ever has to exist on *your* machine, never on the
box you're diagnosing.

When file transfer off the box is blocked or awkward, use `-` to send the
JSON to stdout and just select-and-paste it into a file locally:

```bash
sudo python3 faultone.py --export -                  # JSON on stdout
sudo python3 faultone.py --export - --report         # JSON on stdout, findings on stderr
sudo python3 faultone.py --export - > report.json    # or redirect it
```

With `--export -`, stdout carries nothing but the JSON — every human-readable
line goes to stderr — so piping and redirecting stay clean.

## Optional tools it will use if present

None is required. The rule for every one of them is the same: use it when it's
there, fall back silently when it isn't, and record in the report which tool
produced the data. On a box with nothing but `python3` the tool still runs and
says which checks it couldn't make — an absent tool lowers coverage, it never
becomes a fault.

**Better data than the fallback gives**

- **`mtr`** — per-hop loss over many cycles, which a single traceroute can't
  give you. When present it replaces the traceroute entirely, and the report
  says `path via mtr`. Loss is read from the destination backwards: loss at an
  intermediate hop that clears by the final hop is that router rate-limiting
  ICMP, not a fault, and is reported as such rather than as a problem.
- **`ethtool`** — what the two ends actually negotiated, plus whether
  auto-negotiation was on at all. That's the difference between "half duplex"
  and "half duplex because someone hard-coded one end", which sysfs can't tell
  you. Also the source of optical power readings on fibre.
- **`ss`** — per-connection TCP statistics (`ss -tin`), which is what makes
  loss attributable to a destination instead of an average across the box.
  Always run with `-n`: reverse DNS on a broken network is exactly the hang you
  don't want in a diagnostic.

**Things nothing else can tell you**

- **`dmesg`** / **`journalctl`** — the kernel log, for link transitions and
  adapter resets with the times attached. See
  [the kernel log](#the-window-you-didnt-have-to-wait-for-the-kernel-log-linux).
- **`chronyc`** / **`ntpq`** / **`timedatectl`** — whether the clock is
  synchronised and how far off it is, asked of whichever time daemon is
  actually running. A wrong clock is reported as a certificate fault by
  everything that isn't looking for it.
- **`tcptraceroute`** — a path built from TCP probes, for the networks where
  ICMP and UDP traceroute are filtered and the normal path stops dead.

**Plain fallbacks**

`ip` or `ifconfig`/`netstat` for interfaces and routes; `traceroute` or
`tracepath` when `mtr` is absent; `dig` or `nslookup` for resolver checks.
Whichever is present is used, and the report names it.

## Platform support & timing

**A check that can't run is never reported as a fault.** If `ifconfig`/`ip` or
`netstat` isn't on the box, you get "couldn't read the interface list" as a
warning — not "this device has no IP address". Missing `dig`/`nslookup` falls
back to the resolver queries this program makes itself, which need nothing
installed. On a stripped appliance the difference matters: a false critical is
worse than a gap.

Linux is the best-supported target: error counters and speed/duplex come
straight from sysfs. On macOS/BSD they're parsed from `ifconfig`/`netstat`; on
Windows those two checks report "not available" rather than guessing. Everything
else (interfaces, routes, ping, traceroute, DNS, ports) works on all three —
the tool picks the right command per OS (`ip`/`ifconfig` vs `ipconfig`,
`traceroute` vs `tracert`). Commands run with `LC_ALL=C` so a localized system
doesn't silently break output parsing.

A full `--report` is ~7s on a healthy network: the gateway ping, the target
ping and the trace are independent, so they run together and the run costs
about as long as the trace alone. On a badly broken network it can still reach
a minute, because a traceroute into a black hole runs its full timeout — that's
what `--quick` is for.

`--soak` runs those probes one at a time instead. When you have deliberately
asked to sample for a minute, probes perturbing each other's latency matters
more than the seconds saved.

## Security

This app has **no login and no authentication**. It executes real
system commands with whatever privileges you run it as. That's the
design — the point is to run the common diagnostics on a device you
already have root on — so treat it like a root shell, not a public
web app:

- **It never opens a port.** There is no server, no API and nothing listening,
  so there is no unauthenticated endpoint to reach, no Host header to validate
  and no DNS-rebinding surface. That whole category is absent rather than
  defended - which is why server mode was removed.
- The viewer and the self-contained report are plain files opened from disk.
  They make no network requests of any kind - no CDN, no fonts, no analytics -
  so they work with the internet unplugged, which matters for a tool you reach
  for when the network is what's broken.
- User-supplied targets (for ping/traceroute/DNS) are validated — IPs via
  `inet_pton`, hostnames against a strict regex with a length cap — and
  commands are run as argument lists, never through a shell. So `; rm -rf /`
  style injection isn't possible, and a target can't start with `-` and be
  swallowed as a command-line flag. That's defense in depth, not a replacement
  for keeping the port private: anyone who can reach it can still run
  diagnostics against arbitrary hosts from your machine.
- The port-check list is capped at 32, since each check is a TCP connect with
  a timeout and an unbounded list would keep the box busy for a very long time.
  Truncation is reported in the findings, never silent.
- Exported reports are written `0600`. They contain internal addressing, MAC
  addresses, listening ports, resolver addresses and — where LLDP is available —
  switch names, management IPs and VLAN ids. That's a map of the site's network,
  so treat a `report.json` as sensitive when moving it around.
- DNS queries are sent only to the resolvers this device is already configured
  with, and a reply is accepted only from the address it was sent to, with a
  random query id — so a stray or off-path packet can't be read as a resolver's
  answer.
- `--soak` is capped at an hour, and the port-check list at 32, so neither a
  typo nor a query string can leave the box busy indefinitely.
- Nothing in the UI calls out to the internet (no CDN fonts/scripts) —
  everything needed to run it is in these two files, which matters for
  a tool you might reach for when the network is the thing that's broken.

## Awkward inputs it is hardened against

Four things that aren't parser problems, each found by probing for them
specifically rather than by a check failing in the field:

- **Bytes that aren't text.** An interface alias or SSID containing non-UTF-8
  bytes used to raise `UnicodeDecodeError` and fail the whole check, which
  reads as "not available on this system". Output is now decoded with
  replacement, so one strange byte costs one strange character.
- **Output that doesn't stop.** A single command's output is capped at 64KB
  with an explicit note of how much was dropped. A report travels by paste and
  by email; a huge ARP cache shouldn't turn 60KB into megabytes.
- **Counters that go backwards.** A 32-bit counter wraps, and an interface can
  be reset mid-sample. "-98 errors in 2s" is not a rate, so the window reports
  unknown instead.
- **Numbers that aren't finite.** `json.dumps` writes bare `NaN` and
  `Infinity`, which Python reads back happily and every browser's `JSON.parse`
  refuses — one stray value would make a self-contained report fail to open
  with nothing on screen to explain why. Non-finite floats become `null`.

Non-ASCII text (hostnames, switch names) round-trips intact through JSON, the
HTML island and the terminal output, and a report the tool produced works as
its own `--baseline` with zero spurious changes.

## Tests

```bash
python3 test_faultone.py          # or: python3 -m unittest -v
```

618 tests, no dependencies, no network, a few seconds — so they run
anywhere the tool does, including on the target box itself. That is the point of
having no dependencies: you can validate it in the environment that matters.

They're weighted toward what has actually broken here rather than spread evenly
for coverage's sake. Every real bug in this project came from a **parser**
meeting a format it hadn't seen — a macOS routing table, a traceroute
continuation line — so the parsers get the most cases, each with real captured
output from Linux, macOS/BSD and Windows. The rest cover target validation
(these strings end up in an argv list), the analysis logic, and the verdict's
ordering rule.

Ten realistic compound faults are checked too - situations where several
findings fire at once and only one of them is the cause. A cable corrupting
frames also loses pings, degrades calls and drives retransmits; the verdict has
to name the cable. Each scenario asserts which finding gets blamed and who it
is assigned to, because naming a symptom sends someone to fix the wrong thing.
That sweep found the last ordering defect: on fibre, low optical power was being
blamed on the CRC errors it causes, producing "reseat the cable" for a dirty
connector.

Every finding the tool can emit has a scenario that triggers it end to end -
all 56 of them. Each stubs the collectors so one specific fault is present, runs
the whole diagnosis, and checks the finding fires with the severity intended.
Writing that sweep found five defects nothing else had: two findings that could
never fire at all, a symptom outranking the cause it was computed from,
housekeeping notes reading as failures, and a critical finding leaving its stage
merely warning.

A test also asserts that every code has a scenario, so a new finding cannot be
added without one.

The suite is checked by mutation: each bug that was fixed here gets
reintroduced deliberately and the suite must fail. The five checked are the
macOS gateway branch, traceroute continuation lines, the loose IPv6 regex,
unknown counters reading as zero, and a symptom outranking its cause in the
verdict. That found a real hole the first time — the counter test patched one
layer above the code the bug lived in, so it passed against the bug. Passing
tests are not evidence until you've watched them fail.

## Files

This section described a server with HTTP routing and a `COMMANDS_META` table
until 2026-08-07. None of it had existed for a long time — server mode was
removed, and nothing pins prose the way the counts are pinned.

- `faultone.py` — the whole tool. Collectors (`cmd_*`) gather, checks
  (`_check_*`) turn what they gathered into findings, and `build_verdict`
  ranks those against `VERDICT_RULES` to pick one cause. To add a check:
  write a collector, write a `_check_*` that appends findings, give each new
  code a rule in `VERDICT_RULES`, a stage in `STAGE_RULES`, and a direction in
  `FINDING_SIDE`. The suite will tell you which of those you forgot — every
  one of them is guarded.
- `test_faultone.py` — the suite. Standard library `unittest`, no network,
  a few seconds. Includes the guards that keep these documents honest: counts,
  thresholds, flags, optional tools, and whether the README still describes
  what the tool can do.
- `static/index.html` — the standalone viewer, for reading an exported
  `report.json` on your own machine. Generated from `VIEWER_TEMPLATE` by
  `--emit-viewer`; a test holds the two byte-identical, so edit the template
  and regenerate rather than editing the file.
- `dev/` — two release harnesses that are not part of the tool: `deep_e2e.py`
  runs every finding through the whole pipeline, `equivalence.py` proves a
  change stayed inert by diffing every scenario against a git ref. See
  [dev/README.md](dev/README.md).

## The repository description

GitHub's About box lives outside the repository, so no test here can read it —
which is how it sat quoting a finding count three releases out of date while
every count inside these files stayed green. (Writing that stale number here as
a numeral would trip the very guard this section exists to enable — which is a
fair demonstration that it works.) The canonical text is kept here
instead, where the same guard that pins every other number scans it:

> SSH into a box and get one line: is the fault this box, the way in, or the
> way out - and who owns it. Ranks 122 findings with readable rules instead of
> listing everything that looks wrong. One Python file, no install, nothing
> listens.

Update this block and the About box together. If the finding count moves and
only one of them is changed, the test suite fails on this file — which is the
best that can be done for a string stored on someone else's server.

## Licence

MIT, in [LICENSE](LICENSE). Every file carries an `SPDX-License-Identifier: MIT`
line, including the viewer — so a self-contained `report.html` handed to a
site states its own terms.

Nothing third-party is bundled. The optional tools are executed, not linked, so
their licences (mtr is GPL, for instance) don't attach to this code. That stays
true only as long as nobody copies code *out* of them and into here.

## Extending it

Additions that fit what this tool is for — separating "the device" from
"the network it's plugged into" from "upstream":

- DHCP lease details: whose DHCP answered, and does it match what the site
  says it should be.
- Gateway-vs-internet latency delta, to separate a slow LAN from a slow
  uplink.
- Wi-Fi signal strength on the interface panel (`iwconfig`/`nmcli` on
  Linux, `airport -I` on macOS).

Deliberately **not** on this list:

- **An auth token, or any return of server mode.** Opening a port on a
  site's network was the thing to avoid, not the thing to secure. `--report`
  and `--export` cover every case without one.
- **ASN lookup per hop** (via Team Cymru's DNS interface, the way Kentik
  attributes paths). It needs working DNS and outbound access, which is exactly
  what's missing on the runs where you'd most want it; the PTR-derived network
  handoffs already give most of the value; and it would be the first thing here
  to send site topology to a third party. Considered 2026-08-06 and
  rejected.
