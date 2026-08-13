# FaultOne reference

Everything the tool checks, and how it decides which of those checks is the
answer. For getting started see the
[README](README.md).

## Why the ranking is the point

Every tool in this category collects more than this one does. What none of them
does is decide, from the same counters, which fault is the cause and which are
its consequences, and that decision is where the wrong answer usually comes
from, because the obvious reading of the evidence is often wrong.

Five cases where a competent engineer, looking at exactly the same numbers,
reaches the wrong conclusion:

| The evidence says | The obvious answer | What the ordering says |
|---|---|---|
| CRC errors climbing on the interface | replace the cable | collisions on a **full-duplex** link mean the switch port disagrees about duplex. No cable will fix that |
| Every destination is losing traffic | your link is bad | the box's own receive backlog is overflowing. It is too busy, not broken, and the signature is identical |
| Retransmissions are high | the path is dropping packets | the far end acknowledged data it already had, so the packets arrived: reordering, not loss |
| The certificate won't validate | renew the certificate | it has not started being valid yet, which is almost always this device's clock |
| Clients are losing traffic, and so is the database | one problem, somewhere upstream | two problems facing opposite ways. Neither explains the other, and fixing one leaves the other exactly where it was |

In each, the tool reports the same underlying findings a checklist would. The
difference is which one it puts at the top, and that is the whole product: 160
findings exist and exactly one reaches you as the answer.

The rule is a single sentence. **A broken layer makes every layer above it look
broken, so the lowest layer with a live fault is the cause and the rest are
symptoms.** The word doing the work there is *live*. Bottom-up ordering has one
well-known failure. Taken alone it will chase the lowest layer whether or not
anything there is actually broken, so a finding that describes a risk rather
than a failure (an optic with margin left, a link that flapped yesterday, a
table filling but refusing nothing) is never the headline while something is
actively failing. It is still reported, and it is still the answer when nothing
else is wrong, which is exactly when you want to hear about it. Everything else is bookkeeping: which findings count as
corroboration, which are too weak to be evidence, which are consequences of the
one already named.

It is worth being precise about what this does and does not claim. It applies
one plausible ordering, consistently, every time. It does not know your
network. It still says *likely*. It reports how much of itself managed to run,
names faults it cannot explain, and declines to call something loss when the
sample cannot support it. The value is that the reasoning is the same on every
run and you can read it: `VERDICT_RULES` is an ordered list in the source, not
a model, and every verdict cites the findings it came from.

## A box with no inbound ports at all

A third shape, and the one every check here is quietest about: a connector that
opens no listening ports by design, holds a few long-lived links outward, and
carries traffic over them. Nothing connects *to* it, so every inbound check
stays silent correctly, and that silence used to be the whole report.

**A box with no listeners can still have dependencies.** Backend detection was
gated on serving, which is right for a laptop. The busiest peer there is
whatever application is open, but wrong for a connector, whose handful of
links to an edge is the one thing it needs. The gate is now *serving, or
holding a concentrated handful* (`CONNECTOR_DESTINATIONS`), so a connector's
edge becomes what the run aims at while a laptop browsing thirty sites still
gets nothing.

**A box doing nothing reports nothing wrong, which is why this was invisible.**
No listeners, no connections, every check passing, because a box with no
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
assumptions are wrong on one, and both were wrong in the same direction: they
treat every outbound connection as this box's own business.

**Ephemeral pressure is per destination, not global.** A source port only has
to be unique within the four-tuple, so the same one serves any number of
different destinations at once. `ephemeral_ports_low` counted every outbound
socket against the range, which reports exhaustion on a box holding 26,000
connections spread over 250 destinations, about a hundred per destination, and
nowhere near a limit. It now measures the busiest single destination, names it,
and says how many places the rest are spread across:

| | old reading | correct reading |
|---|---|---|
| 26,000 conns over 250 destinations | 92% (fires | ~104 to the worst) quiet |
| 26,000 conns to one destination | 92% (fires | 92%) fires |

**Its outbound peers are not its dependencies.** `--target auto` picks the
most-connected outbound peer, which on a forwarding box is whichever
destination happens to be popular this minute, diagnosing the path to it says
nothing about the box. A dependency now has to hold `BACKEND_MIN_SHARE` of the
outbound connections as well as clearing the minimum count: a handful of real
backends each hold a large slice, one destination out of hundreds holds almost
none.

When no peer qualifies and there are more than `FORWARDER_DESTINATIONS` of
them, that shape is itself reported (`target_is_forwarded`) and the run falls
back to the default target rather than inventing a dependency. The finding says
what to pass instead, the service this box reports to, or a destination its
users are complaining about.

## Two failures that make every other check pass

**Nothing is reaching this box.** Being taken out of a load balancer's pool is
invisible from the box it happened to: the service is up, the port is open, the
certificate is fine, and no traffic arrives. Every check here passes. It is the
most common way a proxy is "down" and the least visible from inside it.

`no_clients_connected` fires when this box is listening on a port whose purpose
is answering clients and fewer than `SERVING_INBOUND_MIN` connections are open
inbound, naming the peer when there is one, since a single connection from one
address at that volume is a health check rather than traffic.

Gated to `SERVING_PORTS` deliberately. Almost every machine listens on
*something* (sshd, a metrics endpoint, a database bound to the LAN) and
"listening with nobody connected" is only interesting when the thing listening
exists to be connected to. Without that gate it fired on any box running sshd,
which is all of them; it fired on the machine this was written on.

It stays a **warning**: a genuinely quiet period looks the same from here, and
the message says so.

**The answers came from a cache on this box.** `dns_local_cache` reports when a
configured resolver is on loopback, `127.0.0.53` (systemd-resolved),
`127.0.1.1` (dnsmasq or a NetworkManager stub), or any other loopback address.

It is context, never a fault, and it changes what every DNS result below it
means: a stale or poisoned entry in a cache *here* is invisible from anywhere
else, will not reproduce from the next machine somebody tries, and outlives the
upstream being fixed. That is the shape of "it works for me", and it is worth
knowing before a resolver result is read as the network's answer.

## Redundancy: what a neighbour table can and cannot show

A gateway that is a **virtual address** belongs to a redundancy pair, and that
reframes every finding about it, "the gateway is down" on a pair more often
means a failover that did not complete than a router that stopped. The protocol
and group are readable straight off the MAC the neighbour table already gave
us:

| | |
|---|---|
| `00:00:5e:00:01:XX` | VRRP, or CARP. They share this range, which is exactly why a CARP `vhid` and a VRRP `vrid` collide on one segment |
| `00:00:5e:00:02:XX` | VRRP for IPv6 |
| `00:00:0c:07:ac:XX` | HSRPv1 |
| `00:00:0c:9f:fX:XX` | HSRPv2 |
| `00:07:b4:00:XX:YY` | GLBP |

`gateway_is_virtual` reports which, as context. `virtual_router_conflict` fires
when **two different groups** answer for one address: two virtual routers
configured onto the same IP, traffic landing on whichever the switch learned
last, symptoms moving with no pattern.

**What this cannot see, and says so.** A same-group split brain: two masters,
one VRID, is invisible here, because both use the *same* virtual MAC. That is
what VRRP is for. The neighbour table shows one entry and there is nothing to
detect, and a check that implied otherwise would be worse than no check. A
first draft of this had a branch for it that could never execute.

The signal that *is* available is the address **changing hands between
visits**: same IP, different hardware behind it. `--baseline` reports it,
neutrally rather than as a regression. A pair failing over is the pair doing
its job, and only the reader knows whether it should have. One virtual MAC and
one real one stays an ordinary `duplicate_ip`, because one of each is not two
virtual routers and claiming so would outrun the evidence.

## Boxes outside the country the defaults were chosen in

Three assumptions that held on a domestic appliance and do not hold on a fleet.

**IPv6-only is a working configuration, not a fault.** `has_ip_address` looked
for IPv4 and nothing else, so a box on a mobile carrier or in a datacentre that
never handed out IPv4 was reported *critical, exit 2, "this device never got
onto the network"* while holding a global IPv6 address and serving traffic. It
now counts a routable IPv6 address, but not link-local, since every interface
gets an `fe80::` whether or not anything configured it, and accepting that
would make the check unfailable.

The knock-on matters more. Every reachability check here is IPv4-shaped: the
gateway comes from `default via <IPv4>`, the default target is an IPv4 literal.
On an IPv6-only box those aren't failing, they're **unmeasurable**, so they
report `gw_unmeasurable_v4` and `inet_unmeasurable_v4` and conclude nothing,
the same way an absent tool does. The all-clear stops claiming "the gateway and
the internet are reachable" when neither was reached, which is the exact
overclaim that sentence exists to avoid.

This is a contained fix, not IPv6 parity. The tool still diagnoses the IPv4
path; on an IPv6-only box it now says so instead of inventing an outage. Point
`--target` at an IPv6 address or a name with an AAAA record to diagnose the
path that box actually uses.

**Names are not all ASCII.** `--target` accepts an internationalised hostname
and converts it to the punycode form the DNS actually carries, once, at entry: 
so every command run and socket opened downstream sees ASCII, and the report
records what was *reached* rather than what was typed. A box in Tokyo or Munich
has backends named in its own script, and rejecting them as "invalid" made the
tool unusable exactly where nobody can paste an alternative.

**The defaults point at hosts some jurisdictions filter.** `8.8.8.8` and the
`google.com` DNS probe are blocked or poisoned in several countries. The
reachability confirmation covers part of this. Nothing is called unreachable
on ICMP alone, but on a filtered network the honest move is to point
`--target` at something the box is actually supposed to reach. With
`--target auto` on a box serving traffic that already happens: it aims at a
backend it holds connections to, which is by definition reachable.

## A share needs a sample

This file has now been written with the same defect four times. A finding works
out what share of something went wrong, and fires on a sample too small for a
share to mean anything:

| | |
|---|---|
| `drops_live` | one discarded packet, at any volume |
| `regression_since_baseline` | one new error between two visits |
| `udp_recv_buffer_full` | one dropped datagram out of one |
| `fragments_lost` | one failed fragment out of two |

The last two were written **hours after** fixing the first two, which is the
point: knowing the rule does not stop you breaking it, and a guard written per
check is a guard that covers the checks you remembered. One test now sweeps
every counter-driven finding with a sample of two and asserts silence.

It found a fifth on its first run: `tcp_checksum_errors`, which fires on a
single bad checksum by design, because one should never happen. That one is not
the same bug, and the fix was different: it still reports the error, and no
longer quotes "500,000 per million received" for one packet on an idle box.
Below a sample that supports a rate it gives the count and says so.

## A tunnel is not a misconfigured wire

`mtu_nonstandard` fires on any interface not at 1500. On a box terminating a
VPN that is every tunnel it has, because the reduction **is** the header
overhead of whatever wraps the traffic, and with nothing else wrong, a healthy
VPN box came back with *"Interface MTU is not the standard 1500"* as its
verdict, every run.

Interfaces whose names say they are encapsulations: `tun`, `tap`, `utun`,
`wg`, `ppp`, `ipsec`, `vti`, `gre`, and the branded WireGuard names: now get
`tunnel_mtu` instead: **context, exempt from the verdict**. Matched on the name
because that is what the kernel offers; there is no flag in sysfs that says
"this is a tunnel".

The number is still printed, because it is the number that decides whether
traffic inside the tunnel fits. Something inside assuming 1500 and sending
packets that will not fit shows up as large transfers stalling while small ones
are fine, which is worth knowing, and is not the same as the tunnel being
misconfigured.

## Why something we serve did not verify

`own_tls_untrusted` checks the certificate this box serves the way a client
would. OpenSSL reports several quite different situations with one word, and the
distinction matters most on a box that **re-signs traffic on purpose**:

| what OpenSSL said | what it means |
|---|---|
| self signed certificate **in certificate chain** | the chain ends at a root this box does not trust, what a certificate re-signed by a private authority looks like. If this box issues its own, that is it working, and anything never given that root refuses outright |
| unable to get local issuer certificate | the issuer's certificate was not sent and is not held here. The incomplete chain that works from a machine which already has the intermediate and fails from one that does not |
| self signed certificate | the leaf signed itself |

Read off the error string rather than by parsing the certificate, which would
mean the ASN.1 work this file deliberately avoids elsewhere. Both spellings are
handled (newer OpenSSL hyphenates it) and the leaf error is a substring of the
chain error, so the order they are tested in is load-bearing.

## The rest of /proc/net/snmp

The file was already being opened and only the `Tcp:` line read out of it. Two
protocols' worth of counters were going past every run, and both answer
questions nothing else here can.

**DNS runs over UDP.** A box overflowing its receive buffers loses resolver
answers while every TCP check in this tool passes, so the report reads as a
slow or flaky resolver, and the resolver is fine. `udp_recv_buffer_full` is the
finding, and it is owned by **this device, not the resolver it looks like**.

`InErrors` contains `RcvbufErrors` one for one. What is left over arrived and
failed *before any socket saw it* (a bad checksum, a malformed header) which
is damage in the path rather than this box failing to keep up:

| | |
|---|---|
| `udp_recv_buffer_full` | this box had no room. **Local.** No retransmission and no window: the datagram is gone and the sender is never told |
| `udp_datagrams_corrupt` | this box had room; the datagram was already broken. **Upstream.** Ethernet has its own CRC, so whatever re-framed it after that did the damage |

Subtracting the one from the other is what keeps them from being counted twice,
and the two have different owners, which is the whole reason for splitting them.

**Fragments that arrived and never came back together** are the receiving half
of what the path-MTU probe measures on the way out, and evidence that probe
cannot produce: it is about traffic *other people* sent here. `fragments_lost`
fires when a tenth of reassembly attempts fail, and names the usual cause: an
MTU step on the path with the ICMP that would report it filtered, so the sender
never learns to send smaller packets and keeps trying.

## Orphaned sockets

A connection with no file descriptor left to close it, still holding kernel
memory. The kernel counts an orphan at **two to four times its weight** when it
decides whether it is under pressure, so `tcp_max_orphans` bites sooner than the
number suggests, and past it the kernel stops being polite and resets them,
which arrives at the far end as a connection dropped for no reason visible from
there.

Reported at **25%** of the ceiling. Without `tcp_max_orphans` there is no
denominator and nothing is claimed: a count on its own says nothing about
whether it is a lot.

## The path summary agrees with the finding

Naming a hop is a claim that it is the one to go and look at. `latency_wall`
already declines to make that claim below **half** the round trip: the share
test is what makes its own sentence true, and the summary line was making it
anyway:

```
latency_wall fired: False
-> biggest latency jump: +23.0ms at hop 8 (10.0.7.1), 13% of the 182ms end to end
```

Ten hops each adding about the same, and the reader sent to hop 8, where nothing
is unusual. The analysis had refused to say it; the display said it regardless.

```
-> no single hop adds most of the delay: the 182ms builds up across the path,
   the largest step being 13% of it at hop 8
```

Both read the same `LATENCY_WALL_SHARE`, so they cannot drift into disagreeing.
And the delay is still reported: 182ms is worth knowing about even when nothing
on the path is at fault for it. Silence would be worse than the wrong hop.

### Why there is no waterfall

A per-hop latency bar was prototyped and rejected. On a path with one wall it
restates what the summary already says in words, and less precisely: the
sentence also names whose side of the demarc it falls on. On an evenly graded
path every bar comes out the same length, which is the same conclusion the line
above now states outright.

It would have cost around eighteen columns on lines already running to ninety,
plus scaling and width handling, to say something already said. The bar chart
belongs where a reader must compare many values and no rule can summarise them;
here a rule can.

## Which part of its own answer took the time

"The service answered in 900ms" is true and useless. Getting a connection,
finishing a handshake and waiting for the application to think are three
different things with three different owners, and this connection goes to a
listener on the *same box*, so the first two should be almost nothing. That
makes the split unusually easy to read: whatever is left is the service
thinking, and none of it is the network.

```
Port 8080 answered in 307ms, of which 1ms was getting a connection,
and 305ms was waiting for the service itself.
```

Context rather than a fault. What counts as slow depends entirely on what the
service does, and a number picked here would be wrong for most of them: the
same reasoning as the throughput split above.

## Colour, for the terminal reader

`--report` is the primary way this is read. The viewer is optional, and on a
locked-down box often unavailable. The colour vocabulary is deliberately small
and means one thing throughout: **red is critical, amber is warning, green is
fine.** It is switched off unless stdout is a real terminal, and honours
`NO_COLOR`, because reports get pasted into tickets and piped into files where
escape codes are noise. It is off on a `TERM=dumb` terminal too: a dumb
terminal cannot interpret an escape sequence, so it prints it, and a report
read on a serial console or an out-of-band card would come back with `ESC[31m`
through the middle of it. `--no-color` overrides all of that for when the
detection guesses wrong.

Two tables were entirely monochrome, the interface error counters and the link
modes, which are the tables carrying the actual numbers. On a box with eight
interfaces that table is the fastest way to find the bad one, and it gave no cue
at all:

```
iface            packets   errors   drops   err/M   live
eth0          10,000,000        0       0     0.0   steady over 2s
eth1          10,000,000    9,000       0   900.0   steady over 2s     <- amber
eth2          10,000,000        0       0     0.0   steady over 2s
```

The row takes **the severity of what was found about that interface**, read off
the findings by their `scope`. It is not a second opinion formed in the
renderer: the tables would otherwise need their own copy of every threshold: 
what counts as an error rate, a drop rate, a slow link, and a second copy of a
rule is a second chance to disagree with the first.

An `ok`-severity note is not a reason to mark a row. Context like `tunnel_mtu`
or `virtual_nic` carries a scope and leaves its row plain, because nothing about
it is wrong.

**"Needs hands on it" gets no colour of its own**, deliberately. Three colours
that each mean a severity is a vocabulary a reader learns once; a fourth meaning
something else entirely would dilute it. The words carry that distinction, and
the colour keeps meaning severity everywhere it appears.

## A fix that needs hands is marked as one

Findings are separated by a fifth axis, alongside layer, direction, scope and
relation to the verdict: **does fixing this mean somebody in the room?**

```
owner: the fibre link into this device   confidence: medium (15 of 16 checks ran, 1 needing hands on it)

[CRIT] L1 Physical   eth0: optical receive power is -32.0 dBm, below the...
                     ^ the cause · needs hands on it
```

Not a severity, an **action**. Everything else in this report is read,
configured, or escalated to whoever owns the next segment. These thirteen need
a connector reseated, an optic cleaned, a cable swapped, an adapter replaced or
an air intake cleared:

| | |
|---|---|
| the optics | `optics_alarm`, `optics_rx_low`, `optics_rx_marginal`, `optics_warning` |
| frames arriving damaged | `link_errors_live`, `link_errors_historical` |
| a link that keeps going away | `link_flapping_live`, `link_flapping`, `link_flapping_logged` |
| the adapter, and redundancy | `nic_reset_logged`, `bond_degraded` |
| cooling | `cpu_throttled_live`, `cpu_throttled_historical` |

**What it deliberately does not claim.** A duplex mismatch, a link negotiated
below its port's rating, a collision count, a ring overrun and an invalid frame
length are each *either* something physical or a setting forced at one end, and
this tool cannot tell which from where it stands. They are left unmarked rather
than sending somebody to a rack on a coin toss.

So the rule is not "is this hardware". It is **does this tool know the fix is
physical**, which is a smaller and more honest set. Twenty-one findings here are
hardware-derived; thirteen of them are ones where the answer is unambiguous.

## What the stage strip will not be asked to carry

The strip is the chain this tool reasons about: clients, link, address,
gateway, internet, DNS, MTU, ports - the way in, then the box, then the way
out. A finding that moves none of it is allowed: a wrong
clock breaks authentication and certificate validity rather than the wire, and
the strip does not model that, but only as a **warning**.

A *critical* finding that moves no stage produces this:

```
verdict: CRITICAL
strip:   clients -  link SKIP  address PASS  gateway PASS  internet PASS  dns PASS  mtu SKIP  ports SKIP
```

A critical verdict beside a strip on which nothing failed: the same misleading
silence as `link PASS` on an adapter that cannot fail a link check.

The exemption list was flat, so nothing stopped a future hardware fault being
added to it and shipping that report. A guard now refuses to excuse a critical
finding: give it a stage, make it a warning, or do not add it.

**This is why RAID and IPMI are not here.** A failed array member or a dead
power supply read over IPMI is a real, critical fault and belongs to no part of
the network chain. Adding either would mean choosing between a strip that
contradicts the verdict and a strip that stops meaning "the chain", and the
strip is the thing that answers *where*, which is the question this tool is
built around.

Nothing about that is a claim they do not matter. It is a claim that a network
diagnostic saying "your array is degraded" has stopped being a network
diagnostic, and that the honest place to notice a degraded array is a tool that
watches arrays. The one hardware fault that *is* here: CPU thermal throttling: 
earns its place because it costs the cycles that move packets, which is a chain
this tool can follow.

## Nothing is truncated in silence

Two lists were cut to a fixed length and rendered as though that were all there
was.

**The verdict's unrelated faults.** That field exists for one reason: so naming
a root cause does not hide a second, separate problem. It showed two and stopped,
so a box with four unrelated faults reported two, and the field undercut its
own purpose. The cap is still right (the point is not to hand the findings list
back a second time), so the count comes with it:

```
also, unrelated: the certificate on the target expired
also, unrelated: a resolver is answering with the wrong address
and 2 more unrelated finding(s) below
```

**Resolver answers.** The DNS panel showed the first three and no more, so two
resolvers that *disagreed* could render as identical rows: on the one panel a
reader uses to check whether they agree, while `dns_disagree` was firing about
it three lines above.

It now reads `192.0.2.1, 192.0.2.2, 192.0.2.3 (+1 more)`. That does not make two
disagreeing rows look different. Naming the disagreement is what `dns_disagree`
is for, but it stops the row asserting it showed everything, which is what let
the two look alike.

Both are the same defect as the average hiding the peak below: the analysis knew
something the display did not say.

## The table does not let an average hide a peak

The oldest complaint about every tool that consolidates by mean: the peak
flattens as the window grows, until a line that filled every minute reads as
quiet. This report was computing the peak and printing the average, and the two
sat three lines apart, disagreeing:

```
the site uplink hit 50.0 Mbps of 50 Mbps in bursts - full for about 40s of
the 120s window, while averaging only 46% across it...

eth0   10,000,000   0   0   0.0   steady over 120s   23.17/0.0 Mbps rx/tx (2.3% of link)
```

**Full** and **2.3%**, about the same interface, in one report. Both numbers were
correct and nothing said why they differed:

| | |
|---|---|
| the finding | the **peak**, against the **site uplink** given with `--uplink-mbps` |
| the table | the **average**, against the **NIC's** negotiated speed |

Two different statistics against two different denominators, and the table
named neither. It now names both:

```
eth0   ...   23.17/0.0 Mbps rx/tx (2.3% of the 1000M link), peak 50
```

The peak appears only when it exceeds the average by **20%** or more. Below that
the two tell the same story and printing both is noise. It is a ratio rather
than a fixed gap, because a 10 Mbps peak over a 1 Mbps mean matters and a 1000
over a 999 does not.

This is the same lesson `saturation_bursts` was written for. That lesson had
been applied to the *analysis* and never to the *display*, which is a layer with
rules of its own that nothing here was testing.

## The list says what explains what

The relationships were already in the verdict: `based_on`, `explains`,
`unrelated`, and the report printed them as a line of **raw finding codes**
above a flat list:

```
this also accounts for: inet_partial_loss, call_quality_degraded
```

So a reader had to match `inet_partial_loss` against the entries below by eye to
see which fault was the answer and which were its consequences. That structure
is the whole product, and it was the one thing the report did not say.

Every finding now carries where it stands, in both the terminal and the page:

```
[CRIT] L2 Data link   eth0 is running at 1000.0 Mbps on a 1000 Mbps link...
                      ^ the cause
[WARN] L3 Network     Packet loss (7%, 1 of 20 probes) reaching 8.8.8.8...
                      ^ caused by it
```

| | |
|---|---|
| **the cause** | the verdict's own finding, the first entry of `based_on` |
| **backs it up** | an independent fault that corroborates it |
| **caused by it** | a consequence: fix the cause and this goes with it |
| **separate problem** | it will still be there afterwards |

No diagram, and deliberately. A fault tree drawn as a graph would need a layout
library, and this file ships no external assets, but the thing a fault tree is
*for* is knowing which node is the root and which hang off it, and a flat list
that labels each entry says that without drawing anything.

The relation is worked out **once, in Python**, and attached to each finding
before the report is written. The viewer reads it rather than recomputing it:
two copies of a rule are two chances to disagree, and a test pins the page's
wording to the terminal's so the two cannot drift into different vocabularies
for the same idea.

## A virtual NIC cannot fail a physical check

On a paravirtual adapter: `virtio_net`, `vmxnet3`, `hv_netvsc`, `xen-netfront`,
`ena`, `gve`, the CRC, frame, collision and optical counters are **hardwired to
zero by the driver**. There is no cable to damage, no duplex to mismatch, no
optic to dim.

So every physical-layer check passes, and the stage strip reads `link PASS` on a
box where the link could not have failed the check. That is the most misleading
sentence this tool can print, and it was printing it on every cloud instance and
every VM.

`virtual_nic` names the adapter and says what its silence is worth: not that
anything is well, but that the question cannot be asked from inside the guest.
If the physical link is genuinely suspect, it has to be read on the host.

It is context and exempt from the verdict. A virtual NIC is not a fault, and
most boxes this runs on will have one.

The driver comes from the sysfs symlink at
`/sys/class/net/<iface>/device/driver`. Interfaces with no device behind them: 
bonds, VLANs, tunnels, have no driver to read, which is not a failure: there is
nothing there to name.

This is the same rule applied everywhere else here, *a check that could not run
is never reported as a fault*, pointed at a check that **does** run, returns
zero, and could never have returned anything else.

## Which of three is holding throughput back

The kernel times how long a connection could not send because the far end had
no window left, and how long because this box had nothing queued. Whatever is
left of its busy time is time spent **waiting on the path**.

Two of those three already produced findings here: `tcp_flow_receiver_limited`
and `tcp_flow_sendbuf_limited`, and the third never did. So the tool could say
*"it is the far end"* and *"it is this box"*, and could not say *"it is the
network"*, on a run whose entire subject is the network.

```
receiver 2%  +  sender 2%  ->  path 96%
```

Reported as **context, never a fault**: a transfer limited by the path is
usually TCP working exactly as designed. The value is in being able to answer
*why is it slow* with which of three things is responsible, since the three have
three different owners, and to answer it from the traffic the box is really
carrying rather than from a probe.

Only connections that have actually been sending for **1 second** are counted.
The percentages are shares of busy time, so on a connection that has barely
moved they are all zero, and subtracting zero from a hundred would report an
idle socket as limited by the network, confidently, on no evidence at all.

The remainder is clamped at zero. The two shares the kernel reports can overlap
slightly, and a negative share of anything is a nonsense to print.

## A link that was up last time

The live checks say nothing about an interface being down, and that is
deliberate: from a single visit there is no telling a failed link from a spare
NIC nobody ever plugged in, and calling an unused port a fault is the kind of
noise that gets a tool ignored.

**A baseline settles it.** This interface was up when somebody last looked, so
its being down now is a change with a known-good reference behind it, which is
why mature monitoring systems pin the expected interface state at discovery
rather than guessing it. The comparison now reports it, along with an interface
that has gone from the box entirely: renamed, removed, or failed to come back
after a reboot.

Two details worth stating:

**`unknown` counts as up.** Loopback, tun devices and several virtual drivers
never call the kernel's operstate machinery at all, so they sit at `unknown`
while working perfectly. Treating that as down would report every tunnel on the
box as a regression.

**`lowerlayerdown` is kept as the kernel said it.** That state is the kernel
naming the cause for us, a VLAN or bridge member whose parent went away: 
and flattening it to "down" would throw away the one word that says where to
look.

This is the one comparison here with **no rate discipline**, and deliberately.
A link state is not a share of anything: it changed or it did not, so there is
nothing for a floor to protect against. Compare with the counters below, where
the absence of a floor was a real defect.

## A change is not a fault on its own

`--baseline` reports what moved since a previous visit, and anything that moved
in the wrong direction raised `regression_since_baseline`. Applied to the error
counters, that meant **one new error between two visits was a regression**: a
relative deterioration of infinity and an absolute nothing. A healthy box
rechecked next week reported that it had got worse, every time.

The live check on the same counter has always been disciplined about this: it
needs **100 errors per million** across at least **20,000 packets**. The
comparison had no bar at all. It has the same one now, measured on what moved
*between* the two visits rather than on lifetime totals.

Both halves are needed and each rejects what the other lets through. Five errors
in a hundred packets is 50,000 per million and means nothing, because a hundred
packets is not a sample. One error in a billion packets is a real event and not
a rate.

The same rule applies to the call score: 4.5 down to 4.2 moved the wrong way and
is still a call nobody would complain about, so it is reported and not called a
deterioration. It becomes one when the new score is actually poor.

**Below the bar the change is still reported**, as neutral, with the rate it
worked out to. The rule is about what counts as a deterioration, not about
hiding data, somebody hunting an intermittent fault wants to see that two
errors appeared. And where the packet counter did not move at all there is no
rate to compute, so nothing is claimed: a sample that cannot support the claim
does not get to make it, which is the same discipline as everywhere else here.

## The same fault on every cable

The flow checks have always reasoned this way about peers: loss to one
destination is that destination, loss to every destination is the local link.
The same reasoning was missing for the cables. A box with eight NICs all
reporting errors produced eight findings, and the verdict picked whichever came
first and blamed **that cable**, at medium confidence, on a box where the cable
was demonstrably not what they had in common.

`fault_on_every_interface` fires when the same interface-scoped finding covers
**every active interface**, and there are at least three of them. Both halves
matter and each rejects what the other lets through:

| | |
|---|---|
| three, not two | a box with two bad patch leads is a box with two bad patch leads |
| all of them, not merely enough | three bad out of eight is three bad cables, and the five clean ones are the evidence that whatever they all share is working |

A single-NIC box can never reach it, which is the point: one interface is
always "every interface", and saying so would turn the commonest hardware there
is into a shared-cause fault.

## Why a connect failed

A connect that fails instantly because the kernel has no route, and one that
fails after waiting because nothing came back, are opposite situations. Both
landed in the timeout bucket, which describes only the second, and sends the
reader to the network for a routing table on this box.

| errno | reason | owner |
|---|---|---|
| `ENETUNREACH` | `no_route` | **this device's routing table**. Nothing reached the wire, so nothing on the network had the chance to fail |
| `EHOSTUNREACH` | `host_unreachable` | the router that answered, something forwarded partway and reported the destination unreachable from there |
| `ECONNREFUSED` | `refused` | unchanged |
| everything else | `timeout` | unchanged |

`no_route_to_target` is critical even when the port came from the `common`
preset. A preset port asserts nothing about a service, but a missing route is
this box's own configuration whichever port happened to ask the question.

The mapping names both the platform constant and the Linux number, the way the
refused branch beside it already did, `ENETUNREACH` is 101 on Linux and 51 on
BSD.

## Delay that will not sit still

TCP reports its round trip as `rtt:87.5/45.2`, smoothed, then variance. The
parser took the first number, so the second was dropped on the floor. It is the
only jitter figure here **measured on the traffic this box actually carries**;
everything else comes from probes, which a router is free to deprioritise.

It fires at **30ms of variance** *and* **half the round trip**. Both are needed
and each rejects what the other lets through: the absolute figure alone fires on
any long path, where tens of milliseconds of movement is ordinary, and the share
alone fires on a LAN where 0.2ms becomes 0.5ms and nothing is wrong.

Nothing has to be lost for this to bite, which is why it is worth its own
finding: a retransmit timer sized for the worst case is a timer that waits, so
recovery stalls and throughput falls while every loss figure in the report stays
clean. Split by side, because a path to the backends and a path to the users are
two pieces of equipment with two owners.

## Connections killed by the other end

A well-behaved connection ends with a FIN. A reset on an established one means
somebody gave up on it mid-flight. The counter records the teardown **without
saying who sent it**, so this box's own reset count is used as the check: when
it sent far fewer than the number of connections that died, the rest arrived
from outside.

That last step is stated as an inference rather than a measurement, because that
is what it is. A session-tracking firewall timing connections out, a load
balancer recycling them, and a backend restarting all look identical from here.

It faces **upstream** where `resets_sent_high` faces local. One is this box
refusing, the other is this box being refused. The same wire event with opposite
owners, and they must not corroborate each other into a confident wrong answer.

## What the cause accounts for

The verdict has always said what it *cannot* explain. It never said what it
does, and that asymmetry produced the worst sentence this tool has printed:

> **LIKELY ROOT CAUSE:** The link is full. It is being used to capacity, not broken
> *Also, unrelated:* Packet loss reaching 8.8.8.8… Suggests upstream congestion or an unstable WAN link.

The link being full is *what causes* that loss. The report named the fault
correctly and then, in the next line, sent the reader to their carrier about the
symptom of it. That is the exact failure this tool exists to prevent.

The bug was using **layer distance** as the test. Anything above the cause was
called something the cause could not explain, but a layered stack is precisely
a thing where faults below produce symptoms above. A full link is layer 2 and
the loss it causes is layer 3.

Layer alone cannot fix it either, because an expired certificate is also above
a bad cable and no amount of recabling renews it. What separates the two is
**what kind of finding it is**:

| | |
|---|---|
| a *transport symptom* | traffic lost, delayed, or timing out, the shape any fault below produces when it bites. **Explained** by a cause underneath it. |
| a *state or a decision* | a certificate that has run out, an answer that came back wrong, an address claimed twice, a device refusing on purpose. **Survives** fixing anything below, so it is genuinely unrelated. |

Both DNS findings show the split: a resolver **timing out** is what a degraded
path looks like from one layer up, and is explained. A resolver **answering with
the wrong address** is a fault of its own, and is not.

Direction still overrides everything, as it does for corroboration. Loss the
clients see is not a consequence of loss on the path to a backend whatever the
layers say.

The verdict now carries `explains`, and the report prints *"this also accounts
for: …"* beside the count of what corroborates it. Two general assertions hold
it honest across every scenario: nothing is ever both explained and unrelated: 
that would be the report contradicting itself in adjacent lines, and nothing is
ever both corroborating and explained, which would be the verdict using one
fault as its own proof and its own result.

## Too hot to move packets

A CPU that is clocking itself down loses cycles exactly where a box that moves
packets needs them. The receive backlog fills, latency spikes for no reason
visible on the wire, retransmits climb, and every one of those is a finding
here that points somewhere else. None of them is wrong. All of them are
downstream of a box too hot to run at speed.

This reads a **count of throttling events**, not a temperature. Every threshold
anyone picks for "too warm" is wrong on some hardware, whereas a box that has
actually been throttled has already lost the cycles. It is the same preference
as reading a table's refusals rather than how full it looks.

| | |
|---|---|
| `cpu_throttled_live` | the count moved during the check. It is happening now |
| `cpu_throttled_historical` | non-zero since boot, not moving. Cooling that is marginal rather than failed, which bites at the busiest hour and never reproduces afterwards |

The kernel documents every CPU in a package as reporting the same package
counter, so these are **maxed, not summed**: adding them reports sixteen
throttling events on a sixteen-core box that had one.

This is not a load check, and the distinction is the point. A busy box is not a
fault; a box being clocked down by its own hardware is. The guard that keeps
load out of the findings used to ban the `cpu_` prefix outright, which stated
the rule as a spelling convention and blocked a real fault. It now names the
load-derived codes, and the assertion with teeth is still there: load average
99 on one core, and the verdict is `ok`.

## A hop that said why

traceroute prints the ICMP reason next to the time: `!X`, `!H`, `!N`, `!F` and
the rest. All of it was being dropped along with everything else that was not a
number, which is how a hop that told us **exactly** why it would not forward got
reported as an unexplained silent path.

The reasons are now kept on the hop and shown in the path panel, and one of them
produces a finding. `!X` / `!A` / `!T` mean *administratively prohibited*: a
device received the traffic, decided against forwarding it, and reported the
decision. That is configuration, not a fault, so there is a policy to read and
a person to ask, rather than a carrier to open a ticket with.

The condition that matters is **whether the path still completed**. A policy
device that declines traceroute probes while forwarding traffic normally is
common and benign; the same annotation on the hop where the path stops is a
firewall standing in the way. Only the second fires.

`!H` and `!N` are deliberately excluded. A router reporting that it cannot reach
onward is describing a broken path, not making a policy decision: a different
fault with a different owner, and one the existing reachability rules already
cover.

## A baseline that is not a report

`--baseline` takes a file the operator names, and being handed the wrong one is
ordinary: a truncated write, an mtr export, last week's inventory, a typo that
lands on a different JSON file. The loader already rejected anything that would
not parse. What got through was **valid JSON with a foreign shape**, and it
crashed the comparison half way through the run, losing the entire diagnosis
over a piece of optional context.

Two layers now. The file is checked at load for the shape of a report: a
findings list and a verdict object, and rejected with a message that says what
was wrong rather than a traceback. And the comparison itself no longer breaks if
one gets past: a key that is *present and null* is not a key that is absent, and
`.get(k, {})` hands back the `None` rather than the default for it, which is
exactly how somebody else's JSON became an `AttributeError` mid-run.

The rejection is deliberately fatal rather than a warning-and-continue. Somebody
who asked for a comparison and silently did not get one would read the report as
though it had been compared.

## "own" says whose service, not which check

The family heuristic splits a finding's code on its first word: right for four
port results, and wrong when the first word is a scope marker. `own_` means
*this box's own*, and it was putting two genuinely separate checks in one
family: reading the certificate this box serves, and making an HTTP request to
it.

The effect was an understatement rather than an overstatement: an expired
certificate could not corroborate the service erroring, so two independent
signals were counted as one and the confidence came out lower than the evidence
justified. That is the safer direction to be wrong in, and still wrong.

`link_` was looked at for the same reason and deliberately left alone. Errors,
flapping and saturation are arguably three measurements of one cable or one
check of it depending on how you count, and changing it would move the
confidence of many verdicts on a judgement call rather than on a demonstrable
error.

A test now asks the whole override table two things: that every key names a
finding that exists, and that no override puts a code in a family of its own: 
a line that reads as a rule while doing nothing.

## What the tools actually print

Every fixture in this suite was written from an *idea* of what these commands
emit. That idea was checked by describing the real output independently, then
diffing it against the parsers. Four places it was wrong. None of which any
test could have caught, because the tests asserted the same idea the code did.

**A receiver seeing nothing prints `-inf`.** A module with no light arriving
reports `0.0000 mW / -inf dBm`. The dBm regex matches numbers, `-inf` is not
one, so the reading was dropped and **the single fault the optical check exists
for produced no finding at all**. It is now recorded as `rx_dark`: its own
fact, deliberately not a very low dBm figure, because a sentinel chosen to work
as a number ends up printed in the report as a measurement. The message says
what it means: nothing is arriving, check the receive strand specifically,
because the pair can be crossed so this end transmits fine and hears nothing.

**BSD does not zero-pad MAC addresses.** macOS prints `0:0:5e:0:1:1` where
Linux prints `00:00:5e:00:01:01`. Same VRRP virtual router; only one of them
was recognised as one. On a Mac the tool saw two routers arguing over an
address and reported a **duplicate IP** instead of the failover pair it was
looking at, wrong owner, wrong advice, and no way to notice from the output.
Addresses are now normalised at the single point they enter the table.

**Drivers have several ways of saying they don't know the link speed.** Modern
tools print `Speed: Unknown!`, which no number regex matches. Older ethtool
prints the raw u16 sentinel as `65535Mb/s`, and some kernels put the u32 one in
sysfs as `4294967295`. Both parse cleanly as enormous link speeds, and a link
that claims 4 Tbps has a utilisation of zero forever, which **silently retires
every saturation check** rather than failing anywhere visible. The sentinels are
now named as the specific values they are, rather than bounded by "faster than
any real Ethernet", which is a claim that ages badly: 400G was implausible not
long ago.

**A share of an aggregate cannot exceed it.** Many drivers wire
`rx_over_errors` and `rx_missed_errors` to the same hardware counter, so adding
them counts one overrun twice, enough to print *"80 of 40 errors"* and to
drive the comparison in the section below from a number larger than the total
it is a share of. The host share is now the larger of the two rather than their
sum, both shares are capped at the aggregate, and the remainder left to the link
is never negative.

## One error burst, three owners

`rx_errors` is an aggregate. The kernel documents it as including the length,
CRC and frame counters "and other errors not otherwise counted", and this
reported all of it with one sentence, sending the reader to *"cable,
connector/SFP, or a duplex mismatch on the switch port"* whatever had actually
happened. The sub-counters were read, but only to print a parenthetical.

Which one moved decides who owns it:

| what moved | what it means | owner |
|---|---|---|
| `rx_over_errors`, `rx_missed_errors` | the receiver overflowed, or the host had no buffer ready | **this box**, ring buffer, driver, or the CPU servicing the queue |
| `rx_length_errors` | runts and giants (frames arriving at an invalid length | **the segment**) an MTU or VLAN-tagging disagreement |
| `rx_crc_errors`, `rx_frame_errors`, anything else | a frame arrived damaged | the cable, connector, optic or duplex setting |

The frames in the first row **arrived intact**. Nothing about the cable, the
optic or the switch port explains a box that failed to take delivery of them,
and its verdict deliberately contains no phrase that would send anyone to a
port. The guard that makes port-naming verdicts name the port would otherwise
append a switch port to advice that says not to go there.

The dominant cause wins, so one burst produces one finding. Where a driver
breaks nothing down (common on cheap hardware) it falls through to the link,
which is both the old behaviour and the safest guess.

`nic_ring_overruns` shares a family with the softnet backlog findings. Both are
this box failing to take delivery, counted at two depths, so neither is
independent evidence for the other.

## A discard is not an error

These were judged alike: a single dropped packet in the counter window produced
`drops_live`, exactly as a single error produced `link_errors_live`. The two
counters mean opposite things. An error is a frame that arrived damaged and
should never happen. A discard is a frame this box chose not to deliver
upwards (buffer pressure, traffic it was never going to pass on) and happens
on every busy interface there is.

So `drops_live` was the finding that was always present. Worse than noise: it
sits at layer 2, so it corroborated nearly anything above it and lifted the
confidence of conclusions it had nothing to do with.

It now needs **2%** of the window's packets, across a window of at least
**1,000** of them, two orders of magnitude looser than the error threshold,
which is the asymmetry the counters deserve. A percentage of fifty packets is
not a percentage of anything, and the window is seconds long on a box that may
be nearly idle.

One error still speaks where one discard does not. That is the point.

## A bond hides the thing it was built for

Lose one member of a bonded pair and nothing reports a fault. The interface
stays up, the address stays put, no route changes and no alarm fires: because
concealing exactly that is what a bond is for. What has gone is the redundancy
that was the reason for buying two cables, and the next member to fail takes
the box off the network.

`bond_degraded` names the member that is down and the mode the bond is in. It
is deliberately **latent**: nothing is failing, so it can never headline over
something that is. It also carries the interface as its scope, so it corroborates
faults on the same bond and not on some other cable.

All members down is *not* this finding. That is an interface with no carrier,
and the link checks already say so in better words. Reporting both would blame
the redundancy for a cable nobody has plugged in.

## The ceiling on how many neighbours this box can have

The ARP table has a hard limit and no back pressure. Past `gc_thresh3` the
kernel stops resolving addresses, so the box loses the ability to talk to
*some* of its neighbours while everything that does not need one of them keeps
working. The result is intermittent unreachability that follows no pattern and
never reproduces on demand, a setting on this box presenting as the network.

| | |
|---|---|
| `neigh_table_full` | it has already hit the ceiling, `table_fulls` times since boot |
| `neigh_table_near_limit` | at or past **80%** of `gc_thresh3`, and has refused nothing yet |

Both can be true at once; only the one that has already refused something is
reported. The count comes from `/proc/net/stat/arp_cache` rather than from
counting the entries this tool parsed: that column is what `gc_thresh3` is
actually compared against, and the parsed table mixes in IPv6. Like the
conntrack table it repeats the whole total on every CPU's row, so it is
assigned and never accumulated, adding it up puts a two-core box over its own
ceiling.

## Resets this box sends

These counters were collected for several versions before anything read them.
On a box that answers requests they are the wire-level shape of every refusal
it makes, and whoever is on the other end of one sees a connection **dropped**,
not a slow one, which gets reported as the network and is not the network.

A reset is not by itself a fault: an application that closes with data still
unread sends one, and browsers abandon connections all day. So the line sits
where the count stops looking like a by-product, **at least one reset for every
connection the box opened or accepted**. A listener that has stopped, a port
nothing is bound to, and a scan all produce exactly that; ordinary churn does
not come close.

The denominator counts outbound connections as well as accepted ones, because
the original shape of box this tool was written for accepts nothing at all.
`EstabResets` sharpens the sentence rather than firing its own finding: it says
whether the connections torn down were already established or were refused at
the door.

Its direction is **local**. The resets originate here, so this is not a fault
arriving from either side, and it can corroborate one facing either way.

## A link below its own capacity

`slow_link` can only speak in absolute numbers. It fires at 100 Mbps or less,
where a broken pair in a cable drops a gigabit port. That leaves a 10G port
sitting at 1G invisible: not slow by any threshold worth writing down, and a
tenth of what was bought.

`negotiated_below_capacity` compares the negotiated speed against the fastest
mode the hardware itself advertises, read from ethtool's supported-modes block.
It is latent (nothing fails until the traffic needs the capacity) and it
fires only **above** 100 Mbps, so one bad link does not produce two findings.
Below that, `slow_link` already says the more useful thing.

The two share a family. They are one check said two ways, and left in separate
families one link running below par read as two agreeing faults and pushed the
verdict to high confidence.

## Latency has its own words

Until now the only thing this said about a slow path was what it would do to a
phone call. An 800ms round trip to a database reported that *voice and video
will be unusable*, true, and no use whatsoever to whoever runs the database.
The score also needs a loss figure to compute, so a run that could not measure
loss said nothing about latency at all.

`latency_high` fires at **400ms** and says what the delay costs any traffic:
every request pays it before a byte moves, and a new TLS connection pays it
three times over. It is deliberately one threshold rather than a warning and a
critical. The verdict takes its severity from the finding that headlines it,
so a warning-level rule sitting above a critical one would quietly downgrade
the whole run.

400ms is a physical line, not a preference. Light in fibre covers about
200,000 km/s, so the far side of the planet and back is roughly 250ms and the
longest real terrestrial paths measure 250–300ms. Past 400ms distance has
stopped explaining it, with one benign exception the finding names itself, a
geostationary satellite hop, which is 500–650ms on its own with nothing wrong.

Where it sits in the ranking is the rest of the answer:

| | |
|---|---|
| below `latency_wall` | when a single hop adds most of the delay, **where** beats **what it costs** |
| below the loss rules | traffic that never arrives beats traffic that arrives late |
| above the call score | which stays in the report as a consequence of the delay, not a competing answer |

For an internal backend the verdict is re-owned, as the reachability ones
already are. The internet version tells the reader to check whether the target
really is that far away; for a box in your own rack that is the wrong question,
and the delay is queuing or a bad route rather than the width of an ocean.

**The call score does not corroborate it.** It is computed from the same round
trip, so counting it as an independent second opinion put a slow path at high
confidence on a single measurement, the same inflation two cables produced,
in a different guise. Both, and the wall, are now one family.

## Down, or unreachable

A host that is failing and a host you cannot get to are different states with
different owners. Monitoring systems have drawn that line for decades; this
collapsed both into `inet_unreachable`, owner *the provider*, which sends
someone to a carrier about their own server.

When the target answers nothing, the trace decides which it is:

| | |
|---|---|
| the trace **reached** it | `destination_unresponsive`. The path carries traffic and the host itself is silent. Owner: *the destination, not the path to it*. |
| the trace **stopped short** | `inet_unreachable`. The path is broken somewhere before it. Owner: *the provider*, as before. |

With no trace to judge by (a `--quick` run) nothing is concluded between them
and the older, vaguer finding stands. Guessing between two answers with
different owners is worse than being vague about which.

## Two cables are two faults

Findings about an interface carry which one they came from. Corroboration
counts an independent second fault at the same layer or below as agreement, and
without a scope it counted **errors on `eth0` and collisions on `eth1`** as one
problem confirmed twice, high confidence in whichever happened to be named, on
a box with two unrelated bad cables.

Same interface still corroborates: a duplex mismatch and collisions on `eth0`
are the same fault seen twice, which is exactly what the rule is for. A finding
with **no** scope is about the box rather than one of its interfaces: the
softnet backlog belongs to all of them, and agrees with any of them.

This is the same idea an alert manager expresses as scoping suppression by
label: the relationship only holds between things that are about the same
thing.

## Which way a fault faces

The ordering rule (*the lowest layer with a live fault is the cause*) is
right, and it is right **within a direction**. Direction and layer are
orthogonal axes, and the chain collapsed them into one, built for a device that
only talks outward. On a box that answers requests there are two directions:

| | |
|---|---|
| **local** | This box and its own link. Sits in both paths, so it explains symptoms in either, which is the original rule, unchanged. |
| **downstream** | Toward whoever connects to this box: the load balancer, the edge, the accept path. Broken here and clients cannot get in. |
| **upstream** | Toward whatever this box depends on: backends, DNS, the path out. Broken here and this box cannot answer them. |

The two resource ceilings show why this is not cosmetic. `fd_pressure` and
`ephemeral_ports_low` are both "this box ran out of something", and they break
**opposite directions**, descriptors stop it accepting, ports stop it opening.
Before this they were indistinguishable.

### Reading it without knowing what a layer is

"Which of the three is it" comes before "which layer", and it can be answered
by someone who has never heard of layers. The report leads with three boxes and
an arrow:

```
  clients in (10.20.0.7) FAULT  ->  this box ok  ->  depends on (10.60.9.30) degraded
```

- The state is a **word as well as a colour**: colour alone is not readable to
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
  greys out, not green, which would claim something had been examined, and not
  an alarm, because the socket table *was* read and there was nothing coming
  in. That is an answer, not a gap.

```
  clients in none connected  ->  this box FAULT  ->  depends on ok
```

The panel is shown on **every** box, including one that only talks outward. It
was hidden there at first, on the grounds that two boxes and an arrow restate an
eight-stage strip that says the same thing more precisely. That reasoning
optimises for a reader who can already read the strip, and boxes that only
talk outward are the common case, so hiding it there meant the panel written
for someone who *cannot* read the strip was the one they would almost never be
shown.

What it changes:

- **A fault facing the other way is surfaced as `also, unrelated`, whatever its
  layer.** Client-side loss and loss on the path to a backend are both layer 3,
  so the layer rule named one and presented the other as its consequence, and
  said nothing about the second. Fixing the first left the second exactly where
  it was, the failure `also, unrelated` exists to prevent.
- **A fault facing the other way is not corroboration.** Two problems is not
  one problem confirmed twice.

`FINDING_SIDE` is exhaustive rather than defaulting, so every code is a
decision someone made and a new one cannot join by accident. On a box with no
inbound service every finding is local or upstream, nothing here can fire, and
the output is **identical**, verified across all 110 scenarios, comparing
findings, headline, owner, confidence, corroboration, unrelated and every stage.

## The verdict

The top of every report names one likely root cause, who owns it, and what to
do next, so you don't read eight findings to work out which one is the cause
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
*live* fault is the root cause, and each rule names the owner. This device,
the site network, the provider, or the destination. A dead gateway with failing
DNS on top reports the gateway, not DNS.

Confidence is a three-way label, not a percentage. A percentage would imply a
probability calibrated against outcomes, *"of boxes that looked like this, 73%
had this cause"*, and nothing ever tells the tool whether reseating the cable
fixed it, so that number would be a formula's output wearing a decimal point.
What the verdict shows instead is the countable evidence behind the label:

```
owner: this device or its cable   confidence: medium (16 of 18 checks ran)
```

Coverage feeds the label as well as being shown. Below 70% of collections
returning data a verdict cannot be called well-supported, and below 40% it is
low confidence however well corroborated, a conclusion drawn from a third of
the checks is not the same as one drawn from all of them.

The verdict also names a fault it *cannot* explain. The layer rule assumes a
causal chain, which is what makes it useful; where there is no chain: a
flapping link and an expired certificate have nothing to do with each other: 
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
they're the answer, so none of them can raise someone else's. Without that, an
unrelated non-standard MTU sitting in the report turned a `medium` call into a
`high` one purely by being present.

No model is involved. When you're explaining a conclusion you have to be able
to say *why* the
tool concluded what it did, so every verdict cites the finding codes it was
built from (`based_on` in the JSON), and the rules are a readable list in
`VERDICT_RULES`. You can check its work, and it can't invent a cause that
isn't in the data.

## How the diagnosis works

It's a short rule-based pass, not a model: deliberately, so you can
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
6. Traceroute to the target, if every probe times out for the last
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
| **Data collections** | **33** | Distinct things it inspects on the device or the path, the routing table, the error counters, a TLS handshake, and so on. Some run more than once (two pings, one per checked port). |
| **Findings** | **160** | Distinct conclusions it can reach and state in plain language. 134 are faults; 26 are context, like which switch port you're on. |
| **Ranked causes** | **134** | Findings the verdict knows how to rank and assign an owner to. |
| **Automated tests** | **531** | 1075 tests of this program's own code. A developer number, not a measure of what it checks for you. |

**The 160 findings are the useful figure** if you want to know what the tool can
tell you. Every one has a scenario in the test suite that triggers it end to
end.

### The 33 things it inspects

**On the device**
1. Interfaces and addresses
2. Routing table and default gateway
3. Interface error, drop, CRC and collision counters
4. Carrier transitions: how often the link has dropped and returned
5. Kernel log, link transitions and NIC resets, with the times attached (Linux)
6. Packets this device drops itself: receive backlog and accept queues (Linux)
7. Connection tracking table: how full it is, and whether it has refused (Linux)
8. Link speed, duplex and MTU
9. Optical module power and alarms (fibre)
10. LLDP/CDP neighbour: which switch and port
11. ARP / neighbour table
12. TCP socket states
13. TCP retransmission counters
14. Per-connection TCP statistics: loss and stalls broken down by destination (Linux)
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
27. Bonded interface members, and which of them are down (Linux)
28. Neighbour table size against its own ceiling (Linux)
29. CPU thermal throttling counters: times the hardware clocked itself down (Linux)
30. Ephemeral ports, file descriptors and the accept-queue ceiling (Linux)
31. The TLS certificate this box *serves*, read from the outside in
32. This box's own service, asked over HTTP for an answer rather than a connection
33. Proxy configuration, how this box is told to reach the internet: the
    `http_proxy` family, and on macOS the system settings including a PAC file
    or WPAD. Read, never probed

**Derived from the above, not separately collected:** call quality (MOS), the
site edge and network handoffs, latency deltas and jitter per hop, link
utilization, and the comparison against a `--baseline`.

## When the box has a smaller userland

Appliances, containers and embedded builds ship trimmed commands. Busybox and
toybox provide a `ping` that takes `-c` and not `-W`, an `ip` that knows a
subset of the real one, a `netstat` where `ss` is absent. Two different
problems come out of that, and they need different answers.

**A command that is absent** is handled: every check that has more than one way
to ask asks in order, and says none of them is installed rather than inventing
a fault.

| Check | Tried in order |
|---|---|
| interfaces | `ip` then `ifconfig` (`ipconfig` on Windows) |
| routes | `ip` then `netstat` or `route` |
| neighbours | `ip` then `arp` |
| listening ports, sockets | `ss` then `netstat` |
| traceroute | `traceroute`, then `tracepath` (`tracert` on Windows) |
| DNS | `dig`, then `nslookup`, then `host` |
| clock | `chronyc`, then `timedatectl`, then `ntpq` |
| kernel log | `dmesg` then `journalctl` |
| TCP trace | `tcptraceroute`, then `traceroute -T`, then `mtr` |
| switch neighbours | `lldpctl` then `lldpcli` |

Every one of those moves on when a command **fails**, not only when it is
missing. That was four chains and is now all of them: a `dig` that exists and
rejects a flag no longer loses resolution on a box with two other lookup tools
installed, and an `ss` that exists and fails no longer takes the socket table
with it, which every client and serving finding is built from.

Where only one utility can answer, there is nothing to fall through to and the
rule is instead that a failed read is reported as one. `ss -tin` is the case
that matters: parsed as an answer, a trimmed `ss` becomes zero connections, and
zero connections is indistinguishable from a box with nothing connected, which
is a finding rather than a gap.

**A command that is present and does not understand us** is the harder one, and
was losing checks silently. `which` sees `ping`, the tuning flag comes back
rejected, and reachability, loss and latency are all thrown away over an
argument the box never needed. Nothing was wrong with the network and nothing
said so: the report warned that it could not read the gateway.

The ping now asks twice. The informative form first, then the portable one, and
only when the output says the command did not understand the request - an
invalid or unknown option, a usage line, a busybox banner. A command that ran
and returned a bad result is an answer and is never retried: a host at 100%
loss is a finding, not a vocabulary problem, and probing it twice would double
the wait on a slow link to learn the same thing.

**A command that is present and fails** was the same bug wearing different
clothes, and a worse one. Those chains chose on existence: `which` saw `ip`, so
`ifconfig` was never tried, and a trimmed `ip` whose subcommand does not exist
took the whole interface list with it. The result was not a gap. It was `no
IP address on any interface`, the highest-ranked critical in the tool, on a
machine with nothing wrong and `ifconfig` sitting unread beside it.

Interfaces, routes, neighbours and listening ports now run the candidates in
order and take the first that answers. Exit zero with nothing on stdout does
not count as answering, because that is the other way a trimmed command fails:
it accepts the words and prints nothing.

The two retries stay separate because an answer means different things. One
command asked twice: a failure is a result, and only a rejected flag earns a
second attempt. Several commands describing the same state: nothing is an
answer until one of them produces output, so any failure moves to the next.

**A box where none of the commands are ours** is the end of that road. A vendor
OS, a container built from scratch, an appliance with its own shell: `which`
finds names, none of them understand us, and the chain runs out. Two things
were wrong past that point.

The chain handed its last failure upward as a success. A command that ran and
exited non-zero with nothing to say arrived downstream as a successful read of
a machine with no address and no gateway, so the box was told it was broken
rather than that it could not be read. A non-zero exit is a failed read now.
Exit zero with no output is not: an empty neighbour table is a real answer, and
the only honest one on a box that has spoken to nobody.

And nothing asked the one source that cannot be trimmed. The facts are not in
those programs, they are in the kernel, and on Linux the kernel publishes them
as files:

| Read | From | Gives |
|---|---|---|
| default route | `/proc/net/route` | the gateway, so every gateway check still runs |
| neighbours | `/proc/net/arp` | who answered, including entries that never did |
| this box's own address | a UDP `connect`, no packets sent | that it has one, and a way off itself |

These are last resorts, tried only after every command has failed, because a
working `ip route` says more than `/proc` does. They return nothing rather than
an error when they cannot answer, so the reported reason for a run knowing
nothing stays the foreign commands rather than becoming the fallback.

Rendered into the format the richest command prints, so the same parsers and
the same ranked rules produce the verdict. A box with no userland is diagnosed
by the rules everything else is, not by a second thinner set.

The address read is the narrow one. It answers "this box has an address and a
route off itself", which is what the missing-address finding asks, and it
cannot say which interface holds what. A self-assigned `169.254` is not
accepted: that is a box that never got on the network, and offering it as proof
would suppress the finding that says so.

## Choosing a target

Everything measured "off the device" is measured to one host: reachability,
loss, latency, the hop-by-hop path, path MTU, call quality. Change the host and
you change what the verdict is about. `--target auto` picks the backend this
box has the most connections open to, because a service that cannot reach its
database has a problem whether or not the internet is up.

`8.8.8.8` is only the fallback, used when there is no backend to find: a box
with no clients connected, or one forwarding traffic for so many destinations
that no single one is meaningful. The report says so on the second line, so a
verdict about a public resolver is never mistaken for a verdict about your own
service.

**Prefer something you actually depend on.** The database, the API gateway, the
license server, the destination a user is complaining about. That is the path
whose loss matters to you, and the one whose owner you can call.

What to aim at depends on which question is being asked, and the three
questions want different targets.

**"Can people here use the internet at all?"** This is the common one on a box
whose users browse and whose applications live elsewhere. Aim at a large web
host and name the port, which is what turns a reachability check into an
end-to-end one:

```bash
python3 faultone.py --report --target www.google.com --check-ports 443
```

That exercises the whole chain a browser uses: the name resolves, ICMP gets
through, TCP 443 completes, and the TLS handshake succeeds. The port check
reports the certificate as well, which is the part worth reading twice:

```
www.google.com:443       open   TLSv1.2, issued by Google Trust Services, 61d left
```

An issuer that is not the site's own is a proxy re-signing traffic in the
middle. That is a normal thing to find on a corporate line and a surprising one
on a customer's, and nothing else in the report will tell you.

Anycast is not a caveat for this question. A large web host answers from the
nearest edge, which is exactly where the users' traffic goes, so the nearest
edge is the honest thing to measure. `www.google.com`, `wikipedia.org` and
`github.com` all answer ICMP and resolve everywhere; any of them does.

**"Is the path to the thing we depend on healthy?"** Aim at the thing. The
database, the API gateway, the licence server. `--target auto` does this for
you on a box that has connections open to one.

**"Is there loss that only shows over distance?"** Now a regional endpoint
earns its place, because anycast will not put distance in the path:

| Region | Endpoint |
|---|---|
| US East | `ec2.us-east-1.amazonaws.com` |
| US West | `ec2.us-west-2.amazonaws.com` |
| Europe | `ec2.eu-west-1.amazonaws.com` (Ireland), `ec2.eu-central-1.amazonaws.com` (Frankfurt) |
| Asia Pacific | `ec2.ap-southeast-1.amazonaws.com` (Singapore), `ec2.ap-northeast-1.amazonaws.com` (Tokyo) |
| South America | `ec2.sa-east-1.amazonaws.com` |

These are the narrowest of the three, and they cost something. They do not
answer ping at all: they resolve and take TCP on 443, so reachability and the
verdict hold up through the fallback of reaching the target the way an
application would, but the checks that need ICMP have nothing to work with.
Measured here, roughly one full run in three came back with
`pmtu_unmeasurable`, which takes the headline on an otherwise clean box and
exits 1, because it is a warning about coverage rather than a finding about the
network. Pair them with `--quick`, which skips path MTU.

**The neutral addresses** are still the right answer for "is IP working at
all", and they are what `--target auto` falls back to:

| Host | Notes |
|---|---|
| `8.8.8.8`, `8.8.4.4` | Google Public DNS. Answers ICMP reliably |
| `9.9.9.9` | Quad9 |

The fallback is deliberately an address and not a name. Pinging a name needs
DNS to work first, so a name would fold two questions into one and report a
DNS outage as unreachable internet. The resolver checks answer the DNS question
separately.

Two things to know before reading too much into any of them. A public host is
under no obligation to answer you: ICMP is commonly rate-limited or
deprioritised, so a little loss to a public address is often the host
protecting itself rather than a network fault. And they measure the path
outward only, which is why a finding about them names the outbound direction
and says the return path was not tested.

## Choosing what it sends from

`--target` decides where the probes go. On a box holding more than one address,
`--source` decides where they leave from, and on a proxy that is the more
important of the two.

A box terminating a service address holds at least two: its own, which is how
you reached it, and the address clients arrive on. They are not
interchangeable. The kernel picks the interface's primary address unless told
otherwise, so every measurement in a default run is about the management path,
and the path your users take is never touched.

The faults this separates out are the ones that discriminate by source
address, which is most of the interesting ones:

| | |
|---|---|
| policy routing | a rule matching on source sends the two addresses out different interfaces or different uplinks |
| asymmetric return | the reply to the service address comes back a different way, or does not come back |
| filtering or NAT keyed on source | an upstream ACL, or a translation that exists for one address and not the other |
| reverse-path filtering | a router drops what arrives from an address it would not route back to |

Every one of them works from the box's own address and fails from the service
address. A run that lets the kernel choose measures the first, finds nothing,
and reports a healthy box.

```bash
python3 faultone.py --report --source 203.0.113.10 --target 10.0.0.20
```

**What is bound, and what cannot be.** Every probe that can name a source does:
ping, both traceroutes, the TCP trace, the path MTU probe, DNS queries, the
port checks and the TLS handshakes. The socket-based ones bind before
connecting, so an address the box does not hold fails in the kernel before a
packet leaves. The command-driven ones carry the flag their utility takes,
which is three different spellings for one idea: `-I` for Linux ping, `-S` for
BSD and macOS ping, `-s` for both traceroutes, `-a` for mtr, `-b` for dig.

A few utilities have no such option at all: Windows `ping` and `tracert`,
`tracepath`, and `nslookup`. Where one of those is the only one available, that
single check leaves from whichever address the kernel chose, and the finding
says so rather than claiming the whole run was bound. The first version of that
finding did claim it, which was a sentence the code did not keep.

A source of the wrong family is not bound rather than refused. A run bound to
an IPv4 address still has to be able to reach an IPv6-only target, and refusing
would turn "measure from this address" into "only measure what this address can
reach", which is a different and much less useful instruction.

**A box that does not hold the address is the finding, not an error.** The
kernel refuses to bind, before a packet is sent, and that is reported as
critical and outranks everything else in the run. It is what a standby node
looks like: the address lives on its partner, and a run that let the kernel
choose would have measured this node's own address and called the box healthy
while it served nothing.

The address has to be an address. A hostname or an interface name is refused
at the front rather than half-honoured, because Linux `ping -I` would accept an
interface and nothing else in the tool would, which is a flag meaning one thing
on one platform and something else everywhere.

**Without `--source`, a service address is still reported**, as context rather
than a fault. A host route sitting on an interface that also carries a real
subnet, a `/32` beside a `/24`, is the shape keepalived and the load balancers
in front of one leave behind: the box's own address comes with the prefix of
the network it is on, because that is what tells it who is local, and a service
address does not need one. The report names it and says plainly that nothing
was measured from it.

The shape is context and not a certainty, deliberately. Point-to-point links
and several cloud instances present the box's own address as a `/32`, which is
why the second address on the interface is what makes it mean anything: alone,
a `/32` is just how that network is built.

### Whether anything is using it

Holding the address is the easy half. The half that goes wrong quietly is what
happens next: the address is configured, it answers ARP, and the traffic is
going somewhere else. A failover that moved the address without moving the
traffic, a partner that never gave it up, a service that died and left the
address behind. Every other check in this tool passes on that box.

Two readings answer it, and both come from sockets the run already collects:
what is bound, and which of this box's addresses live connections arrived on.
The second is new. The local port of every established connection was already
kept and the local address thrown away, which answers "is anyone connected" and
can never answer "connected to what".

| Finding | What it means |
|---|---|
| `service_address_unserved` | nothing is listening on the address, and no wildcard covers it. Clients get a refused connection while ARP answers normally, which is why the box still looks reachable |
| `service_address_idle` | something is listening, and no connection is arriving here while connections arrive on the box's other addresses. Traffic for this address is going somewhere else |

Both are warnings rather than faults, for the same reason: this reads userland
sockets, and a box forwarding in the kernel serves a service address with
nothing bound to it at all. IPVS, an nftables or iptables DNAT rule, and every
direct-return load balancer look exactly like an unserved address from here.
That is the normal shape of the deployment this section exists for, so an
absent listener is reported as something to look at, never as a broken box.

A wildcard bind counts as serving every address the box holds, including one
added after the process started, with one exception: `0.0.0.0` is the IPv4
wildcard and never accepts an IPv6 connection, so it does not cover an IPv6
service address. `::` does cover both, because a dual-stack listener on it
takes IPv4 as mapped addresses, which is how most of them are built. That is the common case rather than an edge
one: a server on `0.0.0.0` with a service address placed underneath it by
keepalived is most of these boxes, and calling it unserved would be wrong about
nearly all of them.

`service_address_idle` needs traffic arriving elsewhere before it says
anything. A box nobody is talking to is idle, not broken, and the finding is
about traffic that is arriving and choosing another address.

### The way you got in is not traffic

Every connection this tool counts to decide whether a box is doing its job is a
connection somebody made, and some of them are yours. A box being worked on
usually has more than one window open on it, and three admin sessions were
enough to satisfy every "is anyone using this" threshold here. On an idle box
that was enough to report a service address as up and taking nothing while
traffic arrived elsewhere, and to make that the verdict. The traffic arriving
elsewhere was the diagnostic's own presence.

Sessions matching the way in are no longer counted as traffic served. The match
needs both halves, the peer and the port arrived on, and neither alone is
enough: on the peer alone it would discard real traffic from a host that is
both a way in and a client, and on the port alone it would discard every
session on a box whose actual job is SSH.

A jump host is why the peer is read from the connection rather than assumed.
Arriving through one, the box sees the jump host as the client, so every
operator working through it lands on the same address, and all of those
sessions are set aside together. Piping the tool in over `ssh -J` needs nothing
else: it runs on the box, so the paths it measures are the box's paths, and the
jump host is not in any of them.

With no session to read, from a console or from cron, nothing is excluded.
Guessing which connections were somebody's way in would be worse than counting
all of them.

Counts are per address and no peer is ever listed. Who is connected to this box
is not something a report pasted into a ticket should carry; which of its own
addresses they arrived on is a property of the box, and its addresses are in
the report already.

## One row per thing this box serves

A box running several instances behind several addresses has no single answer
to "is the service up", and every check here produced one anyway: a certificate
read off one listener, a connection count for the whole box. `SERVICE
INSTANCES` is a row per endpoint, printed whenever there is more than one,
since a box serving a single thing is already described by the findings and a
one-row table is furniture.

```
SERVICE INSTANCES
  name                  endpoint              up                  serving
  broker-a.example.com  10.0.0.200:443        ok                  5 connection(s)
  broker-b.example.com  10.0.0.201:443        expires in 9d       nothing arriving
```

A row earns its line by having had something learned about it: a probe reached
it, traffic is arriving on it, or somebody bound it to one specific address,
which is a decision rather than a default and is how a deliberate instance is
configured. An ordinary machine holds a dozen wildcard listeners it got from
its own operating system, and a table of those all reading "listening, nothing
arriving" buries the two rows that matter. Every listener stays in the export
either way, because what is listening is a fact.

**Up and serving are two columns, not one light.** An instance that has just
started, or one a load balancer has not sent anything to yet, is up and not
serving. Collapsing those into a single red would make the table lie about the
commonest harmless state there is. `serving` is a count, not a verdict:
whether nothing arriving is wrong depends on what the instance is for, and the
findings above are where that gets said.

**The name comes off the certificate the instance serves**, which is the name
its clients actually use. There is deliberately no reverse-DNS fallback. A PTR
lookup is a network call, this runs on boxes whose DNS is the thing being
diagnosed, and it would hang the run to add a name that is stale as often as
not. Without a certificate the address is the name.

`up` distinguishes `listening` from `ok`. They are different claims, not
strengths of the same one: `listening` means the socket is open and nothing
opened a connection to it this run, because the port is not one conventionally
used for TLS or HTTP. Reporting that as `ok` would be a pass nobody earned.

### Every instance is looked at

The listener checks used to dedupe on the port alone. A box running several
instances behind several addresses on 443, which is the ordinary shape of a
front end rather than an exotic one, had exactly one of them checked: the
certificate expiry those checks exist to catch was read off one instance and
assumed of the rest. They key on address and port now.

`OWN_TLS_MAX_LISTENERS` bounds the cost at twelve, because each one is a
handshake or a request against a service that is probably logging connections.
Anything past the limit is named as not checked rather than dropped, since a
cap that trims quietly reads as full coverage.

## Serving clients while connected to nothing

The shape this is for: something that only exists to relay, brokering between
the clients in front of it and whatever it forwards to, holding a session to
that the whole time it is working. Lose it and the box keeps its address, its
listener and its clients, every connection it accepts fails on the far side,
and nothing else here notices, because everything else here is measuring a box
that is up.

`no_upstream_sessions` is context and never a fault, because one reading cannot
separate two ordinary states. A service that answers from itself is supposed to
hold no outbound sessions, and nothing in a socket table says which kind of box
this is. The message names both readings and lets the person who knows decide.

It stays silent while connections are stuck in `SYN_SENT`. That is a box trying
and failing rather than a box not trying, `syn_sent_backlog` already says so,
and two findings for one condition is how a report stops being a verdict.

**What this does not do** is sweep a subnet. A range cannot be shown
serviceable by probing it: a silent address in the range is the normal case,
not a fault, so the sweep returns a list to interpret rather than a verdict,
and from an internet-facing box it is noisy and slow besides. What makes a
subnet serviceable through a service address is a short list, all of it
checkable against the addresses the box genuinely holds: that it holds the
address, that the prefix and routes cover the instances, that the gateway
answers for it, and that a probe bound to it completes and returns.

## Every flag

```
--report                 print the findings to this terminal and exit
--inventory              list neighbours already known to this device (ARP table;
                         adds only a reverse-DNS lookup per neighbour)
--quiet                  hide the progress line while the checks run
--no-color               never colour the output (already off when redirected,
                         when NO_COLOR is set, and on a dumb terminal;
                         FORCE_COLOR turns it back on, and this flag beats
                         both)
--version                print the version and exit
--quick                  skip the traceroute and path MTU (~2s instead of ~7s, or
                         instead of ~60s where the path answers no traceroute)
--soak SECONDS           sample over a window instead of taking a snapshot
--uplink-mbps MBPS       the site's WAN line rate, so utilisation is measured
                         against the link that actually fills rather than the
                         NIC's own speed. Needs --soak
--baseline FILE          compare against a previous report from this site
--target HOST            what to ping/trace. Default 'auto': the backend this
                         box talks to most, falling back to 8.8.8.8 when there
                         is none. Everything measured off the device is measured
                         to this host
--check-ports 53,443     TCP reachability for specific ports (max 32),
                         or 'common' for 22, 53, 80, 443, 8080.
                         Preset results are informational: naming a port asserts
                         you expect it open, a preset asserts nothing
--source ADDR            send from this address, on a box that holds more than
                         one. Critical if the box does not hold it
--export FILE            write a report; a .html name gives a single
                         self-contained page, any other name gives JSON.
                         Use - for stdout
--export-compact FILE    the same, without the captured output behind the
                         checks that passed. Same verdict, findings, hop
                         diagram and stage strip
--emit-viewer [FILE]     write the standalone viewer (default static/index.html)
```

### `--export-compact`

A full export is mostly captured command output, on a real box the port
probes alone can be half of it, and all of it is kept so a conclusion can be
audited months later. That is the right default, and the wrong thing to carry
off a locked-down box through a console.

`--export-compact` writes the same report with the evidence behind everything
that passed left on the box:

```
--export           119,237 bytes
--export-compact     5,027 bytes      the same run, 96% smaller
```

Nothing the picture needs is lost, because none of it is what makes an export
big. The verdict, the findings, the stage strip, the hop-by-hop path, the
direction panel and the call-quality figures are all **derived**. They total a
couple of kilobytes, and they are what you look at. What goes is the raw
material behind the checks that were fine.

Two things are always kept:

| | |
|---|---|
| evidence for a stage that is **not passing** | it is the reason the report exists |
| a check that **could not run** | a gap in coverage has to stay visible, dropped, it would look exactly like a check that passed |

The report is marked `"compact": true`, so a reader months later can tell why a
panel is missing, and a `--baseline` comparison does not read a trimmed report
as a box that stopped collecting things.

It is a separate flag rather than a mode of `--export` on purpose: the full
export is the auditable one, and the one you would want if the verdict is ever
disputed.

Exit status follows the monitoring-plugin convention, so it drops into a
scheduled check without anything parsing its output:

| | |
|---|---|
| `0` | nothing wrong |
| `1` | at least one warning |
| `2` | at least one critical finding |
| `3` | the check couldn't run, or couldn't deliver, too old a Python, a bad `--target`, an unreadable `--baseline`, a report that couldn't be written, or a crash |

**This changed in 1.3.** It used to be `1` for a critical and `0` for
everything else, which meant a run reporting a degraded link, a flapping
resolver or 7% path loss exited `0`, so a wrapper saw success while the tool
was saying something was wrong. If you script against it, `!= 0` now means
"something to look at" rather than "catastrophe only".

A failed `--export` prints the report to stdout rather than losing it: the
run has already happened, says what went wrong on stderr, and exits `3`.

While the checks run, a single line on **stderr** shows what's happening and
how long it's taken:

```
  [ 0.4s] probing gateway and 8.8.8.8, tracing the path
```

It overwrites itself, and clears before the report prints. Under `--soak` it
counts the remaining window down each second, so a two-minute sample doesn't
look like a hang. It's on stderr rather than stdout so `--export -` still emits
nothing but JSON, it turns itself off when stderr is redirected: a log full of
half-finished lines helps nobody, and `--quiet` disables it entirely.


## Python versions

**Minimum: Python 3.7**, that's where `subprocess.run`'s `capture_output` and
`text` arguments arrived. Nothing newer is used, and nothing outside the
standard library, so there is no dependency to break when the box is patched.

Two tests keep that honest rather than aspirational: one parses the source at
the stated floor (so newer syntax can't slip in and fail months later on an
appliance instead of here), and one asserts every import is standard library.

If the interpreter is older, the tool prints the version it needs and exits
`2`, before running any command, so you get a sentence instead of a
`TypeError` from the first ping.

**After a Python upgrade on the box**, the check is the tool itself:

```bash
python3 faultone.py --version      # runs, so the floor is satisfied
python3 test_faultone.py           # 1075 tests, a few seconds, no dependencies
```

The suite runs on the appliance as happily as anywhere else, which is the point
of having no dependencies. You can validate the tool in the environment that
matters rather than hoping your laptop resembles it.

Every report records the interpreter alongside the tool version:

```
FaultOne 1.11.1 - Linux - python 3.11.2 - 2026-08-06T15:16:44-07:00
```

so a `--baseline` taken before an upgrade reports "python: 3.9.6 -> 3.11.2"
rather than leaving you to wonder why a measurement moved.

## Versioning

Releases are cut with `python3 dev/release.py <version> --push`, which bumps the
version in both files that carry it, runs the suite before committing, tags, and
publishes the GitHub Release in the same step. That last part is why the script
exists: `git push --follow-tags` creates a tag and nothing else, so nine tagged
versions once shipped with no Release and the Releases page kept showing one
from eight releases back.

`python3 faultone.py --version` prints what's on the box, and every report
carries the version that produced it, in the JSON, at the top of the terminal
output, and in the badge of a self-contained page:

```
FaultOne 1.11.1 - Linux - 2026-08-06T14:58:06-07:00
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
| `COLL_PPM_WARN` | **10** | collisions, per million packets, lower, because full duplex shouldn't have any |
| `LINK_FLAP_PER_DAY` | **2** | carrier transitions per day of uptime before a link counts as flapping |
| `KLOG_RECENT_SECONDS` | **3600** | how far back a kernel-log event still counts as happening now |
| `KLOG_FLAPS_RECENT` | **4** | carrier transitions logged within that hour before the link is called unstable. Two is one clean down/up |
| `SOFTNET_DROP_PPM` | **10** | receive-backlog drops per million packets processed |
| `NEIGH_TABLE_WARN_PCT` | **80** | how full the neighbour (ARP) table gets before it is worth saying so. Same figure as the connection-tracking table and for the same reason: both refuse outright at 100% with no back pressure, so the useful moment to speak is before that. Its own constant all the same - two tables, two ceilings, and sharing a number would mean tuning either retuned the other |
| `RESETS_PER_CONN_PCT` | **100** | resets this box sent, as a share of the connections it opened or accepted. A reset is not by itself a fault - an application closing with data unread sends one - so the line sits where the count stops looking like a by-product: at least one reset per connection handled. A dead listener, an unbound port or a scan all produce exactly that |
| `UDP_DROP_PCT` | **1.0** | share of arriving datagrams this box failed to take delivery of. UDP has no retransmission and no window, so a datagram dropped at the socket is gone and the sender is never told. A share rather than a count per minute, because ten a minute means nothing without knowing whether ten thousand or ten million arrived |
| `UDP_DROP_FLOOR` | **10** | and enough of them for the share to be a share. Netdata alerts on more than ten of these a minute with no share at all - a receive-buffer overflow is never routine, unlike a discard, so a small absolute count already means something and the share is what stops a busy box reporting its own noise |
| `REASM_FAIL_PCT` | **10.0** | share of reassembly attempts that failed. Fragments are already unusual on a healthy path, so the bar is on how many of the ones tried never came back together rather than on the raw count |
| `REASM_FAIL_FLOOR` | **10** | same pair, same reason: one failure out of two attempted fragments is 50%, and is two fragments |
| `ORPHAN_WARN_PCT` | **25** | how full the orphan table gets before it is worth saying so. The kernel charges an orphan at two to four times its weight when deciding whether it is under memory pressure, so the ceiling bites earlier than the number suggests |
| `CONNTRACK_WARN_PCT` | **80** | how full the connection tracking table gets before it's mentioned |
| `CONNTRACK_REFUSAL_PER_DAY` | **10** | conntrack refusals per day of uptime for a historical count |
| `ACCEPT_OVERFLOW_PER_DAY` | **10** | accept-queue overflows per day of uptime for a historical count |
| `JITTER_MS` | **30.0** | milliseconds of round-trip variance, from TCP's own measurement on the connections this box carries, before the delay is called unstable |
| `JITTER_SHARE` | **0.5** | and it must be at least this share of the round trip. Both are needed for the same reason as the queue pair below: the absolute figure alone fires on any long path where tens of milliseconds of variance is ordinary, and the share alone fires on a LAN where 0.2ms becomes 0.5ms |
| `ESTAB_RESET_PCT` | **20** | share of connections that reached ESTABLISHED and were then torn down abruptly rather than closed. Some abandonment is normal, so the line sits where it stops looking like a client walking away |
| `SHARED_FAULT_INTERFACES` | **3** | interfaces carrying the same fault before it stops being about a cable. Two is a coincidence worth nothing - a box with two bad patch leads is a box with two bad patch leads |
| `QUEUE_RTT_MULTIPLE` | **2.0** | how far a connection's smoothed round trip must sit above its own lowest-ever before the excess counts as queue rather than distance |
| `QUEUE_DELAY_MS` | **30.0** | and how many milliseconds of excess. Both are needed: the multiple alone fires on a LAN where 0.2ms becomes 2.2ms, the absolute alone fires on a satellite hop whose 45ms of variance is weather |
| `FLOW_LOSSY_PCT` | **2.0** | retransmit ratio at which one connection is called lossy |
| `SYN_RETRANS_PCT` | **5** | share of connection attempts needing their SYN resent before setup is called the problem |
| `ATTEMPT_FAIL_PCT` | **10** | share of connection attempts that never establish at all |
| `CSUM_ERR_PPM` | **1** | segments per million arriving with a bad TCP checksum: should be zero |
| `SPURIOUS_RETRANS_PCT` | **30** | share of retransmissions the far end says were unnecessary before reordering, not loss, is the story |
| `MIN_WINDOW_PACKETS_FOR_RATE` | **1,000** | the same idea for a counter window rather than a lifetime. A percentage of fifty packets is not a percentage of anything, and the window is seconds long on a box that may be nearly idle |
| `DROP_PCT_WARN` | **2.0** | share of a window's packets discarded before it is worth saying so. Two orders of magnitude looser than the error threshold on purpose - the counters mean opposite things: an error is a frame that arrived damaged and should never happen, a discard is a frame this box chose not to deliver upwards and happens on every busy interface there is |
| `MIN_PACKETS_FOR_RATE` | **20000** | packets an interface must have carried before an error or collision *rate* is quoted about it. One error on a nearly idle NIC divides out to twenty times the threshold - the same reasoning `MIN_PROBES_FOR_LOSS` applies to ping, which had never been applied here |
| `MIN_PROBES_FOR_LOSS` | **10** | probes needed before a single unanswered one is allowed to be called a loss rate |
| `LATENCY_HIGH_MS` | **400** | round trip past which distance stops explaining the delay. Light in fibre crosses the planet and returns in about 250ms, and the longest real terrestrial paths measure 250-300ms, so this leaves room for a genuinely long route. One threshold rather than a warn/critical pair: the verdict takes its severity from the finding that headlines it, so a warning-level rule above a critical one would downgrade the whole run |
| `LATENCY_WALL_MS` | **100** | milliseconds a single hop must add before it is worth naming as a wall. The first hop counts its own latency: the path starts there, so everything before it is zero, and a satellite or VPN first hop carrying the whole delay is a wall like any other |
| `LATENCY_WALL_SHARE` | **0.5** | and the share of the end-to-end delay it must be. The finding says a single hop adds *most* of the round trip, so "most" is what it measures - without this a uniformly graded path fired it and named a hop no worse than its neighbours |
| `PEAK_WORTH_SHOWING` | **1.2** | how far a peak must sit above the average before the average is worth distrusting on sight. Below this the two tell the same story and printing both is noise; above it the average is actively hiding something. A ratio rather than a fixed gap, because a 10 Mbps peak over a 1 Mbps mean matters and a 1000 over a 999 does not |
| `BURST_UTIL_PCT` | **25** | utilisation below which a queue overflowing has to be explained by bursts rather than volume |
| `UPLINK_FULL_PCT` | **70** | share of the `--uplink-mbps` rate this device has to be using before the site's own line is called full. Lower than the NIC threshold: CPE queues are small and the line is shared, so loss starts well before the last few percent |
| `SERIES_MAX_SAMPLES` | **900** | most samples a rate series holds. At or below this the interval is one second; a longer soak stretches the interval rather than storing more |
| `EPHEMERAL_PRESSURE_PCT` | **80** | share of `ip_local_port_range` in use before outbound connections are at risk |
| `FD_PRESSURE_PCT` | **80** | share of the system-wide file descriptor ceiling in use before a serving box is in danger of not accepting |
| `ABORT_TIMEOUT_PCT` | **2.0** | share of connections handled that ended with the peer having stopped answering before it stops looking like people leaving and starts looking like a path |
| `SYN_RECV_HIGH` | **256** | half-open connections before the backlog is worth reporting. A busy server always has some |
| `OWN_TLS_MAX_LISTENERS` | **12** | Listeners of our own tested per run, counted per address and port rather than per port. Each costs a handshake or a request against a service that is probably logging connections. Anything past the limit is reported as not checked |
| `BACKEND_MIN_CONNECTIONS` | **2** | connections to one peer before `--target auto` treats it as a dependency rather than a passing conversation |
| `BACKEND_MIN_SHARE` | **0.15** | and the share of outbound connections it must hold. A count alone cannot tell a dependency from a busy destination |
| `FORWARDER_DESTINATIONS` | **50** | distinct outbound destinations above which a box is forwarding traffic rather than consuming a few services |
| `CONNECTOR_DESTINATIONS` | **6** | at or below this, a box with no listening ports is holding a deliberate handful of connections rather than browsing |
| `SERVING_INBOUND_MIN` | **3** | live inbound connections before a box counts as serving traffic. One is a health check or your own SSH session; a handful is clients |
| `UPLINK_UNKNOWN_FLOOR_MBPS` | **5** | traffic below which an upstream verdict needs no "rule out your own line first" caveat - too little to fill any line a site would be sold |
| `COVERAGE_GOOD_PCT` | **70** | share of checks that must return data before a verdict can be called well-supported |
| `COVERAGE_THIN_PCT` | **40** | below this, any verdict is low confidence however well corroborated |
| `FLOW_LIMITED_PCT` | **20.0** | share of a connection's active time blocked before the blocker is named |
| `FLOW_BUSY_MS` | **1000.0** | how long a connection must actually have been sending before the three-way split below means anything. Those percentages are shares of *busy* time, so on a connection that has barely moved they are all zero - and subtracting zero from a hundred would report an idle socket as limited by the network, confidently, on no evidence |
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
| `PORT_CHECK_WORKERS` | **8** | concurrent port connects, bounded so it doesn't resemble a scan |
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

Under the verdict, the whole chain at a glance: the way a handheld tester
shows it:

```
  clients -   link PASS   address PASS   gateway PASS   internet PASS   dns FAIL   mtu -   ports -
```

It reads in the order the traffic does: the way in, then this box, then the
way out. `clients` is the inbound leg - it reads `-` on a box nothing connects
to, which is most of them, and it exists so a fault on the traffic *arriving*
has somewhere of its own to land. Without it those findings marked `internet`,
which is a leg of the way out, and the strip contradicted the verdict above it.

A stage that wasn't measured reads `-`, never `PASS`. Claiming a check passed
when it never ran is the one thing a summary like this must not do.

## What layer each check is testing

Every check and every finding carries an OSI layer tag, shown as a badge
in the UI and as a `layer` field in the exported JSON:

| Layer | Checks | What a failure here means |
|---|---|---|
| **L1 · Physical** | interface has an IPv4 address, error counters, link speed/duplex | cable unseated, Wi-Fi not associated, port down, DHCP never completed, corrupted frames on the wire |
| **L2 · Data link** | ARP/neighbour table, gateway ping, interface MTU, LLDP switch port | local segment problem, switch/AP port, bad cabling, interference |
| **L3 · Network** | routing table, default gateway, internet ping, traceroute, path MTU | addressing or routing: no gateway, upstream/ISP break |
| **L4 · Transport** | listening ports, TCP port checks | firewall rule or the service isn't listening |
| **L7 · Application** | DNS lookup | name resolution, wrong or unreachable DNS server |

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
from the trace already taken: no extra packets:

- **lan / wan**: whether the hop is inside this site (RFC1918, link-local) or
  out on the provider's network. The first hop that is public *or in carrier
  NAT* is marked **site edge**, and that boundary is the demarcation between
  the site's network and their ISP, usually the first thing you want to
  establish. Carrier NAT counts as theirs: 100.64.0.0/10 is not routable on
  the internet, so it reads like a private range, but it is the provider's
  addressing and not the site's. Taking the first *public* hop alone put the
  edge past their NAT layer and drew it as though it were inside the site.
- **+Nms**: latency this hop *added* over the previous one. An accumulating
  total tells you little; the jump tells you where the delay is introduced.
  The largest jump is called out, along with which side of the edge it's on.
- **jitter**: spread between the three probes to that hop (shown at 5ms and
  above). A wide spread means congestion or an unstable link even when the
  average looks healthy.
- **gateway / target**: which hop is this device's default gateway, and
  whether the path actually reached what you aimed at.

- **network handoffs**: where the PTR domain changes, so you can see the path
  pass from one operator into the next (`example-isp.net → dns.google`). The
  summary lists every network crossed.
- **cgnat**: a hop in `100.64.0.0/10` means the provider is NAT-ing this site.
  There's no public address on the connection, so nothing reaches it from
  outside regardless of local configuration: worth knowing before chasing an
  inbound-access problem on the device.

Three structural faults are detected from the same data:

- **Two private networks in series**: two different private subnets before
  the site edge mean traffic crosses at least two routers on the way out.
  Commonly that is double NAT, and it is reported as a likelihood rather than
  a reading: a traceroute cannot tell a translating router from one that only
  routes, and a site with several routed VLANs is ordinary in itself. If it
  is NAT it breaks inbound connections and port forwarding; either way there
  is a second device in the path to rule out. Only hops before the edge are
  counted, plenty of carriers number their own core out of RFC1918, and
  scanning the whole trace reported their addressing as the site's.
- **Routing loop**: the same address answering at two hop numbers. Traffic is
  circling and will die when the TTL runs out; that's an upstream routing
  misconfiguration, not a fault on the device.
- **Latency wall**: a single-hop jump over 100ms, attributed to the correct
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
> 8.8.8.8, so the path is fine and something along it simply doesn't answer
> traceroute probes.

That's the difference between escalating a broken path and knowing the probes
were being filtered. TCP probes need raw sockets, so this is skipped when
running unprivileged, like every other optional step here.

## Interface error counters

Every other check here measures *reachability*. It tells you something is
broken, not whose fault it is. The error counters the NIC keeps are different:
they're evidence that the damage is happening on this device's own link.

- **CRC / frame errors**: bits arriving corrupted: bad cable, dying SFP,
  dirty fiber, or a duplex mismatch. Physical, and on this device's link.
- **Carrier losses**: the link is flapping up and down.
- **Collisions**: on a full-duplex port (nearly all modern ones) these
  shouldn't happen at all; a steady rate is the classic duplex-mismatch
  fingerprint, so they get a lower threshold than generic errors.
- **Drops / overruns**: frames arrived but the box couldn't keep up. That's
  device-side: CPU, ring buffer, or driver, *not* the network.

Counters are cumulative since boot, so a bare number means little: 47 errors
over 200 days of uptime is noise. Three things are reported instead:

1. The raw count per interface,
2. The **rate** (errors per million packets), which separates background
   noise from a real problem, and
3. whether the counters are **climbing right now**: outside `--quick` the
   counters are sampled twice, 2s apart. "1,200 errors, +14 in the last 2s"
   is a live fault; "1,200 errors, steady" is history.

Only interfaces that have actually passed traffic are considered, so the pile
of idle virtual interfaces on a typical box stays out of the way. When
everything is clean, the all-clear says so explicitly: "the physical link
into this device is clean" is exactly the sentence you need when the question
is whether the box is at fault.

Read on Linux from `/sys/class/net/*/statistics` (no output parsing at all)
and on macOS/BSD from `netstat -i -b -n`.

## Speed, duplex, and MTU

**Speed and duplex** are what this interface and the upstream switch port
negotiated with each other, so a problem there is unambiguously about that
cable and those two ports:

- **Half duplex** on a switched link is almost always a failed negotiation or
  a hard-coded mismatch, one side forced, the other auto-negotiating.
  Throughput collapses under load while pings stay perfect, which is why it
  gets misdiagnosed as "the network is slow". Reported critical when
  collisions are also present, since that confirms it.
- **A link at 100 Mbps** on gigabit-capable hardware usually means a damaged
  cable: gigabit needs all four pairs, 100 Mbps needs two, so one broken pair
  silently drops you a tier instead of failing outright.

Collisions are read in light of the negotiated duplex: on a half-duplex link
they're expected, so only the duplex finding is reported rather than both.

**Interface MTU** below 1500 usually means a tunnel (VPN/PPPoE) or a manual
override; above 1500 (jumbo) only works if every device in the path agrees.

**Path MTU** is the more valuable half, and it's the one thing here that
catches a failure invisible to everything else. The interface can say 1500
while something along the path silently drops full-size packets, so pings
and SSH work fine while large transfers, file copies, TLS handshakes and VPN
traffic stall. FaultOne sends do-not-fragment pings at descending sizes
(interface MTU, then 1492/1400/1280/1000: the common tunnel sizes) and
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

A degrading fibre link (dirty connector, tight bend, dying laser) stays
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

Entirely passive. Nothing is sent and nothing is captured; `lldpd` has already
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

- **One of two resolvers dead**: the nastiest DNS fault, because lookups work
  or hang depending on which one the stub picks. It reads as "the network is
  intermittently slow", and a single lookup usually passes.
- **A slow resolver**: every new connection waits on it, so the whole site
  feels broken while every connectivity check succeeds.
- **NXDOMAIN hijacking**: a name in the reserved `.invalid` domain is queried;
  it cannot exist, so an answer means a captive portal or ISP redirect service
  is inventing replies.
- **Disagreement** between resolvers: a stale cache, or a middlebox answering
  selectively.

Queries are built and parsed here in ~60 lines of standard library rather than
shelled out to `dig`, which minimal appliances often don't ship, and which
would make the timings include process startup.

## Call quality (MOS)

Latency, jitter and loss are three numbers most people can't act on. MOS is the
one they're actually complaining about:

```
CALL QUALITY (estimated, to 8.8.8.8)
  MOS 4.39 (excellent)   latency 24ms · jitter 2ms · loss 0%
```

Scored from the measurements already taken (no extra packets) using the
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

A full link behaves exactly like a broken one from the application's side: 
latency climbs, transfers stall, but nothing is faulty. Above 80% this is
reported, and the verdict names it "capacity, not a fault" so nobody replaces
hardware that's working.

### The denominator is usually the wrong one: `--uplink-mbps`

That 94% is against the **NIC's** negotiated speed, which is the only rate this
box can read. On the appliances this tool is built for it is also the wrong
one. A branch box has a gigabit port in front of a 50 Mbps line, so a site
filling that line completely shows as 5% busy, and every symptom it produces
(loss to every destination, latency climbing under load, calls breaking up)
gets read as the carrier dropping traffic. That verdict came out at high
confidence, and it sends someone to open a ticket against a circuit that is
working exactly as sold.

Measuring the line from here would mean generating load on a customer's
connection, which this tool won't do. So it takes the number as an input
instead: it's on the ticket:

```bash
python3 faultone.py --report --soak 60 --uplink-mbps 50
```

With that, utilisation is computed against the line as well as the NIC, and at
`UPLINK_FULL_PCT` (70%) or above one of two findings comes out, and which one
depends on whether anything was actually failing at the time:

| | |
|---|---|
| `uplink_saturated` | Full, **and** something broke while it was: dropped packets, or probes that went unanswered. Ranked above every loss, latency and retransmit verdict it explains, and owned by "the site's own capacity, not the carrier". |
| `uplink_busy` | Full, nothing failing. A backup, a sync, a large transfer, a line being used, which is not a line that is broken. Reported, and `LATENT`, so it can't headline over a live fault but is still the answer when nothing else is wrong. |

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
| the target | A TCP connect to 443, 80 then 53, the host the operator named, not a scan. **A refusal proves it as well as an accept does:** an RST is a completed round trip, so the packets got there and the reply got back. Only a timeout is inconclusive. Reports `inet_icmp_filtered`. |
| the gateway | Its entry in the neighbour table. ARP does not cross a dead cable or a down switch port, so an entry with a hardware address means the link is up whatever ICMP says. An entry with no MAC, or in `FAILED`/`INCOMPLETE`, is the kernel asking rather than the gateway replying, and does not count. Reports `gw_icmp_filtered`. |

Both findings read as `ok`. They exist to stop something else being misread,
and neither is ever a fault. When ICMP *and* the confirming probe both get
nothing, `gw_unreachable` and `inet_unreachable` still fire exactly as before,
still critical, still exit 2. The point was never to stop reporting outages.

## Running this on a server rather than a branch box

Most of this tool assumes a device that *initiates* traffic. The question is
whether it can get out. A box serving inbound traffic inverts that, and two
things follow from it.

**Clients connected right now are proof the network works.** `ss` output is
split into what arrived and what left: a listener on a non-loopback address is
a service, and an established connection whose local port matches one is a
client. `SERVING_INBOUND_MIN` (3) is the bar, because one inbound connection is
your own SSH session or a load-balancer health check.

So when nothing outbound reaches the target (no ICMP, no TCP) but clients are
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
`applicable: False` and drop out of the denominator entirely. The figure is
meant to say how much of what *could* have run did. On a Mac this moved a
routine run from `11 of 15 checks ran` to `11 of 12`.

What is still branch-shaped and simply won't fire on a server: LLDP, optics,
duplex and speed negotiation, carrier flaps, CGNAT detection, `--inventory`.
None of it does harm; it now costs nothing in confidence either.

### The ceilings that look like network faults

Five findings for limits that live on this box and are invisible to every
other check here, which is the point, because from a client's side and from
the wire they are indistinguishable from the path being broken:

| | reads | what it means |
|---|---|---|
| `syncookies_live` | `TcpExt SyncookiesSent` | The kernel saying, in words, that a listen queue overflowed. Connections arrived faster than the service accepted them. The clearest single statement available that a backlog is too small or something is flooding it. |
| `syncookies_historical` | same, since boot | It has overflowed before but not during this run. `LATENT`, so it can't headline over a live fault. |
| `ephemeral_ports_low` | `ip_local_port_range` vs outbound sockets | A proxy talking to backends runs out of source ports long before anything else breaks, and the failure looks exactly like the far end refusing the connection. `TIME_WAIT` is named in the finding because it is usually what is holding them. |
| `fd_pressure` | `/proc/sys/fs/file-nr` | At the ceiling the service stops accepting. Nothing on the wire is wrong. |
| `syn_recv_backlog` | `SYN_RECV` count vs `somaxconn` | Half-open connections piling up, either the accept queue isn't draining or something opens connections and abandons them. The syncookie counter is what tells those apart, which is why both are reported. |

All five are ranked above the path and loss verdicts, because each one makes
this box refuse or fail to open connections, and bottom-up ordering would
otherwise hand the answer to whatever symptom that produced further out.

### What the run aims at: `--target auto`

`8.8.8.8` answers "can this box reach the internet". That is the whole question
on a branch appliance and close to irrelevant on a box whose job is answering
requests. What matters there is whether it can reach the things it *depends
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
- `BACKEND_MIN_CONNECTIONS` (2): one connection somewhere is a DNS lookup or
  a webhook.
- **Ties break by address**, so the choice is the same on every run. A target
  that moves makes two reports impossible to compare.
- Your own SSH session is excluded, as it is everywhere else here.
- The choice is **always** reported (`target_is_a_backend`), and asking for
  `auto` where there is no backend says so (`target_auto_failed`) rather than
  silently leaving you reading a report about `8.8.8.8` believing it is about
  your database.

A dependency on a **public** address (a managed database, an external API) is
still worth aiming at, and is reported as `dependency` rather than `backend`.
The path to it genuinely leaves the site, so it aims there without claiming the
readings are about an internal segment.

**The attribution changes with it.** "The provider" is right for `8.8.8.8` and
flatly wrong for a database on the other side of a rack, so
`BACKEND_TARGET_VERDICTS` re-owns the five verdicts about reaching the target: 
`inet_unreachable`, `inet_partial_loss`, `trace_stalls`, `loop`,
`egress_blocked`, to the internal segment. One rule per fault, with only the
attribution overridden, rather than a parallel set of near-duplicate codes. The
`--uplink-mbps` caveat also switches off: "rule out the site's own line" is
about the WAN, which an internal segment does not go near.

### The path only goes one way, and says so

A traceroute is outbound. This box can send probes toward a client, but nothing
here can observe the route a client's packets took to *arrive*. That is a
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
  it says that instead, the spread *is* the answer.
- On a box nothing connects to there is no inbound direction, so the panel is
  absent and the outbound one keeps its original title. Drawing an empty
  inbound leg would be inventing a measurement.

### Queue, or distance

`ss` reports two round-trip figures per connection and this tool used one of
them. `rtt` is the smoothed average; `minrtt` is the lowest that same socket has
ever seen. The difference between them is time spent **waiting**, and it is the
one number that separates *this path is long* from *something on it is
buffering*, two faults with different owners and different fixes, which every
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
| LAN backend, 0.2ms → 2.2ms | fires, 11× | quiet | quiet ✓ |
| satellite hop, 575ms → 620ms | quiet | fires: 45ms | quiet ✓ |
| backend behind a full interconnect, 8ms → 96ms | fires | fires | fires ✓ |

Chosen by running candidate rules against twelve paths that should and should
not fire; this pair was the only one that got all twelve right.

A connection's own minimum is the honest floor for it. The same socket has
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
stays `None`, and nothing about this changes. Inventing a side there would be
a claim the data cannot support.

### Whether the service answers, not just whether it accepts

Every other check here stops at the handshake: the port is open, the TLS
completes, the certificate is valid, the TCP connection is established. A
service that accepts connections and then **answers nothing** passes all of it
while being completely down from a client's side, and that is the commonest
way a service is broken and the least visible from the box it runs on.

One `HEAD /` per listener, no redirects followed, no body read, no credentials,
and only against ports this box is **already listening on** that are
conventionally HTTP, so it never becomes a probe. Skipped under `--quick`.

| | |
|---|---|
| `own_service_silent` | Accepted a connection, took the request, answered nothing. Ranked above the certificate findings: a client meets this first, and it is more broken than a wrong certificate. |
| `own_service_upstream_error` | Answered 502, 503 or 504, the service running and reporting that *what it depends on* failed. Classified **upstream**: this box is not the fault. |
| `own_service_erroring` | Any other 5xx. The service accepting connections and failing to serve them, which no network change will fix. |
| `own_service_not_http` | Answered with something that is not an HTTP status line. Either the wrong thing is bound to that port, or it speaks a protocol this cannot read. |

A 4xx is **an answer**, not a failure, 401 and 404 mean the service is up and
replying, and only the server errors are its own fault.

The gateway split is the useful one on a box that proxies: a 502 is the
difference between *the service is broken* and *the service is fine and its
backend is not*, which are different faults with different owners. It is the
one finding here whose evidence is seen downstream and whose cause is upstream.

### The certificate this box serves

Every other TLS check here points outward, at something this device connects
to. A box terminating HTTPS is the opposite case, and its own certificate is
the one that takes the site down when it expires, and nothing was looking at
it. A proxy could be two days from an outage and the report read healthy.

On every full run, for each TLS port this box is **already listening on** (at
most `OWN_TLS_MAX_LISTENERS`, and only ports conventionally used for TLS, so this
never becomes a probe):

| | |
|---|---|
| `own_tls_expired` | Browsers are refusing it now. Ranked above everything about the path: when this is wrong the path is irrelevant. |
| `own_tls_expiring` | Within `CERT_EXPIRY_WARN_DAYS`. `LATENT`, real, dated, and not yet refusing anyone. |
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
  wrong machine, and a chain that only completes because of *this* machine's
  trust store is exactly the failure that reaches customers and not you.

A certificate that doesn't verify never reaches Python's parsed dates, and a
private CA is most of what a proxy serves internally. ASN.1 encodes times as
printable ASCII, so `der_validity` takes them from the same string scan
`der_strings` already does, no hand-written X.509 parsing, which this file
deliberately avoids.

### Resets, and why the count of them is not a finding

A proxy sends a lot of TCP resets, and most of them are housekeeping.
[HAProxy closes backend connections with RST on purpose](https://gitlab.com/gitlab-com/gl-infra/production-engineering/-/issues/10589),
via `SO_LINGER`, to conserve ports and memory. So `OutRsts` is recorded in the
report and **never becomes a finding**. The same number is normal on one box
and alarming on another, and a tool whose job is deciding which fault matters
has no business guessing.

What is diagnostic is *why* a connection was aborted, which the kernel counts
separately:

| | |
|---|---|
| `aborts_on_memory` | `TCPAbortOnMemory` moving. The box ran out of socket memory and killed established connections to cope. Unambiguous, and never normal. |
| `reqq_full_drops` | `TCPReqQFullDrop` moving. SYNs dropped before reaching a queue. The client sees a connection that never opens and retries, indistinguishable from packet loss, and there is none. |
| `aborts_on_timeout` | `TCPAbortOnTimeout` as a **share** of connections handled (`PassiveOpens` + `ActiveOpens`), above `ABORT_TIMEOUT_PCT`. A count alone means nothing: some of this is ordinary on any public service, because people close laptops. Needs at least 100 connections in the window before a percentage is allowed to exist at all. |

### Per-flow analysis at proxy scale

`ss -tin` is about 430 bytes per connection. Command output is capped at
`MAX_OUTPUT_BYTES` (64 KB) so that a report stays a size you can paste, which
on a box holding tens of thousands of connections meant the per-flow analysis
ran on an arbitrary first ~150 sockets, 0.3% of them, and "worst peer" was
picked out of that sample.

The socket table is never stored: it names every peer this box talks to and is
replaced by a digest before the report is written. So the cap that mattered was
never the report's. `FLOW_READ_BYTES` (12 MB) is how much is *read* and
`FLOW_MAX` (20,000) how many connections are analysed; 40,000 sockets parse in
about 125 ms and analyse in about 20 ms. A sample that hits either limit still
reports `tcp_flow_sample_partial`, exactly as before. The aim was to make the
sample representative, not to stop admitting when it isn't.

## Duplicate IP and TCP retransmits (Wireshark findings, without a capture)

Two of Wireshark's most useful signals are available without capturing any
traffic, which matters on someone else's network, where capture is a consent
question, not a technical one:

- **Duplicate IP**: Wireshark flags an address claimed by two MACs. The same
  conflict is visible in the ARP/neighbour table this box already keeps. The
  reverse (one MAC, many IPs) is a router answering proxy ARP and is *not*
  reported. A duplicate address makes symptoms move around with no pattern,
  which is why it wastes so much time.
- **TCP retransmits**: read from `/proc/net/snmp` on Linux (`netstat -s` on
  BSD). This is loss measured on the box's **real traffic**, not probe traffic,
  so it catches drops that ICMP tests miss. Under `--soak` it's a live rate;
  otherwise a lifetime figure, and the report says which.

### Which destination the retransmits belong to

The counter above gives one number for the whole box. It can tell you traffic
is being dropped; it cannot tell you whether that's one sick destination or all
of them, and those have different owners. On Linux, `ss -tin` reports the
kernel's own per-connection statistics, so the split is available without
capturing anything or reading any payload.

| What the connections show | Reading | Owner |
|---|---|---|
| Every network lossy | Loss that follows every destination equally isn't out in the network | this device or its segment |
| Some networks lossy, others clean | The link carries the clean traffic fine, so the drops are further out | the provider or upstream |
| Only one destination measured | Nothing to compare against, stated as the weaker finding it is | that path, or that host |

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
  used instead, and the report says which basis it used: without that fallback
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
  read, and `ss` prints in kernel table order, so a prefix can easily be one
  busy application's connections. "No destination is clean" is a claim about
  what *isn't* there, so it needs the whole sample and is withheld; the loss is
  still reported, with the owner left open rather than guessed. "This one is
  lossy, that one is clean" is a claim about what *is* there, and still holds.
- The report stores a digest, never the socket table: that table names every
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

**It is not a scan.** Nothing is probed, pinged or connected to: every entry
is a device that was already talking to this one. That distinction is the
reason it can run on a network nobody gave you permission to sweep, and it
costs nothing because the table was already collected for the duplicate-address
check.

What it deliberately excludes: incomplete entries (a lookup that failed is not
a device), broadcast and multicast addresses. Including them turned 36 real
neighbours into 257 phantom ones the first time this ran.

The trade is honest: this shows what this device *has talked to*, not what
*exists* on the segment. A host that has never exchanged a frame with it won't
appear. If you need real discovery, use a scanner built for it. That job wants
a different tool, and sweeping someone else's network is a consent question
rather than a technical one.

Name lookups run in parallel against the resolvers already configured, and are
abandoned after a couple of seconds: an inventory is not worth stalling a
diagnosis for.

## Socket states

What this device's own TCP sockets are doing right now, read from `ss`/`netstat`,
the same signal Zeek derives from the wire, without a capture:

```
SOCKETS (this device)
  established 31   listen 17   time_wait 8
```

Two states carry a diagnosis:

- **SYN_SENT piling up**: this device is trying and nothing is answering. That
  is traffic being filtered, not a slow network, and the finding names the
  address it's failing to reach. From the application's side a dropped SYN and
  a slow server look identical.
- **CLOSE_WAIT piling up**: the far end hung up and the local application never
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

- **The port opens but TLS doesn't complete**: something is listening and it
  isn't the service you wanted. A port check alone calls this healthy.
- **An expired certificate**: clients refuse outright while the network is
  perfect. Reported critical, with days remaining.
- **A certificate close to expiry**: cheaper to fix now than during the outage
  it becomes.
- **Interception**: if the issuer is a known inspection product rather than a
  public CA, traffic is being re-signed in the path.
  Anything that pins or verifies certificates fails while ping and port checks
  look perfect.

Verification failures aren't fatal to the check: the handshake is retried
without verification purely to read the certificate, because a bad certificate
is exactly what needs describing.

**Banners.** Ports that aren't TLS get a short read after connecting: SSH and
SMTP announce themselves immediately. A quiet port costs 0.5s and nothing else.

## Listening ports

What this device has bound, and on which interface rather than just loopback.
It pairs with the port checks below: those ask whether something answers from
outside, this shows whether anything is listening here at all: the difference
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

A normal run is a snapshot. The faults that are hardest to place: a marginal
cable, a hop dropping 3%, a link that flaps, are invisible in one pass and
obvious over a minute. `--soak SECONDS` samples over a window instead:

```bash
python3 faultone.py --report --soak 120
```

- **Error counters** are watched for the whole window, not 2 seconds, so
  "+14 errors in 120s" is a rate you can trust rather than a coin flip. The
  window runs alongside everything else rather than as a dedicated pause, so a
  normal run reports the error rate over its full duration (~7s) at no extra
  cost, and `--soak 60` takes about 60 seconds rather than 60 plus the run.
- **Per-hop loss** comes from `mtr` when it's installed: hundreds of probes per
  hop instead of traceroute's three.
- **Pings** run for longer, so partial loss shows up as a percentage.
- **Throughput** is sampled every second through the window, not just at its
  two ends, see below.

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
Longer soaks made it worse, not better, more window to average the burst away.

The progress line already ticked once a second through the wait. It now reads
the counters on the same tick, which costs about 2.4 ms per read: 0.29 s of
work across a `--soak 120`. Each interface carries `peak_mbps` and the series
itself, and `SERIES_MAX_SAMPLES` bounds what a long soak stores: at or below
900 seconds the interval is one second, above it the interval stretches, so an
hour-long window costs the same to carry as a two-minute one and every sample
stays a real measurement over a real interval rather than a decimated guess.

The series covers the part of the window still left to wait when the other
checks finish, not the whole of it. The counter window deliberately runs
alongside everything else, and under `--soak` the probes stretch too, so about
40 s of the window goes to the rest of the run. Measured on a real box:

| | sampler gets | samples |
|---|---|---|
| `--soak 20` | nothing, the run outlasts the window | 0 |
| `--soak 60` | 21 s | 21 |
| `--soak 120` | 83 s | 82 |

**So bursts need `--soak 60` at the least, and 120 is where it works properly**: 
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

A line going to 100% in bursts is normal. That is a line doing its job. Firing
on the shape alone cries wolf on every site with a backup window. So
`saturation_bursts` requires **harm in the same window**: packets this device
dropped, or probes to the target that went unanswered. Neither is inferred from
the throughput itself, which would make the test circular.

That rule was picked by testing candidates against patterns that should fire
and patterns that should not. It was the only one that got all seven right: 
`peak >= 70%`, `p95 >= 70%` and a duty-cycle threshold each raised false alarms
on an ordinary download or backup window.

### The window you didn't have to wait for: the kernel log (Linux)

A soak catches a fault while you're watching. The kernel has been watching
since boot, and every carrier transition and adapter reset went into its log
with a timestamp, the one thing a counter doesn't carry.

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
| `nic_reset_logged` | The driver reset the adapter, "Detected Hardware Unit Hang", a transmit queue timeout, a firmware crash. Every connection drops each time and **no interface counter records that it happened**, so the log is the only place this is visible at all. |

How it reads the log, and why in that order:

- `dmesg` first, with its default `[  1234.567]` seconds-since-boot stamps.
  Subtracting from `/proc/uptime` gives an exact age, and unlike `dmesg -T`
  it cannot be broken by a locale.
- `journalctl -k -o short-unix` when dmesg is restricted: `dmesg_restrict=1`
  is the default on Debian and Ubuntu, which gives epoch stamps.
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
target can change between visits with nobody touching a flag: no clients on
the first visit, clients on the second. Everything measured *to the target*
(call quality, hop count, where the site edge falls) is therefore only compared
when both runs went to the same place; the change of target is reported on its
own, neutrally, so a shorter diff is never mistaken for a quieter network.

Without that, comparing call quality to `8.8.8.8` against call quality to a
database two racks away reported *"something changed since the last visit, and
not for the better"* on a network where nothing had changed at all.

A field tool can't keep history, but you keep the reports, so "what changed"
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
and has been collecting errors since, a story no single reading tells. Changes
that got *worse* also become a finding, so they can't be scrolled past, and the
verdict will name the change rather than the symptom.

Two things it deliberately won't do: report a difference when either side is
missing the data (a `--quick` baseline, or a tool that wasn't installed last
time, would otherwise manufacture regressions), and report negative error
counts when the box has rebooted, a counter that went backwards is reported as
a reboot instead.

## Export / import workflow (no server, no open port)

There is no server mode: the tool never listens on anything. Run the diagnosis
once and write it to a file instead:

```bash
sudo python3 faultone.py --export report.json
sudo python3 faultone.py --export report.json --target 1.1.1.1   # trace/ping a different target
sudo python3 faultone.py --export report.json --target 8.8.8.8 --check-ports 53,443
```

This runs the same collection and heuristics as the terminal report but opens
no port at all. Copy `report.json` to your laptop (`scp`, USB, email, whatever),
then open `static/index.html` **directly in a browser**. No server is needed
for this part. There are three ways in: **Load exported report**, dropping the
file anywhere on the page, or pasting the JSON into the box in the sidebar.
Everything is built client-side from the report; the page makes no network
request of any kind.

The page reads in the order the questions arrive: the verdict first, then which
direction the fault is on and the path out beneath it, then the findings, then
what was checked, then the captured output behind it. Each group is marked by a
rail down its side.

Hop colour comes from what the report concluded, not from a second reading of
the timings: a hop a finding named, a destination something has established is
unreachable, and the state of the way in and of this box are all taken from the
verdict and the direction panel. Hops the trace never heard from are drawn as
one node, because a run of timeouts to the end of a trace establishes that it
stopped, not how far the path runs past there.

It follows your system's light or dark setting, prints to paper on a light
ground with the panels opened out, and the evidence panels can be opened from
the keyboard.

`static/index.html` only ever has to exist on *your* machine, never on the
box you're diagnosing.

When file transfer off the box is blocked or awkward, use `-` to send the
JSON to stdout, then select it in your terminal and paste it straight into the
viewer, no file needed at either end. SSH sends characters and your own
terminal draws them, so the selection never involves the box, which is why this
works where `scp` does not:

```bash
sudo python3 faultone.py --export -                  # JSON on stdout
sudo python3 faultone.py --export - --report         # JSON on stdout, findings on stderr
sudo python3 faultone.py --export - > report.json    # or redirect it
```

With `--export -`, stdout carries nothing but the JSON: every human-readable
line goes to stderr, so piping and redirecting stay clean.

Sent to stdout the JSON is written on **one line**; written to a named file it
keeps its indentation. The two destinations are for different things. A file is
read, diffed and handed to `--baseline`, so it stays legible. Stdout is piped or
pasted, and a compact report indented is 192 logical lines: about 198 rows on
an 80-column terminal, which on a box you can't copy a file from means dragging
a selection across all of it and scrolling part-way through. On one line a
terminal's triple-click takes the whole thing, because a soft wrap is not a line
break to it. The viewer's paste box removes the wrapping again and ignores a
shell prompt either side.

`-` is always JSON. The format is taken from the filename extension and `-`
hasn't got one, so there is no way to ask for the self-contained page here: 
`--export - > report.html` gives you JSON in a file named `.html`. Name the file
instead.

## Optional tools it will use if present

None is required. The rule for every one of them is the same: use it when it's
there, fall back silently when it isn't, and record in the report which tool
produced the data. On a box with nothing but `python3` the tool still runs and
says which checks it couldn't make, an absent tool lowers coverage, it never
becomes a fault.

**Better data than the fallback gives**

- **`scutil`**: macOS only, and part of the system rather than something
  to install. It is how the system-wide proxy settings are read: an explicit
  HTTP or HTTPS proxy, a PAC file and its URL, or WPAD auto-discovery. On
  Linux the same question is answered only by the `http_proxy` family of
  environment variables, which is the honest limit: a system-wide proxy
  there is a per-application convention rather than a setting anything can
  read. Absent either way, no proxy is reported, which is not the same as
  reporting there is none.

- **`mtr`**: per-hop loss over many cycles, which a single traceroute can't
  give you. When present it replaces the traceroute entirely, and the report
  says `path via mtr`. Loss is read from the destination backwards: loss at an
  intermediate hop that clears by the final hop is that router rate-limiting
  ICMP, not a fault, and is reported as such rather than as a problem.
- **`ethtool`**: what the two ends actually negotiated, plus whether
  auto-negotiation was on at all. That's the difference between "half duplex"
  and "half duplex because someone hard-coded one end", which sysfs can't tell
  you. Also the source of optical power readings on fibre.
- **`ss`**: per-connection TCP statistics (`ss -tin`), which is what makes
  loss attributable to a destination instead of an average across the box.
  Always run with `-n`: reverse DNS on a broken network is exactly the hang you
  don't want in a diagnostic.

**Things nothing else can tell you**

- **`dmesg`** / **`journalctl`**: the kernel log, for link transitions and
  adapter resets with the times attached. See
  [the kernel log](#the-window-you-didnt-have-to-wait-for-the-kernel-log-linux).
- **`chronyc`** / **`ntpq`** / **`timedatectl`**: whether the clock is
  synchronised and how far off it is, asked of whichever time daemon is
  actually running. A wrong clock is reported as a certificate fault by
  everything that isn't looking for it.
- **`tcptraceroute`**: a path built from TCP probes, for the networks where
  ICMP and UDP traceroute are filtered and the normal path stops dead.

**Plain fallbacks**

`ip` or `ifconfig`/`netstat` for interfaces and routes; `traceroute` or
`tracepath` when `mtr` is absent; `dig` or `nslookup` for resolver checks.
Whichever is present is used, and the report names it.

## Platform support & timing

**A check that can't run is never reported as a fault.** If `ifconfig`/`ip` or
`netstat` isn't on the box, you get "couldn't read the interface list" as a
warning, not "this device has no IP address". Missing `dig`/`nslookup` falls
back to the resolver queries this program makes itself, which need nothing
installed. On a stripped appliance the difference matters: a false critical is
worse than a gap.

Linux is the best-supported target: error counters and speed/duplex come
straight from sysfs. On macOS/BSD they're parsed from `ifconfig`/`netstat`; on
Windows those two checks report "not available" rather than guessing. Everything
else (interfaces, routes, ping, traceroute, DNS, ports) works on all three: 
the tool picks the right command per OS (`ip`/`ifconfig` vs `ipconfig`,
`traceroute` vs `tracert`). Commands run with `LC_ALL=C` so a localized system
doesn't silently break output parsing.

A full `--report` is ~7s where the path answers the trace: the gateway ping,
the target ping and the trace are independent, so they run together and the run
costs about as long as the trace alone. Where it doesn't answer, the trace runs
its full 60s timeout and the whole run costs that instead: that's what
`--quick` is for. Being broken is not the only way to get there: a network in
perfect health that filters traceroute reaches the same timeout, so this is a
normal cost on a locked-down path rather than a symptom of anything.

`--soak` runs those probes one at a time instead. When you have deliberately
asked to sample for a minute, probes perturbing each other's latency matters
more than the seconds saved.

## Which of two faults the verdict names

Every scenario in the test corpus is single-fault by construction: a fixture is
written to make one thing go wrong. So the ranking *between* two findings, which
is the whole product, is the least exercised logic in the tool.

`dev/audit.py` draws random combinations and checks the rules hold: exactly one
cause, a consequence never also unrelated, nothing sitting below the fault that
explains it. Those confirm the verdict obeys the layer rule. They cannot say
whether the layer rule gives the right answer, because the rule is what decides
it.

`dev/deep_e2e.py` asks the other question. It puts two scenarios on one box and
declares which of them the verdict should reach for, reasoned before it is run.
Recording whatever the tool says today would describe current behaviour rather
than claim a right answer.

The first thing it found was an inversion. `duplicate_ip` and
`virtual_router_conflict` ranked below the gateway packet loss they explain, so
a box with two devices on one address was told to look for a marginal cable,
while both of those findings say in their own next step that the symptoms move
with no pattern and to fix the addressing before chasing anything else. One
hundred and sixty single-fault scenarios could not see it, and neither could a
rule check that starts from the ranking.

## Security

This app has **no login and no authentication**. It executes real
system commands with whatever privileges you run it as. That's the
design. The point is to run the common diagnostics on a device you
already have root on, so treat it like a root shell, not a public
web app:

- **It never opens a port.** There is no server, no API and nothing listening,
  so there is no unauthenticated endpoint to reach, no Host header to validate
  and no DNS-rebinding surface. That whole category is absent rather than
  defended - which is why server mode was removed.
- The viewer and the self-contained report are plain files opened from disk.
  They make no network requests of any kind - no CDN, no fonts, no analytics -
  so they work with the internet unplugged, which matters for a tool you reach
  for when the network is what's broken.
- **Nothing in a report can become markup.** A report is full of bytes this box
  did not choose: hostnames out of reverse DNS, banners off whatever answered a
  port, strings out of somebody else's certificate. All of it lands in a page
  that gets opened, and often pasted somewhere and opened again. Two things
  keep it inert, and both are tested. The data rides in a JSON island, where
  `</` is escaped so a closing tag in the data cannot end the script block
  early and take the rest of the page with it. On the way into the document
  every value is escaped, and where markup is built deliberately it is built
  around values that were escaped first.

  The render half is checked by running the viewer's own functions with a
  payload in the fields and reading what they would put into the document. One
  of those tests runs the same code with the escaping removed and fails if the
  payload does *not* get through, because a security test that quietly stops
  exercising its own path is worse than none.

  There is deliberately no Content-Security-Policy meta tag. The viewer is
  inline script by necessity, so any workable policy would have to allow inline
  script, which protects nothing. A policy that looks like care and provides
  none is worse than its absence.
- User-supplied targets (for ping/traceroute/DNS) are validated: IPs via
  `inet_pton`, hostnames against a strict regex with a length cap, and
  commands are run as argument lists, never through a shell. So `; rm -rf /`
  style injection isn't possible, and a target can't start with `-` and be
  swallowed as a command-line flag. That's defense in depth, not a replacement
  for keeping the port private: anyone who can reach it can still run
  diagnostics against arbitrary hosts from your machine.
- The port-check list is capped at 32, since each check is a TCP connect with
  a timeout and an unbounded list would keep the box busy for a very long time.
  Truncation is reported in the findings, never silent.
- Exported reports are written `0600`. They contain internal addressing, MAC
  addresses, listening ports, resolver addresses and. Where LLDP is available: 
  switch names, management IPs and VLAN ids. That's a map of the site's network,
  so treat a `report.json` as sensitive when moving it around.
- DNS queries are sent only to the resolvers this device is already configured
  with, and a reply is accepted only from the address it was sent to, with a
  random query id, so a stray or off-path packet can't be read as a resolver's
  answer.
- `--soak` is capped at an hour, and the port-check list at 32, so neither a
  typo nor a query string can leave the box busy indefinitely.
- Nothing in the UI calls out to the internet (no CDN fonts/scripts): 
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
  refuses. One stray value would make a self-contained report fail to open
  with nothing on screen to explain why. Non-finite floats become `null`.

Non-ASCII text (hostnames, switch names) round-trips intact through JSON, the
HTML island and the terminal output, and a report the tool produced works as
its own `--baseline` with zero spurious changes.

## Tests

```bash
python3 test_faultone.py          # or: python3 -m unittest -v
```

1075 tests, no dependencies, no network, a few seconds, so they run
anywhere the tool does, including on the target box itself. That is the point of
having no dependencies: you can validate it in the environment that matters.

They're weighted toward what has actually broken here rather than spread evenly
for coverage's sake. Every real bug in this project came from a **parser**
meeting a format it hadn't seen, a macOS routing table, a traceroute
continuation line, so the parsers get the most cases, each with real captured
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
verdict. That found a real hole the first time: the counter test patched one
layer above the code the bug lived in, so it passed against the bug. Passing
tests are not evidence until you've watched them fail.

## Files

This section described a server with HTTP routing and a `COMMANDS_META` table
until 2026-08-07. None of it had existed for a long time. Server mode was
removed, and nothing pins prose the way the counts are pinned.

- `faultone.py`: the whole tool. Collectors (`cmd_*`) gather, checks
  (`_check_*`) turn what they gathered into findings, and `build_verdict`
  ranks those against `VERDICT_RULES` to pick one cause. To add a check:
  write a collector, write a `_check_*` that appends findings, give each new
  code a rule in `VERDICT_RULES`, a stage in `STAGE_RULES`, and a direction in
  `FINDING_SIDE`. The suite will tell you which of those you forgot: every
  one of them is guarded.
- `test_faultone.py`: the suite. Standard library `unittest`, no network,
  a few seconds. Includes the guards that keep these documents honest: counts,
  thresholds, flags, optional tools, and whether the README still describes
  what the tool can do.
- `static/index.html`: the standalone viewer, for reading an exported
  `report.json` on your own machine. Generated from `VIEWER_TEMPLATE` by
  `--emit-viewer`; a test holds the two byte-identical, so edit the template
  and regenerate rather than editing the file.
- `dev/`: five harnesses that are not part of the tool: `deep_e2e.py` runs
  every finding through the whole pipeline, `equivalence.py` proves a change
  stayed inert by diffing every scenario against a git ref, `audit.py` checks
  the rules between findings under one fault and under six, `about.py` compares
  the GitHub description against this file, and `release.py` cuts a release
  without dropping half of it. `HANDOVER.md` alongside them records what is
  unfinished and what was tried and rejected. See [dev/README.md](dev/README.md).

## The repository description

GitHub's About box lives outside the repository, so no test here can read it: 
which is how it sat quoting a finding count three releases out of date while
every count inside these files stayed green. (Writing that stale number here as
a numeral would trip the very guard this section exists to enable, which is a
fair demonstration that it works.) The canonical text is kept here
instead, where the same guard that pins every other number scans it:

> SSH into a box and get one line: is the fault this box, the way in, or the
> way out - and who owns it. Ranks 160 findings with readable rules instead of
> listing everything that looks wrong. One Python file, no install, nothing
> listens.

Update this block and the About box together. If the finding count moves and
only one of them is changed, the test suite fails on this file.

That only ever caught half of it: the suite pins the block, and nothing could
see the box itself. It sat quoting a count eighteen findings out of date while
every number inside the repository stayed green: the exact drift the guards
exist to prevent, in the one place they cannot look. `dev/about.py` closes it:

```bash
python3 dev/about.py          # compare, exit 1 if they differ
python3 dev/about.py --fix    # set the About box from this block
```

It is a dev harness rather than a test because it needs the network and an
authenticated `gh`, and the suite has to run on a box with neither. Run it when
you tag.

## Licence

MIT, in [LICENSE](LICENSE). Every file carries an `SPDX-License-Identifier: MIT`
line, including the viewer, so a self-contained `report.html` handed to a
site states its own terms.

Nothing third-party is bundled. The optional tools are executed, not linked, so
their licences (mtr is GPL, for instance) don't attach to this code. That stays
true only as long as nobody copies code *out* of them and into here.

## Extending it

Additions that fit what this tool is for: separating "the device" from
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
