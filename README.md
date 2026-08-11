# FaultOne

**152 findings it can reach. One line saying which one to fix first.**

You're SSH'd into a box and something is broken. **Is it this box, the way in,
or the way out?** FaultOne runs the checks you'd run by hand, then does the part
that actually takes experience: it works out which fault is the **cause** and
which are its consequences, and names who owns it.

The name is the promise — one fault to act on, not a list to triage. It will
still tell you if something unrelated is also broken; it just won't make you
work out which of the two to start with.

It fits two shapes of box and tells them apart on its own:

- **a box that only talks outward** — an appliance at a customer site, a
  jump host, a worker. There is no way in, so the question is this box or
  everything past it.
- **a box that answers requests** — a proxy, an API server, anything with
  clients connected. Now there are two directions, and they have different
  owners: the loss your users see and the loss your database sees are not the
  same fault.

```
========================================================================
LIKELY ROOT CAUSE: The loss is on what talks to this box, not on what it
talks to
  owner: the path between this box and the people using it   confidence: medium (15 of 18 checks ran)
  next: Everything this box depends on is clean, so the service itself
  is healthy. The loss is between here and your users - the edge, the
  load balancer in front, or the internet path to them.
========================================================================

  clients in FAULT  ->  this box ok  ->  depends on ok

  link PASS   address PASS   gateway PASS   internet FAIL   dns PASS   mtu PASS   ports PASS
```

Three boxes and an arrow answer *where* before anything asks you to know what a
layer is. On a box nothing connects to, the first one reads `none connected` and
the strip below carries the detail.

One Python file. Nothing to install, nothing left behind, no port opened.

## Use it

**On the box, over SSH:**

```bash
python3 faultone.py --report           # full check, ~7 seconds
python3 faultone.py --report --quick   # the essentials, ~2 seconds
```

That's the whole tool. Everything below is optional.

**What it aims at.** By default (`--target auto`) a box with clients connected
is diagnosed against **the backend it depends on most** — read off its own open
connections — because whether a service can reach its database matters more
than whether it can reach `8.8.8.8`. A box with no clients connected falls back
to `8.8.8.8`. Either way the report names what it chose and why, and
`--target host` overrides it.

**Can't copy files onto the box?** Pipe it in — it runs from memory and leaves
nothing behind:

```bash
ssh -C -J jump user@box "python3 - --report --quick" < faultone.py
```

`-C` because OpenSSH doesn't compress by default, and the file is 597 KB of
repetitive text: it goes over the wire at 178 KB with compression on, for the
cost of one flag.

**On a painfully slow console?** Comments and docstrings are about a quarter of
the file. The standard library will drop them for the trip — no build step, no
second version to keep in step, same behaviour:

```bash
python3 -c "import ast;print(ast.unparse(ast.parse(open('faultone.py').read())))" > /tmp/faultone.py
ssh -C -J jump user@box "python3 - --report" < /tmp/faultone.py    # 127 KB on the wire
```

That needs Python 3.9 on **your** machine; the box still only needs 3.7.
Stripped and compressed together it's 127 KB instead of 597 — 79% less, which
is nine minutes down to under two on a 9600-baud console, and nothing you'd
notice on anything faster.

**Want the visual version?** Two ways, both offline:

```bash
python3 faultone.py --export report.html   # one file - copy it off and open it
python3 faultone.py --export report.json   # smaller - drop it on static/index.html
```

The `.html` carries the report inside it: double-click and you're looking at the
verdict, which direction the fault is on, the hop-by-hop path and the evidence
behind all of it. It follows your system's light or dark setting, prints to
paper properly, and opens from the keyboard. The `.json` is smaller and carries
no viewer, so it's the one to paste through a terminal — and it's what
`--baseline` reads on the next visit.

**Getting it back off a box you can barely reach?** Most of an export is the
captured output of every command, kept so a conclusion can be audited later.
`--export-compact` leaves the evidence for everything that *passed* on the box:

```bash
python3 faultone.py --export-compact report.json    # ~5 KB instead of ~120 KB
```

Same verdict, same findings, same hop diagram, same stage strip — all of that is
derived and none of it is what makes an export big. What's kept is the evidence
behind the stages that aren't passing, plus any check that couldn't run, because
a gap in coverage has to stay visible or it reads as a pass.

**Can't copy a file off it at all?** No `scp`, no outbound connection, nothing
to install — but you can always read the screen. Print the report instead:

```bash
python3 faultone.py --export-compact -              # one line, on stdout
```

Triple-click it, copy, and paste it into the box in the viewer's sidebar. SSH
sends characters and your own terminal draws them, so the selection never
involves the box — which is exactly why this works where a file transfer
doesn't. It comes out on one line so a single click takes all of it, and the
viewer copes with the wrapping and with a stray shell prompt either side.

Either way there's no server, no internet, and nothing installed on either
machine.

## Eight flags worth knowing

| | |
|---|---|
| `--quick` | Skips the slow parts. Use it when someone's on the phone. |
| `--soak 120` | Watches for two minutes instead of taking a snapshot. Use it for faults that come and go. |
| `--target auto` | The default. On a box that accepts connections, aims at the backend it depends on most rather than at 8.8.8.8 — and re-owns the verdicts accordingly. |
| `--uplink-mbps 50` | The site's line rate, off the ticket. Without it the tool measures against the NIC's speed and can blame the carrier for a line the site is filling itself. |
| `--baseline old.json` | Compares against a previous visit and tells you what changed. |
| `--check-ports common` | Checks 22, 53, 80, 443, 8080 without typing them out. |
| `--inventory` | Lists the neighbours this device already knows. Passive — nothing is probed. |
| `--export-compact` | An export without the evidence behind the checks that passed. Around a twentieth of the size, same picture. |

[Every flag is listed here.](REFERENCE.md#every-flag)

## Why the ranking is the point

Every tool in this category collects more than this one does. None of them
decides, from the same counters, which fault is the cause — and that decision is
where the wrong answer usually comes from, because the obvious reading of the
evidence is often wrong.

Five cases where a competent engineer, looking at exactly the same numbers,
reaches the wrong conclusion:

| The evidence says | The obvious answer | What the ordering says |
|---|---|---|
| CRC errors climbing | replace the cable | collisions on a **full-duplex** link mean the switch port disagrees about duplex — no cable fixes that |
| Every destination lossy | your link is bad | the box's own receive backlog is overflowing — too busy, not broken |
| Retransmissions high | the path is dropping | the far end acknowledged data it already had — reordering, not loss |
| Certificate won't validate | renew the certificate | it isn't valid *yet*, which is almost always this device's clock |
| Clients losing traffic, and so is the database | one problem, upstream | two problems facing opposite ways — neither explains the other, and fixing one leaves the other exactly where it was |

The rule is one sentence: **a broken layer makes every layer above it look
broken, so the lowest layer with a live fault is the cause and the rest are
symptoms.** A dead gateway with failing DNS on top reports the gateway.

That rule is right, and it is right *within a direction*. Layer and direction
are separate axes, so every finding also carries which way it faces — the way
in, this box, or the way out. A fault facing one way can neither explain nor
corroborate one facing the other, and this box faces both. Without that, client
loss and backend loss are both layer 3 and the tool named one while presenting
the other as its consequence.

What it doesn't claim: it applies one plausible ordering, consistently — it
doesn't know your network. It still says *likely*. It tells you how much of
itself managed to run, names faults it can't explain, and refuses to call
something loss when the sample can't support it:

```
  owner: capacity, not a fault   confidence: medium (16 of 18 checks ran, 2 explained by it)
  next: Nothing here is faulty. Either the link is undersized for the traffic
  or something is consuming more than it should.
  this also accounts for: inet_partial_loss, call_quality_degraded
  also, unrelated: The certificate on 8.8.8.8:443 expired 40 day(s) ago
```

Both halves matter. The line above says the packet loss and the poor call
quality are **this fault's symptoms** — fix the saturated link and they go with
it. The line below says the expired certificate is **not**: it will still be
expired afterwards. Getting that backwards is how a report sends someone to
their carrier about a fault on their own box.

No model is involved — `VERDICT_RULES` is an ordered list you can read, and
every verdict cites the findings it came from. [The rules, and the numbers
behind them.](REFERENCE.md#why-the-ranking-is-the-point)

## The evidence it ranks

Two axes, because they answer different questions. **Which layer** decides what
explains what:

| Layer | Checks | Answers |
|---|---|---|
| **L1** Physical | address present, error/CRC counters, collisions, carrier flaps, speed & duplex, fibre optical power | Is this device's own link healthy? |
| **L2** Data link | ARP table, gateway reachability, MTU, LLDP switch port, receive-backlog drops | Is the local segment healthy — and is this box keeping up with it? |
| **L3** Network | routing, gateway, internet, traceroute, path MTU, checksum errors, call quality | Does traffic leave the site and arrive intact? |
| **L4** Transport | listening ports, socket states, TCP port checks, per-connection loss and stalls, connection tracking, accept queues, connection setup, ephemeral ports, file descriptors | Is the service reachable — and is this device's own stack in the way? |
| **L7** Application | DNS and each resolver, TLS handshake and certificate, the certificate this box serves, clock synchronisation | Do names resolve, and does the service actually work? |

**Which direction** decides who owns it:

| Direction | Checks | Answers |
|---|---|---|
| **the way in** | loss and latency on clients' own connections, the load balancer in front, accept queues, SYN cookies and backlog, file descriptors, the certificate this box serves | Can people reach this box, and does it answer them? |
| **this box** | its link, hardware, kernel log, drops, connection tracking, socket memory, clock | Is the box itself in the way? |
| **the way out** | backends, DNS, the hop-by-hop path, path MTU, ephemeral ports, egress | Can it reach what it needs to answer them? |

The two ceilings show why this is not cosmetic: running out of **file
descriptors** stops a box *accepting*, running out of **ephemeral ports** stops
it *opening*. Both are "it ran out of something", and they break opposite
directions.

### What it actually checks

**32 things are inspected**, and **152 distinct conclusions** can come out of
them — 131 are faults, 21 are context.

*On the device:* interfaces and addresses · routing table and default gateway ·
interface error, drop, CRC and collision counters · how often the link has
dropped and returned · what the kernel logged and when · packets this device
drops itself · connection tracking table pressure · link speed, duplex and
MTU · optical power and alarms on fibre · which switch port you're on
(LLDP/CDP) · ARP/neighbour table · TCP socket states · TCP retransmission
counters · per-connection TCP loss and stalls, broken down by destination ·
clock synchronisation · CPU thermal throttling · bonded interface members ·
the neighbour table against its own ceiling · listening ports · neighbour
inventory

*Serving traffic, if anything is connected:* who is connected and through
which load balancer · loss and latency on clients' own connections, separately
from backends' · the certificate this box serves · accept queues and SYN
cookies · half-open connections against the listen backlog · ephemeral ports
and file descriptors · why connections were aborted

*Off the device:* gateway reachability and loss · target reachability and loss ·
hop-by-hop path · a TCP path when the normal one is filtered · path MTU · DNS
resolution · each configured resolver individually · TCP reachability of
specific ports · TLS handshake and certificate

*Worked out from those, not separately collected:* call quality (MOS), where
your network ends and the provider's begins, per-hop latency and jitter, link
utilisation, which side of this box a fault is on, and what changed since a
previous visit.

[The same list with what each one catches.](REFERENCE.md#what-a-check-means-here-and-how-many-there-are)

Those are the inputs, not the product. A tool with twice as many checks and no
ordering hands you twice as much to read and no answer.

## What you need

**Python 3.7 or newer, and nothing else.** No packages, no virtualenv, no
build. It works on Linux, macOS and Windows; Linux is the best-supported
target.

If the box has something older, it says so and stops rather than failing
halfway through a check. If Python is upgraded on the box later, nothing here
needs changing — only the standard library is used, and every report records
which interpreter produced it, so a `--baseline` across an upgrade tells you
the interpreter changed instead of blaming the network.

If `mtr`, `ethtool`, `lldpd` or `tcptraceroute` happen to be installed it uses
them for better data — per-hop loss, negotiated duplex, which switch port
you're plugged into. If they aren't, it says less and carries on.

**Several checks read Linux-specific counters and stay silent elsewhere**: the
per-connection breakdown (`ss`), carrier flap history, receive-backlog and
accept-queue drops, connection tracking, and the TCP extended counters behind
the checksum and connection-setup findings. The clock check needs one of
`chronyc`, `timedatectl` or `ntpq` to be present. On macOS or Windows those
report that they couldn't run rather than that nothing is wrong, and the
verdict's confidence drops accordingly — which is the honest answer, since less
of the tool ran.

**A check that can't run is never reported as a fault.** Missing `ifconfig`
gives you "couldn't read the interface list", not "this device has no IP
address". A false diagnosis is worse than a gap.

## Security, and the reports

It never opens a port and never listens for anything — there's no server to
secure. It does run real commands with your privileges.

A report is a **map of the network it was taken on** — internal addressing, MAC
addresses, switch names, VLANs, resolvers, listening ports. Exports are written
`0600` for that reason. Treat one like a network diagram: fine in a ticket, fine
with the people who own that network, **not** committed to a repository or
pasted somewhere public. `.gitignore` here covers `report.json` and
`report.html`, but it can't know what you named yours.

[Full security notes.](REFERENCE.md#security)

## Licence

MIT — see [LICENSE](LICENSE). Use it, change it, ship it inside whatever you
like; it comes with no warranty.

Nothing is vendored, so no other licence travels with the file. The optional
tools it can use (`mtr`, `ethtool`, `lldpd`, `tcptraceroute`) are run as
separate programs, never linked or copied in.

## More

- **[REFERENCE.md](REFERENCE.md)** — every check explained, and why it's worth checking
- `faultone.py` — the whole tool
- `static/index.html` — the report viewer, for your machine rather than theirs (regenerate with `--emit-viewer`)
- `test_faultone.py` — `python3 test_faultone.py`, 918 tests, no dependencies
- `dev/` — release harnesses, not part of the tool: every finding through the whole pipeline, and a diff of every scenario against a previous version

Every report records the version that produced it, so a page opened months
later — or a `--baseline` from a previous visit — can be read for what made it.
`python3 faultone.py --version` tells you what's on the box.
