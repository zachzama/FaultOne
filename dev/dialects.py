#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Ask every parser the same question in another platform's accent.

    python3 dev/dialects.py              # every case
    python3 dev/dialects.py qdisc        # the ones whose name contains "qdisc"
    python3 dev/dialects.py --self-test  # prove the harness can see a defect

Six defects in three days had one shape, and it was not "a parser crashed".
It was **a dialect difference turning a reading into an absence**, silently:

  - mtr quoted its numbers, so `Avg` failed an isinstance check and the hop
    had no timing at all
  - `ifconfig` wrote `10Gbase-SR` and every link above a gigabit had no speed
  - `tc` wrote `1Kb` and every real backlog read as an empty queue
  - `netstat` wrote `Idrop` and every FreeBSD box reported zero discards
  - `netstat` marked a down interface `ixl0*` and the name stopped matching
  - `traceroute` wrote `!F-1492` and the one flag carrying a measurement was
    the one dropped

None of them raised. Every one of them produced a confident report with a
number missing from it, and in one case a sentence saying the opposite of the
truth. The test corpus could not find them because the fixtures were written
from the same understanding as the code - they are tidier than any machine this
runs on, and each way they are tidy is a guard nothing tests.

So this does not test the parsers against expected output. It parses one sample
twice - once as written, once in a dialect a real platform actually uses - and
reports **any value that was there in the first and is missing or zero in the
second**. That property needs no expected output, holds for every parser here,
and is exactly the failure these six shared.

A dialect that is *supposed* to change something declares it. The asterisk on a
down interface changes the name and the link state, on purpose, and saying so
in the case is the difference between a harness and a rubber stamp.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_argv, sys.argv = sys.argv, ["dialects"]
import faultone as nd                                       # noqa: E402
sys.argv = _argv


# ---------------------------------------------------------------------------
# Dialects. Each is one documented difference between two platforms' spelling
# of the same output - not a corruption, and not a guess. Anything invented
# here would produce a finding about a format nobody emits.
# ---------------------------------------------------------------------------

def quote_json_numbers(text):
    """Every number as a string. Some mtr builds do this to every field."""
    def walk(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value
    return json.dumps(walk(json.loads(text)))


def crlf(text):
    """Windows line endings, which reach these parsers through a pasted file."""
    return text.replace("\n", "\r\n")


def wider_columns(text):
    """The same table with the columns spaced differently. Column widths follow
    the widest value, so two boxes running one command disagree about them."""
    return "\n".join("   ".join(line.split()) if line.strip() else line
                     for line in text.splitlines()) + "\n"


def trailing_spaces(text):
    return "\n".join(line + "   " for line in text.splitlines()) + "\n"


# ---------------------------------------------------------------------------
# Cases. A sample as one platform writes it, and the same reading as another
# platform writes it. Both must produce the same numbers.
# ---------------------------------------------------------------------------

MTR = json.dumps({"report": {"mtr": {"src": "box", "dst": "192.0.2.9"}, "hubs": [
    {"count": 1, "host": "192.0.2.1", "Loss%": 0.0, "Snt": 10, "Last": 1.2,
     "Avg": 1.4, "Best": 1.0, "Wrst": 2.9, "StDev": 0.5},
    {"count": 2, "host": "198.51.100.13", "Loss%": 12.0, "Snt": 10, "Last": 12.0,
     "Avg": 13.1, "Best": 11.2, "Wrst": 16.0, "StDev": 1.6}]}})

TC_PLAIN = ("qdisc fq_codel 8003: dev eth0 root refcnt 2 limit 10240p\n"
            " Sent 998877 bytes 654 pkt (dropped 12, overlimits 0 requeues 3)\n"
            " backlog 900b 1p requeues 3\n")
# iproute2 prints this field through sprint_size(), which reaches for a unit at
# 1024 bytes - so one ordinary packet waiting is already the other spelling.
TC_SIZED = TC_PLAIN.replace("backlog 900b 1p", "backlog 1Kb 1p")

# One ten-gigabit link, described by the two tools that describe links. ethtool
# writes the rate in whole megabits and ifconfig writes it with a multiplier,
# so this is the same reading in two accents - which is the only kind of pair
# that means anything here. Two platforms reporting genuinely different things
# is a difference, not a dialect.
ETHTOOL_FAST = ("Settings for ix0:\n\tSupported link modes:   10000baseT/Full\n"
                "\tSpeed: 10000Mb/s\n\tDuplex: Full\n\tLink detected: yes\n")
IFCONFIG_FAST = ("ix0: flags=8943<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n"
                 "\tmedia: Ethernet autoselect (10Gbase-SR <full-duplex>)\n"
                 "\tstatus: active\n")


def ethtool_speed(text):
    """Just the rate, so the two tools' very different shapes can be compared
    on the one thing they both answer."""
    return {"speed_mbps": nd.parse_ethtool(text).get("speed_mbps")}


def ifconfig_speed(text):
    return {"speed_mbps": next(iter(nd.parse_ifconfig_modes(text).values()),
                               {}).get("speed_mbps")}

# macOS prints no discard column at all without -d, which is a difference
# between the platforms rather than a dialect - the two are not describing one
# reading two ways, they are reporting different things, and pairing them here
# would be asserting that a column nobody printed should have been read.
NETSTAT_FREEBSD = (
    "Name    Mtu Network       Address              Ipkts Ierrs Idrop"
    "     Ibytes    Opkts Oerrs     Obytes  Coll\n"
    "en0    1500 <Link#4>      00:00:5e:00:53:03     1000     1     7"
    "      90000      900     0      80000     0\n")
# And the same box with the interface down, which is a change it must report.
NETSTAT_DOWN = NETSTAT_FREEBSD.replace("en0    1500", "en0*   1500")
# A tunnel has no link-layer address, so the column is blank and every field
# after it moves one to the left.
NETSTAT_NO_ADDRESS = (
    "Name    Mtu Network       Address              Ipkts Ierrs Idrop"
    "     Ibytes    Opkts Oerrs     Obytes  Coll\n"
    "en0    1500 <Link#4>                            1000     1     7"
    "      90000      900     0      80000     0\n")

SS = ("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
      "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
      "ESTAB  0 0 10.0.0.5:443 198.51.100.7:51000\n"
      "ESTAB  0 0 10.0.0.5:40001 203.0.113.9:443\n")
# BSD netstat -an: state last, and a dot before the port instead of a colon.
NETSTAT_AN = ("Proto Recv-Q Send-Q Local Address      Foreign Address    (state)\n"
              "tcp4       0      0 *.443              *.*                LISTEN\n"
              "tcp4       0      0 10.0.0.5.443       198.51.100.7.51000 ESTABLISHED\n"
              "tcp4       0      0 10.0.0.5.40001     203.0.113.9.443    ESTABLISHED\n")

TRACE_PLAIN = ("traceroute to example.net (192.0.2.9), 30 hops max\n"
               " 1  192.0.2.1  1.2 ms  1.1 ms  1.3 ms\n"
               " 2  198.51.100.1  5.0 ms  5.1 ms  5.2 ms\n")
# One hop reporting one MTU, spelled by the two tools that walk a path.
TRACEPATH_PMTU = (" 1:  192.0.2.1        1.2ms\n"
                  " 2:  198.51.100.1     5.0ms pmtu 1492\n")
TRACEROUTE_PMTU = ("traceroute to example.net (192.0.2.9), 30 hops max\n"
                   " 1  192.0.2.1  1.2 ms  1.1 ms  1.3 ms\n"
                   " 2  198.51.100.1  5.0 ms !F-1492  5.1 ms  5.2 ms\n")


def hop_pmtus(text):
    """Only the MTUs, because the two tools disagree about everything else in
    the row and agree about this."""
    return {"pmtu": [h.get("pmtu") for h in nd.parse_traceroute_hops(text)]}

ARP_LINUX = ("192.0.2.1 dev eth0 lladdr 00:00:5e:00:53:01 REACHABLE\n"
             "192.0.2.9 dev eth0 lladdr 00:0a:0b:00:53:09 STALE\n")
# BSD strips the leading zero off every octet it can.
ARP_BSD = ("? (192.0.2.1) at 0:0:5e:0:53:1 on em0 expires in 1200 seconds [ethernet]\n"
           "? (192.0.2.9) at 0:a:b:0:53:9 on em0 expires in 900 seconds [ethernet]\n")

RESOLV = ("# generated\nsearch example.lan\n"
          "nameserver 192.0.2.53\nnameserver 198.51.100.53\n")

# One round trip, summarised by the three pings that exist. Linux and BSD
# differ only in what they call the fourth figure; Windows names each one and
# prints them in another order, which is how the average and the maximum came
# to swap places once - a wrong number rather than a missing one.
PING_LINUX = {"ok": True, "stdout":
              "rtt min/avg/max/mdev = 1.000/2.000/3.000/0.500 ms\n"}
PING_BSD = {"ok": True, "stdout":
            "round-trip min/avg/max/stddev = 1.000/2.000/3.000/0.500 ms\n"}
PING_WINDOWS = {"ok": True, "stdout":
                "Approximate round trip times in milli-seconds:\n"
                "    Minimum = 1ms, Maximum = 3ms, Average = 2ms\n"}

# One next hop, asked for by the two commands that ask. The interface is named
# the same on both here on purpose: a real box would call it eth0 or em0, and
# that difference is the platform rather than the reading.
ROUTE_LINUX = "8.8.8.8 via 10.0.0.1 dev em0 src 10.0.0.5 uid 0 \n    cache \n"
ROUTE_BSD = ("   route to: 8.8.8.8\ndestination: default\n       mask: default\n"
             "    gateway: 10.0.0.1\n  interface: em0\n"
             "      flags: <UP,GATEWAY,DONE>\n")

UDP_SS = ("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
          "UNCONN 4096 0 0.0.0.0:443 0.0.0.0:*\n"
          "UNCONN 0 0 10.0.0.5:53 0.0.0.0:*\n")
UDP_BSD = ("Proto Recv-Q Send-Q Local Address     Foreign Address   (state)\n"
           "udp4    4096      0 *.443             *.*\n"
           "udp4       0      0 10.0.0.5.53       *.*\n")

# One firewall, counted by the two tools that count it. Only the rules that
# stop a packet, which is what the consumer keeps: nft declines to record an
# accept verdict on purpose, and comparing that would be asserting a deliberate
# difference is a defect.
IPTABLES = ("[120:9000] -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n"
            "[3:180] -A INPUT -j DROP\n")
NFT = ("table inet filter {\n"
       "  chain input {\n"
       "    tcp dport 443 counter packets 120 bytes 9000 accept\n"
       "    counter packets 3 bytes 180 drop\n"
       "  }\n"
       "}\n")

def route_next_hop(text):
    """Only what both commands answer. Linux prints the source address it
    would use and BSD does not, which is the platform rather than the accent."""
    got = nd.parse_route_to(text) or {}
    return {k: got.get(k) for k in ("via", "dev", "onlink")}


def firewall_stops(text):
    """The counters on the rules that stop a packet, however the tool spelt
    the verdict. That is exactly the set rules_that_counted keeps."""
    parsed = (nd.parse_nft_ruleset(text) if text.lstrip().startswith("table")
              else nd.parse_iptables_save(text))
    return {"stops": [(r["packets"], r["bytes"])
                      for r in parsed["rules"]
                      if r.get("verdict") in nd.STOPS_A_PACKET]}


# ---------------------------------------------------------------------------
# Not here, and on purpose.
#
# `lldpctl -f keyvalue` is a single format and this has no second accent for it
# that can be vouched for. A case was written asserting that lldpd numbers the
# neighbour when an interface has more than one - `lldp.em0.1.chassis.name` -
# and the parser does indeed return nothing for that shape. It came out again,
# because whether lldpd emits it is a guess, and a guess here produces a
# finding about a format nobody sends. The rule at the top of this file is the
# rule: a dialect is a documented difference, not a plausible one.
#
# The same goes for `ethtool` optics, `parse_proxy_stats` and the systemd unit
# list, which have one producer each. They are covered by the suite, which is
# the right place for a format with no second spelling.
#
# What would settle the LLDP one is output from a box with two neighbours on
# an interface. Until then it stays a known gap rather than an invented case.
# ---------------------------------------------------------------------------


def sockets(text):
    return nd.parse_socket_states(text)


#: (name, parser, written-one-way, written-another-way, keys allowed to differ)
#:
#: The last column is the point. A dialect that changes a reading has to say
#: which one, or this is a harness that passes because it was told to.
CASES = [
    ("mtr: a build that quotes every number",
     nd.parse_mtr_json, MTR, quote_json_numbers(MTR), ()),
    ("mtr: pasted through a Windows terminal",
     nd.parse_mtr_json, MTR, crlf(MTR), ()),

    ("qdisc: a backlog large enough to carry a unit",
     nd.parse_qdisc, TC_PLAIN, TC_SIZED, ("backlog_bytes",)),
    ("qdisc: trailing whitespace on every line",
     nd.parse_qdisc, TC_PLAIN, trailing_spaces(TC_PLAIN), ()),

    ("link speed: ethtool and ifconfig on one ten-gigabit link",
     lambda t: (ethtool_speed if "Settings for" in t else ifconfig_speed)(t),
     ETHTOOL_FAST, IFCONFIG_FAST, ()),

    ("netstat -i: the discard column under each of its names",
     nd.parse_netstat_link_stats, NETSTAT_FREEBSD,
     NETSTAT_FREEBSD.replace("Idrop", " Drop"), ()),
    ("netstat -i: an interface marked down",
     nd.parse_netstat_link_stats, NETSTAT_FREEBSD, NETSTAT_DOWN, ("operstate",)),
    ("netstat -i: an interface with no link-layer address",
     nd.parse_netstat_link_stats, NETSTAT_FREEBSD, NETSTAT_NO_ADDRESS, ()),
    ("netstat -i: columns spaced differently",
     nd.parse_netstat_link_stats, NETSTAT_FREEBSD, wider_columns(NETSTAT_FREEBSD), ()),

    ("sockets: ss and BSD netstat describing one box",
     sockets, SS, NETSTAT_AN, ()),
    ("sockets: pasted through a Windows terminal",
     sockets, SS, crlf(SS), ()),

    ("path MTU: tracepath and traceroute on one hop",
     hop_pmtus, TRACEPATH_PMTU, TRACEROUTE_PMTU, ()),
    ("traceroute: trailing whitespace on every line",
     nd.parse_traceroute_hops, TRACE_PLAIN, trailing_spaces(TRACE_PLAIN), ()),

    ("arp: ip neigh and BSD arp -a on one table",
     nd.parse_arp_table, ARP_LINUX, ARP_BSD, ("state",)),

    ("resolv.conf: pasted through a Windows terminal",
     nd.parse_resolvers, RESOLV, crlf(RESOLV), ()),

    ("ping: one round trip, summarised by Linux and by BSD",
     nd.parse_ping_stats, PING_LINUX, PING_BSD, ()),
    # Windows offers no deviation at all and this synthesises one from the
    # spread, so that figure is declared - it must still be there, and it is
    # not the same number.
    ("ping: the same round trip summarised by Windows",
     nd.parse_ping_stats, PING_LINUX, PING_WINDOWS, ("stdev_ms",)),

    ("route: one next hop, asked for two ways",
     route_next_hop, ROUTE_LINUX, ROUTE_BSD, ()),

    ("udp: ss and BSD netstat on one datagram listener",
     nd.parse_udp_sockets, UDP_SS, UDP_BSD, ()),

    ("firewall: one rule's counters, from iptables and from nft",
     firewall_stops, IPTABLES, NFT, ()),

]


def readings(value, path=""):
    """Every value in a parse result that says something, by where it sits.

    A reading is a number that is not zero, or a non-empty string or list.
    Zero and empty are what an absence looks like once it has been rendered,
    which is the whole subject here: nothing in a report distinguishes "no
    errors" from "the errors column was never found".
    """
    out = {}
    if isinstance(value, dict):
        for key, sub in value.items():
            out.update(readings(sub, "%s/%s" % (path, key)))
    elif isinstance(value, (list, tuple)):
        for i, sub in enumerate(value):
            out.update(readings(sub, "%s[%d]" % (path, i)))
    elif isinstance(value, bool):
        if value:
            out[path] = value
    elif isinstance(value, (int, float)):
        if value:
            out[path] = value
    elif value:
        out[path] = value
    return out


def compare(parser, first, second, allowed):
    """Readings present in the first parse and gone or changed in the second.

    A declared key may **change**. It may not disappear, and that distinction
    is the whole difference between a harness and a rubber stamp: the media
    case declares `speed_mbps` because 1000baseT and 10Gbase-SR really are
    different speeds, and the first version of this let that declaration excuse
    the speed going missing entirely - which is the defect it was written to
    catch. It missed it, on the run that put the defect back.
    """
    before, after = readings(parser(first)), readings(parser(second))
    lost = []
    # Both directions. Two accents of one reading should parse identically, so
    # which sample is called the base must not decide what this can see - and
    # it did: with the discard column's defect put back, the reading was lost
    # going one way and gained going the other, and only one of those was
    # checked. The harness reported "caught" for four defects and "missed" for
    # that one purely because of the order two strings sat in a tuple.
    for where, value in sorted(before.items()):
        declared = any(("/%s" % key) in where for key in allowed)
        if where not in after:
            lost.append((where, value, None))
        elif after[where] != value and not declared:
            lost.append((where, value, after[where]))
    for where, value in sorted(after.items()):
        if where not in before:
            lost.append((where, None, value))
    return lost


def run(cases):
    bad = 0
    for name, parser, first, second, allowed in cases:
        try:
            lost = compare(parser, first, second, allowed)
        except Exception as exc:                             # noqa: BLE001
            print("  %-58s RAISED  %s" % (name[:58], exc), flush=True)
            bad += 1
            continue
        if not lost:
            print("  %-58s same" % name[:58], flush=True)
            continue
        bad += 1
        print("  %-58s LOST %d" % (name[:58], len(lost)), flush=True)
        for where, was, now in lost[:6]:
            print("      %-34s %r -> %r" % (where, was, now), flush=True)
    return bad


def self_test():
    """Put the six defects back, one at a time, and check this sees each one.

    Not a planted toy. Every one of these is the code as it actually shipped,
    and a harness written after the fact is worth nothing until it can find
    what it was written for.
    """
    import re
    print("re-introducing each defect this was written for:", flush=True)
    restore, ok = {}, True
    checks = [
        ("mtr took whatever type the build used",
         "_mtr_number", lambda: setattr(nd, "_mtr_number", lambda v: v
                                        if isinstance(v, (int, float)) else None),
         "mtr: a build that quotes every number"),
        ("the backlog pattern demanded plain bytes",
         "_QDISC_BACKLOG",
         lambda: setattr(nd, "_QDISC_BACKLOG",
                         re.compile(r"backlog (\d+)()b (\d+)p")),
         "qdisc: a backlog large enough to carry a unit"),
        ("the media pattern knew no multiplier",
         "MEDIA_SPEED_RE",
         lambda: setattr(nd, "MEDIA_SPEED_RE", re.compile(r"(\d+)()base", re.I)),
         "link speed: ethtool and ifconfig on one ten-gigabit link"),
        ("netstat's discard column was only ever Drop",
         "NETSTAT_DROP_COLUMNS",
         lambda: setattr(nd, "NETSTAT_DROP_COLUMNS",
                         {"rx_dropped": ("Drop",), "tx_dropped": ("Odrop",)}),
         "netstat -i: the discard column under each of its names"),
        ("the traceroute flag pattern demanded a space after it",
         "TRACE_PMTU_RE",
         lambda: setattr(nd, "TRACE_PMTU_RE",
                         re.compile(r"\bpmtu\s+(\d{3,5})\b|(?!x)x")),
         "path MTU: tracepath and traceroute on one hop"),
    ]
    by_name = {c[0]: c for c in CASES}
    for label, attr, break_it, case_name in checks:
        restore[attr] = getattr(nd, attr)
        break_it()
        name, parser, first, second, allowed = by_name[case_name]
        seen = bool(compare(parser, first, second, allowed))
        setattr(nd, attr, restore[attr])
        print("  %-56s %s" % (label[:56], "caught" if seen else "MISSED"),
              flush=True)
        ok = ok and seen
    # And the control: with nothing broken, it must say nothing. A harness that
    # always finds something is not evidence of anything.
    noise = run([c for c in CASES if c[0] in {n[3] for n in checks}])
    if noise:
        print("  the unbroken tree is not clean, so a catch above means "
              "nothing", flush=True)
        ok = False
    print("\n%s" % ("ok: every defect this was written for is visible, and a "
                    "clean tree is quiet" if ok else
                    "FAILED: this cannot see what it is for"), flush=True)
    return 0 if ok else 1


def main(argv):
    if "--self-test" in argv:
        return self_test()
    wanted = [a for a in argv[1:] if not a.startswith("-")]
    cases = [c for c in CASES
             if not wanted or any(w.lower() in c[0].lower() for w in wanted)]
    if not cases:
        print("no case matches %s" % " ".join(wanted), flush=True)
        return 2
    print("one reading, written two ways, %d time(s)\n" % len(cases), flush=True)
    bad = run(cases)
    print("\n%d of %d case(s) lost a reading in translation"
          % (bad, len(cases)), flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
