#!/usr/bin/env python3
"""
FaultOne - a tiny, dependency-free network diagnostics console.

Run the common networking commands (interfaces, routes, ARP, ping,
traceroute, DNS lookup, listening ports) on a box you're logged into, and
get a rule-based read on whether the fault is this device, the network it
is plugged into, or something upstream.

Usage:
    # Over SSH, no browser, no port opened - findings straight to the
    # terminal you're already sitting in. Exits 1 on a critical finding.
    sudo python3 faultone.py --report
    sudo python3 faultone.py --report --quick   # skip traceroute, ~2s

    # Nothing may be written to the target box? Pipe this file in over
    # SSH - it runs from memory and leaves nothing behind:
    #   ssh -J jump user@box "python3 - --report --quick" < faultone.py
    #   ssh -J jump user@box "python3 - --export -" < faultone.py > report.json

    # Local web UI (binds 127.0.0.1 - see the SECURITY note below):
    sudo python3 faultone.py                  # binds to 127.0.0.1:8080
    sudo python3 faultone.py --port 9000

    # JSON report instead, for the richer offline view:
    sudo python3 faultone.py --export report.json
    sudo python3 faultone.py --export report.json --target 1.1.1.1
    sudo python3 faultone.py --export -         # stdout, for copy/paste

    # Then copy report.json to any machine and open static/index.html
    # directly in a browser (no server needed) and use "Load report".
    # static/index.html is only ever needed on YOUR machine - faultone.py
    # is standalone on the box being diagnosed.

SECURITY
--------
This tool executes real system commands (ping, traceroute, etc.) with
whatever privileges you run it as - typically root, since some of these
commands need elevated privileges on some OSes. There is NO authentication
built in. It binds to 127.0.0.1 (localhost only) by default for that
reason. Only bind it to a non-localhost address on a trusted network, and
ideally put it behind SSH port-forwarding or a reverse proxy with auth
instead. User-supplied hostnames/IPs are strictly validated and commands
are run without a shell, so classic "; rm -rf" style injection isn't
possible - but there is still no login, so anyone who can reach the port
can run diagnostics against arbitrary hosts from your machine.

No third-party dependencies - standard library only. Nothing is vendored, so
nothing else's licence travels with this file: the optional tools it can use
(mtr, ethtool, lldpd, tcptraceroute) are executed as separate programs, never
linked or copied in.

Copyright (c) 2026 Zachary Zamarripa. MIT licensed - see LICENSE.
SPDX-License-Identifier: MIT
"""

import argparse
import errno
import concurrent.futures
import datetime
import json
import math
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import textwrap

# Reports carry this, so a page opened months later, or a --baseline from a
# previous visit, can be read in the light of what produced it.
__version__ = "1.7.3"

# Python 3.7 is the floor: subprocess.run's capture_output and text arguments
# arrived there. The syntax parses on 3.6, so without this check that box gets
# a confusing TypeError from the first command it runs instead of being told.
MIN_PYTHON = (3, 7)
if sys.version_info < MIN_PYTHON:
    sys.stderr.write(
        "FaultOne needs Python {}.{} or newer; this is {}.{}.\n"
        "Everything here is standard library, so a newer python3 on the box is "
        "all that's required - there is nothing to install.\n".format(
            MIN_PYTHON[0], MIN_PYTHON[1],
            sys.version_info[0], sys.version_info[1]))
    # 3 is UNKNOWN in the monitoring-plugin convention this follows: the check
    # could not run, which is not the same as finding nothing wrong. Spelled
    # out because this guard runs before the constants are defined.
    raise SystemExit(3)

OS_NAME = platform.system()  # 'Linux', 'Darwin' (macOS), or 'Windows'

# platform.system() answers with the kernel's name, so a Mac calls itself
# "Darwin". That is accurate and means nothing to most people reading a report;
# the other two already read the way anyone would say them. The raw value stays
# in the report for anything reading it by machine - only the label changes.
OS_LABELS = {"Darwin": "macOS"}


def os_label(name=None):
    """How to write the platform's name for someone reading the report."""
    name = name or OS_NAME
    return OS_LABELS.get(name, name)

# ---------------------------------------------------------------------------
# Input validation - only hostnames / IPv4 / IPv6 are accepted as targets.
# Commands are always invoked as arg lists (no shell=True), so this is a
# defense-in-depth belt-and-suspenders check, not the only thing standing
# between user input and the shell.
# ---------------------------------------------------------------------------

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
# Zone id on a link-local address, e.g. fe80::1%en0 - inet_pton rejects the
# suffix, but it's a legitimate target (the gateway may be link-local).
ZONE_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def valid_ip(t):
    """Exact IPv4/IPv6 check via inet_pton rather than a permissive regex."""
    addr, _, zone = t.partition("%")
    if zone and not ZONE_RE.match(zone):
        return False
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, addr)
            return True
        except (OSError, ValueError):
            continue
    return False


def valid_target(t):
    """Is this something we can be pointed at?

    Accepts an internationalised name by converting it the way a resolver
    would. A box in Tokyo or Munich has backends with names in its own script,
    and rejecting them as "invalid" made the tool unusable for exactly the
    deployments where nobody can paste an ASCII alternative.
    """
    # Length is checked first so no pathological input ever reaches the regex.
    if not t or len(t) > 253:
        return False
    return bool(valid_ip(t) or HOSTNAME_RE.match(t) or HOSTNAME_RE.match(idna_host(t) or ""))


def idna_host(name):
    """A non-ASCII hostname in the punycode form the DNS actually carries.

    Returns None when it is not convertible, which includes every ASCII name -
    those never needed converting and are matched directly.
    """
    if not name or all(ord(c) < 128 for c in name):
        return None
    try:
        return name.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Empty labels, over-long labels, and anything the codec refuses. An
        # unconvertible name is not a name, and saying so beats guessing.
        return None


# Tool availability doesn't change during a run, and this is called per
# interface in a couple of places - so look each name up once.
_WHICH_CACHE = {}


def which(cmd):
    if cmd not in _WHICH_CACHE:
        _WHICH_CACHE[cmd] = shutil.which(cmd) is not None
    return _WHICH_CACHE[cmd]


# Every parser in this file reads English command output ("100% packet loss",
# "Request timed out"). On a box with a localized LANG those strings change and
# the parsing silently returns nothing - which reads as "couldn't determine"
# rather than an obvious failure. Pin the locale for the commands we run.
C_LOCALE_ENV = dict(os.environ, LC_ALL="C", LANG="C")


def _nonneg(value):
    """None for a negative delta - a counter that went backwards wrapped or was
    reset, and neither is a rate."""
    return value if value is None or value >= 0 else None


def _cap(text, limit=None, keep="head"):
    """Keep a command's output to something a report can carry.

    keep="tail" for output where the end is the interesting part. A kernel ring
    buffer is megabytes of boot messages followed by the handful of lines that
    describe what went wrong ten minutes ago; capping from the front throws
    away exactly the part worth reading.
    """
    limit = limit or MAX_OUTPUT_BYTES
    if text and len(text) > limit:
        dropped = len(text) - limit
        if keep == "tail":
            return f"... [{dropped:,} earlier characters not stored]\n" + text[-limit:]
        return text[:limit] + f"\n... [{dropped:,} more characters not stored]"
    return text


def run(cmd, timeout=15, limit=None):
    """Run a command as an argv list (never a shell string) and capture output.

    `limit` raises the cap for a command whose output is read and reduced to a
    digest rather than stored - the socket table on a busy proxy is megabytes,
    and truncating it to the report's budget meant analysing an arbitrary first
    slice of it.
    """
    try:
        # errors="replace": an interface alias or SSID with non-UTF-8 bytes would
        # otherwise raise UnicodeDecodeError and fail the entire check, which
        # reads as "not available on this system" rather than "one odd byte".
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=C_LOCALE_ENV, errors="replace")
        return {"ok": True, "cmd": " ".join(cmd), "stdout": _cap(p.stdout, limit),
                "stderr": _cap(p.stderr), "code": p.returncode}
    except FileNotFoundError:
        return {"ok": False, "cmd": " ".join(cmd), "error": f"command not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "cmd": " ".join(cmd), "error": "command timed out"}
    except Exception as e:
        # Deliberately broad: this is the boundary where an external command
        # becomes data. Whatever else goes wrong out there, the check reports
        # itself unavailable rather than taking the whole diagnosis down - and
        # an unavailable check is never rendered as a fault. KeyboardInterrupt
        # is a BaseException, so Ctrl-C still stops the run.
        return {"ok": False, "cmd": " ".join(cmd), "error": str(e)}


def bad_target():
    return {"ok": False, "error": "invalid target - only hostnames or IPv4/IPv6 addresses are accepted"}


# ---------------------------------------------------------------------------
# Command builders, per OS. Each returns a run() result dict.
# ---------------------------------------------------------------------------

def cmd_interfaces():
    if OS_NAME == "Windows":
        return run(["ipconfig", "/all"])
    if which("ip"):
        return run(["ip", "addr", "show"])
    return run(["ifconfig", "-a"])


def cmd_routes():
    if OS_NAME == "Windows":
        return run(["route", "print"])
    if which("ip"):
        return run(["ip", "route"])
    return run(["netstat", "-rn"])


def cmd_arp():
    if OS_NAME == "Windows":
        return run(["arp", "-a"])
    if which("ip"):
        return run(["ip", "neigh"])
    return run(["arp", "-a"])


def cmd_listen_ports():
    if OS_NAME == "Windows":
        return run(["netstat", "-an"])
    if which("ss"):
        return run(["ss", "-tuln"])
    return run(["netstat", "-an"])


def cmd_ping(target, count=4, wait=2):
    if not valid_target(target):
        return bad_target()
    if OS_NAME == "Windows":
        return run(["ping", "-n", str(count), target])
    # -W is seconds on Linux but milliseconds on BSD/macOS - passing "2" there
    # means 2ms, which marks every reply "out of wait time".
    wait_arg = str(wait * 1000) if OS_NAME == "Darwin" else str(wait)
    return run(["ping", "-c", str(count), "-W", wait_arg, target])


def cmd_traceroute(target):
    if not valid_target(target):
        return bad_target()
    if OS_NAME == "Windows":
        return run(["tracert", "-h", "20", target], timeout=60)
    if which("traceroute"):
        return run(["traceroute", "-m", "20", "-w", "2", target], timeout=60)
    if which("tracepath"):
        return run(["tracepath", target], timeout=60)
    return {"ok": False, "error": "no traceroute/tracepath utility found on this system"}


def cmd_dns(target):
    if not valid_target(target):
        return bad_target()
    if which("dig"):
        return run(["dig", "+noall", "+answer", target])
    if which("nslookup"):
        return run(["nslookup", target])
    return {"ok": False, "error": "no DNS lookup utility (dig/nslookup) found on this system"}


# ---------------------------------------------------------------------------
# Optional external tools. Both are common on Linux appliances and absent on
# plenty of others, so the rule is: use them when present, fall back silently
# when not, and record in the report which tool produced the data. Nothing
# here is ever required - the tool still has to run on a box with nothing but
# python3.
# ---------------------------------------------------------------------------

def parse_mtr_json(text):
    """Turn `mtr --json` output into the same hop shape as parse_traceroute_hops.

    mtr's value over traceroute is that it sends many cycles, so each hop has a
    real loss percentage instead of one sample. Hop dicts therefore carry an
    extra loss_pct, and everything downstream (annotate_hops, the diagram, the
    text report) works unchanged.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    hubs = (data.get("report") or {}).get("hubs") or []
    hops = []
    for hub in hubs:
        raw_host = (hub.get("host") or "").strip()
        display, host = raw_host, raw_host
        # With -b, mtr renders "name (192.0.2.4)"; keep both halves.
        m = re.match(r"^(\S+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)$", raw_host)
        if m:
            display, host = m.group(1), m.group(2)
        elif not IP_ANY_RE.fullmatch(raw_host):
            host = None          # a name with no address - can't classify it
        if raw_host in ("???", "", "waiting for reply"):
            display, host = "*", None

        loss = hub.get("Loss%")
        avg = hub.get("Avg")
        times = []
        # mtr reports aggregates, not individual probes. Synthesize a single
        # representative timing so shared code (avg, jitter) keeps working, and
        # carry the real statistics alongside.
        if isinstance(avg, (int, float)) and avg > 0:
            times = [float(avg)]
        hops.append({
            "hop": hub.get("count"),
            "host": host,
            "display": display or "*",
            "times_ms": times,
            "timed_out": bool(loss is not None and float(loss) >= 100),
            "loss_pct": round(float(loss), 1) if isinstance(loss, (int, float)) else None,
            "sent": hub.get("Snt"),
            "best_ms": hub.get("Best"),
            "worst_ms": hub.get("Wrst"),
            "stdev_ms": hub.get("StDev"),
        })
    return hops


def cmd_mtr(target, cycles=10):
    """Per-hop loss over many cycles. Returns None when mtr isn't available."""
    if not valid_target(target) or not which("mtr"):
        return None
    # -b keeps both hostname and address so hops stay classifiable; a few older
    # builds reject it, so fall back to plain output.
    for args in (["-b"], []):
        cmd = ["mtr", "--json", "-c", str(int(cycles))] + args + [target]
        # cycles are ~1s apart, so allow the full window plus setup slack.
        res = run(cmd, timeout=int(cycles) + 20)
        if res.get("ok") and res.get("code") == 0 and res.get("stdout", "").strip():
            res["hops"] = parse_mtr_json(res["stdout"])
            res["cycles"] = int(cycles)
            if res["hops"]:
                return res
    return None


# Optical receive power. A fibre link degrading from a dirty connector, a bend,
# or a dying laser stays "up" and passes every reachability check while quietly
# corrupting frames - the counters show errors but nothing says why. The module
# itself measures its received power, and reports its own alarm thresholds.
OPTIC_RX_CRIT_DBM = -25.0   # below typical receiver sensitivity: link is failing
OPTIC_RX_WARN_DBM = -20.0   # marginal: works now, first thing to go

OPTIC_LINE_RE = re.compile(r"^\s*([A-Za-z][^:]*?)\s*:\s*(.+?)\s*$", re.M)
DBM_RE = re.compile(r"(-?\d+(?:\.\d+)?)\s*dBm")
# A receiver seeing nothing at all prints "0.0000 mW / -inf dBm". The number
# regex above does not match "-inf", so the reading was dropped and the fault
# that most deserves reporting - a dark fibre - produced no optical finding
# whatsoever, on a check that exists to catch exactly that.
DARK_RE = re.compile(r"-inf\s*dBm", re.I)


def parse_ethtool_optics(text):
    """Module type, power levels and any alarm flags from `ethtool -m`."""
    out = {"alarms": [], "warnings": []}
    for m in OPTIC_LINE_RE.finditer(text or ""):
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if key.startswith("identifier"):
            out["identifier"] = value
        elif key.startswith("vendor name"):
            out["vendor"] = value
        elif key.startswith("vendor pn"):
            out["part"] = value
        elif "laser output power" in key and "dBm" in value:
            d = DBM_RE.search(value)
            if d:
                out["tx_dbm"] = float(d.group(1))
        elif ("receiver signal average optical power" in key or "rcvr signal avg optical power" in key):
            d = DBM_RE.search(value)
            if d:
                out["rx_dbm"] = float(d.group(1))
            elif DARK_RE.search(value):
                # Not a number, and not a missing reading either: it is the
                # module reporting no light. Kept as its own fact rather than
                # forced into a dBm figure, because there isn't one - and
                # because a sentinel low enough to work as a number is a
                # sentinel that leaks into the report as a measurement.
                out["rx_dark"] = True
        elif key.startswith("module temperature"):
            out["temperature"] = value
        elif value.lower() == "on" and ("alarm" in key or "warning" in key):
            # The module's own thresholds beat any generic number we pick.
            (out["alarms"] if "alarm" in key else out["warnings"]).append(m.group(1).strip())
    return out


def cmd_optics(iface):
    """SFP/optical diagnostics for one interface, or None if it isn't fibre."""
    if not which("ethtool") or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", iface or ""):
        return None
    res = run(["ethtool", "-m", iface], timeout=8)
    # Copper ports and modules without diagnostics fail here, which is normal.
    if not res.get("ok") or res.get("code") != 0:
        return None
    parsed = parse_ethtool_optics(res.get("stdout", ""))
    if not parsed.get("rx_dbm") and not parsed.get("identifier"):
        return None
    res["parsed"] = parsed
    return res


def trace_reached(hops, target):
    """Did the trace actually get to the target, or just stop somewhere?"""
    if not hops:
        return False
    last = hops[-1]
    if last.get("timed_out"):
        return False
    return any(h.get("host") == target or h.get("display") == target for h in hops[-2:])


def cmd_traceroute_tcp(target, port=443):
    """Trace with TCP SYN probes instead of ICMP/UDP.

    Plenty of networks drop the probes classic traceroute uses while forwarding
    ordinary traffic perfectly. When that happens the path looks broken and
    isn't - a TCP trace to a port that's actually open walks straight through.
    Needs raw sockets, so it's skipped when we don't have the privilege.
    """
    if not valid_target(target):
        return None
    attempts = []
    if which("tcptraceroute"):
        attempts.append(["tcptraceroute", "-m", "20", "-w", "2", target, str(port)])
    if which("traceroute") and OS_NAME != "Windows":
        attempts.append(["traceroute", "-T", "-p", str(port), "-m", "20", "-w", "2", target])
    if which("mtr"):
        attempts.append(["mtr", "--tcp", "-P", str(port), "--json", "-c", "5", "-b", target])
    for cmd in attempts:
        res = run(cmd, timeout=70)
        if not res.get("ok") or res.get("code") != 0:
            continue
        out = res.get("stdout", "") or ""
        hops = parse_mtr_json(out) if cmd[0] == "mtr" else parse_traceroute_hops(out)
        if hops:
            res["hops"] = hops
            res["port"] = port
            res["tool"] = cmd[0]
            return res
    return None


# Unknown speed has been spelled several ways. Modern tools print "Unknown!",
# which no number regex matches, but older ethtool prints the raw u16 sentinel
# as "65535Mb/s" and some kernels put the u32 one in sysfs as 4294967295. Both
# parse cleanly as enormous link speeds, and a link that claims 4 Tbps is a
# link whose utilisation is always zero - which silently retires the
# saturation checks rather than failing where anyone would see it.
# Named as the specific values they are rather than bounded by "faster than
# any real Ethernet", which is a claim that ages badly - 400G was implausible
# not long ago.
SPEED_SENTINELS = frozenset((65535, 4294967295))


def plausible_mbps(value):
    """The speed, or None if it is one of the ways drivers say they don't know."""
    return None if value is None or value <= 0 or value in SPEED_SENTINELS else value

ETHTOOL_SPEED_RE = re.compile(r"^\s*Speed:\s*(\d+)", re.M)
ETHTOOL_DUPLEX_RE = re.compile(r"^\s*Duplex:\s*(\w+)", re.M)
ETHTOOL_AUTONEG_RE = re.compile(r"^\s*Auto-negotiation:\s*(\w+)", re.M)
ETHTOOL_LINK_RE = re.compile(r"^\s*Link detected:\s*(\w+)", re.M)
# The supported-modes block runs over several lines and ends at the next
# "Something:" key, so it is taken whole and the speeds picked out of it.
ETHTOOL_SUPPORTED_RE = re.compile(
    r"^\s*Supported link modes:(.*?)(?=^\s*[A-Z][\w -]*:)", re.M | re.S)
ETHTOOL_BASE_RE = re.compile(r"(\d+)base", re.I)


def parse_ethtool(text):
    """Pull negotiated link state out of `ethtool <iface>` output.

    ethtool is authoritative where sysfs is inferred: it reports what the two
    ends actually negotiated, and whether auto-negotiation was on at all -
    which is what separates a duplex mismatch from a deliberate setting.
    """
    out = {}
    m = ETHTOOL_SPEED_RE.search(text or "")
    if m and plausible_mbps(int(m.group(1))) is not None:
        out["speed_mbps"] = int(m.group(1))
    m = ETHTOOL_DUPLEX_RE.search(text or "")
    if m and m.group(1).lower() in ("full", "half"):
        out["duplex"] = m.group(1).lower()
    m = ETHTOOL_AUTONEG_RE.search(text or "")
    if m:
        out["autoneg"] = m.group(1).lower() == "on"
    m = ETHTOOL_LINK_RE.search(text or "")
    if m:
        out["carrier"] = m.group(1).lower() == "yes"
    # The fastest mode the hardware itself can do. Without it "slow" can only
    # be an absolute number, and a 10G port sitting at 1G is not slow by any
    # absolute measure while being a tenth of what was paid for.
    m = ETHTOOL_SUPPORTED_RE.search(text or "")
    if m:
        speeds = [int(v) for v in ETHTOOL_BASE_RE.findall(m.group(1))]
        if speeds:
            out["max_mbps"] = max(speeds)
    return out


def cmd_ethtool(iface):
    """Negotiated link state for one interface, or None if ethtool isn't there."""
    if not which("ethtool") or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", iface or ""):
        return None
    res = run(["ethtool", iface], timeout=5)
    if not res.get("ok") or res.get("code") != 0:
        return None
    res["parsed"] = parse_ethtool(res.get("stdout", ""))
    return res if res["parsed"] else None


# ---------------------------------------------------------------------------
# DNS at the resolver level. "Does google.com resolve" through the system
# resolver hides the failures that actually bite: one of two resolvers dead
# (intermittent everything), a resolver answering in 900ms (feels broken while
# every connectivity check passes), or NXDOMAIN being hijacked by a captive
# portal or ISP redirect service.
#
# Queries are built here rather than shelled out to dig, which minimal
# appliances often don't ship, and which would make timing dependent on process
# startup. UDP only, one packet per query, no dependencies.
# ---------------------------------------------------------------------------

DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}

# .invalid is reserved by RFC 6761 and can never resolve, so a NOERROR answer
# for it means something in the path is inventing replies.
NXDOMAIN_PROBE = "faultone-nonexistent-probe.invalid"

def _new_dns_qid():
    """Random per query. A predictable id plus UDP's willingness to accept any
    sender is what makes off-path answer spoofing easy; both are closed here.
    Also avoids two threads of the HTTP server colliding on a shared counter."""
    return int.from_bytes(os.urandom(2), "big")


def _dns_encode_name(name):
    out = b""
    for label in (name or "").rstrip(".").split("."):
        raw = label.encode("ascii", "ignore")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _dns_skip_name(data, offset):
    """Step over a (possibly compressed) name and return the next offset."""
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:      # compression pointer, always 2 bytes
            return offset + 2
        offset += 1 + length


def parse_dns_response(data, expect_qid=None):
    """Return {rcode, rcode_name, answers, ancount} from a raw DNS reply."""
    if len(data) < 12:
        raise ValueError("response too short")
    qid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if expect_qid is not None and qid != expect_qid:
        raise ValueError("reply id does not match the query")
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        offset = _dns_skip_name(data, offset) + 4      # + qtype/qclass
    answers = []
    for _ in range(ancount):
        offset = _dns_skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in rdata))
        elif rtype == 28 and rdlen == 16:
            try:
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
            except (OSError, ValueError):
                pass   # unreadable AAAA record: skip it, the rest still parses
    return {"rcode": rcode, "rcode_name": DNS_RCODES.get(rcode, str(rcode)),
            "answers": answers, "ancount": ancount}


def dns_query(server, name, qtype=1, timeout=2.0):
    """One UDP query to one resolver. Times the round trip; never raises."""
    if not valid_target(server):
        return {"ok": False, "error": "invalid resolver address"}
    qid = _new_dns_qid()
    packet = (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
              + _dns_encode_name(name) + struct.pack(">HH", qtype, 1))
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    addr = server.split("%")[0]
    # monotonic, not wall clock: an NTP step mid-query would otherwise produce
    # a negative or wildly wrong latency, and latency is the point here.
    started = time.monotonic()
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (addr, 53))
            # UDP accepts a datagram from anyone; take only the reply from the
            # resolver we actually asked, so a stray or spoofed packet can't be
            # read as this resolver's answer.
            deadline = time.monotonic() + timeout
            while True:
                data, src = sock.recvfrom(4096)
                if src and src[0] == addr:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout()
                sock.settimeout(remaining)
        elapsed = (time.monotonic() - started) * 1000
        parsed = parse_dns_response(data, qid)
        parsed.update({"ok": True, "elapsed_ms": round(elapsed, 1), "server": server})
        return parsed
    except socket.timeout:
        return {"ok": False, "server": server, "error": "no reply within "
                f"{timeout:.0f}s", "elapsed_ms": round((time.monotonic() - started) * 1000, 1)}
    except (OSError, ValueError, struct.error) as e:
        return {"ok": False, "server": server, "error": str(e),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1)}


def parse_resolvers(text):
    """nameserver lines from resolv.conf, in order."""
    servers = []
    for line in (text or "").splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if line.lower().startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2 and valid_ip(parts[1]) and parts[1] not in servers:
                servers.append(parts[1])
    return servers


def list_resolvers(with_reason=False):
    found, seen, reason = [], set(), None
    if OS_NAME == "Windows":
        res = run(["ipconfig", "/all"], timeout=10)
        if res.get("ok"):
            for m in re.finditer(r"DNS Servers[ .]*:\s*(.+)", res.get("stdout", "")):
                for cand in re.findall(r"[0-9a-fA-F:.]+", m.group(1)):
                    if valid_ip(cand) and cand not in seen:
                        seen.add(cand)
                        found.append(cand)
        else:
            reason = res.get("error") or "ipconfig would not run"
    else:
        try:
            with open("/etc/resolv.conf") as fh:
                found = parse_resolvers(fh.read())
        except OSError as e:
            reason = f"/etc/resolv.conf could not be read ({e.strerror or e})"
    return (found, reason) if with_reason else found


# Above this, name resolution is slow enough that everything feels broken even
# though every connectivity check passes.
DNS_SLOW_MS = 500


def _answer_summary(answers, keep=3):
    """The first few answers, and how many were not shown.

    Truncating in silence let two resolvers that disagree render as identical
    rows - on the one panel a reader uses to check whether they agree, and
    while dns_disagree was firing about it three lines above.
    """
    answers = list(answers or [])
    if not answers:
        return "-"
    shown = ", ".join(answers[:keep])
    return shown + (f" (+{len(answers) - keep} more)" if len(answers) > keep else "")


def cmd_dns_health(probe_name="google.com", check_hijack=True):
    """Query each configured resolver individually and compare them."""
    resolvers, unreadable = list_resolvers(with_reason=True)
    if not resolvers:
        # An empty list means two different things. "Nothing is configured" is
        # a fault on this device; "the configuration couldn't be read" is a gap
        # in this run, and reporting a gap as a fault is the failure mode this
        # tool exists to avoid.
        return {"ok": False, "cmd": "resolver check",
                "error": unreadable or "no DNS resolvers are configured on this device",
                "unreadable": unreadable,
                "resolvers": []}
    results = []
    for server in resolvers:
        r = dns_query(server, probe_name)
        entry = {"server": server, "ok": bool(r.get("ok")) and r.get("rcode") == 0,
                 "rcode": r.get("rcode_name"), "elapsed_ms": r.get("elapsed_ms"),
                 "answers": sorted(r.get("answers", [])), "error": r.get("error")}
        if check_hijack:
            hj = dns_query(server, NXDOMAIN_PROBE)
            # A name in .invalid must not resolve; an answer means interception.
            entry["hijacks_nxdomain"] = bool(hj.get("ok") and hj.get("rcode") == 0
                                             and hj.get("answers"))
        results.append(entry)

    rows = [f"{'resolver':<24}{'status':<10}{'ms':>7}  answers"]
    for r in results:
        status = r["rcode"] if r["ok"] else (r.get("rcode") or "no reply")
        rows.append(f"{r['server']:<24}{status:<10}{str(r['elapsed_ms'] or '-'):>7}  "
                    f"{_answer_summary(r['answers'])}"
                    + ("   [NXDOMAIN hijacked]" if r.get("hijacks_nxdomain") else ""))
    return {"ok": True, "cmd": f"dns query {probe_name} -> each configured resolver",
            "stdout": "\n".join(rows), "stderr": "", "code": 0,
            "resolvers": results, "probe": probe_name}


# ---------------------------------------------------------------------------
# Passive inventory. Not a scan: this is the neighbour table the kernel has
# already built from traffic that happened anyway, formatted so it is readable.
# Nothing here probes a host that wasn't already talking to this device - which
# is the whole reason it can run on a network nobody gave you permission to
# sweep.
#
# Names come from reverse DNS against the resolvers this device is already
# configured with, bounded by a deadline so a slow resolver costs seconds
# rather than the run.
# ---------------------------------------------------------------------------

PTR_DEADLINE_SECONDS = 2.0
PTR_WORKERS = 8


def _dns_read_name(data, offset, depth=0):
    """Read a (possibly compressed) name, following pointers. Returns the name.

    Compression pointers can legally point backwards, and a hostile reply can
    point in a loop, so the depth is capped rather than trusted.
    """
    labels = []
    while depth < 10:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:                       # pointer
            if offset + 1 >= len(data):
                break
            target = ((length & 0x3F) << 8) | data[offset + 1]
            return ".".join(labels + [_dns_read_name(data, target, depth + 1)]).strip(".")
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels)


def dns_ptr(server, ip, timeout=1.0):
    """Reverse lookup for one address, via a resolver we already know about."""
    parts = (ip or "").split(".")
    if len(parts) != 4:
        return None
    name = ".".join(reversed(parts)) + ".in-addr.arpa"
    qid = _new_dns_qid()
    packet = (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
              + _dns_encode_name(name) + struct.pack(">HH", 12, 1))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server.split("%")[0], 53))
            data, src = sock.recvfrom(4096)
            if not src or src[0] != server.split("%")[0]:
                return None
    except (OSError, ValueError):
        return None
    try:
        if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
            return None
        _qid, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            offset = _dns_skip_name(data, offset) + 4
        for _ in range(an):
            offset = _dns_skip_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 12:
                return _dns_read_name(data, offset).rstrip(".") or None
            offset += rdlen
    except (struct.error, ValueError, IndexError):
        return None
    return None


def build_inventory(arp_entries, resolvers=None, resolve_names=True):
    """Turn the neighbour table into a readable inventory of the local segment.

    Names are looked up in parallel against the first configured resolver and
    abandoned at a deadline - an inventory is not worth stalling a diagnosis
    for.
    """
    hosts = []
    seen = set()
    for entry in arp_entries or []:
        ip = entry.get("ip")
        if not ip or ip in seen:
            continue
        octets = ip.split(".")
        if len(octets) != 4 or not all(o.isdigit() for o in octets):
            continue
        first, last = int(octets[0]), int(octets[3])
        # Multicast and broadcast aren't hosts, and an entry with no MAC is a
        # lookup that failed rather than a neighbour that answered - counting
        # either would turn "36 devices here" into "257 devices here".
        if first >= 224 or last == 255 or not entry.get("mac"):
            continue
        seen.add(ip)
        hosts.append({"ip": ip, "mac": entry.get("mac"), "state": entry.get("state"),
                      "subnet": ".".join(ip.split(".")[:3]), "name": None})

    resolver = (resolvers or [None])[0]
    if resolve_names and resolver and hosts:
        deadline = time.monotonic() + PTR_DEADLINE_SECONDS
        def lookup(host):
            if time.monotonic() > deadline:
                return None
            return dns_ptr(resolver, host["ip"], timeout=1.0)
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(PTR_WORKERS, len(hosts))) as pool:
            for host, name in zip(hosts, pool.map(lookup, hosts)):
                host["name"] = name

    subnets = {}
    for host in hosts:
        subnets[host["subnet"]] = subnets.get(host["subnet"], 0) + 1
    named = sum(1 for h in hosts if h["name"])
    with_mac = sum(1 for h in hosts if h["mac"])
    return {
        "hosts": sorted(hosts, key=lambda h: tuple(int(p) for p in h["ip"].split("."))),
        "subnets": subnets, "count": len(hosts), "named": named, "with_mac": with_mac,
    }


# ---------------------------------------------------------------------------
# LLDP / CDP neighbours. Switches advertise their identity and the port you're
# plugged into; lldpd collects those frames passively. This is the difference
# between a finding that says "check the switch port" and one that says which
# switch and which port - the site doesn't have to go hunting.
#
# Passive and local: nothing is sent, nothing is captured, and it needs lldpd
# to be installed and the switch to have LLDP or CDP enabled. Absent either,
# this is skipped like every other optional tool here.
# ---------------------------------------------------------------------------

def parse_lldp_keyvalue(text):
    """Parse `lldpctl -f keyvalue` into one neighbour record per interface.

    Lines look like: lldp.eth0.chassis.name=SW-CLOSET-2
    """
    ifaces = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("lldp.") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        parts = key.split(".")
        if len(parts) < 3:
            continue
        iface, field = parts[1], ".".join(parts[2:])
        rec = ifaces.setdefault(iface, {"iface": iface})
        if field == "chassis.name":
            rec["switch"] = value
        elif field == "chassis.descr":
            rec["switch_descr"] = value
        elif field.startswith("chassis.mgmt-ip"):
            rec.setdefault("mgmt_ip", value)
        elif field == "chassis.mac" or field.startswith("chassis.mac"):
            rec.setdefault("chassis_mac", value.lower())
        elif field in ("port.ifname", "port.descr", "port.local"):
            # ifname is the real port id; descr is often prettier. Prefer the
            # first one seen of each so a later, vaguer field can't overwrite.
            rec.setdefault("port" if field == "port.ifname" else "port_descr", value)
        elif field == "vlan.vlan-id" or field == "vlan-id":
            rec.setdefault("vlan", value)
        elif field == "via":
            rec["via"] = value
        elif field == "age":
            rec["age"] = value
    # An interface with no identifying detail isn't a neighbour, just noise.
    return [r for r in ifaces.values() if r.get("switch") or r.get("port") or r.get("chassis_mac")]


def cmd_lldp():
    """Neighbour switch and port per interface, or None when lldpd isn't here."""
    for argv in (["lldpctl", "-f", "keyvalue"],
                 ["lldpcli", "show", "neighbors", "-f", "keyvalue"]):
        if not which(argv[0]):
            continue
        res = run(argv, timeout=8)
        if not res.get("ok") or res.get("code") != 0:
            continue
        neighbours = parse_lldp_keyvalue(res.get("stdout", ""))
        if neighbours:
            res["neighbours"] = neighbours
            rows = []
            for n in neighbours:
                rows.append(f"{n['iface']:<10} {n.get('switch', '?'):<24} "
                            f"{n.get('port') or n.get('port_descr') or '?':<20} "
                            f"{('vlan ' + n['vlan']) if n.get('vlan') else ''} "
                            f"{('via ' + n['via']) if n.get('via') else ''}".rstrip())
            res["stdout"] = "\n".join(rows) or res.get("stdout", "")
            return res
    return None


# ---------------------------------------------------------------------------
# TLS. A TCP connect proves something accepts connections; it says nothing
# about whether the service behind it works. A handshake says a great deal:
# whether it completes at all, what certificate comes back, when that expires,
# and - the one nothing else here can see - whether something in the path is
# intercepting and re-signing traffic, which looks like "the app is broken"
# while every reachability check passes.
# ---------------------------------------------------------------------------

# Ports where a TLS handshake is the right question to ask.
TLS_PORTS = {443, 465, 636, 989, 990, 993, 995, 5061, 8443, 9443}
CERT_EXPIRY_WARN_DAYS = 21

# Issuers that mean "something is re-signing this", not a public CA.
INTERCEPTION_HINTS = ("fortinet", "fortigate", "bluecoat", "blue coat",
                      "sophos", "mcafee", "websense", "forcepoint", "checkpoint",
                      "check point", "sonicwall", "cisco umbrella", "squid",
                      "mitmproxy", "charles", "burp")


def der_strings(der, minimum=4):
    """Printable ASCII runs inside a DER certificate.

    Deliberately not an ASN.1 parser: all we need is whether the issuer name
    contains a known inspection product, and parsing untrusted X.509 by hand to
    learn that would be a much larger risk than reading strings out of it.
    """
    out, run = [], []
    for byte in der or b"":
        if 32 <= byte < 127:
            run.append(chr(byte))
        else:
            if len(run) >= minimum:
                out.append("".join(run))
            run = []
    if len(run) >= minimum:
        out.append("".join(run))
    return out


def looks_intercepted(strings):
    """Does anything in the certificate name an interception product?"""
    joined = " ".join(strings).lower()
    return next((hint for hint in INTERCEPTION_HINTS if hint in joined), None)


def _cert_name(entry):
    """Pull a readable name out of the nested tuples getpeercert returns."""
    for part in entry or ():
        for key, value in part:
            if key in ("commonName", "organizationName"):
                return value
    return None


# TLS listeners of our own to test, at most. A box with more than a couple is
# unusual, and each costs a handshake against a service that is probably
# logging connections.
OWN_TLS_MAX_PORTS = 3


def _cert_names(der):
    """Hostnames a certificate appears to be for, best first.

    Read out of the printable runs rather than by parsing ASN.1 - the same
    deliberate choice der_strings documents. A name that is wrong simply fails
    to verify, which is a result this check reports either way, so the cost of
    guessing badly is a worse error message and never a wrong answer.
    """
    names = []
    for text in der_strings(der, minimum=4):
        # Case-sensitive on purpose. A certificate carries its names in
        # lowercase, and the printable runs in a DER are full of key material
        # that reads as text - a random "v.RD" matched an earlier, laxer
        # pattern and became the name this box was verified against, so the
        # handshake failed for a reason that had nothing to do with the
        # certificate.
        for token in re.findall(r"(?:\*\.)?(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}", text):
            name = token.lstrip("*.")
            if len(name) < 6 or name in names:
                continue
            names.append(name)
    return names


def _listener_address(bind_addr):
    """Where to connect to reach a listener bound to `bind_addr`.

    A wildcard bind answers on loopback; a specific address has to be dialled
    directly, because a service bound only to a public address is perfectly
    healthy and simply not on 127.0.0.1.
    """
    if not bind_addr or bind_addr in ("0.0.0.0", "*", "::", "[::]"):
        return "127.0.0.1"
    return bind_addr.strip("[]")


def der_validity(der):
    """(notBefore, notAfter) as dates, read out of the certificate's own bytes.

    ASN.1 encodes times as printable ASCII - "260812120000Z" for UTCTime and a
    four-digit year for GeneralizedTime - so they come out of the same string
    scan der_strings already does, without parsing X.509 by hand. The two
    earliest such stamps in a certificate are its validity window; taking the
    min and max of what is found means a stamp appearing in an extension
    cannot shift the answer to something *narrower* than the truth.

    Needed because a certificate that does not verify - self-signed, or from a
    private CA, which is most of what a proxy serves internally - never reaches
    the path where Python hands over parsed dates, and its expiry is exactly
    what someone wants to know.
    """
    found = []
    for text in der_strings(der, minimum=13):
        for stamp in re.findall(r"\d{12,14}Z", text):
            digits = stamp[:-1]
            fmt = "%y%m%d%H%M%S" if len(digits) == 12 else "%Y%m%d%H%M%S"
            try:
                found.append(datetime.datetime.strptime(digits, fmt))
            except ValueError:
                continue
    if len(found) < 2:
        return None, None
    return min(found), max(found)


# Gateway errors: the service answered, and what it answered is that something
# behind it did not. On a box that proxies, this is the difference between "the
# service is broken" and "the service is fine and its backend is not" - which
# are different faults with different owners.
GATEWAY_ERRORS = {502, 503, 504}


def cmd_own_http(port, timeout=5, address="127.0.0.1", tls=False):
    """Ask this box's own service for a response, not just a connection.

    Every other check here stops at the handshake: the port is open, the
    certificate is valid, the TCP connection completes. A service that accepts
    connections and then answers nothing - or answers 502 to every one of them
    - passes all of it while being completely down from a client's side. That
    is the commonest way a proxy is broken and the least visible from on it.

    One HEAD to the root path, no redirects followed, no body read, no
    credentials. Only against a port this box is already listening on.
    """
    result = {"ok": False, "cmd": f"HEAD / {address}:{port}", "port": port,
              "host": address, "tls": tls}
    raw = None
    # Timed in phases, not as one number. "The service answered in 900ms" is
    # true and useless: the connect, the handshake and the application thinking
    # about it are three different things with three different owners, and on a
    # connection to this box's own listener the first two should be almost
    # nothing - which makes the split unusually easy to read.
    try:
        started = time.monotonic()
        raw = socket.create_connection((address, port), timeout=timeout)
        connected = time.monotonic()
    except (OSError, ValueError) as e:
        result["unreachable_locally"] = str(e)
        return result
    try:
        sock = raw
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw)
        secured = time.monotonic()
        with sock:
            sock.settimeout(timeout)
            sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {address}\r\n"
                         f"User-Agent: FaultOne/{__version__}\r\n"
                         f"Connection: close\r\n\r\n".encode())
            asked = time.monotonic()
            data = b""
            while b"\r\n" not in data and len(data) < 4096:
                chunk = sock.recv(512)
                if not chunk:
                    break
                data += chunk
            answered = time.monotonic()
        result["phases"] = {
            "connect_ms": round((connected - started) * 1000, 1),
            "tls_ms": round((secured - connected) * 1000, 1) if tls else None,
            "wait_ms": round((answered - asked) * 1000, 1),
        }
    except socket.timeout:
        result["silent"] = True
        result["ms"] = round((time.monotonic() - started) * 1000, 1)
        return result
    except (OSError, ssl.SSLError, ValueError) as e:
        result["error"] = str(e)
        return result
    result["ms"] = round((time.monotonic() - started) * 1000, 1)
    if not data:
        # Accepted the connection, read the request, closed without answering.
        result["silent"] = True
        return result
    line = data.split(b"\r\n", 1)[0].decode("ascii", "replace").strip()
    result["status_line"] = line[:120]
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", line)
    if not m:
        result["not_http"] = True
        return result
    result.update({"ok": True, "status": int(m.group(1))})
    return result


def cmd_own_tls(port, timeout=5, address="127.0.0.1"):
    """The certificate this box is serving, as a client on the internet sees it.

    Every other TLS check here points outward, at something this device
    connects to. A proxy terminating HTTPS is the other case entirely: its own
    certificate is the one that takes the site down when it expires, and
    nothing was looking at it.

    Connects to the loopback address so the answer is about *this* box - the
    public name may well resolve to a load balancer in front of it - but
    verifies against the name on the certificate, so the result is what a
    browser would get. A chain that only completes because of something in
    this machine's own trust store is exactly the failure worth catching.
    """
    result = {"ok": False, "cmd": f"tls handshake {address}:{port} (own listener)",
              "host": address, "port": port, "own_listener": True}
    # The two failures mean opposite things and must not share a code path. No
    # TCP means the service is not on this address - a bind choice, not a
    # fault, and nothing this check can say anything about. A completed TCP
    # connection followed by a failed handshake is the service's TLS.
    try:
        started = time.monotonic()
        raw = socket.create_connection((address, port), timeout=timeout)
    except (OSError, ValueError) as e:
        result["unreachable_locally"] = str(e)
        return result
    connected = time.monotonic()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with raw, ctx.wrap_socket(raw) as sock:
            der = sock.getpeercert(binary_form=True)
            result.update({"ok": True, "tls_version": sock.version(),
                           "cipher": (sock.cipher() or ("",))[0],
                           "tcp_ms": round((connected - started) * 1000, 1),
                           "tls_ms": round((time.monotonic() - connected) * 1000, 1)})
    except (OSError, ssl.SSLError, ValueError) as e:
        result["error"] = str(e)
        return result

    names = _cert_names(der)
    result["names"] = names[:4]
    if not names:
        result["verify_error"] = "no hostname found on the certificate"
        return result

    # Second handshake, verified the way a client would: same socket address,
    # the certificate's own name for SNI and hostname checking.
    verified = cmd_tls_check_local(port, names[0], timeout, address)
    for key in ("verified", "verify_error", "subject", "issuer", "expires",
                "days_left", "starts", "not_yet_valid_days", "expired"):
        if key in verified:
            result[key] = verified[key]
    result["verified_as"] = names[0]
    # A certificate that does not verify never reaches Python's parsed dates,
    # and its expiry is the thing most worth knowing.
    if result.get("days_left") is None:
        _starts, expires = der_validity(der)
        if expires:
            result["expires"] = expires.strftime("%Y-%m-%d")
            result["days_left"] = (expires - datetime.datetime.utcnow()).days
            result["expiry_from"] = "the certificate's own bytes"
    return result


def cmd_tls_check_local(port, server_name, timeout=5, address="127.0.0.1"):
    """A verified handshake to this box, presenting `server_name`."""
    out = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name) as sock:
                cert = sock.getpeercert() or {}
        out["verified"] = True
    except ssl.SSLError as e:
        out["verified"] = False
        out["verify_error"] = str(e).split("(")[0].strip()
        if "expired" in out["verify_error"].lower():
            out["expired"] = True
        return out
    except (OSError, ValueError) as e:
        out["verified"] = False
        out["verify_error"] = str(e)
        return out
    _cert_dates(cert, out)
    out["subject"] = _cert_name(cert.get("subject"))
    out["issuer"] = _cert_name(cert.get("issuer"))
    return out


# Why a certificate this box serves failed to verify. OpenSSL says the same
# sentence for situations that need different people to do different things, and
# the distinction matters most on a box that re-signs traffic on purpose: a
# private root in the chain is that box working, and an absent issuer is a chain
# it forgot to send. Read off the error string rather than by parsing the
# certificate, which would mean the ASN.1 work this file deliberately avoids.
PRIVATE_CA_ERRORS = ("self signed certificate in certificate chain",
                     "self-signed certificate in certificate chain")
SELF_SIGNED_ERRORS = ("self signed certificate", "self-signed certificate")


def own_cert_trust_note(verify_error):
    """The sentence that follows "this did not verify", or None."""
    text = (verify_error or "").lower()
    if any(e in text for e in PRIVATE_CA_ERRORS):
        return ("The chain ends at a root this box does not trust, which is what a "
                "certificate re-signed by a private authority looks like. If this box "
                "issues its own certificates that is it working, and every client that "
                "was never given that root - anything unmanaged, and most things that "
                "are not a browser - refuses the connection outright.")
    if any(e in text for e in SELF_SIGNED_ERRORS):
        return ("The certificate signed itself. Fine for something only reached by "
                "things told to expect it, and refused by everything else.")
    if "unable to get local issuer" in text:
        return ("The issuer's own certificate was not sent and is not held here, which "
                "is the incomplete chain that works from a machine which already has "
                "the intermediate and fails from one that does not.")
    return None


def _cert_dates(cert, out):
    """notBefore/notAfter off a verified certificate, into `out`.

    Both ends of the validity window, not just the expiry. A certificate that
    has not started being valid yet is far more often this box's clock than a
    genuinely future-dated certificate - and if the clock is the problem, every
    TLS reading on the run is measuring the clock rather than the service.
    """
    for field, prefix in (("notAfter", "expires"), ("notBefore", "starts")):
        raw_value = cert.get(field)
        if not raw_value:
            continue
        try:
            when = datetime.datetime.strptime(raw_value, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            continue
        out[prefix] = when.strftime("%Y-%m-%d")
        if field == "notAfter":
            out["days_left"] = (when - datetime.datetime.utcnow()).days
        else:
            ahead = (when - datetime.datetime.utcnow()).days
            if ahead > 0:
                out["not_yet_valid_days"] = ahead


def cmd_tls_check(host, port=443, timeout=5):
    """Complete a TLS handshake and report what came back.

    Verification failures are not fatal here: an expired or re-signed
    certificate is exactly what we want to see and describe, so the handshake
    is retried without verification purely to read the certificate.
    """
    if not valid_target(host):
        return None
    result = {"ok": False, "cmd": f"tls handshake {host}:{port}", "host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        # Timed separately because they answer to different people. The connect
        # is one round trip and belongs to the path; the handshake is key
        # exchange and certificate work, and belongs to the server.
        started = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            connected = time.monotonic()
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                result.update({"ok": True, "verified": True, "tls_version": sock.version(),
                               "cipher": (sock.cipher() or ("",))[0],
                               "tcp_ms": round((connected - started) * 1000, 1),
                               "tls_ms": round((time.monotonic() - connected) * 1000, 1)})
    except ssl.SSLError as e:
        result["verify_error"] = str(e).split("(")[0].strip()
        # Retry without verification purely to read the certificate. Python
        # returns an empty dict for an unvalidated peer, so the details come
        # from the DER itself - and this is the only path on which an
        # intercepted or expired certificate can ever be seen.
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as sock:
                    der = sock.getpeercert(binary_form=True)
                    result.update({"ok": True, "verified": False,
                                   "tls_version": sock.version(),
                                   "cipher": (sock.cipher() or ("",))[0]})
            names = der_strings(der)
            hint = looks_intercepted(names)
            if hint:
                result["intercepted_by"] = hint
                result["issuer"] = next((n for n in names if hint in n.lower()), hint)
            reason = result.get("verify_error", "").lower()
            if "expired" in reason:
                result["expired"] = True
        except (OSError, ssl.SSLError, ValueError) as inner:
            result["error"] = str(inner)
            return result
        cert = None
    except (OSError, ValueError) as e:
        result["error"] = str(e)
        return result

    if result.get("verified") and cert:
        result["subject"] = _cert_name(cert.get("subject"))
        result["issuer"] = _cert_name(cert.get("issuer"))
        _cert_dates(cert, result)

    lines = [f"{host}:{port}  {result.get('tls_version', 'no handshake')}"]
    if result.get("subject"):
        lines.append(f"  subject : {result['subject']}")
    if result.get("issuer"):
        lines.append(f"  issuer  : {result['issuer']}")
    if result.get("days_left") is not None:
        lines.append(f"  expires : {result.get('expires')} ({result['days_left']} days)")
    if result.get("verify_error"):
        lines.append(f"  verify  : FAILED - {result['verify_error']}")
    result["stdout"] = "\n".join(lines)
    return result


# ---------------------------------------------------------------------------
# Socket states. Zeek reads connection states off the wire to tell a refused
# connection from one that got no answer at all; the kernel already knows the
# same thing about this box, and reading it needs no capture and no privilege.
#
# The states that matter for triage:
#   SYN_SENT piling up   - this device is talking and nothing is answering,
#                          which is egress being filtered rather than "slow"
#   CLOSE_WAIT piling up - the far end hung up and the local application never
#                          closed its socket. That is an application bug, and
#                          it is the clearest "stop blaming the network" signal
#                          available from here.
# ---------------------------------------------------------------------------

# Below these a handful of sockets in an odd state is just normal churn.
SYN_SENT_WARN = 3
CLOSE_WAIT_WARN = 20

SS_STATE_RE = re.compile(
    r"^(?P<state>LISTEN|ESTAB|ESTABLISHED|SYN-SENT|SYN_SENT|SYN-RECV|SYN_RECV|"
    r"FIN-WAIT-\d|FIN_WAIT_\d|TIME-WAIT|TIME_WAIT|CLOSE-WAIT|CLOSE_WAIT|"
    r"LAST-ACK|LAST_ACK|CLOSING|CLOSED)\s", re.M)


def peer_host(addr):
    """Strip the port off a socket address, whichever way the tool wrote it.

    Four forms turn up across the commands this reads:

        10.0.0.1:443        ss, Linux netstat
        [2001:db8::1]:443   ss with IPv6
        10.0.0.1.443        BSD netstat
        2001:db8::1.443     BSD netstat with IPv6

    The BSD form is why this can't just split on the last colon: an IPv6
    address is mostly colons and its port isn't after one. Getting that wrong
    turned 2001:db8::1.443 into "2001:db8:", so the separator has to be
    identified before anything is split on it.
    """
    if not addr:
        return None
    if addr.startswith("["):
        end = addr.find("]")
        return addr[1:end] if end > 0 else addr
    head, dot, tail = addr.rpartition(".")
    if dot and tail.isdigit():
        return head                       # v4.port or v6.port
    head, colon, tail = addr.rpartition(":")
    if colon and tail.isdigit():
        return head                       # v4:port, ::1:22, :::22, and ":443"
    return addr


# Assumes every address it is given carries a port, which is true of every
# socket table this reads. A bare IPv6 address with no port would be cut at its
# last colon - there is no way to tell "2001:db8::1" from "host:1" in isolation.


def _is_loopback_socket(addr):
    """A listener only the box itself can reach is not the box serving anyone.

    Defers to _flow_is_local rather than repeating it: two nearly-identical
    address tests drift apart the first time either is corrected, and one of
    them decides which flows count while the other decides which listeners do.
    """
    return _flow_is_local(peer_host(addr))


def peer_port(addr):
    """The port from an ss/netstat address, whichever separator was used."""
    if not addr:
        return None
    m = re.search(r"[:.](\d{1,5})$", addr)
    return m.group(1) if m else None


def parse_socket_states(text):
    """Count sockets by state, and note who the pending ones are talking to.

    Handles `ss -tan` (state first) and `netstat -an` (state last), which is
    why the peer is picked out by position rather than by column name.
    """
    states = {}
    pending = {}
    # Which ports this box accepts on, and how many of its live connections
    # arrived rather than left. That split is what separates a server from a
    # client, and a server with clients connected to it right now has a working
    # network however little it can reach on its own.
    listening, established, bound, peers, outbound_dests = set(), [], [], [], []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        state = None
        peer = None
        local = parts[3] if len(parts) > 3 else None
        if SS_STATE_RE.match(line):                      # ss: STATE first
            state = parts[0]
            peer = parts[4] if len(parts) > 4 else None
        elif parts[0].lower().startswith("tcp"):          # netstat: state last
            candidate = parts[-1].upper()
            if candidate.replace("-", "_") in (
                    "LISTEN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "TIME_WAIT",
                    "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "LAST_ACK", "CLOSING", "CLOSED"):
                state = candidate
                peer = parts[-2] if len(parts) >= 2 else None
        if not state:
            continue
        key = state.replace("-", "_").upper()
        key = "ESTABLISHED" if key == "ESTAB" else key
        states[key] = states.get(key, 0) + 1
        if key == "LISTEN" and local and not _is_loopback_socket(local):
            port = peer_port(local)
            if port:
                listening.add(port)
                # The address it is bound to, so a check can reach it. A
                # service on 0.0.0.0 answers on loopback; one bound to a
                # single public address does not, and that is not a fault.
                bound.append((peer_host(local) or "", port))
        elif key == "ESTABLISHED" and local:
            established.append(peer_port(local))
            peers.append((peer_host(peer), peer_port(local)))
            outbound_dests.append((peer_host(peer), peer_port(peer)))
        if key in ("SYN_SENT", "CLOSE_WAIT") and peer:
            host = peer_host(peer)
            pending.setdefault(key, {})
            pending[key][host] = pending[key].get(host, 0) + 1
    # A source port is only unique per destination: the same one can serve any
    # number of different destinations at once. So the pressure on the range is
    # the busiest single destination, not the total - and on a box brokering
    # traffic to thousands of places those two numbers are nothing alike.
    # Counted here and reduced to numbers: the destination list is every place
    # this box has been, and does not belong in a report.
    dest_counts = {}
    for host, port in outbound_dests:
        if host and port and peer_port(f"x:{port}") and port not in listening:
            dest_counts[(host, port)] = dest_counts.get((host, port), 0) + 1
    worst = max(dest_counts.items(), key=lambda kv: (kv[1], kv[0]), default=None)
    inbound = sum(1 for p in established if p and p in listening)
    return {"states": states, "pending": pending,
            "listen_ports": sorted(listening), "bound": bound, "peers": peers,
            "outbound_destinations": len(dest_counts),
            "outbound_worst_dest": f"{worst[0][0]}:{worst[0][1]}" if worst else None,
            "outbound_worst_count": worst[1] if worst else 0,
            "inbound": inbound, "outbound": len(established) - inbound}


def cmd_socket_states():
    """This device's own TCP sockets, by state."""
    if OS_NAME == "Windows":
        res = run(["netstat", "-an", "-p", "TCP"], timeout=15)
    elif which("ss"):
        res = run(["ss", "-tan"], timeout=15)
    else:
        res = run(["netstat", "-an"], timeout=15)
    if not res.get("ok"):
        return res
    parsed = parse_socket_states(res.get("stdout", ""))
    res.update(parsed)
    order = ["ESTABLISHED", "LISTEN", "SYN_SENT", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT_1",
             "FIN_WAIT_2", "LAST_ACK", "CLOSING", "SYN_RECV"]
    rows = [f"{state:<14}{parsed['states'][state]:>6}"
            for state in order if parsed["states"].get(state)]
    for state, peers in parsed["pending"].items():
        for host, count in sorted(peers.items(), key=lambda kv: -kv[1])[:5]:
            rows.append(f"  {state} -> {host} x{count}")
    res["stdout"] = "\n".join(rows) or res.get("stdout", "")
    return res


# ---------------------------------------------------------------------------
# Call quality (MOS). Latency, jitter and loss are three numbers most people
# can't act on; "MOS 3.1, calls will sound rough" is one they can. The E-model
# arithmetic below is the same shape PingPlotter uses, and it costs nothing -
# no extra packets, just the measurements already taken.
# ---------------------------------------------------------------------------

def mos_score(avg_ms, jitter_ms=0.0, loss_pct=0.0):
    """Return (mos, r_factor) from latency/jitter/loss, or (None, None).

    Jitter is doubled because variation hurts a call more than steady delay,
    and 10ms is added for codec/protocol overhead the network can't see.
    """
    if avg_ms is None:
        return None, None
    try:
        avg = float(avg_ms)
        jitter = float(jitter_ms or 0.0)
        loss = float(loss_pct or 0.0)
    except (TypeError, ValueError):
        return None, None

    effective = avg + jitter * 2 + 10
    if effective < 160:
        r = 93.2 - effective / 40
    else:
        r = 93.2 - (effective - 120) / 10
    # Each 1% of loss costs ~2.5 R points - loss dominates once it appears.
    r -= loss * 2.5
    r = max(0.0, min(r, 93.2))
    if r <= 0:
        return 1.0, 0.0
    mos = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    return round(max(1.0, min(mos, 4.5)), 2), round(r, 1)


# The usual scale: 4.3+ excellent, 4.0-4.3 good, 3.6-4.0 fair, below 3.6 most
# users call it bad. 4.4 is the ceiling for G.711, so a perfect LAN scores 4.4,
# not 5.
MOS_WARN = 4.0
MOS_BAD = 3.6

PING_STATS_RE = re.compile(
    r"=\s*([\d.]+)\s*/\s*([\d.]+)\s*/\s*([\d.]+)(?:\s*/\s*([\d.]+))?\s*ms")


def parse_ping_stats(ping_result):
    """min/avg/max/stddev from a ping summary, on Linux (mdev) or BSD (stddev)."""
    if not ping_result.get("ok"):
        return {}
    m = PING_STATS_RE.search(ping_result.get("stdout") or "")
    if not m:
        return {}
    out = {"min_ms": float(m.group(1)), "avg_ms": float(m.group(2)),
           "max_ms": float(m.group(3))}
    if m.group(4):
        out["stdev_ms"] = float(m.group(4))
    else:
        # Windows gives no deviation; spread is a usable stand-in for jitter.
        out["stdev_ms"] = round(out["max_ms"] - out["min_ms"], 2)
    return out


# ---------------------------------------------------------------------------
# ARP / neighbour table. Wireshark flags a duplicate IP by seeing one address
# claimed by two MACs; the same conflict is visible in the table this box
# already keeps, with no packet capture and so no exposure to the site's
# traffic.
# ---------------------------------------------------------------------------

ARP_BSD_RE = re.compile(
    r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{11,17}|\(incomplete\))")
ARP_LINUX_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9a-fA-F:]{11,17}))?"
    r"(?:.*?\b(REACHABLE|STALE|DELAY|PROBE|FAILED|INCOMPLETE|PERMANENT))?", re.M)


def normalise_mac(mac):
    """Zero-pad and lowercase, so one address has one spelling.

    BSD and macOS print `0:0:5e:0:1:1` where Linux prints `00:00:5e:00:01:01`.
    Both are the same VRRP virtual router, and only one of them was recognised
    as one - so on a Mac the tool saw two routers arguing over an address and
    reported a duplicate IP instead of the failover pair it was looking at.
    """
    if not mac:
        return mac
    parts = mac.split(":")
    if len(parts) != 6 or not all(p and len(p) <= 2 for p in parts):
        return mac.lower()
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return mac.lower()


def parse_arp_table(text):
    """Entries as {ip, mac, state}. Handles `ip neigh` and BSD/macOS `arp -a`."""
    entries = []
    for m in ARP_LINUX_RE.finditer(text or ""):
        ip, _dev, mac, state = m.group(1), m.group(2), m.group(3), m.group(4)
        entries.append({"ip": ip, "mac": normalise_mac(mac) or None,
                        "state": (state or "").lower() or None})
    if entries:
        return entries
    for line in (text or "").splitlines():
        m = ARP_BSD_RE.search(line)
        if not m:
            continue
        mac = m.group(2)
        incomplete = mac.startswith("(")
        entries.append({"ip": m.group(1),
                        "mac": None if incomplete else normalise_mac(mac),
                        "state": "incomplete" if incomplete else None})
    return entries


# A gateway that is a virtual address belongs to a redundancy pair, and that
# reframes every finding about it: "the gateway is down" becomes "a failover
# did not complete". The protocol and group are readable straight off the MAC,
# which the neighbour table already gave us.
#
#   VRRP    00:00:5e:00:01:XX   XX is the VRID. CARP shares this range, which
#                               is precisely why a CARP vhid and a VRRP vrid
#                               collide on a shared segment.
#   HSRPv1  00:00:0c:07:ac:XX   XX is the group.
#   HSRPv2  00:00:0c:9f:fX:XX   the last three nibbles are the group.
#   GLBP    00:07:b4:00:XX:YY   XX is the group, YY the forwarder.
VIRTUAL_ROUTER_MACS = (
    (re.compile(r"^00:00:5e:00:01:([0-9a-f]{2})$", re.I), "VRRP or CARP", "group"),
    (re.compile(r"^00:00:5e:00:02:([0-9a-f]{2})$", re.I), "VRRP for IPv6", "group"),
    (re.compile(r"^00:00:0c:07:ac:([0-9a-f]{2})$", re.I), "HSRPv1", "group"),
    (re.compile(r"^00:00:0c:9f:f([0-9a-f])(:[0-9a-f]{2})$", re.I), "HSRPv2", "group"),
    (re.compile(r"^00:07:b4:00:([0-9a-f]{2}):[0-9a-f]{2}$", re.I), "GLBP", "group"),
)


def virtual_router_mac(mac):
    """(protocol, group) when this MAC belongs to a redundancy protocol.

    The group number matters as much as the protocol: two routers answering for
    one address on the *same* group are a split brain, and on different groups
    are two virtual routers configured onto one address. Different faults.
    """
    if not mac:
        return None
    for pattern, proto, _label in VIRTUAL_ROUTER_MACS:
        m = pattern.match(mac.strip())
        if not m:
            continue
        group = "".join(g for g in m.groups() if g).replace(":", "")
        try:
            return proto, int(group, 16)
        except ValueError:
            return proto, None
    return None


def find_arp_conflicts(entries):
    """IPs claimed by more than one MAC. The reverse (one MAC, many IPs) is
    normal - that's a router answering proxy ARP - and is not reported."""
    by_ip = {}
    for e in entries:
        if e.get("mac"):
            by_ip.setdefault(e["ip"], set()).add(e["mac"])
    return [{"ip": ip, "macs": sorted(macs)} for ip, macs in by_ip.items() if len(macs) > 1]


# ---------------------------------------------------------------------------
# TCP retransmissions. Wireshark's headline signal, taken from the kernel's own
# counters instead of a capture: this is the box's real traffic, not probe
# traffic, and reading it needs no privileges and records nothing.
# ---------------------------------------------------------------------------

def _snmp_counters_linux():
    """The counters in /proc/net/snmp, by protocol.

    The file was already being opened and only the Tcp: line read out of it,
    which left the box's UDP and fragmentation counters on the floor. Both
    matter here: DNS is UDP, so a box dropping datagrams presents as a resolver
    problem while every TCP check passes, and reassembly failures are the
    receiving half of the MTU story the path probe measures from the sending
    side.

    Tcp keys keep their bare names because the rest of the tool already reads
    them that way. The others are prefixed, because the protocols reuse names -
    InErrors and InCsumErrors exist on both Tcp and Udp and mean different
    things - and a collision here would be silent.
    """
    try:
        with open("/proc/net/snmp") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return {}
    out = {}
    for i, line in enumerate(lines):
        head = line.split(":", 1)[0]
        if head not in ("Tcp", "Udp", "Ip"):
            continue
        if i + 1 >= len(lines) or not lines[i + 1].startswith(head + ":"):
            continue
        prefix = "" if head == "Tcp" else head.lower() + "_"
        for k, v in zip(line.split()[1:], lines[i + 1].split()[1:]):
            try:
                out[prefix + k] = int(v)
            except ValueError:
                pass   # non-numeric counter: skip it, others are still usable
    return out


def _tcp_counters_linux():
    """Kept as the name the BSD twin is paired with."""
    return _snmp_counters_linux()


def _tcp_counters_bsd():
    res = run(["netstat", "-s", "-p", "tcp"], timeout=10)
    if not res.get("ok"):
        return {}
    out = {}
    # BSD switches to singular at 1 ("0 data packet (0 byte)"), so both forms
    # have to match or the counters silently vanish.
    text = res.get("stdout", "")
    m = re.search(r"([\d,]+)\s+data packets?\s+\(\d+\s+bytes?\)\s+retransmitted", text)
    if m:
        out["RetransSegs"] = int(m.group(1).replace(",", ""))
    m = re.search(r"([\d,]+)\s+data packets?\s+\(\d+\s+bytes?\)\s*$", text, re.M)
    if m:
        out["OutSegs"] = int(m.group(1).replace(",", ""))
    # Recent macOS prints the whole tcp block as zeros to an unprivileged
    # process rather than refusing, so the parse succeeds and yields nothing
    # usable. Zero segments sent is not a state a box you are logged into can
    # be in - the session itself is TCP - so treat it as "couldn't read" and
    # let the check report itself unavailable, which is what every other
    # unreadable source here does.
    if not out.get("OutSegs"):
        return {}
    return out


def _read_tcp_counters():
    return _tcp_counters_linux() if OS_NAME == "Linux" else _tcp_counters_bsd()


# Packets this device loses on its own, before anything on the network is
# involved. Both are the same shape of fault - the box could not keep up - and
# both are invisible to every other check here, which measures the network.
# They matter most because they *look* like network loss: a box dropping
# received packets makes every destination retransmit equally, which is the
# exact signature the per-flow check reads as "your link is bad".

# Drops per million packets processed before the backlog is worth reporting.
# Netdata's equivalent alarm is widely reported as too sensitive, so this is a
# rate rather than "any drop at all" - a single transient on a busy box is not
# a fault.
SOFTNET_DROP_PPM = 10

# Accept-queue overflows per day of uptime before a historical count is worth
# mentioning, on the same reasoning as the flap counter.
ACCEPT_OVERFLOW_PER_DAY = 10

# How full the connection-tracking table gets before it's worth saying so. It
# refuses new connections at 100%, and the symptom is connections failing at
# random on a box that passes every other check here.
CONNTRACK_WARN_PCT = 80

# How full the neighbour table gets before it is worth saying so. Same figure
# as the connection-tracking table above and for the same reason: both refuse
# outright at 100% with no back pressure, so the useful moment to speak is
# before that rather than after. Its own constant all the same - the two are
# different tables with different ceilings, and sharing one number would mean
# tuning either retuned the other.
NEIGH_TABLE_WARN_PCT = 80

# Refusals per day of uptime before a history of them is worth mentioning.
# Its own constant: this shared ACCEPT_OVERFLOW_PER_DAY, so tuning the accept
# queue silently retuned connection tracking, which is a different check
# measuring a different thing on a different part of the stack.
CONNTRACK_REFUSAL_PER_DAY = 10

# Share of outbound connection attempts that needed the SYN sent again. On a
# healthy path this is near zero: a SYN is one packet and nothing has warmed up
# yet, so losing it points at something dropping connection setup specifically.
SYN_RETRANS_PCT = 5

# Segments arriving with a bad TCP checksum, per million received. Ethernet's
# own CRC catches corruption on the wire, so a segment that passes that and
# fails this was corrupted somewhere that re-framed it - a switch, a router, a
# middlebox, or an offload engine getting it wrong. It should be zero.
CSUM_ERR_PPM = 1

# Share of retransmissions the far end has told us were unnecessary, via DSACK.
# Above this, a meaningful part of what the retransmit rate is calling loss was
# data that had already arrived - which makes reordering the story rather than
# a lossy path, and sends the search somewhere completely different.
SPURIOUS_RETRANS_PCT = 30

# Share of the tool's collections that has to return data before a conclusion
# drawn from them is allowed to be called well-supported. A verdict from eight
# checks is not the same as one from twenty-four, and saying so is the same
# discipline as never reporting a missing tool as a fault.
COVERAGE_GOOD_PCT = 70
COVERAGE_THIN_PCT = 40

# Share of connection attempts that never reached ESTABLISHED at all. Distinct
# from a retransmitted SYN, which eventually got there.
ATTEMPT_FAIL_PCT = 10

# Resets this box sent, as a share of the connections it took part in. A reset
# is not by itself a fault - an application that closes with data still unread
# sends one, and browsers abandon connections all day - so the line is drawn
# where the count stops looking like a by-product: at least one reset for every
# connection the box handled. A listener that has died, or a port nothing is
# bound to, produces exactly that, and so does a scan.
RESETS_PER_CONN_PCT = 100

# Share of this box's connections that reached ESTABLISHED and were then torn
# down abruptly rather than closed. A well-behaved connection ends with a FIN;
# a reset on an established one means somebody gave up on it mid-flight. Some
# of that is normal - a client walking away, an application aborting - so the
# line sits where it stops looking like ordinary abandonment.
ESTAB_RESET_PCT = 20

# Share of arriving datagrams this box failed to take delivery of before it is
# worth saying so. UDP has no retransmission and no window: a datagram dropped
# at the socket is gone, and the sender is never told. Netdata warns above ten
# a minute; this is a share instead, for the same reason the discard rule is -
# ten a minute means nothing without knowing whether ten thousand or ten
# million arrived.
UDP_DROP_PCT = 1.0

# ...and enough of them for the share to be a share. This is the third time the
# same defect has been written in this file: a percentage of three datagrams
# fired on one datagram lost. The number is Netdata's, which alerts on more than
# ten of these a minute with no share at all - a receive-buffer overflow is
# never routine, unlike a discard, so a small absolute count is already worth
# something and the share is what stops a busy box reporting its own noise.
UDP_DROP_FLOOR = 10

# Share of reassembly attempts that failed. Fragments are already unusual on a
# healthy path, so the bar is on how many of the ones that were tried never
# came back together rather than on the raw count.
REASM_FAIL_PCT = 10.0

# Same pair, same reason: one failure out of two attempted fragments is 50% and
# is two fragments.
REASM_FAIL_FLOOR = 10

# How full the orphan table gets before it is worth saying so. The kernel
# charges an orphan at two to four times its weight when deciding whether it is
# under memory pressure, so the ceiling bites earlier than the number suggests.
ORPHAN_WARN_PCT = 25

# A TLS handshake is one or two round trips. Past this multiple of the connect
# that preceded it, the extra time is the server doing work - key exchange, or
# fetching something it needed - rather than distance.
TLS_HANDSHAKE_RATIO = 4

# Below this the ratio is noise: on a 1ms LAN a 6ms handshake is 6x and fine.
TLS_HANDSHAKE_FLOOR_MS = 250


def _read_softnet():
    """Receive-backlog statistics, summed across CPUs.

    /proc/net/softnet_stat has one row per CPU and the columns are hex, which
    is the obvious way to misread it. Column 1 is packets processed, column 2
    is packets dropped because the backlog queue was full.
    """
    processed = dropped = 0
    try:
        with open("/proc/net/softnet_stat") as fh:
            rows = 0
            for line in fh:
                cols = line.split()
                if len(cols) < 2:
                    continue
                processed += int(cols[0], 16)
                dropped += int(cols[1], 16)
                rows += 1
    except (OSError, ValueError):
        return {}
    return {"softnet_processed": processed, "softnet_dropped": dropped} if rows else {}


def _read_listen_drops():
    """TcpExt counters for connections dropped because a listen queue was full."""
    try:
        with open("/proc/net/netstat") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return {}
    for i, line in enumerate(lines):
        if line.startswith("TcpExt:") and i + 1 < len(lines) and lines[i + 1].startswith("TcpExt:"):
            keys, vals = line.split()[1:], lines[i + 1].split()[1:]
            out = {}
            for key, val in zip(keys, vals):
                # Two of these were being read out of a file with roughly
                # eighty counters in it. SYN retransmits are the interesting
                # one: they separate "connection setup is failing" from
                # "traffic is being lost", which have different causes and
                # different owners. Pruning is the kernel discarding received
                # packets because it could not find memory for them.
                if key in ("ListenOverflows", "ListenDrops", "TCPSynRetrans",
                           # Syncookies are the kernel saying outright that a
                           # listen queue overflowed under load. On a
                           # public-facing box this is the clearest statement
                           # available that the backlog is too small, or that
                           # something is flooding it.
                           "SyncookiesSent", "SyncookiesRecv", "SyncookiesFailed",
                           "TCPTimeWaitOverflow",
                           # Why a connection was aborted, which is the part a
                           # raw reset count cannot tell you. OnMemory is the
                           # box out of socket memory; OnData is data still
                           # unread when the application closed; OnTimeout is
                           # a peer that stopped answering. Three different
                           # owners behind one wire-level symptom.
                           "TCPAbortOnMemory", "TCPAbortOnData",
                           "TCPAbortOnTimeout", "TCPAbortOnClose",
                           "TCPAbortFailed", "TCPReqQFullDrop",
                           "PruneCalled", "RcvPruned", "TCPBacklogDrop",
                           # Evidence that a retransmission was unnecessary.
                           # Without these the tool reports every retransmit as
                           # loss, which is what a packet capture would argue
                           # with first.
                           "TCPDSACKRecv", "TCPDSACKOfoRecv", "TCPSpuriousRTOs",
                           "TCPSACKReorder", "TCPOFOQueue"):
                    try:
                        out[key] = int(val)
                    except ValueError:
                        pass       # a counter that won't parse is unknown, not zero
            return out
    return {}


def _load_average():
    """(one-minute load, CPU count), or (None, 0) where that isn't readable."""
    try:
        return os.getloadavg()[0], (os.cpu_count() or 0)
    except (OSError, AttributeError):
        return None, 0


def _load_context():
    """How busy this box is, phrased for the findings that already blame load.

    Both directions are worth saying, which is why this isn't gated on the load
    being high. A box dropping packets under a load average of 40 has run out
    of capacity. The same box dropping them at 0.2 has a limit set too low -
    and that is a different fix, in a different file, often by a different
    person.
    """
    load1, cpus = _load_average()
    if load1 is None:
        return ""
    if not cpus:
        return f" Load average is {load1:.2f}."
    if load1 / cpus >= 1.0:
        return (f" Load average is {load1:.2f} across {cpus} CPU(s), so the run queue is "
                f"saturated - this is capacity, not configuration.")
    return (f" Load average is {load1:.2f} across {cpus} CPU(s), which is not busy - so the "
            f"limit being hit is a setting rather than a shortage of capacity.")


def _read_text(path):
    """A small file's contents, or None if it isn't there.

    Every /proc and /sys reader here wants exactly this and three of them had
    written it out as their own closure. The int-reading variants beside it are
    deliberately *not* folded in: they differ in what a failure means - unknown,
    skip the field, or leave the default - and that distinction is load-bearing.
    """
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def _read_conntrack():
    """Connection-tracking table pressure, and whether it has actually refused.

    Two different things, both cheap. count/max is how full the table is;
    insert_failed and drop are connections it turned away, which is the part
    that has already hurt someone. Only the counters are read - never the flow
    table itself, which lists who this box has been talking to and is both
    large and nobody's business.
    """
    out = {}
    for key, paths in (
            ("ct_count", ("/proc/sys/net/netfilter/nf_conntrack_count",)),
            ("ct_max", ("/proc/sys/net/netfilter/nf_conntrack_max",
                        "/proc/sys/net/nf_conntrack_max"))):
        for path in paths:
            try:
                with open(path) as fh:
                    out[key] = int(fh.read().strip())
                break
            except (OSError, ValueError):
                continue
    try:
        with open("/proc/net/stat/nf_conntrack") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    if len(lines) < 2:
        return out
    # Column names come from the header because they vary by kernel version.
    # Rows are hex, one per CPU - except "entries", which repeats the table
    # total on every row and must not be summed. insert_failed and drop are
    # genuinely per-CPU, and they are the two worth having.
    names = lines[0].split()
    wanted = {"insert_failed": 0, "drop": 0}
    for row in lines[1:]:
        cols = row.split()
        if len(cols) != len(names):
            continue
        for name in wanted:
            if name in names:
                try:
                    wanted[name] += int(cols[names.index(name)], 16)
                except ValueError:
                    pass
    for name, value in wanted.items():
        if name in names:
            out["ct_" + name] = value
    return out


def _read_neigh_table(base="/proc"):
    """How full the neighbour table is, and whether it has already overflowed.

    The ARP cache has a hard ceiling and no back pressure: past gc_thresh3 the
    kernel simply stops resolving, and the box loses the ability to talk to
    some of its neighbours while every check that does not need one of them
    passes. The symptom is intermittent unreachability that follows no pattern,
    which is the exact shape of fault this tool exists to attribute.

    `base` is a parameter for the same reason the sysfs readers take one - so
    the file handling can be driven from a fixture tree rather than stubbed a
    layer above.
    """
    out = {}
    try:
        with open(os.path.join(base, "sys/net/ipv4/neigh/default/gc_thresh3")) as fh:
            out["gc_thresh3"] = int(fh.read().strip())
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(base, "net/stat/arp_cache")) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    if len(lines) < 2:
        return out
    # Same shape as the conntrack table: hex, one row per CPU, and "entries"
    # repeats the table total on every row rather than being a per-CPU share.
    names = lines[0].split()
    fulls = 0
    for row in lines[1:]:
        cols = row.split()
        if len(cols) != len(names):
            continue
        if "entries" in names:
            try:
                # Assigned, never accumulated: this column repeats the whole
                # table on every row rather than holding a per-CPU share, so
                # adding it up would report a table over its own ceiling on any
                # box with more than one core.
                out["entries"] = int(cols[names.index("entries")], 16)
            except ValueError:
                pass
        if "table_fulls" in names:
            try:
                fulls += int(cols[names.index("table_fulls")], 16)
            except ValueError:
                pass
    if "table_fulls" in names:
        out["table_fulls"] = fulls
    return out


def _bond_members_linux(base="/sys/class/net"):
    """Which interfaces are bonds, and which of their members are down.

    A bond hides its own failures by design: lose one member of a pair and the
    interface stays up, the address stays put, and nothing anywhere reports a
    fault. What has actually gone is the redundancy that was the reason for
    bonding in the first place, plus half the capacity, and the next member to
    fail takes the box off the network.
    """
    out = {}
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return {}
    for name in names:
        bdir = os.path.join(base, name, "bonding")
        if not os.path.isdir(bdir):
            continue

        slaves = (_read_text(os.path.join(bdir, "slaves")) or "").split()
        if not slaves:
            continue
        down = []
        for slave in slaves:
            status = _read_text(os.path.join(base, slave, "bonding_slave", "mii_status"))
            if status is None:
                # No per-slave view: fall back to the member's own link state,
                # which says the same thing one level less directly.
                status = _read_text(os.path.join(base, slave, "operstate"))
            if status is not None and status.lower() not in ("up", "unknown"):
                down.append(slave)
        mode = ((_read_text(os.path.join(bdir, "mode")) or "").split() or [None])[0]
        out[name] = {"members": slaves, "down": down, "mode": mode}
    return out


def _read_server_limits():
    """Ceilings a box serving traffic hits, none of which are the network.

    Each presents as "the network is broken" from outside: connections that
    will not open, connections that are refused, a service that stops
    accepting. All are local limits, and the counters that name them are three
    small reads.
    """
    return parse_server_limits(_read_text("/proc/sys/net/ipv4/ip_local_port_range"),
                               _read_text("/proc/sys/fs/file-nr"),
                               _read_text("/proc/sys/net/core/somaxconn"))


def parse_server_limits(port_range, file_nr, somaxconn):
    """The three readings, turned into numbers. Pure, so the arithmetic in it
    can be tested without a /proc to read from."""
    out = {}
    rng = (port_range or "").split()
    if len(rng) == 2:
        try:
            lo, hi = int(rng[0]), int(rng[1])
            if hi >= lo:
                out["ephemeral_low"], out["ephemeral_high"] = lo, hi
                out["ephemeral_total"] = hi - lo + 1
        except ValueError:
            pass

    # file-nr is "allocated free max". Allocated minus free is what is actually
    # in use; reading the first column as usage overstates it on every kernel
    # that keeps a free list, which is all of them.
    fnr = (file_nr or "").split()
    if len(fnr) == 3:
        try:
            allocated, free, maximum = (int(x) for x in fnr)
            out["fd_used"], out["fd_max"] = max(0, allocated - free), maximum
        except ValueError:
            pass

    if somaxconn and somaxconn.strip().isdigit():
        out["somaxconn"] = int(somaxconn.strip())
    return out


def _read_thermal_throttle(base="/sys/devices/system/cpu"):
    """How many times this CPU has been clocked down to save itself.

    A count rather than a temperature on purpose. A warm box is not a fault and
    every threshold anyone picks for one is wrong on some hardware; a box that
    has actually been throttled has already lost cycles, and the kernel counts
    those. It is the same preference as reading a table's refusals rather than
    how full it looks.

    Per the kernel's own documentation every CPU in a package reports the same
    package counter, so these are maxed rather than summed - adding them would
    multiply one throttling event by the core count.
    """
    out = {}
    try:
        names = sorted(n for n in os.listdir(base) if re.fullmatch(r"cpu\d+", n))
    except OSError:
        return out
    for key, field in (("core_throttles", "core_throttle_count"),
                       ("package_throttles", "package_throttle_count")):
        best = None
        for name in names:
            try:
                with open(os.path.join(base, name, "thermal_throttle", field)) as fh:
                    value = int(fh.read().strip())
            except (OSError, ValueError):
                continue
            best = value if best is None else max(best, value)
        if best is not None:
            out[key] = best
    return out


def _read_kernel_drops():
    """Everything this box drops on its own, in one reading."""
    out = {}
    out.update(_read_softnet())
    out.update(_read_thermal_throttle())
    out.update(_read_listen_drops())
    out.update(_read_conntrack())
    out.update(_read_server_limits())
    # The denominator for SYN retransmits, taken from the same snapshot so the
    # two can be divided. It was already being parsed off the Tcp: line and
    # thrown away with the rest of it.
    tcp = _tcp_counters_linux()
    # The Tcp: line is parsed whole and three fields were being kept. These are
    # the others worth having: attempts that never reached ESTABLISHED, and
    # segments that arrived with a bad checksum.
    for key in ("ActiveOpens", "AttemptFails", "InSegs", "InCsumErrors", "RetransSegs",
                # Resets this box sent, and connections torn down rather than
                # closed. On a proxy these are the wire-level shape of every
                # refusal it makes, and nothing here was reading them.
                "OutRsts", "EstabResets", "PassiveOpens",
                # Datagrams this box could not take delivery of, and the wider
                # bucket that contains them. DNS is UDP: a box dropping these
                # looks like a resolver problem from every other check here.
                "udp_InDatagrams", "udp_InErrors", "udp_RcvbufErrors",
                "udp_SndbufErrors", "udp_NoPorts",
                # Fragments that never came back together. The receiving half
                # of what the path-MTU probe measures on the way out.
                "ip_ReasmReqds", "ip_ReasmOKs", "ip_ReasmFails"):
        if isinstance(tcp.get(key), int):
            out[key] = tcp[key]
    out.update(_read_orphans())
    return out


def _read_orphans(base="/proc"):
    """Sockets torn down without being closed, against the ceiling on them.

    An orphan holds kernel memory with no file descriptor left to close it, and
    the kernel charges them at twice or four times their weight when deciding
    whether it is under pressure. Past tcp_max_orphans it stops being polite
    about it and resets them, which arrives at the far end as a connection
    dropped for no reason anybody here can see.
    """
    out = {}
    text = _read_text(os.path.join(base, "net/sockstat"))
    for line in (text or "").splitlines():
        if line.startswith("TCP:"):
            parts = line.split()
            for i, token in enumerate(parts):
                if token == "orphan" and i + 1 < len(parts):
                    try:
                        out["tcp_orphans"] = int(parts[i + 1])
                    except ValueError:
                        pass
    limit = _read_text(os.path.join(base, "sys/net/ipv4/tcp_max_orphans"))
    try:
        out["tcp_max_orphans"] = int(limit)
    except (TypeError, ValueError):
        pass
    return out


# A clock this far out breaks things that have nothing to do with the network,
# and gets reported as the network. Five minutes is Kerberos' default tolerance
# - past it, domain authentication simply stops - and certificate validity
# windows start to bite. Five seconds breaks nothing on its own but makes log
# correlation across machines useless, which is how most people first notice.
CLOCK_SKEW_BAD_MS = 300_000
CLOCK_SKEW_WARN_MS = 5_000


def parse_chrony_tracking(text):
    """(offset in ms, synchronised) from `chronyc tracking`.

    The line reads "System time : 0.000000123 seconds fast of NTP time", and
    chrony says "Leap status : Not synchronised" when it has no source.
    """
    offset = synced = None
    m = re.search(r"System time\s*:\s*([\d.]+)\s*seconds\s+(fast|slow)", text or "")
    if m:
        offset = float(m.group(1)) * 1000.0
        offset = -offset if m.group(2) == "slow" else offset
    m = re.search(r"Leap status\s*:\s*(.+)", text or "")
    if m:
        synced = "not synchron" not in m.group(1).strip().lower()
    return offset, synced


def parse_ntpq_peers(text):
    """(offset in ms, synchronised) from `ntpq -p`.

    The peer the daemon is actually using is prefixed '*'. Without one, the
    daemon is running but has settled on nothing.
    """
    for line in (text or "").splitlines():
        if not line.startswith("*"):
            continue
        cols = line.split()
        if len(cols) >= 9:
            try:
                return float(cols[8]), True
            except ValueError:
                return None, True
    return None, False if "remote" in (text or "") else None


def cmd_clock_sync():
    """Is this device's clock disciplined, and how far out is it?

    Opportunistic, like ethtool and lldpctl: whichever of the three time
    daemons is present answers, and a box with none reports that it cannot say
    rather than that the clock is fine.
    """
    if which("chronyc"):
        res = run(["chronyc", "tracking"], timeout=5)
        if res.get("ok"):
            offset, synced = parse_chrony_tracking(res.get("stdout", ""))
            res.update({"offset_ms": offset, "synced": synced, "source": "chronyc"})
            return res
    if which("timedatectl"):
        res = run(["timedatectl", "show"], timeout=5)
        if res.get("ok"):
            out = res.get("stdout", "")
            m = re.search(r"NTPSynchronized=(yes|no)", out)
            # timedatectl reports whether the clock is disciplined, never by
            # how much - so an unsynchronised clock is reported without a
            # figure rather than with a guessed one.
            res.update({"offset_ms": None,
                        "synced": (m.group(1) == "yes") if m else None,
                        "source": "timedatectl"})
            return res
    if which("ntpq"):
        res = run(["ntpq", "-p"], timeout=5)
        if res.get("ok"):
            offset, synced = parse_ntpq_peers(res.get("stdout", ""))
            res.update({"offset_ms": offset, "synced": synced, "source": "ntpq"})
            return res
    return {"ok": False, "cmd": "chronyc / timedatectl / ntpq",
            "error": "no time daemon available to ask (chronyc, timedatectl or ntpq)"}


def cmd_kernel_drops(sample_seconds=0, baseline=None):
    """Loss this device inflicts on itself: NIC backlog and accept queues."""
    if OS_NAME != "Linux":
        return {"ok": False, "cmd": "/proc/net/softnet_stat",
                "error": "kernel drop counters are Linux-only", "applicable": False}
    first = baseline if baseline else _read_kernel_drops()
    if not first:
        return {"ok": False, "cmd": "/proc/net/softnet_stat",
                "error": "kernel drop counters are not readable on this system"}
    delta = {}
    if sample_seconds:
        second = _read_kernel_drops()
        delta = {k: second[k] - v for k, v in first.items()
                 if k in second and second[k] >= v}    # a reset is not a rate

    def ppm(counters):
        processed = counters.get("softnet_processed") or 0
        return (round(counters.get("softnet_dropped", 0) * 1_000_000 / processed, 1)
                if processed > 0 else None)

    lines = []
    if "softnet_dropped" in first:
        lines.append(f"backlog drops : {first['softnet_dropped']:,} of "
                     f"{first.get('softnet_processed', 0):,} processed since boot")
    overflows = first.get("ListenOverflows")
    if overflows is not None:
        lines.append(f"accept queue  : {overflows:,} overflow(s) since boot")
    if delta:
        lines.append(f"during sample : {delta.get('softnet_dropped', 0)} backlog, "
                     f"{delta.get('ListenOverflows', 0)} accept-queue")
    load1, cpus = _load_average()
    if load1 is not None:
        lines.append(f"load average  : {load1:.2f}" + (f" across {cpus} CPU(s)" if cpus else ""))
    return {"ok": True, "cmd": "/proc/net/softnet_stat + /proc/net/netstat",
            "stdout": "\n".join(lines), "stderr": "", "code": 0,
            "lifetime": first, "delta": delta or None,
            "drop_ppm_lifetime": ppm(first),
            "drop_ppm_live": ppm(delta) if delta.get("softnet_processed") else None,
            "sample_seconds": sample_seconds or None}


# How far back a kernel-log event still counts as "now". An hour is short
# enough that nobody argues it was last week and long enough to cover the walk
# from the complaint to the SSH session.
KLOG_RECENT_SECONDS = 3600

# Carrier transitions inside KLOG_RECENT_SECONDS before the link is called
# unstable. Two is one clean down/up - a switch reboot, someone moving a cable.
KLOG_FLAPS_RECENT = 4


# The kernel says these things in plain words, and each one is a fault this
# tool otherwise has to infer from a counter with no clock attached. Matched
# case-insensitively against each line.
KLOG_PATTERNS = [
    ("carrier", re.compile(
        r"(?:link is down|link down|link is up|link becomes ready|"
        r"carrier lost|carrier acquired|nic link is (?:up|down))", re.I)),
    ("reset", re.compile(
        r"(?:detected hardware unit hang|reset adapter|resetting adapter|"
        r"transmit queue \d+ timed out|tx timeout|tx hang|"
        r"initiating reset due to|firmware crash)", re.I)),
]

# The interface a kernel line is about: "eth0: NIC Link is Down", or the
# driver's own "e1000e 0000:00:1f.6 eno1: ...". Take the last name-like token
# before the colon.
_KLOG_IFACE = re.compile(r"(?:^|\s)([a-z][a-z0-9_.-]{1,14}):(?:\s|$)", re.I)


def _klog_lines(text, now_monotonic=None, epoch_now=None):
    """[(seconds_ago | None, line)] from dmesg or journalctl output.

    dmesg prints "[  1234.567] eth0: ..." - seconds since boot, which with
    uptime gives an exact age and, unlike `dmesg -T`, cannot be broken by a
    locale. journalctl -o short-unix prints an epoch stamp instead. A kernel
    built with printk.time=0 prints neither, and then the line is still worth
    reporting with an unknown age rather than thrown away.
    """
    out = []
    for line in (text or "").splitlines():
        age = None
        m = re.match(r"\[\s*(\d+(?:\.\d+)?)\]\s*(.*)", line)
        if m and now_monotonic is not None:
            age = max(0.0, now_monotonic - float(m.group(1)))
            line = m.group(2)
        elif m:
            line = m.group(2)
        else:
            m = re.match(r"(\d{9,}(?:\.\d+)?)\s+(.*)", line)   # journalctl -o short-unix
            if m and epoch_now is not None:
                age = max(0.0, epoch_now - float(m.group(1)))
                line = m.group(2)
        if line.strip():
            out.append((age, line.strip()))
    return out


def cmd_kernel_log():
    """What the kernel already recorded, with the times attached.

    Every rate this tool derives from a lifetime counter is divided by uptime,
    which is fine for a fault that has been trickling along and useless for one
    that started this morning: eighty carrier transitions on a box with ninety
    days of uptime averages to under one a day and reads as a healthy link. The
    kernel logged all eighty with timestamps. This reads them.

    Opportunistic like ethtool and lldpctl. dmesg is commonly restricted to
    root (kernel.dmesg_restrict), journalctl to the systemd-journal group, and
    an unreadable log is "couldn't look" - never "nothing happened".
    """
    if OS_NAME != "Linux":
        return {"ok": False, "cmd": "dmesg", "error": "kernel log reading is Linux-only",
                "applicable": False}

    res, uptime, epoch_now = None, _uptime_seconds(), time.time()
    if which("dmesg"):
        res = run(["dmesg"], timeout=10)
        # Restricted rings exit non-zero with "Operation not permitted", and
        # some containers hand back an empty buffer instead.
        if res.get("ok") and (res.get("code") or not (res.get("stdout") or "").strip()):
            res = None
    if res is None and which("journalctl"):
        res = run(["journalctl", "-k", "--no-pager", "-o", "short-unix",
                   "--since", "-2 hours"], timeout=10)
        if res.get("ok") and res.get("code"):
            res = None
    if res is None:
        return {"ok": False, "cmd": "dmesg",
                "error": "the kernel log is not readable by this user "
                         "(dmesg_restrict, or no journal access)"}
    if not res.get("ok"):
        return res

    res["stdout"] = _cap(res.get("stdout"), keep="tail")
    events = []
    for age, line in _klog_lines(res["stdout"], uptime, epoch_now):
        for kind, pat in KLOG_PATTERNS:
            if pat.search(line):
                m = _KLOG_IFACE.search(line)
                events.append({"kind": kind, "age_seconds": age, "text": line,
                               "iface": m.group(1) if m else None})
                break

    recent = [e for e in events
              if e["age_seconds"] is not None and e["age_seconds"] <= KLOG_RECENT_SECONDS]
    res.update({
        "events": events,
        "recent": recent,
        # Times are what this check is for. Without them it can still say the
        # kernel logged something, but not that it logged it today.
        "timed": any(e["age_seconds"] is not None for e in events),
        "uptime_seconds": uptime,
    })
    return res


def cmd_tcp_health(sample_seconds=0, baseline=None):
    """Retransmission rate for this box's own TCP traffic.

    Counters are cumulative since boot, so as with the interface counters a
    lifetime figure is weak evidence; with a sampling window the delta is a
    rate happening now.
    """
    # baseline lets the caller reuse a window someone else already slept
    # through (the interface counters), instead of sleeping twice.
    first = baseline if baseline else _read_tcp_counters()
    if not first:
        return {"ok": False, "cmd": "tcp counters",
                "error": "TCP counters are not available on this system",
                "applicable": False}
    delta = {}
    if sample_seconds:
        if baseline is None:
            time.sleep(sample_seconds)
        second = _read_tcp_counters()
        delta = {k: second.get(k, 0) - v for k, v in first.items() if k in second}

    def pct(counters):
        out_segs = counters.get("OutSegs") or 0
        retrans = counters.get("RetransSegs") or 0
        return round(retrans * 100.0 / out_segs, 2) if out_segs > 0 else None

    lifetime = pct(first)
    live = pct(delta) if delta else None
    lines = [f"out segments : {first.get('OutSegs', '?'):,}" if isinstance(first.get("OutSegs"), int)
             else "out segments : ?",
             f"retransmitted: {first.get('RetransSegs', '?'):,}" if isinstance(first.get("RetransSegs"), int)
             else "retransmitted: ?",
             f"rate         : {lifetime}% since boot" if lifetime is not None else "rate         : ?"]
    if live is not None:
        lines.append(f"during sample: {live}% over {sample_seconds}s")
    return {"ok": True, "cmd": "/proc/net/snmp" if OS_NAME == "Linux" else "netstat -s -p tcp",
            "stdout": "\n".join(lines), "stderr": "", "code": 0,
            "retrans_pct_lifetime": lifetime, "retrans_pct_live": live,
            "sample_seconds": sample_seconds or None}


# ---------------------------------------------------------------------------
# Per-flow TCP analysis.
#
# The counter above says how much of this box's traffic is being retransmitted.
# It cannot say whether that is one sick destination or every destination - and
# those have different owners. Loss common to every peer is this device's own
# link; loss to one peer while the others are clean is that path. The kernel
# already tracks this per connection, so `ss -tin` only has to print it.
#
# Nothing is captured and no payload is read. These are the kernel's own
# statistics for connections this box already has open.
# ---------------------------------------------------------------------------

# A connection has to have moved real data before a loss ratio means anything:
# below this, one retransmit reads as a catastrophic percentage.
FLOW_MIN_BYTES = 50_000

# The same bar for the old-kernel path, which counts segments instead of bytes.
FLOW_MIN_SEGS = 40

# Retransmit ratio at which one connection is called lossy.
FLOW_LOSSY_PCT = 2.0

# A connection is queuing when its smoothed round trip sits well above the
# lowest it has ever seen on that same connection. Both tests are needed and
# each rejects cases the other lets through: the multiple alone fires on a LAN
# where 0.2ms becomes 2.2ms and nothing is wrong, and the absolute alone fires
# on a satellite hop whose 45ms of ordinary variance is weather rather than a
# buffer. Chosen by running candidate rules against twelve paths that should
# and should not fire; this pair was the only one that got all twelve right.
QUEUE_RTT_MULTIPLE = 2.0
QUEUE_DELAY_MS = 30.0

# How unstable a path's delay has to be before it is worth naming, measured as
# TCP's own round-trip variance on the connections this box is carrying.
#
# Two tests again, and for the same reason as the pair above. The absolute
# figure alone fires on any long path, where tens of milliseconds of variance
# is ordinary; the share alone fires on a LAN where 0.2ms becomes 0.5ms and
# nothing is wrong. Variance at half the round trip means the delay is moving
# about as much as it lasts - which is what makes TCP's retransmit timer back
# off and hold recovery, so it is felt long before any packet is lost.
JITTER_MS = 30.0
JITTER_SHARE = 0.5


# Share of a connection's active time spent blocked before the blocking side is
# named as the bottleneck rather than the network.
FLOW_LIMITED_PCT = 20.0

# How long a connection has to have been actively sending before the split
# below means anything. The percentages ss reports are shares of *busy* time,
# so on a connection that has barely moved they are all zero - and subtracting
# zero from a hundred would report an idle socket as limited by the network,
# confidently, on no evidence at all.
FLOW_BUSY_MS = 1000.0

# ss prints roughly 430 bytes per socket, so MAX_OUTPUT_BYTES starts cutting in
# around here. Past this the sample is a biased prefix, and it says so.
FLOW_MAX = 20_000

# How much socket-table output to read before analysing it. `ss -tin` is about
# 430 bytes per connection, so the report's usual 64 KB cap was an arbitrary
# first ~150 sockets - on a proxy holding tens of thousands, a 0.3% sample that
# "worst peer" was then picked from. None of this is stored: the raw table
# names every peer this box talks to and is replaced by a digest before the
# report is written, so the cost is memory during the run and nothing else.
FLOW_READ_BYTES = 12_000_000

# Peers named in the report, so a busy box doesn't export its whole address book.
FLOW_PEERS_SHOWN = 10

FLOW_STATE_RE = re.compile(
    r"^(ESTAB|SYN-SENT|SYN-RECV|FIN-WAIT-\d|CLOSE-WAIT|LAST-ACK|CLOSING)\s")

# key:value pairs, where the value may carry a second number or a percentage:
#   rtt:12.4/3.1   retrans:0/12   rwnd_limited:1230ms(4.5%)   cwnd:10
FLOW_KV_RE = re.compile(r"(?<![\w.])([a-z_]+):([\d.]+(?:/[\d.]+)?(?:ms)?(?:\([\d.]+%\))?)")
FLOW_PCT_RE = re.compile(r"\(([\d.]+)%\)")


def _flow_num(text):
    """First number in a value like '1230ms(4.5%)' or '12.4/3.1'."""
    if text is None:
        return None
    m = re.match(r"[\d.]+", text)
    try:
        return float(m.group(0)) if m else None
    except ValueError:
        return None


def _flow_subnet(peer):
    """The network a peer sits in, so two addresses reached over one upstream
    path aren't counted as two independent faults."""
    if not peer:
        return None
    if ":" in peer:
        head = peer.split("::")[0] if "::" in peer else peer
        parts = [p for p in head.split(":") if p][:4]
        return ":".join(parts) + "::/64" if parts else peer
    octets = peer.split(".")
    return ".".join(octets[:3]) + ".0/24" if len(octets) == 4 else peer


def _flow_is_local(peer):
    """Loopback and link-local peers are not the network under test. Loss on
    loopback is memory pressure, and must never read as a path fault."""
    if not peer:
        return True
    lower = peer.lower().strip("[]")
    return (lower.startswith("127.") or lower in ("::1", "localhost")
            or lower.startswith("169.254.") or lower.startswith("fe80:"))


def _own_ssh_peer():
    """The client end of the SSH session this tool is probably running over.

    That flow is real, but blaming the network for the session we arrived on is
    a distraction - and on a quiet box it can be the only sample there is.
    """
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return (parts[0], parts[1]) if len(parts) >= 2 else (None, None)


def parse_tcp_flows(text, max_flows=FLOW_MAX):
    """Parse `ss -tin` into one record per connection.

    A socket is a state line followed by one or more indented detail lines. The
    detail block is joined before matching, so a wrapped line cannot split a
    key:value pair in half and lose it.
    """
    flows = []
    lines = (text or "").splitlines()
    i, total = 0, len(lines)
    while i < total and len(flows) < max_flows:
        line = lines[i]
        i += 1
        if not FLOW_STATE_RE.match(line):
            continue
        parts = line.split()
        peer = peer_host(parts[4]) if len(parts) > 4 else None
        flow = {
            "state": parts[0],
            "peer": peer,
            "peer_port": parts[4].rsplit(":", 1)[1] if len(parts) > 4 and ":" in parts[4] else None,
            # The local port decides which side of a proxy a flow belongs to,
            # and that decides who owns any loss on it.
            "local_port": peer_port(parts[3]) if len(parts) > 3 else None,
        }
        detail = []
        while i < total and lines[i][:1] in (" ", "\t"):
            detail.append(lines[i].strip())
            i += 1
        blob = " ".join(detail)
        kv = dict(FLOW_KV_RE.findall(blob))
        flow["rtt_ms"] = _flow_num(kv.get("rtt"))
        # The lowest round trip this connection has ever seen. Subtract it from
        # the smoothed rtt and what is left is time spent in a queue - the one
        # number that separates "this path is long" from "something on it is
        # buffering", which have different owners and different fixes. Parsed
        # and thrown away until now; the kernel has always offered it.
        flow["minrtt_ms"] = _flow_num(kv.get("minrtt"))
        # rtt: is "smoothed/variance". The second half was being discarded by
        # the parser that takes the first number, and it is the only jitter
        # figure here measured on the traffic this box actually carries -
        # everything else comes from probes a router is free to deprioritise.
        rtt_raw = kv.get("rtt") or ""
        flow["rtt_var_ms"] = (_flow_num(rtt_raw.split("/", 1)[1])
                              if "/" in rtt_raw else None)
        flow["bytes_sent"] = _flow_num(kv.get("bytes_sent")) or 0.0
        flow["bytes_retrans"] = _flow_num(kv.get("bytes_retrans")) or 0.0
        flow["segs_out"] = _flow_num(kv.get("segs_out")) or 0.0
        # retrans:cur/total - the running total is the one worth keeping.
        retrans = kv.get("retrans")
        flow["retrans_total"] = _flow_num(retrans.split("/")[-1]) if retrans else None
        # How long this connection has actually been sending. Needed because
        # the two percentages below are shares of it.
        flow["busy_ms"] = _flow_num((kv.get("busy") or "").replace("ms", ""))
        for key in ("rwnd_limited", "sndbuf_limited"):
            found = FLOW_PCT_RE.search(kv.get(key) or "")
            flow[key + "_pct"] = float(found.group(1)) if found else 0.0
        flows.append(flow)
    return flows


def _flow_loss_pct(flow):
    """Retransmit ratio for one connection, and what it was worked out from.

    Kernels before ~4.15 have no bytes_sent/bytes_retrans, only a segment
    count. Without the fallback a genuinely lossy box on an older kernel reads
    as perfectly clean, which is the worst answer this tool can give.
    """
    if flow["bytes_sent"] >= FLOW_MIN_BYTES:
        ratio = 100.0 * flow["bytes_retrans"] / flow["bytes_sent"]
        # bytes_retrans counts every resend of the same bytes, so a badly stuck
        # flow can exceed 100%. Reporting "900% loss" reads as a bug.
        return min(round(ratio, 2), 100.0), "bytes"
    if flow["retrans_total"] is not None and flow["segs_out"] >= FLOW_MIN_SEGS:
        ratio = 100.0 * flow["retrans_total"] / flow["segs_out"]
        return min(round(ratio, 2), 100.0), "segments"
    return None, None


def _queue_message(info, where):
    """One sentence for a queue, wherever it was found."""
    return (f"{info['queued']} connection(s) {where} are waiting in a queue rather "
            f"than travelling: the worst is {info['queue_peer']} at "
            f"{info['queue_rtt_ms']}ms against its own best of {info['queue_min_ms']}ms, "
            f"so {info['queue_ms']}ms of every round trip is spent buffered. That is "
            f"not distance - the same connection has been faster. Something on this "
            f"path is holding traffic instead of dropping it: a full link, an overrun "
            f"interface queue, or a device buffering to hide one.")


def _queue_summary(flows):
    """How much of the round trip is queue rather than distance, at worst.

    A connection's own minimum is the honest floor for it: the same socket has
    been that fast, so anything above it is time spent waiting somewhere. Both
    tests are needed - see QUEUE_RTT_MULTIPLE for why either alone is wrong.
    """
    worst, count = None, 0
    for flow in flows or []:
        rtt, floor = flow.get("rtt_ms"), flow.get("minrtt_ms")
        if not rtt or not floor:
            continue
        if rtt < QUEUE_RTT_MULTIPLE * floor or rtt - floor < QUEUE_DELAY_MS:
            continue
        count += 1
        if worst is None or rtt - floor > worst[0]:
            worst = (rtt - floor, flow)
    if not worst:
        return None
    delay, flow = worst
    return {"queued": count, "queue_ms": round(delay, 1), "queue_peer": flow["peer"],
            "queue_rtt_ms": flow["rtt_ms"], "queue_min_ms": flow["minrtt_ms"]}


def analyze_tcp_flows(flows, truncated=False, listen_ports=None):
    """Aggregate per-connection statistics into who owns the problem.

    `listen_ports` splits the connections into the ones that arrived and the
    ones this box opened. On a proxy those are two different networks with two
    different owners - clients out on the internet, backends on an internal
    segment - and averaging them produced the wrong answer with confidence: a
    lossy database on 10.0.0.90 came out as "some destinations are losing
    traffic", owner *the provider or upstream*, which sends someone to argue
    with a carrier about the inside of their own rack.
    """
    listen_ports = set(listen_ports or ())
    ssh_peer, ssh_port = _own_ssh_peer()
    measurable, skipped_own = [], 0
    for flow in flows:
        if _flow_is_local(flow["peer"]):
            continue
        if flow["peer"] == ssh_peer and flow["peer_port"] == ssh_port:
            skipped_own += 1
            continue
        pct, basis = _flow_loss_pct(flow)
        if pct is None:
            continue
        flow["retrans_pct"], flow["basis"] = pct, basis
        flow["side"] = ("client" if flow.get("local_port") in listen_ports
                        else "backend" if listen_ports else None)
        measurable.append(flow)

    lossy = [f for f in measurable if f["retrans_pct"] >= FLOW_LOSSY_PCT]
    clean = [f for f in measurable if f["retrans_pct"] < FLOW_LOSSY_PCT]
    lossy_nets = {_flow_subnet(f["peer"]) for f in lossy}
    clean_nets = {_flow_subnet(f["peer"]) for f in clean} - lossy_nets

    # Every figure describing "the worst" has to come off the same connection.
    # Reading the percentage from one and the basis from another reported a
    # segment-derived rate as a byte-derived one, and naming the peer from a
    # sorted list attributed the worst loss to whoever sorted first.
    worst = max(lossy, key=lambda f: f["retrans_pct"]) if lossy else None
    out = {
        "flows_seen": len(flows),
        "flows_measurable": len(measurable),
        "flows_own_session": skipped_own,
        "networks_lossy": len(lossy_nets),
        "networks_clean": len(clean_nets),
        "lossy_peers": sorted({f["peer"] for f in lossy})[:FLOW_PEERS_SHOWN],
        "worst_loss_pct": worst["retrans_pct"] if worst else None,
        "worst_peer": worst["peer"] if worst else None,
        # Smoothed RTT to the destination that is actually suffering, measured
        # on its own traffic rather than on a probe to somewhere else. It was
        # parsed and thrown away; a loss figure without the latency beside it
        # tells half the story.
        "worst_rtt_ms": worst.get("rtt_ms") if worst else None,
        "basis": worst["basis"] if worst else None,
        "truncated": truncated,
        # The queuing picture across everything, for a box with no listening
        # ports and therefore no sides to split by. A digest, never the flow
        # list itself - that names every peer this box talks to.
        "queue": _queue_summary(measurable),
        "shape": None,
        # Which side of a proxy the loss is on. Only meaningful when the
        # listening ports were known, so it stays None on a box that is not
        # serving anything - where every flow is outbound by definition and
        # the distinction would be an invention.
        "lossy_side": None,
        "clients_lossy": None,
        "backends_lossy": None,
    }
    if listen_ports:
        # Latency and loss per direction, measured on the connections
        # themselves. This is the only view of the inbound side there is:
        # traceroute goes one way, and no probe from here can observe the
        # route a client's packets took to arrive. TCP_INFO is better evidence
        # anyway - it is the real traffic, not probes a router may deprioritise.
        out["by_side"] = {}
        for name in ("client", "backend"):
            group = [f for f in measurable if f.get("side") == name]
            if not group:
                continue
            rtts = sorted(f["rtt_ms"] for f in group if f.get("rtt_ms"))
            jitter = sorted(f["rtt_var_ms"] for f in group if f.get("rtt_var_ms"))
            queued = _queue_summary(group)
            worst_flow = max(group, key=lambda f: f.get("retrans_pct") or 0)
            peers = {}
            for f in group:
                peers[f["peer"]] = peers.get(f["peer"], 0) + 1
            out["by_side"][name] = {
                "connections": len(group),
                # Median, not worst: one stalled connection should not stand in
                # for how the other side is being served.
                "rtt_ms": rtts[len(rtts) // 2] if rtts else None,
                # Median for the same reason as the round trip beside it.
                "jitter_ms": jitter[len(jitter) // 2] if jitter else None,
                "worst_loss_pct": worst_flow.get("retrans_pct"),
                "worst_peer": worst_flow["peer"],
                "via": dominant_peer(peers),
                # Connections whose smoothed rtt sits far above their own
                # floor. Per side, because a queue in front of the clients and
                # a queue in front of the backends are two different pieces of
                # equipment with two different owners.
                **(queued or {"queued": 0}),
            }
        sides = {"client": [], "backend": []}
        for flow in lossy:
            sides.get(flow.get("side"), []).append(flow)
        out["clients_lossy"] = len(sides["client"])
        out["backends_lossy"] = len(sides["backend"])
        if sides["backend"] and not sides["client"]:
            out["lossy_side"] = "backend"
        elif sides["client"] and not sides["backend"]:
            out["lossy_side"] = "client"
        elif sides["client"] and sides["backend"]:
            out["lossy_side"] = "both"
    if lossy:
        # One network lossy while others are clean is a path fault. Every
        # network lossy is this device's own link. Neither reading is available
        # from the host-wide counter, which sees only one number.
        if lossy_nets and not clean_nets and len(lossy_nets) >= 2:
            # "No destination is clean" is a claim about what *isn't* there, so
            # it needs the whole sample. ss prints in kernel table order, and a
            # truncated prefix of that is not a random selection - it can easily
            # be one busy application's connections. "This one is lossy, that
            # one is clean" is a claim about what *is* there, and survives a
            # partial read, so only the local-blame conclusion is withheld -
            # the loss itself is still reported, with the owner left open.
            out["shape"] = "unclear" if truncated else "all_peers"
        elif clean_nets:
            out["shape"] = "some_peers"
        else:
            out["shape"] = "one_peer"
    limited = [f for f in measurable if f["rwnd_limited_pct"] >= FLOW_LIMITED_PCT]
    stalled = [f for f in measurable if f["sndbuf_limited_pct"] >= FLOW_LIMITED_PCT]
    out["receiver_limited"] = len(limited)
    out["receiver_limited_pct"] = max((f["rwnd_limited_pct"] for f in limited), default=None)
    out["sendbuf_limited"] = len(stalled)
    out["sendbuf_limited_pct"] = max((f["sndbuf_limited_pct"] for f in stalled), default=None)

    # Which of the three is holding throughput back. The kernel times how long
    # a connection spent unable to send because the receiver had no window left
    # and because this box's own send buffer was empty; whatever is left of its
    # busy time is time it spent waiting on the path.
    #
    # Two of the three already produce findings here and the third never did,
    # which left the tool able to say "it is the far end" and "it is this box"
    # and not "it is the network" - on a run whose whole subject is the
    # network. It is reported as context rather than as a fault, because a
    # transfer being limited by the path is usually TCP working correctly.
    busy = [f for f in measurable if (f.get("busy_ms") or 0) >= FLOW_BUSY_MS]
    if busy:
        rwnd = sum(f["rwnd_limited_pct"] for f in busy) / len(busy)
        sndbuf = sum(f["sndbuf_limited_pct"] for f in busy) / len(busy)
        out["limits"] = {
            "connections": len(busy),
            "receiver_pct": round(rwnd, 1),
            "sender_pct": round(sndbuf, 1),
            # Clamped: the two the kernel reports can overlap slightly, and a
            # negative share of anything would be a nonsense to print.
            "path_pct": round(max(100.0 - rwnd - sndbuf, 0.0), 1),
        }
    return out


def cmd_tcp_flows(listen_ports=None):
    """Per-connection TCP statistics for the connections this box has open."""
    if OS_NAME != "Linux" or not which("ss"):
        return {"ok": False, "cmd": "ss -tin",
                "error": "per-connection TCP statistics need `ss` on Linux",
                "applicable": False}
    # -n is not cosmetic: without it, ss reverse-resolves every peer, so the
    # command hangs exactly when DNS is the thing that's broken.
    res = run(["ss", "-tin"], timeout=15, limit=FLOW_READ_BYTES)
    if not res.get("ok"):
        return res
    text = res.get("stdout") or ""
    truncated = "more characters not stored" in text
    flows = parse_tcp_flows(text)
    stats = analyze_tcp_flows(flows, truncated=truncated or len(flows) >= FLOW_MAX,
                              listen_ports=listen_ports)
    res.update(stats)
    # The raw table is ~430 bytes per socket and names every peer this box
    # talks to. The digest is what the report carries instead.
    lines = [f"connections  : {stats['flows_seen']} seen, "
             f"{stats['flows_measurable']} with enough traffic to judge"]
    if stats["flows_own_session"]:
        lines.append(f"             : {stats['flows_own_session']} skipped (this SSH session)")
    if stats["worst_loss_pct"] is not None:
        lines.append(f"worst loss   : {stats['worst_loss_pct']}% "
                     f"(by {stats['basis']}) to {stats['worst_peer']}"
                     + (f", rtt {stats['worst_rtt_ms']}ms" if stats.get("worst_rtt_ms")
                        else ""))
        lines.append(f"networks     : {stats['networks_lossy']} lossy, "
                     f"{stats['networks_clean']} clean")
    elif stats["flows_measurable"]:
        lines.append("worst loss   : none - no connection is retransmitting")
    else:
        lines.append("worst loss   : not enough traffic to judge")
    if stats["receiver_limited"]:
        lines.append(f"far-end wait : {stats['receiver_limited_pct']}% of active time "
                     f"on {stats['receiver_limited']} connection(s)")
    if stats["sendbuf_limited"]:
        lines.append(f"send buffer  : {stats['sendbuf_limited_pct']}% of active time "
                     f"on {stats['sendbuf_limited']} connection(s)")
    res["stdout"] = "\n".join(lines)
    res["stderr"] = ""
    return res


# ---------------------------------------------------------------------------
# Interface error counters. These are the strongest local evidence for "the
# fault is this device or its cable" vs "the fault is out in the network":
# every other check here measures reachability, which tells you something is
# wrong but not whose it is. Corrupted frames arriving on the wire are.
#
# The counters are cumulative since boot, so a raw number means little - 47
# errors over 200 days of uptime is noise. We therefore report the rate (per
# million packets) and, when not in quick mode, sample twice to see whether
# the counters are climbing *right now*, which is a different finding.
# ---------------------------------------------------------------------------

# Errors per million packets before a historical count is worth mentioning.
# Below this, normal links accumulate stray errors over months of uptime.
# Each port check is a TCP connect with a timeout, so an unbounded list is a
# way to make this box spend an hour connecting. Truncation is reported, never
# silent.
COMMON_PORTS = ["22", "53", "80", "443", "8080"]

# A report travels off the box - by paste, by email, inside an HTML page. One
# command with a huge table (a big ARP cache, netstat on a busy host) should not
# be able to turn a 60KB report into a multi-megabyte one.
MAX_OUTPUT_BYTES = 64_000

MAX_CHECK_PORTS = 32

# Enough to collapse a list of timeouts, small enough not to look like a scan.
PORT_CHECK_WORKERS = 8

# Long enough for a service that greets you, short enough that a silent one
# doesn't dominate the run - a quiet port costs exactly this.
BANNER_TIMEOUT = 0.5

# An hour is already far past useful; --soak 999999 would otherwise sleep
# for days on a box someone is waiting on.
MAX_SOAK_SECONDS = 3600

# Exit status follows the monitoring-plugin convention - 0 OK, 1 WARNING,
# 2 CRITICAL, 3 UNKNOWN - so this drops into a scheduled check without anything
# parsing its output. It also fixes a quieter problem: a run reporting a
# degraded link used to exit 0, so a wrapper saw success while the tool was
# saying something was wrong.
EXIT_OK, EXIT_WARNING, EXIT_CRITICAL, EXIT_UNKNOWN = 0, 1, 2, 3


def exit_status(report):
    """The worst thing the report found, as a status code."""
    severities = {f.get("severity") for f in report.get("findings", [])}
    if "critical" in severities:
        return EXIT_CRITICAL
    if "warning" in severities:
        return EXIT_WARNING
    # No verdict at all means the run produced nothing to judge.
    return EXIT_OK if report.get("verdict") else EXIT_UNKNOWN


ERR_PPM_WARN = 100

# Carrier transitions per day before a link counts as flapping. The kernel
# counts the first transition to up, so a link that has never dropped reads 1
# or 2; anything beyond that is the port going away and coming back. A stable
# link does that when someone reboots the switch, and not otherwise.
LINK_FLAP_PER_DAY = 2

# Transitions a healthy link accumulates simply by coming up at boot.
LINK_FLAP_BASELINE = 2


def _uptime_seconds():
    """How long this box has been up, or None where that isn't readable.

    A lifetime flap count means nothing on its own - 40 transitions across two
    years of uptime is somebody rebooting a switch twice a year, and the same
    40 in a day is a dying cable. Without the denominator the check says
    nothing rather than guessing.
    """
    try:
        with open("/proc/uptime") as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None

# Collisions get a lower bar than generic errors: nearly every modern link is
# full duplex, where a collision shouldn't happen at all, so a steady trickle
# is the classic fingerprint of a duplex mismatch with the switch port.
COLL_PPM_WARN = 10

LINK_COUNTERS = (
    "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
    "rx_errors", "tx_errors", "rx_dropped",
    "tx_dropped", "rx_crc_errors", "rx_frame_errors", "rx_over_errors",
    "collisions",
    # rx_errors is an aggregate - the kernel documents it as including the
    # length, CRC and frame counters "and other errors not otherwise counted".
    # Which of them moved decides who owns the fault, and without these three
    # every one of them was reported as a cable.
    "rx_missed_errors", "rx_length_errors", "tx_carrier_errors",
)


# NIC drivers that present a paravirtual or cloud-hypervisor interface rather
# than a wire. What matters here is not that the box is a VM - it is that on
# these drivers the physical-layer counters are hardwired to zero. There is no
# CRC to fail, no duplex to mismatch, no optic to dim, so a clean physical layer
# on one of them is not evidence that anything is well: it is evidence that the
# question cannot be asked.
#
# That is the same rule this tool applies everywhere else - a check that could
# not run is never reported as a fault - pointed at a check that runs, returns
# zero, and could never have returned anything else.
VIRTUAL_NIC_DRIVERS = {
    "virtio_net": "a KVM or QEMU paravirtual adapter",
    "vmxnet3": "a VMware paravirtual adapter",
    "vmxnet": "a VMware paravirtual adapter",
    "hv_netvsc": "a Hyper-V synthetic adapter",
    "netvsc": "a Hyper-V synthetic adapter",
    "xen-netfront": "a Xen paravirtual adapter",
    "ena": "an AWS Elastic Network Adapter",
    "gve": "a Google Compute Engine virtual adapter",
    "veth": "one end of a container pair",
}


def _link_drivers_linux(base="/sys/class/net"):
    """The kernel driver behind each interface, from the sysfs symlink.

    `base` is a parameter for the same reason its neighbours take one: so the
    link handling can be driven from a fixture tree rather than stubbed a layer
    above.
    """
    out = {}
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return {}
    for name in names:
        link = os.path.join(base, name, "device", "driver")
        try:
            out[name] = os.path.basename(os.readlink(link))
        except OSError:
            # Bonds, VLANs and tunnels have no device behind them at all, which
            # is not a failure to read - there is nothing there to name.
            continue
    return out


def _link_stats_linux(base="/sys/class/net"):
    """Read counters straight from sysfs - no parsing of human-facing output.

    base is a parameter so tests can point it at a fixture tree; nothing else
    should pass it.
    """
    stats = {}
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return {}
    for name in names:
        sdir = os.path.join(base, name, "statistics")
        if not os.path.isdir(sdir):
            continue
        vals = {}
        for field in LINK_COUNTERS:
            try:
                with open(os.path.join(sdir, field)) as fh:
                    vals[field] = int(fh.read().strip())
            except (OSError, ValueError):
                # Not every driver exports every counter. None means "unknown",
                # which must not be presented as "zero errors" - see below.
                vals[field] = None
        try:
            with open(os.path.join(base, name, "operstate")) as fh:
                vals["operstate"] = fh.read().strip()
        except OSError:
            vals["operstate"] = "unknown"
        # How many times the link has gone down and come back. operstate says
        # what the link is doing now; this says what it has been doing. A port
        # that has flapped hundreds of times still reads "up" between drops,
        # which is exactly why an intermittent fault survives a snapshot.
        try:
            with open(os.path.join(base, name, "carrier_changes")) as fh:
                vals["carrier_changes"] = int(fh.read().strip())
        except (OSError, ValueError):
            vals["carrier_changes"] = None     # kernels before 3.15, or not a real NIC
        stats[name] = vals
    return stats


def _link_stats_bsd():
    """macOS/BSD: parse `netstat -i -b -n`, using only the <Link#...> rows so
    per-address-family rows don't double-count."""
    res = run(["netstat", "-i", "-b", "-n"])
    if not res.get("ok"):
        return {}
    lines = [ln for ln in res.get("stdout", "").splitlines() if ln.strip()]
    if not lines:
        return {}
    hdr = lines[0].split()
    idx = {h: i for i, h in enumerate(hdr)}
    if not all(k in idx for k in ("Name", "Network", "Ipkts", "Ierrs", "Opkts", "Oerrs")):
        return {}
    stats = {}
    for line in lines[1:]:
        parts = line.split()
        if len(parts) <= max(idx.values()):
            continue
        if not parts[idx["Network"]].startswith("<Link"):
            continue

        def get(key):
            try:
                return int(parts[idx[key]])
            except (KeyError, ValueError, IndexError):
                return 0

        stats[parts[idx["Name"]]] = {
            "rx_packets": get("Ipkts"), "tx_packets": get("Opkts"),
            "rx_bytes": get("Ibytes"), "tx_bytes": get("Obytes"),
            "rx_errors": get("Ierrs"), "tx_errors": get("Oerrs"),
            "rx_dropped": get("Drop"), "tx_dropped": 0,
            "rx_crc_errors": 0, "rx_frame_errors": 0, "rx_over_errors": 0,
            "collisions": get("Coll"), "operstate": "unknown",
        }
    return stats


def _read_link_stats():
    if OS_NAME == "Linux":
        stats = _link_stats_linux()
        if stats:
            return stats, "/sys/class/net/*/statistics"
    if OS_NAME != "Windows":
        return _link_stats_bsd(), "netstat -i -b -n"
    return {}, "netstat -e"


# A delta needs a window long enough to mean something. Below this the rate is
# mostly noise, so a fast run waits out the remainder rather than reporting
# "+1 error in 0.4s".
MIN_COUNTER_WINDOW = 2


def start_link_sample():
    """Take the first counter reading. Pair with finish_link_sample()."""
    first, source = _read_link_stats()
    return {"first": first, "source": source, "started": time.monotonic()}


# The most samples a rate series will hold. At or below this the interval is
# one second, which is the resolution a burst needs; a longer soak stretches
# the interval rather than storing more, so an hour-long window costs the same
# to carry as a two-minute one and each sample stays a real measurement over a
# real interval instead of a decimated guess.
SERIES_MAX_SAMPLES = 900


def _sample_through(remaining, progress=None):
    """Read the byte counters while waiting out the window, not just at its ends.

    The counters were sampled once at each end and divided, which gives a mean
    - and a mean is exactly the wrong statistic for the fault --soak exists to
    find. A line that is completely full for twenty seconds of every minute
    averages to a third and reads as quiet, while calls break three times a
    minute. Ticking here already happened for the progress line; this reads the
    counters on the same tick.

    Returns ({iface: [Mbps, ...]}, seconds_covered) - the busier direction per
    interval, which is what every utilisation threshold compares against.

    The series covers only the part of the window still left to wait. The
    counter window deliberately runs alongside the rest of the checks, so a
    --soak shorter than the run itself (about 15s) has nothing left to sample
    through and returns nothing rather than a series covering a fraction of the
    window and pretending otherwise.
    """
    interval = max(1.0, remaining / SERIES_MAX_SAMPLES)
    series, prev, prev_t = {}, None, None
    left = remaining
    # Counted down rather than driven off the clock: a test that stubs sleep
    # would otherwise spin here until real time caught up, and the loop must
    # always terminate in as many steps as there are intervals.
    while left > 0:
        if progress:
            progress(f"sampling error counters ({left:.0f}s left)")
        step = min(interval, left)
        time.sleep(step)
        left -= step
        now, _src = _read_link_stats()
        t = time.monotonic()
        if prev is not None:
            # The measured interval, not the one we asked for. A tick that
            # lands late and is divided by the nominal step reads high.
            dt = (t - prev_t) if prev_t is not None and t > prev_t else step
            for name, vals in now.items():
                if name not in prev:
                    continue        # an interface that appeared mid-window
                rx = _delta(prev[name], vals, "rx_bytes")
                tx = _delta(prev[name], vals, "tx_bytes")
                if rx is None or tx is None:
                    continue        # counters wrapped or were reset - not a rate
                series.setdefault(name, []).append(
                    round(max(rx, tx) * 8 / dt / 1e6, 2))
        prev, prev_t = now, t
    return (series or None), (remaining - left)


def _delta(before, after, key):
    """A counter difference, or None where it cannot be one.

    None rather than zero on a reset: a zero is a claim that the interface was
    idle for that second, which would pull the mean down and hide the very
    burst this is here to find.
    """
    a, b = before.get(key), after.get(key)
    if not isinstance(a, int) or not isinstance(b, int) or b < a:
        return None
    return b - a


def cmd_link_stats(sample_seconds=0, sample=None, progress=None):
    """Collect per-interface error counters, optionally sampling twice.

    With sample_seconds > 0 the counters are read again after that delay and
    the deltas recorded, which is what separates "this link is failing now"
    from "this link accumulated a few errors since boot".

    Passing a `sample` from start_link_sample() means the window has already
    been running while other checks worked, so only the remainder is waited
    out - the measurement covers the whole run instead of a dead 2 seconds.
    """
    if sample is not None:
        first, source = sample["first"], sample["source"]
        series, series_seconds = None, 0
        elapsed = time.monotonic() - sample["started"]
        # Only wait when sampling was actually asked for. A --quick run that
        # finishes in under two seconds must not be made slower by a floor
        # meant to keep rates meaningful.
        if sample_seconds:
            remaining = max(0.0, max(sample_seconds, MIN_COUNTER_WINDOW) - elapsed)
            if remaining > 0:
                # Tick once a second rather than sleeping the whole remainder in
                # silence - a --soak 120 that shows nothing for two minutes looks
                # indistinguishable from one that has hung.
                # Counted down rather than driven off the clock: a test that
                # stubs sleep would otherwise spin here until real time caught
                # up, and the loop must always terminate in as many steps as
                # there are seconds.
                series, series_seconds = _sample_through(remaining, progress)
            sample_seconds = round(max(elapsed + remaining, MIN_COUNTER_WINDOW))
        return _finish_link_sample(first, source, sample_seconds, already_waited=True,
                                   series=series, series_seconds=series_seconds)
    first, source = _read_link_stats()
    if not first:
        return {
            "ok": False,
            "cmd": source,
            "error": "interface error counters are not available on this system",
            "applicable": False,
            "interfaces": [],
        }

    return _finish_link_sample(first, source, sample_seconds)


def _finish_link_sample(first, source, sample_seconds, already_waited=False,
                        series=None, series_seconds=0):
    def num(mapping, key):
        v = mapping.get(key)
        return v if isinstance(v, int) else 0

    deltas = {}
    if sample_seconds:
        if not already_waited:
            time.sleep(sample_seconds)
        second, _ = _read_link_stats()
        for name, vals in second.items():
            if name in first:
                deltas[name] = {
                    k: num(vals, k) - num(first[name], k)
                    for k in LINK_COUNTERS
                }
                # Not a statistics/ counter, and None must stay None: a driver
                # that doesn't export it hasn't reported "no flaps".
                before, after = first[name].get("carrier_changes"), vals.get("carrier_changes")
                deltas[name]["carrier_changes"] = (
                    after - before if isinstance(before, int) and isinstance(after, int)
                    else None)

    interfaces = []
    for name, vals in sorted(first.items()):
        errors = num(vals, "rx_errors") + num(vals, "tx_errors")
        drops = num(vals, "rx_dropped") + num(vals, "tx_dropped")
        packets = num(vals, "rx_packets") + num(vals, "tx_packets")
        unknown = [k for k in LINK_COUNTERS if vals.get(k) is None]
        d = deltas.get(name, {})
        interfaces.append({
            "name": name,
            "operstate": vals.get("operstate", "unknown"),
            "packets": packets,
            "errors": errors,
            "drops": drops,
            "crc": num(vals, "rx_crc_errors"),
            "frame": num(vals, "rx_frame_errors"),
            "overruns": num(vals, "rx_over_errors"),
            "collisions": num(vals, "collisions"),
            "err_ppm": round(errors * 1_000_000 / packets, 1) if packets else 0,
            "coll_ppm": round(num(vals, "collisions") * 1_000_000 / packets, 1) if packets else 0,
            "unknown_counters": unknown,
            # A negative delta means the counter wrapped or the interface was
            # reset mid-sample. Reporting "-98 errors in 2s" would be nonsense,
            # so the rate is unknown for that window rather than negative.
            "delta_errors": _nonneg(d.get("rx_errors", 0) + d.get("tx_errors", 0)) if d else None,
            "delta_drops": _nonneg(d.get("rx_dropped", 0) + d.get("tx_dropped", 0)) if d else None,
            "delta_packets": _nonneg(d.get("rx_packets", 0) + d.get("tx_packets", 0)) if d else None,
            # The same error burst, split by who has to fix it. A FIFO overflow
            # and a packet the host had no buffer for are this box failing to
            # take delivery; an invalid length is a frame that arrived the
            # wrong size. Neither is the cable the aggregate counter sends
            # people to check.
            # max, not sum: many drivers wire rx_over_errors and
            # rx_missed_errors to the same hardware counter, so adding them
            # counts one overrun twice - enough to make the host share exceed
            # the total it is a share of, and print "80 of 40 errors".
            "delta_host_errors": (_nonneg(max(d.get("rx_over_errors", 0),
                                              d.get("rx_missed_errors", 0))) if d else None),
            "delta_length_errors": _nonneg(d.get("rx_length_errors", 0)) if d else None,
            # Throughput over the sampling window: the answer to "the network
            # is slow" is often "your link is full", which no other check sees.
            "rx_mbps": (round(d.get("rx_bytes", 0) * 8 / sample_seconds / 1e6, 2)
                        if d and sample_seconds else None),
            "tx_mbps": (round(d.get("tx_bytes", 0) * 8 / sample_seconds / 1e6, 2)
                        if d and sample_seconds else None),
            # What the window looked like second by second, rather than
            # averaged flat. peak_mbps is the number that matches the
            # complaint; the mean is the number that hides it.
            # Only for interfaces that actually moved something. Every box has
            # a pile of idle virtual interfaces, and a series of zeros for each
            # is noise in the report and storage in a long soak.
            "rate_series": ((series or {}).get(name) or None
                            if max((series or {}).get(name) or [0]) else None),
            "peak_mbps": max((series or {}).get(name) or [0]) or None,
            # How much of the window the series actually covers, which is not
            # the whole of it - see _sample_through.
            "series_seconds": round(series_seconds) or None if series else None,
            "carrier_changes": vals.get("carrier_changes"),
            "delta_carrier_changes": _nonneg(d.get("carrier_changes")) if d else None,
            "sample_seconds": sample_seconds or None,
        })

    # A readable table for the raw-output panel, so this looks like every
    # other command result in the UI.
    head = f"{'iface':<12}{'packets':>14}{'errors':>9}{'drops':>8}{'err/M':>9}  live"
    rows = [head, "-" * len(head)]
    for i in interfaces:
        live = "" if i["delta_errors"] is None else (
            f"+{i['delta_errors']} err in {sample_seconds}s" if i["delta_errors"] else "steady"
        )
        rows.append(f"{i['name']:<12}{i['packets']:>14,}{i['errors']:>9,}"
                    f"{i['drops']:>8,}{i['err_ppm']:>9}  {live}")
    return {"ok": True, "cmd": source, "stdout": "\n".join(rows), "stderr": "",
            "code": 0, "interfaces": interfaces}


# ---------------------------------------------------------------------------
# Link mode (speed / duplex / MTU) and path MTU.
#
# Speed and duplex are what the interface negotiated with the switch port it's
# plugged into, so a disagreement there is a fault in the link between this
# device and the upstream switch - one of the few things visible from here
# that is unambiguously about that cable and those two ports.
#
# Path MTU is the other half: the interface can be configured for 1500 while
# something along the path silently drops full-size packets. Small packets
# (pings) sail through and large ones vanish, so the box looks reachable while
# real traffic stalls. That's a PMTU blackhole, and it's invisible to every
# other check in this tool.
# ---------------------------------------------------------------------------

# How far a peak has to sit above the average before the average is worth
# distrusting on sight. Below this the two tell the same story and printing both
# is noise; above it the average is actively hiding something, which is the
# oldest complaint about every graphing tool that consolidates by mean - the
# peak flattens as the window grows until a line that filled every minute reads
# as quiet.
PEAK_WORTH_SHOWING = 1.2

STANDARD_MTU = 1500

# Interfaces that carry someone else's packets inside this box's packets. A
# reduced MTU on one of these is not a misconfiguration, it is the header
# overhead of whatever is wrapping the traffic - and reporting it as a fault
# meant a healthy VPN box came back with "Interface MTU is not the standard
# 1500" as its verdict, every single run, because nothing else was wrong.
#
# Matched on the name because that is what the kernel gives us: there is no
# flag in sysfs that says "this is a tunnel". utun is macOS, nordlynx and
# proton are WireGuard under other names, and the rest are the kernel's own.
# "ts" is not here on purpose. It was, for Tailscale, and it matched tsn0 -
# a Time-Sensitive Networking port, which is a physical NIC on industrial and
# automotive hardware. "tailscale" already covers the real interface name, so
# the short form bought nothing and mislabelled a wire as an encapsulation.
TUNNEL_PREFIXES = ("tun", "tap", "utun", "wg", "ppp", "ipsec", "vti", "gre",
                   "sit", "gif", "nordlynx", "proton", "wireguard", "ovpn",
                   "zt", "tailscale")


def is_tunnel(name):
    """Is this interface an encapsulation rather than a wire?"""
    return bool(name) and name.lower().startswith(TUNNEL_PREFIXES)
# IPv4 header (20) + ICMP header (8): the payload that exactly fills an MTU.
MTU_OVERHEAD = 28


def _link_modes_linux(base="/sys/class/net"):
    """Speed, duplex, MTU and carrier per interface, from sysfs.

    `base` is a parameter for the same reason its counter-reading twin takes
    one: so the file handling can be tested against a fixture tree. Without it
    every test had to stub the layer above, and the parsing here - a speed of
    -1 on a virtual NIC, a driver that exports nothing, carrier as a string -
    was never exercised at all.
    """
    modes = {}
    drivers = _link_drivers_linux(base)
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return {}
    for name in names:
        idir = os.path.join(base, name)
        if not os.path.isdir(idir):
            continue

        def read(field):
            # speed/duplex raise EINVAL on interfaces with no carrier, which is
            # normal rather than an error worth reporting.
            return _read_text(os.path.join(idir, field))

        speed = read("speed")
        try:
            speed = int(speed) if speed is not None else None
            speed = plausible_mbps(speed)
        except ValueError:
            speed = None
        mtu = read("mtu")
        modes[name] = {
            "speed_mbps": speed,
            "duplex": read("duplex"),
            "mtu": int(mtu) if mtu and mtu.isdigit() else None,
            "carrier": read("carrier") == "1",
            "operstate": read("operstate") or "unknown",
            "driver": drivers.get(name),
        }
    return modes


MEDIA_SPEED_RE = re.compile(r"(\d+)base", re.I)


def _link_modes_bsd():
    """macOS/BSD: pull mtu and the negotiated media line out of `ifconfig -a`."""
    res = run(["ifconfig", "-a"])
    if not res.get("ok"):
        return {}
    modes, current = {}, None
    for line in res.get("stdout", "").splitlines():
        head = re.match(r"^([A-Za-z0-9_.\-]+):\s", line)
        if head:
            current = head.group(1)
            mtu = re.search(r"\bmtu (\d+)", line)
            modes[current] = {
                "speed_mbps": None, "duplex": None,
                "mtu": int(mtu.group(1)) if mtu else None,
                "carrier": None, "operstate": "unknown",
            }
            continue
        if not current:
            continue
        stripped = line.strip()
        if stripped.startswith("media:"):
            sm = MEDIA_SPEED_RE.search(stripped)
            if sm:
                modes[current]["speed_mbps"] = int(sm.group(1))
            if "full-duplex" in stripped:
                modes[current]["duplex"] = "full"
            elif "half-duplex" in stripped:
                modes[current]["duplex"] = "half"
        elif stripped.startswith("status:"):
            active = "active" in stripped
            modes[current]["carrier"] = active
            modes[current]["operstate"] = "up" if active else "down"
    return modes


def cmd_link_modes():
    """Per-interface negotiated speed, duplex, and configured MTU.

    Prefers ethtool where it exists: sysfs reports what the driver believes,
    ethtool reports what the two ends negotiated and whether auto-negotiation
    was even on - the difference between "half duplex" and "half duplex because
    someone hard-coded one end".
    """
    if OS_NAME == "Linux":
        modes, source = _link_modes_linux(), "/sys/class/net/*/{speed,duplex,mtu}"
        enriched = False
        for name, vals in modes.items():
            et = cmd_ethtool(name)
            if not et:
                continue
            enriched = True
            vals.update(et["parsed"])
            vals["source"] = "ethtool"
        if enriched:
            source += " + ethtool"
    elif OS_NAME != "Windows":
        modes, source = _link_modes_bsd(), "ifconfig -a"
    else:
        modes, source = {}, "wmic nic"
    if not modes:
        return {"ok": False, "cmd": source,
                "error": "link speed/duplex/MTU are not available on this system",
                "applicable": False,
                "interfaces": []}

    interfaces = [dict(name=n, **v) for n, v in sorted(modes.items())]
    head = f"{'iface':<12}{'speed':>10}{'duplex':>9}{'mtu':>7}   link"
    rows = [head, "-" * len(head)]
    for i in interfaces:
        speed = f"{i['speed_mbps']}M" if i["speed_mbps"] else "-"
        link = "up" if i["carrier"] else ("down" if i["carrier"] is False else "?")
        rows.append(f"{i['name']:<12}{speed:>10}{(i['duplex'] or '-'):>9}"
                    f"{(i['mtu'] if i['mtu'] else '-'):>7}   {link}")
    return {"ok": True, "cmd": source, "stdout": "\n".join(rows), "stderr": "",
            "code": 0, "interfaces": interfaces}


def cmd_path_mtu(target, iface_mtu=STANDARD_MTU):
    """Find the largest packet that actually reaches the target unfragmented.

    Sends do-not-fragment pings at descending sizes. If the interface says 1500
    but only 1400 gets through, everything small works and large transfers hang
    - the failure mode that looks like "the network is fine but the app is
    broken".
    """
    if not valid_target(target):
        return bad_target()
    ceiling = iface_mtu or STANDARD_MTU
    # Probe the configured MTU first, then common tunnel sizes (PPPoE, IPsec,
    # GRE/VXLAN), then a floor that almost anything passes.
    candidates = [c for c in (ceiling, 1492, 1400, 1280, 1000) if c <= ceiling]
    attempts = []
    for mtu in candidates:
        payload = mtu - MTU_OVERHEAD
        if OS_NAME == "Windows":
            cmd = ["ping", "-f", "-l", str(payload), "-n", "1", "-w", "2000", target]
        elif OS_NAME == "Darwin":
            cmd = ["ping", "-D", "-s", str(payload), "-c", "1", "-t", "3", target]
        else:
            cmd = ["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", "2", target]
        res = run(cmd, timeout=6)
        got = bool(res.get("ok")) and res.get("code") == 0
        attempts.append({"mtu": mtu, "payload": payload, "ok": got,
                         "cmd": res.get("cmd", " ".join(cmd))})
        if got:
            break

    working = next((a["mtu"] for a in attempts if a["ok"]), None)
    lines = [f"probing path MTU to {target} (interface MTU {ceiling})", ""]
    for a in attempts:
        lines.append(f"  {a['mtu']:>5} bytes  {'passes' if a['ok'] else 'blocked'}")
    if working is None:
        lines.append("\n  no size got through - the target may not answer pings at all")
    return {"ok": True, "cmd": f"ping -c1 (do-not-fragment) x{len(attempts)} -> {target}",
            "stdout": "\n".join(lines), "stderr": "", "code": 0,
            "target": target, "iface_mtu": ceiling, "path_mtu": working,
            "attempts": attempts}


def cmd_check_port(host, port, timeout=5):
    """Check if a port is reachable via TCP connect (doesn't require root or special tools)."""
    if not valid_target(host):
        return bad_target()
    try:
        port_num = int(port)
        if not 1 <= port_num <= 65535:
            return {"ok": False, "error": f"port {port_num} out of range (1-65535)"}
    except ValueError:
        return {"ok": False, "error": f"invalid port: {port}"}

    # Resolve first, and take the family from the answer. This used to open an
    # AF_INET socket unconditionally, so an IPv6 target - which valid_target
    # accepts, and which the TLS check handles fine - came back as "hostname
    # resolution failed" for an address that was neither a hostname nor
    # unresolvable. getaddrinfo also picks the family the way an application
    # would for a dual-stack name, which is the behaviour worth reproducing.
    try:
        infos = socket.getaddrinfo(host, port_num, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return {"ok": False, "cmd": f"tcp connect {host}:{port_num}",
                "error": f"hostname resolution failed: {e}", "reason": "dns"}
    if not infos:
        return {"ok": False, "cmd": f"tcp connect {host}:{port_num}",
                "error": "no address to connect to", "reason": "dns"}
    # One candidate per family, in the order the resolver offered them. Taking
    # only the first would have made this worse than the bug it fixes: a
    # dual-stack name on a network with broken IPv6 would newly time out, where
    # the old AF_INET-only code happened to work. Trying both also turns "it
    # works from my laptop" into an answer - one family up, the other not.
    candidates, seen = [], set()
    for family, socktype, proto, _canon, sockaddr in infos:
        if family not in seen:
            seen.add(family)
            candidates.append((family, socktype, proto, sockaddr))

    attempts = []
    for family, socktype, proto, sockaddr in candidates:
        ip_version = 6 if family == socket.AF_INET6 else 4
        result = _connect_once(host, port_num, family, socktype, proto, sockaddr,
                               ip_version, timeout)
        attempts.append(result)
        if result.get("ok"):
            break
    best = next((a for a in attempts if a.get("ok")), attempts[0])
    # When the families disagree, say so: that is the whole answer to a service
    # that works for one person and not another on the same network.
    if len(attempts) > 1:
        best["families_tried"] = [a.get("ip_version") for a in attempts]
        failed = [a.get("ip_version") for a in attempts if not a.get("ok")]
        if best.get("ok") and failed:
            best["family_mismatch"] = failed
    return best


def _connect_once(host, port_num, family, socktype, proto, sockaddr, ip_version, timeout):
    """One TCP connect over one address family."""
    def fail(reason, error):
        return {"ok": False, "cmd": f"tcp connect {host}:{port_num}",
                "ip_version": ip_version, "error": error, "reason": reason}

    try:
        # closed via context manager so a raise mid-connect can't leak the fd
        banner = ""
        with socket.socket(family, socktype, proto) as s:
            s.settimeout(timeout)
            # A completed TCP connect is one round trip, so this figure is the
            # path's own latency to that service - not a guess derived from ping.
            started = time.monotonic()
            result = s.connect_ex(sockaddr)
            connect_ms = round((time.monotonic() - started) * 1000, 1)
            # Read the greeting on the connection that is already open, while
            # it is still open - one connection per port rather than two, which
            # halves both the time and how much this resembles probing. Plenty
            # of services announce themselves (SSH, SMTP); the quiet ones cost
            # the short timeout and nothing else. TLS ports are skipped, since
            # the handshake tells us far more than a byte string would.
            if result == 0 and port_num not in TLS_PORTS:
                try:
                    s.settimeout(BANNER_TIMEOUT)
                    raw = s.recv(256)
                    banner = "".join(ch for ch in raw.decode("utf-8", "replace")
                                     if ch.isprintable())[:120].strip()
                except (OSError, socket.timeout):
                    banner = ""
        if result == 0:
            return {
                "ok": True,
                "cmd": f"tcp connect {host}:{port_num}",
                "ip_version": ip_version,
                "stdout": f"Port {port_num} is open (TCP connection successful)"
                          + f" in {connect_ms}ms"
                          + (f"\n{banner}" if banner else ""),
                "banner": banner or None,
                "connect_ms": connect_ms,
                "stderr": "",
                "code": 0,
            }
        else:
            # Why it failed, and who that makes it. The Linux numbers sit
            # beside the constants because errno values differ by platform -
            # ENETUNREACH is 101 on Linux and 51 on BSD, and this has to give
            # the same answer whichever it is asked on.
            #
            # The route cases are the point of the split. A connect that never
            # left the box and one that left and got nothing back are opposite
            # situations, and both used to land in the timeout bucket - which
            # describes only the second, and sends the reader to the network
            # for a routing table on this box.
            if result == errno.ECONNREFUSED or result == 111:
                return fail("refused",
                            f"Connection refused (port {port_num} closed or "
                            f"filtered by firewall)")
            if result in (errno.ENETUNREACH, 101):
                return fail("no_route",
                            f"Network unreachable - this device has no route to "
                            f"{host}. The kernel refused before sending anything.")
            if result in (errno.EHOSTUNREACH, 113):
                return fail("host_unreachable",
                            f"Host unreachable - a router on the path reported it "
                            f"cannot reach {host}.")
            return fail("timeout",
                        f"Connection timeout (port {port_num} unreachable - "
                        f"packet loss or routing issue)")
    except socket.gaierror as e:
        return {"ok": False, "cmd": f"tcp connect {host}:{port_num}", "error": f"hostname resolution failed: {e}"}
    except socket.timeout:
        return fail("timeout", f"Connection timeout (port {port_num} unreachable - "
                               f"packet loss or routing issue)")
    except Exception as e:
        # Broad for the same reason as run(): one odd socket error shouldn't
        # cost the other checks. The port reads as unknown, not as closed.
        return {"ok": False, "cmd": f"tcp connect {host}:{port_num}", "error": str(e)}


# OSI layers this tool can actually say something about. A check is tagged with
# the LOWEST layer it can implicate, not the layer of the protocol it speaks:
# pinging the gateway is an L3 (ICMP) operation, but 100% loss to your own
# gateway is evidence about the local link, so that finding is tagged L2. This
# keeps the findings list readable bottom-up, which is the order you'd fix
# things in - a broken layer makes every layer above it look broken too.
LAYERS = {
    1: {"name": "Physical", "hint": "cabling, radio, link light, port up/down"},
    2: {"name": "Data link", "hint": "switch/AP, ARP, MAC, local segment"},
    3: {"name": "Network", "hint": "IP addressing, routing, gateway, ICMP reachability"},
    4: {"name": "Transport", "hint": "TCP/UDP ports, firewall rules, listening services"},
    7: {"name": "Application", "hint": "DNS and other name/service resolution"},
}


def layer_label(n):
    """'L3 - Network' for display; falls back gracefully on an unknown layer."""
    meta = LAYERS.get(n)
    return f"L{n} - {meta['name']}" if meta else f"L{n}"


# "desc" is what the UI shows on hover: what the check inspects, and what a
# failure of it actually tells you. Keep these to a sentence or two - they are
# a tooltip, not documentation.
# What each result panel is, keyed by its raw-report key. The sidebar buttons
# carry their own "desc" (shown on hover); these cover the panels the full
# diagnosis produces, which have no button behind them. Shipped inside every
# report so an exported JSON explains itself on a machine that has never run
# the server.
PANEL_HELP = {
    "link_stats": {
        "label": "interface error counters", "layer": 1,
        "desc": "Error, drop, CRC and collision counters per interface. Errors climbing here "
                "mean the fault is this device or its cable, not the network beyond it.",
    },
    "link_modes": {
        "label": "link speed / duplex / MTU", "layer": 1,
        "desc": "What each interface negotiated with the switch port. Half duplex or an "
                "unexpectedly slow link points at that cable or a mismatched port.",
    },
    "path_mtu": {
        "label": "path MTU probe", "layer": 3,
        "desc": "Largest packet that reaches the target unfragmented. A result below the "
                "interface MTU means big transfers stall while pings look perfect.",
    },
    "ping_gateway": {
        "label": "ping the default gateway", "layer": 2,
        "desc": "Reachability of the first hop off this device. Total loss points at the "
                "local link - cable, switch port, or AP; partial loss at an unstable one.",
    },
    "ping_internet": {
        "label": "ping the target", "layer": 3,
        "desc": "Reachability past the gateway. Failing here while the gateway answers "
                "means the router's uplink or something upstream, not this device.",
    },
    "path_trace": {
        "label": "traceroute to the target", "layer": 3,
        "desc": "Hop-by-hop path to the target. Where replies stop is roughly where the "
                "path breaks - though some routers forward traffic fine while ignoring probes.",
    },
    "dns_lookup": {
        "label": "DNS lookup", "layer": 7,
        "desc": "Resolves a name to an IP. Failing here while ping by IP works means the "
                "DNS server is wrong or unreachable - not a connectivity fault.",
    },
    "routes": {
        "label": "routing table", "layer": 3,
        "desc": "Where this device sends traffic, and which gateway is the default route. "
                "No default route means traffic can never leave the local subnet.",
    },
    "interfaces": {
        "label": "interfaces", "layer": 1,
        "desc": "Every interface with its addresses, MAC, and link state. No IPv4 address "
                "anywhere means the link is down or DHCP never completed.",
    },
    "arp": {
        "label": "ARP / neighbor table", "layer": 2,
        "desc": "Neighbor IP-to-MAC mappings on the local segment. An incomplete entry for "
                "the gateway points at cabling, a switch port, or Wi-Fi.",
    },
    "ports": {
        "label": "listening ports", "layer": 4,
        "desc": "Sockets this machine is listening on, and on which interface rather than "
                "just localhost.",
    },
    "dns_health": {
        "label": "DNS resolvers", "layer": 7,
        "desc": "Each configured resolver queried individually: does it answer, how fast, do "
                "they agree, and does it invent answers for names that cannot exist.",
    },
    "optics": {
        "label": "optical module (SFP)", "layer": 1,
        "desc": "Receive and transmit power on a fibre link, plus the module's own alarm "
                "thresholds. A dirty connector or dying laser stays \"up\" while corrupting "
                "frames, and nothing else here can see it.",
    },
    "lldp": {
        "label": "switch port (LLDP/CDP)", "layer": 2,
        "desc": "Which switch and port this device is plugged into, learned passively from "
                "the switch's own LLDP or CDP advertisements. Turns \"check the switch port\" "
                "into a specific port.",
    },
    "tcp_health": {
        "label": "TCP retransmissions", "layer": 3,
        "desc": "Retransmit rate for this device's real traffic, from the kernel's counters. "
                "Catches loss that ICMP probes miss, with nothing captured.",
    },
    "inventory": {
        "label": "neighbours", "layer": 2,
        "desc": "Devices this box has already exchanged traffic with, from its own neighbour "
                "table. Passive: nothing was probed or scanned, so it says what this device "
                "has talked to rather than what exists on the segment.",
    },
    "sockets": {
        "label": "socket states", "layer": 4,
        "desc": "This device's own TCP sockets by state. Connections stuck in SYN_SENT mean "
                "nothing is answering; a pile of CLOSE_WAIT means an application isn't closing "
                "its sockets, which is not a network fault.",
    },
    "port_check": {
        "label": "TCP port check", "layer": 4,
        "desc": "Plain TCP connect to a port on the target. Refused means something answered "
                "and said no; a timeout means nothing answered at all.",
    },
}


# ---------------------------------------------------------------------------
# Diagnosis heuristics
# ---------------------------------------------------------------------------

def parse_ping_loss(ping_result):
    """Return packet loss percent (float) or None if it can't be determined."""
    if not ping_result.get("ok"):
        return None
    out = ping_result.get("stdout") or ""
    m = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet )?loss", out)
    if m:
        return float(m.group(1))
    return None


def parse_ping_counts(ping_result):
    """(sent, lost) from a ping summary, or (None, None).

    The percentage on its own hides the sample it came from. Four probes can
    only express loss in steps of 25%, and two - which is what --quick sends -
    in steps of 50%, so a single unanswered probe arrives looking like a
    quarter or half of the traffic. Any judgement about loss needs to know how
    many probes are behind it.
    """
    if not ping_result.get("ok"):
        return None, None
    out = ping_result.get("stdout") or ""
    m = re.search(r"(\d+)\s+packets? transmitted,\s*(\d+)\s+(?:packets? )?received", out)
    if not m:
        return None, None
    sent, received = int(m.group(1)), int(m.group(2))
    return sent, max(0, sent - received)


# Below this many packets, an error count is not an error rate. One error on a
# nearly idle interface - a management NIC, a bond member carrying nothing, an
# interface that just came up - divides out to twenty times the threshold and
# says the link has a problem. The same reasoning MIN_PROBES_FOR_LOSS applies
# to ping was never applied here: a rate needs a denominator big enough that a
# single event cannot be one. Set so one error stays under ERR_PPM_WARN.
MIN_PACKETS_FOR_RATE = 20_000

# The same idea for a counter window rather than a lifetime. A percentage of
# fifty packets is not a percentage of anything, and the window is seconds long
# on a box that may be nearly idle.
MIN_WINDOW_PACKETS_FOR_RATE = 1_000

# Share of a window's packets that has to be discarded before it is worth
# saying so. Deliberately two orders of magnitude looser than the error
# threshold above, because the two counters mean opposite things: an error is a
# frame that arrived damaged and should never happen, while a discard is a
# frame this box chose not to deliver upwards and happens on every busy
# interface there is. Treating them alike made discards fire on a single
# packet.
DROP_PCT_WARN = 2.0

# Below this many probes, one unanswered packet is not a loss rate. Hosts and
# routers rate-limit ICMP replies as a matter of course - 8.8.8.8 among them -
# so a single missing reply in a short run is the expected cost of asking,
# not evidence of a damaged path.
MIN_PROBES_FOR_LOSS = 10

# Where a run aims when nobody says otherwise and the box has no dependencies
# of its own to aim at.
DEFAULT_TARGET = "8.8.8.8"


def _default_route_iface(raw):
    """Which interface the default route leaves by, or None if it can't be read.

    Only used to decide which NIC to hold against the site's uplink figure. On
    the single-homed appliances this runs on there is usually one candidate
    anyway, so None means "don't rule any interface out" rather than "give up".
    """
    out = (raw.get("routes") or {}).get("stdout") or ""
    known = {i["name"] for i in (raw.get("link_stats") or {}).get("interfaces", [])}
    for line in out.splitlines():
        line = line.strip()
        if not re.match(r"(?:default|0\.0\.0\.0)\b", line):
            continue
        m = re.search(r"\bdev\s+(\S+)", line)           # ip route
        if m:
            return m.group(1)
        # netstat -rn puts the interface last on Linux and macOS, but Windows
        # `route print` ends the line with a metric. Only accept a token that
        # names an interface this run actually saw, so a number is not mistaken
        # for one - a wrong name here silently disables the uplink check.
        for tok in reversed(line.split()):
            if tok in known:
                return tok
    return None


def guess_default_gateway(route_result):
    if not route_result.get("ok"):
        return None
    out = route_result.get("stdout") or ""
    m = re.search(r"default via (\S+)", out)  # `ip route`
    if m:
        return m.group(1)
    # Linux `netstat -rn` ("0.0.0.0  192.168.1.1  0.0.0.0  UG ...") and Windows
    # `route print` ("0.0.0.0  0.0.0.0  192.168.0.1  ..."), where the gateway
    # sits past a netmask column - so take the first non-zero IPv4 on the line.
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] != "0.0.0.0":
            continue
        for hop in parts[1:]:
            if hop != "0.0.0.0" and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hop):
                return hop
    # BSD/macOS `netstat -rn` names the destination "default" instead of
    # 0.0.0.0: "default   192.168.1.1   UGScg   en0". Prefer an IPv4 next
    # hop; fall back to IPv6 (the Internet6 table) and ignore "link#N".
    v6 = None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "default":
            continue
        hop = parts[1]
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hop):
            return hop
        if ":" in hop and v6 is None:
            v6 = hop
    return v6


IP_ANY_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


# What a router says when it refuses rather than forwards. traceroute prints
# these next to the time, and they were being dropped along with everything
# else that was not a number - which is how a hop that told us exactly why it
# would not forward was reported as an unexplained silent path.
TRACE_ANNOTATIONS = {
    "!X": "administratively prohibited",
    "!A": "administratively prohibited",
    "!H": "host unreachable",
    "!N": "network unreachable",
    "!P": "protocol unreachable",
    "!F": "fragmentation needed",
    "!S": "source route failed",
    "!C": "precedence cutoff",
    "!T": "communication with destination network administratively prohibited",
}
TRACE_ANNOTATION_RE = re.compile(r"(![A-Z]|!\d{1,3})(?=\s|$)")
# A deliberate refusal by a policy device, as opposed to a path that is broken
# or silent. Different owner entirely: somebody configured this.
TRACE_PROHIBITED = ("!X", "!A", "!T")


def parse_traceroute_hops(output):
    """Turn traceroute/tracert text into a list of hop dicts, best-effort.

    Handles the common Linux `traceroute` and Windows `tracert` layouts.
    Unrecognized lines are skipped rather than raising - this is for the
    visual path diagram, the raw text is always shown too.
    """
    hops = []
    for raw_line in (output or "").splitlines():
        if not raw_line.strip():
            continue
        # A hop header is a number followed by whitespace. A continuation line -
        # emitted when several routers answer probes for the same hop, which is
        # normal with ECMP - starts with an address instead. Matching on the
        # unstripped line matters: "    203.0.113.67 (...)" would otherwise
        # parse as hop 108, inventing hops and splitting one hop's timings
        # across several fake ones (which then look like partial reply loss).
        m = re.match(r"^\s*(\d{1,3})\s+", raw_line)
        line = raw_line.strip()
        times = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)]
        ip_match = IP_ANY_RE.search(line)
        host = ip_match.group(0) if ip_match else None
        display = host or "*"
        if ip_match:
            name_match = re.search(
                r"([A-Za-z0-9_.\-]+)\s*\(" + re.escape(ip_match.group(0)) + r"\)", line
            )
            if name_match:
                display = name_match.group(1)

        if not m:
            if hops:
                hops[-1]["times_ms"].extend(times)
                if times:
                    hops[-1]["timed_out"] = False
                if host and not hops[-1]["host"]:
                    hops[-1]["host"], hops[-1]["display"] = host, display
                elif host and host != hops[-1]["host"]:
                    # Same hop, different router answered - worth keeping, since
                    # an unstable set of responders is itself a useful signal.
                    hops[-1].setdefault("also", [])
                    if display not in hops[-1]["also"]:
                        hops[-1]["also"].append(display)
            continue

        hop_num = int(m.group(1))
        timed_out = not times and "*" in line
        flags = TRACE_ANNOTATION_RE.findall(line)
        hops.append({
            "hop": hop_num,
            "host": host,
            "display": display,
            "times_ms": times,
            "timed_out": timed_out,
            # Kept in the order the router gave them, deduplicated: three
            # probes to one refusing hop print the same flag three times.
            "flags": list(dict.fromkeys(flags)) or None,
        })
    return hops


def is_private_ip(ip):
    """RFC1918 / link-local / loopback / CGNAT. Used to work out where traffic
    stops being the site's network and starts being their ISP's."""
    if not ip:
        return None
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 100 and 64 <= b <= 127:  # CGNAT - still the provider's side
        return True
    return False


# Second-level suffixes where the registrable name needs three labels, so
# "bt.co.uk" doesn't collapse to "co.uk".
MULTI_LABEL_TLDS = {"co", "com", "net", "org", "ac", "gov", "edu"}


def ptr_network(display, host):
    """Registrable domain of a hop's PTR name - 'example-isp.net' from
    'be-300-arsc1.example-isp.net'. Returns None for bare IPs, which is most of
    the internet's core, so this is a best-effort label only."""
    if not display or display == "*" or display == host:
        return None
    labels = [l for l in display.split(".") if l]
    if len(labels) < 2:
        return None
    tail = labels[-2:]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in MULTI_LABEL_TLDS:
        tail = labels[-3:]
    return ".".join(tail).lower()


def subnet24(ip):
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else None


def annotate_hops(hops, gateway=None, target=None):
    """Add per-hop insight derived from what we already measured: average and
    spread of the probe times, how much latency this hop added over the last
    one, whether it's inside the site, and its role in the path.

    No extra packets are sent - this is arithmetic on the trace we already have.
    """
    prev_avg = None
    for h in hops:
        times = [t for t in (h.get("times_ms") or []) if t is not None]
        avg = sum(times) / len(times) if times else None
        h["avg_ms"] = round(avg, 1) if avg is not None else None
        # Spread across probes to the same hop: a wide spread means the hop is
        # congested or flapping even when the average looks healthy.
        h["jitter_ms"] = round(max(times) - min(times), 1) if len(times) > 1 else None
        # Latency this hop added. Negative deltas are normal noise (a later hop
        # can answer faster than an earlier one), so they're clamped away.
        #
        # The first hop counts its own latency: the path starts there, so
        # everything before it is zero by definition. It was left as None,
        # which meant a first hop carrying the entire delay - a satellite link,
        # a VPN concentrator, a distant CPE - could never be the worst jump and
        # the tool said nothing about the one thing that mattered on that path.
        if avg is not None:
            h["delta_ms"] = round(max(avg - (prev_avg or 0.0), 0), 1)
        else:
            h["delta_ms"] = None
        if avg is not None:
            prev_avg = avg

        # Call quality at this hop, where we know enough to say. mtr supplies
        # loss and spread; a plain traceroute doesn't, so this stays absent
        # rather than being guessed from three samples.
        jitter = h.get("jitter_ms")
        if jitter is None and h.get("stdev_ms") is not None:
            jitter = h["stdev_ms"]
        if h.get("avg_ms") is not None and h.get("loss_pct") is not None:
            h["mos"], h["r_factor"] = mos_score(h["avg_ms"], jitter, h["loss_pct"])
        else:
            h["mos"], h["r_factor"] = None, None

        h["private"] = is_private_ip(h.get("host"))
        h["network"] = ptr_network(h.get("display"), h.get("host"))
        # A timed-out hop has host=None, so don't assume a string here.
        h["cgnat"] = bool((h.get("host") or "").startswith("100.") and h.get("private"))
        roles = []
        if gateway and h.get("host") == gateway:
            roles.append("gateway")
        if target and h.get("host") == target:
            roles.append("target")
        h["roles"] = roles

    # Provider handoffs: where the PTR domain changes, i.e. traffic passing from
    # one operator's network into another's. Same idea as the site edge, one
    # level out - it shows how many networks the path actually crosses.
    last_net = None
    networks = []
    for h in hops:
        net = h.get("network")
        h["handoff_from"] = None
        h["enters_network"] = None
        # A PTR name on a private hop is the site's own naming, not a network
        # boundary; marking it as a handoff buries the one that matters.
        if h.get("private"):
            net = None
            h["network"] = None
        if net and net != last_net:
            # enters_network marks the boundary itself; handoff_from is set only
            # when we know which network it came from (None at the first named
            # one, since core routers usually have no PTR to identify).
            h["enters_network"] = net
            h["handoff_from"] = last_net
            networks.append({"network": net, "from_hop": h["hop"], "from": last_net})
            last_net = net

    # Two different private /24s before the edge means two routers in series.
    private_subnets = []
    for h in hops:
        if h.get("private") and not h.get("cgnat"):
            sn = subnet24(h.get("host"))
            if sn and sn not in private_subnets:
                private_subnets.append(sn)
    double_nat = private_subnets if len(private_subnets) > 1 else []

    # The same router answering at two hop numbers is a loop (or a path that
    # doubles back), which stalls traffic well before it reaches the target.
    seen, loop_at = {}, None
    for h in hops:
        host = h.get("host")
        if not host:
            continue
        if host in seen and loop_at is None:
            loop_at = {"host": host, "hops": [seen[host], h["hop"]]}
        seen.setdefault(host, h["hop"])

    cgnat_hop = next((h["hop"] for h in hops if h.get("cgnat")), None)

    # First public hop: the point where traffic leaves the site's network.
    demarc = next((h["hop"] for h in hops if h.get("private") is False), None)
    # Biggest single latency jump, which is where the delay is introduced.
    jumps = [h for h in hops if h.get("delta_ms")]
    worst = max(jumps, key=lambda h: h["delta_ms"]) if jumps else None
    # And what share of the end-to-end latency that jump accounts for. "+65ms"
    # doesn't say whether fixing that hop would matter; "+65ms, 71% of the
    # total" does. The denominator is the last hop that answered, so a path
    # ending in silence has no total to take a share of and reports none.
    answered = [h["avg_ms"] for h in hops if h.get("avg_ms") is not None]
    total_ms = answered[-1] if answered else None
    worst_share = None
    if worst and total_ms:
        # Deltas are clamped at zero, so they can't quite sum to the total;
        # capping keeps a rounding artefact from reading as "more than all".
        worst_share = min(round(100.0 * worst["delta_ms"] / total_ms), 100)
    return {
        "networks_crossed": networks,
        "double_nat": double_nat,
        "loop_at": loop_at,
        "cgnat_hop": cgnat_hop,
        "demarc_hop": demarc,
        "worst_jump": {"hop": worst["hop"], "delta_ms": worst["delta_ms"],
                       "host": worst.get("display") or worst.get("host"),
                       "private": worst.get("private"),
                       "share_pct": worst_share,
                       "total_ms": total_ms,
                       "cgnat": worst.get("cgnat")} if worst else None,
    }


def has_ip_address(iface_result):
    """Is this box on the network at all - by either protocol?

    IPv4 only, until 2026-08-08. An IPv6-only box - ordinary on mobile
    networks and in plenty of datacentres outside the US - was reported as
    critical, "this device never got onto the network", exit 2, while holding a
    global IPv6 address and working perfectly.

    Link-local (fe80::) does not count: every interface has one whether or not
    anything configured it, so accepting it would mean this check could never
    fail.
    """
    if not iface_result.get("ok"):
        return False
    out = iface_result.get("stdout") or ""
    return bool(has_ipv4(iface_result) or _global_ipv6(out))


def has_ipv4(iface_result):
    if not iface_result.get("ok"):
        return False
    out = iface_result.get("stdout") or ""
    return bool(re.search(r"\binet \d{1,3}(\.\d{1,3}){3}", out) or "IPv4 Address" in out)


def _global_ipv6(out):
    """A routable IPv6 address, ignoring link-local and loopback."""
    for m in re.finditer(r"\binet6\s+([0-9a-f:]+)", out or "", re.I):
        addr = m.group(1).lower()
        if addr.startswith("fe80") or addr in ("::1", "::"):
            continue
        return True
    # Windows spells it differently and does not prefix the family.
    return bool(re.search(r"IPv6 Address[^\n]*:\s*(?!fe80)[0-9a-f]+:", out or "", re.I))


# ---------------------------------------------------------------------------
# Verdict: one line naming the most likely root cause and who owns it.
#
# This is ordering, not intelligence. A broken layer makes every layer above it
# look broken, so the lowest layer with a LIVE fault is the root cause and
# everything above it is a symptom. Each rule also names the owner - this
# device, the site's network, the provider, or the destination - because
# "where is the fault" is really "whose is it".
#
# Deliberately rule-based: on a call you have to be able to say why
# the tool concluded what it concluded, and each verdict cites the findings it
# was built from. Ordered most-fundamental first; the first match wins.
# ---------------------------------------------------------------------------

# code -> (owner, headline, what to do next)
VERDICT_RULES = [
    ("no_ipv4", "this device",
     "No IP address on any interface - this device never got onto the network",
     "Check the cable is seated and the link light is on, then whether DHCP is "
     "reaching this device (or set a static address to test)."),
    ("optics_alarm", "the fibre link into this device",
     "The optical module is outside its rated operating range",
     "The module's own alarm thresholds are firing. Clean the connectors, check "
     "for bends, and compare with the optic at the far end."),
    ("optics_rx_low", "the fibre link into this device",
     "Optical receive power is below what the receiver can work with",
     "The link can stay up while corrupting frames. Dirty or loose connector, a "
     "tight bend, or a dying laser at the far end - in that order of likelihood."),
    ("nic_ring_overruns", "this device, not the link into it",
     "Frames are arriving intact and this device is failing to take delivery",
     "The link delivered the frames, so this is not something to take to "
     "whoever owns the cable. Look at the ring buffer size, the driver, and "
     "whether the CPU that services this queue is keeping up."),
    ("frame_length_errors", "the segment, over how big a frame may be",
     "Frames are arriving on this segment at an invalid length",
     "Runts and giants mean something here disagrees about frame size. Compare "
     "the MTU at both ends of this link, and check for a VLAN tag being added "
     "or stripped where it is not expected."),
    ("cpu_throttled_live", "this device's cooling, not the network",
     "This device is too hot to run at full speed and is clocking itself down",
     "Nothing on the wire is at fault. The lost cycles are the ones that move "
     "packets, so read every other finding here as a consequence until the "
     "airflow, dust and fans have been checked."),
    ("cpu_throttled_historical", "this device's cooling",
     "This device has been throttling itself, though not while we watched",
     "Cooling that is marginal rather than failed - it bites under load and "
     "clears when the load does. That is the shape of a fault that only shows "
     "at the busiest hour and never reproduces afterwards."),
    ("fault_on_every_interface", "whatever the interfaces share - not any one cable",
     "Every interface on this device has the same problem",
     "They do not share a cable, so the cable is not it. Check what they do "
     "share: the driver, the adapter or its firmware, the heat and power "
     "around it, or the single switch they all land in."),
    ("nic_reset_logged", "this device's NIC or its driver",
     "The kernel has been resetting this device's network hardware",
     "The adapter or its driver is failing, not the network. Every connection "
     "drops each time it resets, and no interface counter records it - the log "
     "is the only place this shows up. Update or reload the driver, and treat "
     "the hardware as suspect if it continues."),
    ("link_flapping_logged", "this device or its cable",
     "The link has been dropping and coming back - the kernel logged each time",
     "The port is up now, which is why everything else here reads clean. This "
     "is physical: reseat the cable, try a different switch port, and compare "
     "the times below against the port's own log at the other end."),
    ("link_flapping_live", "this device or its cable",
     "The link dropped and came back while this was running",
     "A port that goes away while you are watching it is physical: reseat the cable, "
     "try a different switch port, and check the port's own log for the other side of "
     "these transitions."),
    ("collisions", "this device's link to the switch",
     "Collisions on a full-duplex link - the switch port likely disagrees about duplex",
     "Check the duplex setting on the switch port. One end auto-negotiating "
     "while the other is hard-coded produces exactly this."),
    ("pmtu_blackhole", "the path between here and the target",
     "Full-size packets are being dropped while small ones pass",
     "Ping works and large transfers hang. Look for a tunnel or firewall in the "
     "path with a lower MTU that isn't sending the ICMP needed to adapt."),
    ("link_errors_live", "this device or its cable",
     "The physical link into this device is corrupting frames right now",
     "Reseat or replace the cable and try a different switch port; if the errors "
     "follow the device, it's the NIC or its transceiver."),
    ("rcv_buffer_pruned", "this device - it is out of socket memory",
     "This device is discarding received data for lack of buffer memory",
     "The kernel could not find memory for packets it had already accepted. It produces "
     "retransmits that look exactly like a lossy path. Check memory pressure and "
     "net.ipv4.tcp_rmem before looking at the network."),
    ("nic_drops_live", "this device - its load, not its cable",
     "This device is discarding incoming packets before they reach the stack",
     "The receive backlog is overflowing, which looks exactly like link loss but is the "
     "box failing to keep up. Check CPU and net.core.netdev_max_backlog before replacing "
     "any hardware."),
    ("conntrack_drops_live", "this device - its connection tracking table",
     "This device's connection tracking table is refusing new connections",
     "Nothing gets out once the table is full, so it reads as the network dropping "
     "connections at random. Raise net.netfilter.nf_conntrack_max, or exempt traffic that "
     "doesn't need tracking."),
    ("optics_rx_marginal", "the fibre link into this device",
     "Optical receive power is working but has little margin",
     "Clean the connectors and check the patching now; this is what degrades into "
     "intermittent errors later."),
    ("optics_warning", "the fibre link into this device",
     "The optical module is reporting one of its own warning thresholds",
     "Not failing yet. Note it, and check it again on the next visit - with "
     "--baseline the drift will be visible."),
    ("duplex_mismatch", "this device's link to the switch",
     "Duplex mismatch between this interface and the switch port",
     "Set both ends to auto-negotiate (or both hard-coded to the same values). "
     "Throughput will stay terrible under load until they agree."),
    ("loop", "the provider or upstream routing",
     "Routing loop upstream - traffic is circling instead of advancing",
     "Nothing to fix on this device. Give the provider the two hop numbers and "
     "the address that answers at both."),
    ("gw_unreachable", "the site network",
     "The gateway does not answer at all - the local link is down",
     "Check the switch port, cabling, and whether the gateway itself is up. "
     "This device is configured but has nothing to talk to."),
    ("interfaces_unreadable", "unclear - the check couldn't run",
     "The interface list couldn't be read, so nothing here is established",
     "Whatever lists interfaces on this box (ip/ifconfig/ipconfig) isn't "
     "available. Read it by hand before trusting anything below."),
    ("routes_unreadable", "unclear - the check couldn't run",
     "The routing table couldn't be read",
     "Check the routing table by hand; this run can't say whether a default "
     "route exists."),
    ("no_gateway", "this device",
     "No default gateway configured - this device can only reach its own subnet",
     "Check DHCP or the static route configuration on this device."),
    ("gw_partial_loss", "the site network",
     "Packet loss to the gateway - the local link is unstable, not down",
     "Look for a marginal cable, a failing switch port, or Wi-Fi interference "
     "between this device and the gateway."),
    ("slow_link", "this device's cable or switch port",
     "Link negotiated below its capable speed",
     "Usually a damaged pair in the cable. Replace it, or check for a speed "
     "forced on one end."),
    ("destination_unresponsive", "the destination, not the path to it",
     "The path reaches the target and the target answers nothing",
     "The trace got all the way there, so the network between here and it is "
     "carrying traffic. What is not answering is the host itself, or something "
     "filtering directly in front of it. Do not escalate this to whoever owns "
     "the path - it is not theirs."),
    ("inet_unreachable", "the provider",
     "The gateway answers but nothing beyond it does - the site's uplink is down",
     "This device and the local network are fine. Escalate to whoever owns the "
     "circuit, with the gateway ping as evidence."),
    ("regression_since_baseline", "whatever changed - see the comparison",
     "Something changed since the last visit, and not for the better",
     "A dated change beats any absolute reading: start with what moved rather "
     "than with what looks unusual."),
    ("virtual_router_conflict", "the redundancy configuration on this segment",
     "Two virtual routers are configured onto one address",
     "Different groups answering for the same address - commonly a CARP vhid "
     "and a VRRP vrid colliding, since both live in the same MAC range. Traffic "
     "lands on whichever the switch learned last, so symptoms move with no "
     "pattern. Fix the group numbering before chasing anything else here."),
    ("duplicate_ip", "the site network",
     "Two devices are using the same IP address",
     "Find the second device and change one of them. Until then the symptoms "
     "move around with no pattern, which is why this wastes so much time."),
    ("link_saturated", "capacity, not a fault",
     "The link is full - it is being used to capacity, not broken",
     "Nothing here is faulty. Either the link is undersized for the traffic or "
     "something is consuming more than it should; find the traffic before "
     "replacing any hardware."),
    # Ranked above every loss, latency and retransmit verdict that blames the
    # path, because it explains all of them and they do not explain it. Without
    # this the same run reported "packet loss beyond the gateway, owner: the
    # provider" at high confidence while the site was filling its own line.
    ("uplink_saturated", "the site's own capacity, not the carrier",
     "The site's uplink is full - the congestion starts here, not upstream",
     "Do not open a carrier ticket on this. Find what is using the line, or the "
     "line is undersized for what the site now does. The loss and latency "
     "further down this report are what a full uplink looks like from here."),
    # Directly below the sustained case and above every loss verdict it
    # explains. Without a rule here the finding fired and inet_partial_loss
    # still took the headline and blamed the provider at high confidence -
    # the same wrong answer the sustained case used to give.
    ("saturation_bursts", "the site's own capacity, not the carrier",
     "The line is filling in bursts - full a few times a minute, quiet on average",
     "The average across the window is why nothing else here shows this. Traffic "
     "arriving while the line is full is delayed or dropped, which is what breaks "
     "calls and stalls transfers intermittently. Find what is bursting, or the "
     "line is undersized for what the site now does - this is not the carrier."),
    # Local ceilings on a box that serves traffic. Ranked here - above the
    # path and loss verdicts - because each one makes this box refuse or fail
    # to open connections, and from every other check in this tool that is
    # indistinguishable from the network being broken.
    # This box's own certificate. Ranked above everything about the path,
    # because when it is wrong the path is irrelevant - every client is being
    # refused before a single byte of the service is reached.
    # Which side of a proxy the loss is on, ranked above every direction-blind
    # loss verdict below. Without these a lossy database on an internal segment
    # came out as "the provider or upstream".
    ("queuing_delay_backends", "whatever is buffering between here and that backend",
     "The delay to the backend is queue, not distance",
     "The same connections have been far faster, so this is not how far away the "
     "backend is - traffic is waiting somewhere on the internal path. Look for a "
     "full link or an interface queue between here and it, not for a routing "
     "change."),
    ("queuing_delay_clients", "whatever is buffering between here and your users",
     "The delay to clients is queue, not distance",
     "The same connections have been far faster, so this is not the internet "
     "being far away - traffic is waiting somewhere on the way in. A full uplink "
     "and an over-buffered edge device both look like this."),
    ("path_jitter_backends", "the path between this box and what it depends on",
     "The delay to the backends will not sit still",
     "Measured on the real connections rather than probes. Nothing needs to be "
     "lost for this to bite: a retransmit timer sized for the worst case is a "
     "timer that waits, so recovery stalls while the loss figures stay clean."),
    ("path_jitter_clients", "the path between this box and the people using it",
     "The delay to the clients will not sit still",
     "Measured on the connections the users are actually on. This is felt as "
     "inconsistency rather than slowness - most requests fine, some very much "
     "not - which is the complaint that never reproduces on demand."),
    ("queuing_delay", "whatever is buffering on the path out of this box",
     "The delay on this box's connections is queue, not distance",
     "The same connections have been far faster. Something on the path is "
     "holding traffic rather than dropping it - the classic signature of a link "
     "running full with a large buffer in front of it."),
    ("tcp_flow_loss_backends", "the segment between this box and what it depends on",
     "The loss is on what this box talks to, not on what talks to it",
     "Client connections are clean, so the service and the path to your users "
     "are fine. Look at the internal segment between here and the backend named "
     "in the finding - this is inside your own network, not the carrier's."),
    ("tcp_flow_loss_clients", "the path between this box and the people using it",
     "The loss is on what talks to this box, not on what it talks to",
     "Everything this box depends on is clean, so the service itself is healthy. "
     "The loss is between here and your users - the edge, the load balancer in "
     "front, or the internet path to them."),
    # Above the certificate findings: a service that answers nothing is more
    # broken than one whose certificate is wrong, and a client meets it first.
    ("own_service_silent", "the service on this box, not the network",
     "The service accepts connections and answers nothing",
     "The port is open, the handshake completes and no client gets a reply. "
     "Every network check here passes while this is true. Look at the service "
     "and what it is blocked on - this is not the network."),
    ("own_service_upstream_error", "what this box depends on, not this box",
     "The service is up and says what it depends on is not",
     "It answered a gateway error, which is the service reporting that its own "
     "backend failed. This box and the path to it are fine; look at what it "
     "proxies to, and the path from here to that."),
    ("own_service_erroring", "the service on this box, not the network",
     "The service answers its own root path with an error",
     "It is accepting connections and failing to serve them. Nothing on the "
     "network explains this, and no network change will fix it."),
    ("own_service_not_http", "whatever is bound to that port",
     "A port answered, but not with what was expected",
     "Either something other than the intended service is bound here, or it "
     "speaks a protocol this check cannot read. Confirm which before trusting "
     "anything else about that port."),
    ("own_tls_expired", "this box's own certificate",
     "The certificate this box serves has expired - clients are being refused now",
     "Renew it. Nothing about the network is wrong, and no amount of looking at "
     "the network will find this: every check that points outward from here "
     "passes while every client is turned away."),
    ("own_tls_handshake_failed", "this box's TLS listener",
     "This box is listening for TLS and will not complete a handshake",
     "Every client trying to reach the service is getting exactly this. Check "
     "the certificate and key the service loaded, and whether it loaded them at "
     "all after the last reload."),
    ("own_tls_untrusted", "this box's certificate chain",
     "The certificate this box serves does not verify as a client would see it",
     "Usually an incomplete chain: the service works from any machine that "
     "already trusts the issuer, which is why it works for you and not for "
     "customers. Serve the full chain, not just the leaf."),
    ("own_tls_expiring", "this box's own certificate",
     "The certificate this box serves is close to expiry",
     "Renew it before it becomes an outage that looks like a network fault to "
     "everyone who reports it."),
    ("aborts_on_memory", "this box's socket memory, not the network",
     "This box is killing established connections because it has no memory for them",
     "Not the network refusing anything: the box is out of socket memory and "
     "tearing down connections to cope. Check tcp_mem and how much the service "
     "is buffering per connection."),
    ("reqq_full_drops", "this box's SYN queue, not the path",
     "Incoming connections are being dropped before they reach a queue",
     "The client sees a connection that never opens and retries, which is "
     "indistinguishable from packet loss - and there is none. Raise "
     "tcp_max_syn_backlog and the service's own listen backlog."),
    ("syncookies_live", "this box's listen backlog, not the network",
     "The kernel is falling back to SYN cookies - a listen queue is overflowing",
     "Connections are arriving faster than the service accepts them. Raise the "
     "application's listen backlog and somaxconn, find why accept is slow, or "
     "find what is flooding it. Nothing on the wire is wrong."),
    ("ephemeral_ports_low", "this box's local port range, not the network",
     "This box is running out of ports to open connections from",
     "Outbound connections start failing in a way that looks exactly like the "
     "far end refusing them. Widen ip_local_port_range, or find what is holding "
     "the sockets open - TIME_WAIT is usually the answer."),
    ("fd_pressure", "this box's file descriptor limit, not the network",
     "This box is close to its system-wide file descriptor ceiling",
     "At the ceiling the service stops accepting connections, and from a "
     "client's side that is indistinguishable from the network being down. "
     "Raise fs.file-max and the service's own nofile limit."),
    ("aborts_on_timeout", "the path to whoever stopped answering - see the per-destination split",
     "Connections are being torn down because the other end stopped answering",
     "Some of this is ordinary on a public service. At this share it is traffic "
     "being dropped mid-connection rather than users leaving; the client/backend "
     "split above says which side of this box it is on."),
    ("syn_recv_backlog", "this box's accept path, or something opening and abandoning connections",
     "Half-open connections are piling up faster than they are being accepted",
     "Clients started a handshake this box never finished. Check whether the "
     "accept queue is draining and whether the syncookie counter is moving - "
     "that is what separates a backlog too small from a flood."),
    ("no_traffic_at_all", "whatever should be running on this box",
     "This box is neither listening for anything nor talking to anything",
     "A box doing nothing has nothing wrong with its network, which is why every "
     "check here passes. If it should be carrying traffic over links it opens "
     "itself, those links are gone - check the service is running and can reach "
     "what it registers with."),
    ("no_clients_connected", "whatever should be sending traffic here",
     "The service is up and nothing is reaching it",
     "Being taken out of a load balancer's pool looks exactly like this from the "
     "inside: the port is open, the certificate is fine, every check passes and "
     "no traffic arrives. Check the balancer's view of this box before the box "
     "itself - and rule out a firewall in front, or DNS pointing somewhere else."),
    ("syncookies_historical", "this box's listen backlog, not the network",
     "The accept queue has overflowed before, though not during this run",
     "Not happening right now, but the backlog is too small for the peaks this "
     "box actually sees. Worth fixing before the next one."),
    ("egress_blocked", "this box's egress policy, probably by design",
     "No outbound internet from here, while clients are connected inbound",
     "The network works in the direction a service needs: clients are reaching "
     "this box right now. What is missing is outbound internet access, which on "
     "a server is usually deliberate. Check the egress rules and whether this "
     "box is meant to reach the internet at all before escalating anywhere."),
    ("uplink_busy", "capacity, not a fault",
     "The site's uplink was full during the check, with nothing failing",
     "A line being used is not a line that is broken. Worth knowing if the site "
     "has outgrown its circuit; worth ruling out first if trouble gets reported "
     "at this time of day."),
    ("link_busy", "capacity, not a fault",
     "The link ran at capacity during the check, with nothing failing",
     "Nothing here is faulty. If the site's uplink is slower than this NIC, "
     "pass --uplink-mbps - how full the line was is the number that matters, "
     "not how full the port was."),
    ("clock_skewed", "this device's clock",
     "This device's clock has drifted from its time source",
     "Fix the clock before reading anything else here about certificates. Authentication "
     "and log correlation depend on it, and none of that is the network's doing."),
    ("clock_unsynced", "this device's time configuration",
     "This device is not synchronised to any time source",
     "It may be right now and it will drift. Point it at a working time source before the "
     "drift starts breaking authentication."),
    ("tls_not_yet_valid", "this device's clock, before the certificate",
     "A certificate here has not started being valid yet",
     "Check the clock on this device first - a certificate issued for the future is rare "
     "and a clock that is behind is common. If it is wrong, every TLS result in this report "
     "is measuring the clock."),
    ("tls_expired", "the service, not the network",
     "The certificate has expired - clients will refuse to connect",
     "Nothing here is a network fault. Renew it; everything below this passes."),
    ("tls_intercepted", "something in the path re-signing traffic",
     "TLS is being intercepted and re-signed",
     "An inspection proxy or portal sits in the path. Anything that verifies or "
     "pins certificates fails while ping and port checks look perfect."),
    ("tls_untrusted", "the service's certificate, or something in the path",
     "The certificate doesn't verify",
     "Either genuinely bad, or being re-signed. Compare the issuer against what "
     "the service is supposed to present."),
    ("tls_handshake_failed", "the service behind the port",
     "The port accepts connections but TLS doesn't complete",
     "Something is listening and it isn't serving TLS. A port check alone would "
     "have called this healthy."),
    ("close_wait_backlog", "an application on this device",
     "An application is leaking sockets - it isn't closing connections",
     "Not a network fault. Find the process holding them; it runs out of file "
     "descriptors before anything else breaks."),
    ("syn_sent_backlog", "the path out of this device",
     "Connections are being attempted and nothing answers",
     "A dropped SYN looks like a slow server from the application's side. Check "
     "egress filtering to the address named in the finding."),
    ("family_unreachable", "the site's IPv6, or the path to it",
     "This service answers on one address family but not the other",
     "It publishes an address for both, so clients try the broken one first and wait out "
     "the timeout before falling back. Either fix the route or withdraw the record."),
    ("tls_handshake_slow", "the service, not the path to it",
     "Most of the time reaching this service is its own TLS handshake",
     "The connect is a round trip and it was fast; the handshake afterwards is the server "
     "doing work. Take it to whoever runs the service - more bandwidth won't move it."),
    ("tls_expiring", "the service's certificate",
     "A certificate is close to expiry",
     "Not a fault yet, and much cheaper to fix now than during the outage it "
     "becomes."),
    ("path_loss", "the segment where the loss starts - see the finding",
     "Packets are being dropped along the path, all the way to the destination",
     "Loss that persists to the final hop is real. Take it to whoever owns the "
     "hop where it starts; if that's past the site edge, it's the provider's."),
    ("no_route_to_target", "this device's routing table, not the network",
     "This device has no route to the target and never sent anything",
     "Nothing reached the wire, so nothing on the network had a chance to "
     "fail. Check this device's routes: either nothing covers that "
     "destination, or the route that should points at an interface that is "
     "down."),
    ("port_host_unreachable", "the router that answered - the trace names it",
     "A router on the path says it cannot reach the target",
     "Something forwarded the traffic partway and then reported the "
     "destination unreachable from there. That router knows why, and it is a "
     "more specific answer than a silent path."),
    ("path_admin_prohibited", "whoever owns the policy on the hop that refused",
     "A device on the path is refusing this traffic on purpose",
     "It answered rather than went silent, which means the decision is "
     "configuration rather than a fault. Read the rule set on that hop - and "
     "if it is not yours, the answer is whoever runs it, not the carrier."),
    ("latency_wall", "see the finding - it names the segment",
     "A single hop adds most of the round-trip delay",
     "Everything past that hop inherits the delay; take it up with whoever owns "
     "that segment rather than tuning anything here."),
    ("gw_unknown", "unclear - the gateway didn't give a readable answer",
     "Couldn't determine whether the gateway is reachable",
     "Ping the gateway by hand and check the output; the automatic read failed, "
     "which is not the same as the gateway being down."),
    ("pmtu_unmeasurable", "unclear - DF probes are being filtered",
     "Path MTU can't be measured from here",
     "Something in the path drops do-not-fragment probes. Not a fault in itself, "
     "but it means an MTU problem can't be ruled out from this box."),
    ("resolvers_unreadable", "unclear - the check couldn't run",
     "The resolver configuration couldn't be read",
     "Read it by hand (/etc/resolv.conf, or ipconfig /all on Windows). This run can't say "
     "which resolvers are configured, only whether resolution worked."),
    ("dns_no_resolvers", "this device's configuration",
     "No DNS resolvers configured at all",
     "Nothing will resolve here whatever the network does. Check DHCP, or set "
     "resolvers statically to test."),
    ("dns_all_resolvers_down", "DNS servers, or the path to them",
     "Every configured resolver is unreachable",
     "IP connectivity may be fine - check whether the resolvers themselves are "
     "up and whether anything is blocking port 53 out of this site."),
    ("dns_resolver_down", "one of the configured DNS servers",
     "One resolver is dead while another works - lookups will be intermittent",
     "This is why it looks random rather than broken. Remove or fix the dead "
     "resolver; until then, roughly half of lookups take the slow path."),
    ("dns_hijack", "something intercepting DNS in the path",
     "DNS answers are being invented for names that don't exist",
     "A captive portal or ISP redirect service is intercepting queries. Anything "
     "that depends on a lookup failing will behave strangely."),
    ("dns_resolver_slow", "the configured DNS server",
     "Name resolution is slow enough to make everything feel broken",
     "Every new connection waits on this. Point the device at a faster resolver "
     "to confirm before chasing anything else."),
    ("dns_disagree", "the configured DNS servers",
     "Resolvers disagree about the same name",
     "Usually a stale cache on one, or a middlebox answering selectively."),
    ("dns_fail", "DNS configuration",
     "Connectivity works by IP, but names don't resolve",
     "The network is fine. Check which resolvers this device is configured with "
     "and whether they answer."),
    ("gw_loss_unmeasured", "unclear - too few probes to call it loss",
     "One probe to the gateway went unanswered, out of very few",
     "Not established as loss: at this sample size nothing smaller can be expressed, and a "
     "busy gateway deprioritises echo replies. Run --soak to measure a rate."),
    ("inet_loss_unmeasured", "unclear - too few probes to call it loss",
     "One probe to the target went unanswered, out of very few",
     "Not established as loss: hosts rate-limit ICMP replies as a matter of course. Run "
     "--soak to send enough probes to measure a rate."),
    ("inet_partial_loss", "the provider",
     "Packet loss beyond the gateway while the local link is clean",
     "Loss starts upstream of this site. Escalate with the hop where it begins."),
    ("drops_live", "this device",
     "Frames arrive but this device is dropping them",
     "The wire is fine - this is CPU, ring buffer, or driver on the box itself."),
    ("port_timeout", "the destination or a firewall in between",
     "The host is reachable but the port doesn't answer",
     "Connectivity is proven; the service or a firewall is the problem, not the path."),
    ("port_refused", "the destination service",
     "The port actively refused the connection",
     "Something answered and said no - the service isn't listening. Not a network fault."),
    ("trace_stalls", "the provider or upstream",
     "The path stops responding before reaching the target",
     "Confirm against the ping result - many routers forward traffic fine while "
     "ignoring traceroute probes."),
    ("double_nat", "the site network",
     "Two routers in series before traffic leaves the site",
     "Works for outbound, breaks inbound and port forwarding. Worth simplifying "
     "if anything needs to reach this site from outside."),
    ("cgnat", "the provider",
     "This site is behind carrier-grade NAT",
     "There's no public address here, so nothing external can reach it. If "
     "inbound access is the requirement, that's a conversation with the ISP."),
    ("conntrack_near_limit", "this device's configuration",
     "The connection tracking table is close to full",
     "Nothing has been refused yet. At 100% new connections fail for no visible reason, so "
     "raise nf_conntrack_max before it becomes the call-out."),
    ("conntrack_drops_historical", "possibly this device's load",
     "The connection tracking table has refused connections before",
     "None during this run. It fills under load, which is why the failures cluster at busy "
     "times and never reproduce afterwards."),
    ("nic_drops_historical", "possibly this device's load",
     "This device has discarded incoming packets when its backlog filled",
     "Nothing is being dropped right now. It tracks load on this box, so it explains loss "
     "that comes and goes with how busy the device is."),
    ("link_flapping", "possibly this device or its cable",
     "The link has a history of dropping and coming back",
     "It is up now, which is why nothing else shows it. Pair the transition count with "
     "the switch port's own log, and use --soak to try to catch a drop live."),
    ("link_errors_historical", "possibly this device or its cable",
     "Error counters carry history but nothing is incrementing now",
     "Not a current fault. Worth noting if the problem is intermittent."),
    # MOS is computed from the very latency and loss measured above, so it can
    # only ever be a restatement of those findings - it ranks below them, or the
    # verdict names a symptom while the cause sits lower in the list.
    # The three below are the same retransmits as tcp_retransmits, split by
    # destination, so they rank above it: each one names an owner where the
    # host-wide rate can only say "something is dropping".
    ("tcp_checksum_errors", "a device in the path, or this one's offload engine",
     "Segments are arriving corrupted, past the point the link layer checks",
     "Ethernet's CRC already passed them, so the damage happened somewhere that re-framed "
     "the packet. Suspect a middlebox in the path, or disable checksum offload on this "
     "interface to see whether the errors move."),
    ("connect_failures_high", "the destinations this box is trying to reach",
     "Connections from this device are failing to establish at all",
     "These gave up rather than retried. Measured on real traffic, so it covers "
     "destinations nothing here probes - check what this box is actually talking to."),
    ("syn_retrans_high", "something stateful in the path",
     "Connection setup is failing while established traffic is fine",
     "A SYN is one packet sent before anything has warmed up. Losing it repeatedly is not "
     "general loss - look for a firewall out of session slots, or flood protection between "
     "here and the destination."),
    ("retrans_spurious", "the path's ordering, not its loss",
     "Much of what looks like loss here is retransmission that wasn't needed",
     "The far end acknowledged data it already had, so the packets arrived - late or out "
     "of order. Look for per-packet load balancing across a link bundle rather than for a "
     "damaged segment, and read the loss figures below as overstated."),
    ("tcp_flow_loss_all_peers", "this device or the segment it's on",
     "Every destination this device talks to is losing traffic equally",
     "Loss that follows every peer is local. Check the link errors and duplex "
     "above first; if those are clean, suspect the switch port or the cable."),
    ("tcp_flow_loss_some_peers", "the provider or upstream",
     "Some destinations are losing traffic while others stay clean",
     "This device's link is carrying the clean traffic fine, so the drops are "
     "out on the path. Compare with the hop-by-hop figures to place them."),
    ("tcp_flow_loss_one_peer", "the path to that destination, or that host",
     "The only destination measured is losing traffic",
     "With one sample there's nothing to compare against. Generate traffic to a "
     "second destination and re-run to tell a path fault from a local one."),
    ("tcp_flow_loss_unclear", "unclear - too few connections could be read to say",
     "Connections are losing traffic, but not enough were readable to say whose fault it is",
     "The loss is real; the owner isn't established. Re-run when the box is quieter, or "
     "check by hand - `ss -tin` on connections to two different destinations shows "
     "whether the loss follows all of them or just one."),
    ("accept_overflow_live", "an application on this device",
     "A service here is turning connections away with a full accept queue",
     "Clients see a refusal or a hang and report the network, but nothing here reached it. "
     "The application isn't accepting fast enough, or its listen backlog is too small."),
    ("accept_overflow_historical", "an application on this device",
     "Services here have been turning connections away under load",
     "None during this run, so it tracks load rather than a fault you can reproduce now. "
     "Worth quoting when the complaint is that the network drops connections at busy times."),
    ("connections_reset_by_peer", "the far end, or a middlebox between - not this device",
     "Established connections are being killed rather than closed",
     "This box is not the one sending most of these. Look for a "
     "session-tracking firewall timing connections out, a load balancer "
     "recycling them, or a service at the far end restarting."),
    ("udp_recv_buffer_full", "this device, not the resolver it looks like",
     "This device is dropping incoming datagrams because it cannot take them",
     "UDP has no retransmission, so these are gone and the sender was never "
     "told. DNS runs over it: read every resolver finding here as a "
     "consequence until the receive buffers and whatever reads them have been "
     "looked at."),
    ("tcp_orphans_high", "this device's socket table",
     "Orphaned connections are filling this device's socket table",
     "Each one holds kernel memory with nothing left to close it, and the "
     "kernel weighs them at two to four times their size. Past the ceiling it "
     "resets them, which the far end sees as a connection dropped for no "
     "reason. Find what is abandoning connections rather than closing them."),
    ("udp_datagrams_corrupt", "a device in the path, or an offload engine here",
     "Datagrams are arriving damaged rather than being dropped for space",
     "This box had room for them; they failed a checksum or arrived malformed. "
     "Ethernet has its own CRC, so the corruption happened somewhere that "
     "re-framed the packet after that check."),
    ("fragments_lost", "the path, over how big a packet may be",
     "Fragmented packets are arriving incomplete and being discarded",
     "Some pieces are not turning up inside the reassembly timeout. Look for "
     "an MTU step on the path with the ICMP that would report it filtered - "
     "the sender never learns to send smaller packets and keeps trying."),
    ("resets_sent_high", "this device, which is the one sending them",
     "This device is resetting the connections it takes part in",
     "The resets originate here, so this is not something arriving from the "
     "network. Check that whatever should be listening still is, and whether "
     "the application is aborting connections rather than closing them."),
    ("tcp_flow_sendbuf_limited", "this device",
     "Connections are blocking on this device's own send buffer",
     "A local socket or memory limit, not a network fault. Check the sending "
     "application's buffer settings and this box's memory pressure."),
    ("tcp_retransmits", "the path between here and whatever this box talks to",
     "This device's real TCP traffic is being retransmitted",
     "Measured on actual traffic rather than probes. Pair it with the path loss "
     "figures to place where the drops happen."),
    # Above call quality because voice is one thing a slow path ruins and the
    # report has to work for a box whose traffic is requests and responses.
    # Below latency_wall, which names the hop: where the delay accumulates
    # beats what it costs, when the path can say.
    ("latency_high", "the path to the target - distance if it is genuinely far away",
     "The round trip to the target is long enough to slow every request",
     "Nothing is being dropped, so this is delay rather than damage and more "
     "bandwidth will not move it. Read the per-hop times in the path panel for "
     "where it accumulates, and confirm the target is as far away as this "
     "implies before taking it to anyone."),
    ("call_quality_bad", "the path to the target - see the latency/jitter/loss split",
     "Voice and video will be unusable on this connection",
     "Check which of the three is to blame: jitter points at congestion or a "
     "flapping link, loss at a damaged segment, latency at distance or routing."),
    ("call_quality_degraded", "the path to the target",
     "Voice and video will be rough but usable",
     "Worth quoting to whoever is reporting bad calls - it turns three numbers "
     "into the score their complaint is really about."),
    # Deliberately near the bottom. When a real network fault fired, that fault
    # is the answer and this is a detail; when nothing else fired, "the far end
    # is the bottleneck" is the most useful thing left to say - and it's the one
    # verdict here that tells you to stop looking at the network.
    ("tcp_flow_receiver_limited", "the remote service, not the network",
     "Connections are waiting on the far end rather than on the network",
     "The remote application is reading slower than the network delivers. Take "
     "this to whoever owns that service; more bandwidth here won't help."),
    ("bond_degraded", "the cable or switch port behind the failed member",
     "This box is running on fewer bonded cables than it was given",
     "Nothing is failing yet - the bond is doing its job of hiding it. Find "
     "the member that is down and the port at its far end, before the next "
     "one goes and takes the box off the network."),
    ("neigh_table_full", "this box's neighbour table, not the network",
     "This box has run out of room to remember its neighbours",
     "Raise net.ipv4.neigh.default.gc_thresh3, and gc_thresh2 and gc_thresh1 "
     "with it. Until then this box will keep losing neighbours at random on a "
     "segment where nothing is wrong."),
    ("neigh_table_near_limit", "this box's neighbour table, not the network",
     "This box is close to running out of room to remember its neighbours",
     "It refuses outright rather than queuing when it fills, so raise "
     "net.ipv4.neigh.default.gc_thresh3 now rather than after the first "
     "unexplained outage."),
    ("negotiated_below_capacity", "the cable, optic or port setting - not the network",
     "This link negotiated below what the port is capable of",
     "Nothing is failing on it today. Check the cable or optic rating and "
     "whether a speed has been forced at either end, before the traffic needs "
     "the capacity that was paid for."),
    ("mtu_nonstandard", "site configuration",
     "Interface MTU is not the standard 1500",
     "Fine if deliberate (a tunnel), a problem if the far end expects 1500."),
]


# Findings that are context or housekeeping, never a root cause. Kept explicit
# so the coverage test can tell "deliberately unranked" from "forgotten".
VERDICT_EXEMPT = {"all_clear", "path_loss_cosmetic", "ports_truncated", "switch_port",
                  "baseline_changes", "icmp_filtered", "tcp_flow_sample_partial",
                  # Both say "this looked like an outage and is not" - context
                  # that stops something else being misread, never a fault.
                  "gw_icmp_filtered", "inet_icmp_filtered",
                  # This box cannot speak the family the check needed. Not a
                  # fault, and never a conclusion.
                  "ipv6_only", "gw_unmeasurable_v4", "inet_unmeasurable_v4",
                  # Which kind of thing answers for the gateway. Context that
                  # reframes every gateway finding, never a fault itself.
                  "gateway_is_virtual",
                  # Where DNS answers came from. Context that reframes every
                  # resolver result below it, never a fault on its own.
                  "dns_local_cache",
                  # Which host the run aimed at and why - provenance for
                  # everything below it, never a fault in itself.
                  "target_is_a_backend", "target_auto_failed", "target_is_forwarded",
                  # A tunnel being smaller than a wire is the tunnel working.
                  "tunnel_mtu",
                  # Which of three things is limiting throughput. Always true
                  # of a box that is sending anything, so never a fault.
                  "throughput_limited_by",
                  # Which part of its own service's answer took the time.
                  "own_service_timing",
                  # What kind of adapter this is. Context that reframes every
                  # physical-layer reading below it, never a fault itself.
                  "virtual_nic"}


# Findings too weak to be evidence for anything else: a count of errors that
# stopped happening, an MTU that's merely unusual, a router that declines to
# answer traceroute. Each is already forced to low confidence when it is itself
# the verdict - so it shouldn't be able to raise someone else's. Without this, a
# non-standard MTU sitting in the report turned an unrelated medium call into a
# high one purely by being present.
# Conditions that are real, worth reporting, and by their own description not
# currently causing anything to fail: an optic with margin left, a link that
# flapped yesterday, a table that is filling but has refused nothing. Pure
# bottom-up ordering let one of these headline over a live outage - a
# temperature warning on a working optic outranked DNS being completely dead -
# because rank is by layer and nothing consulted whether the finding was
# actually breaking something. Something that says "not failing yet" cannot be
# the explanation for something that is failing now.
LATENT = {
    "optics_warning", "optics_rx_marginal", "link_errors_historical",
    "negotiated_below_capacity", "bond_degraded", "neigh_table_near_limit",
    "neigh_table_full",
    "link_flapping", "nic_drops_historical", "conntrack_near_limit",
    "conntrack_drops_historical", "accept_overflow_historical",
    "mtu_nonstandard", "regression_since_baseline", "tls_expiring",
    # A line at capacity with nothing failing beside it. The prototype for the
    # burst work caught this: a nightly backup put the uplink at 75% and
    # headlined as root cause over everything else in the report.
    "uplink_busy", "link_busy",
    # Overflowed at some point since boot, but not while we were looking.
    "syncookies_historical",
    # Real, dated, and not yet refusing anyone.
    "own_tls_expiring",
    # It throttled earlier and is not throttling now.
    "cpu_throttled_historical",
}


WEAK_EVIDENCE = {"link_errors_historical", "mtu_nonstandard", "trace_stalls"}


# Findings whose fix is somebody putting their hands on something: reseating a
# connector, cleaning an optic, swapping a cable, replacing an adapter, clearing
# an air intake. Marked because it is a different kind of answer from the rest
# of this report - not a different severity, a different *action*. Everything
# else here is read, configured, or escalated to whoever owns the next segment;
# these need a person in the room.
#
# Deliberately narrower than "hardware caused it". A duplex mismatch, a link
# negotiated below its port's rating and a collision count are all *either* a
# damaged cable or a setting forced at one end, and the tool cannot tell which
# from here - so they are left unmarked rather than sending somebody to a rack
# on a coin toss. The rule is not "is this hardware" but "does this tool know
# the fix is physical".
HARDWARE_FINDINGS = {
    # The optic, its fibre, and the connectors at both ends.
    "optics_alarm", "optics_rx_low", "optics_rx_marginal", "optics_warning",
    # Frames arriving damaged. Ethernet's own CRC caught them, which puts the
    # corruption on the cable, the connector or the module.
    "link_errors_live", "link_errors_historical",
    # A link that keeps going away and coming back.
    "link_flapping_live", "link_flapping", "link_flapping_logged",
    # The adapter resetting itself, and a bonded member that is down.
    "nic_reset_logged", "bond_degraded",
    # Cooling. Airflow, dust, a failed fan - all of them a person in the room.
    "cpu_throttled_live", "cpu_throttled_historical",
}


# Findings that describe traffic being lost, delayed or refused, rather than a
# thing being misconfigured. The distinction decides whether a fault further up
# the stack is this cause's consequence or somebody else's problem, and layer
# distance alone cannot express it: a full link is layer 2 and the loss it
# produces is layer 3, while an expired certificate is also layer 7 and no
# amount of fixing the cable will renew it.
#
# Everything here is the *shape* a lower-layer fault produces when it bites -
# so when the verdict sits underneath one of these, and faces the same way, it
# explains it. Anything not in this set is a state or a decision: a certificate
# that has run out, an answer that came back wrong, an address claimed twice, a
# device refusing on purpose. Those survive fixing whatever is below them, and
# are the ones actually worth calling unrelated.
TRANSPORT_SYMPTOMS = {
    # Traffic that did not arrive, or did not arrive on time.
    "inet_partial_loss", "inet_loss_unmeasured", "inet_unreachable",
    "gw_partial_loss", "gw_loss_unmeasured", "gw_unreachable",
    "path_loss", "trace_stalls", "destination_unresponsive",
    "latency_wall", "latency_high", "call_quality_bad", "call_quality_degraded",
    "queuing_delay", "queuing_delay_backends", "queuing_delay_clients",
    "path_jitter_backends", "path_jitter_clients",
    # TCP reacting to a path that is losing or delaying traffic.
    "tcp_retransmits", "syn_retrans_high", "connect_failures_high",
    "retrans_spurious", "tcp_flow_loss_all_peers", "tcp_flow_loss_some_peers",
    "tcp_flow_loss_one_peer", "tcp_flow_loss_unclear", "tcp_flow_loss_backends",
    "tcp_flow_loss_clients",
    # Services timing out rather than answering wrongly. A resolver that is
    # slow, or a handshake that never completes, is what a degraded path looks
    # like from one layer up - unlike a resolver that answers with the wrong
    # address, which is a fault of its own.
    "dns_resolver_slow", "dns_fail", "tls_handshake_slow", "port_timeout",
    "fragments_lost", "udp_datagrams_corrupt",
    "own_service_silent",
}


# Verdicts that send the reader to a switch port. When LLDP has told us which
# port this device is in, the next step names it: "check the switch port" is
# advice, "check SW-CLOSET-2 port Gi1/0/12" is an instruction someone can act
# on without hunting. Module-level so the suite can assert against the real set
# rather than a copy of it - a copy is what let three rules go missing.
# When the run is aimed at a backend rather than the internet, the verdicts
# about reaching it are the same findings with a different owner. "The
# provider" is the right answer for 8.8.8.8 and flatly wrong for a database on
# the other side of a rack - and sending someone to a carrier for an internal
# segment is the exact failure this tool exists to prevent. Overridden here
# rather than duplicated as parallel finding codes, so there is one rule per
# fault and only the attribution changes.
BACKEND_TARGET_VERDICTS = {
    "inet_unreachable": (
        "the segment between this box and that backend",
        "This box cannot reach the backend it depends on",
        "The gateway answers, so this box's own link is fine. Nothing about "
        "this is the internet or the carrier: the break is between here and "
        "that backend, or the backend is down."),
    "inet_partial_loss": (
        "the segment between this box and that backend",
        "Traffic to the backend this box depends on is being lost",
        "The local link is clean, so the loss is on the internal path to that "
        "backend. Take the hop where it starts to whoever runs that segment - "
        "this is inside your own network."),
    "latency_high": (
        "the segment between this box and that backend",
        "The backend this box depends on is hundreds of milliseconds away",
        "Distance does not explain this one - it is an internal path, so the "
        "delay is queuing or a bad route inside your own network rather than "
        "the width of an ocean. Every request this box serves waits behind it."),
    "trace_stalls": (
        "the internal path to that backend",
        "The path to the backend stops responding before reaching it",
        "Routers inside your own network commonly decline to answer traceroute, "
        "so this is weak evidence on its own. Check it against whether the "
        "backend itself is answering."),
    "loop": (
        "routing inside your own network",
        "Routing loop on the way to the backend - traffic is circling",
        "This is your own routing rather than the provider's: something between "
        "here and that backend is sending traffic back where it came from."),
    "egress_blocked": (
        "reaching that backend, which is not an egress question",
        "Nothing reaches the backend this box depends on",
        "Clients are connected, so this box's network works. What it cannot "
        "reach is the thing it needs to answer them - check the backend and the "
        "path to it before anything else."),
}


# Which way a fault faces. Direction and layer are orthogonal, and the ordering
# rule collapsed them into one chain built for a device that only talks
# outward. On a box that answers requests there are two directions, and a fault
# on one side cannot explain a symptom on the other: client-side loss and loss
# on the path to a backend are both layer 3, so the layer rule alone presented
# one as the consequence of the other and said nothing about the second.
#
#   local       this box and its own link. Explains both directions, so it
#               stays the cause when it is present - which is the old rule.
#   downstream  toward whoever connects to this box: the load balancer, the
#               edge, the accept path. Broken here and clients cannot get in.
#   upstream    toward whatever this box depends on: backends, DNS, the path
#               out. Broken here and this box cannot answer them.
#
# The table is exhaustive rather than defaulting, so every code is a decision
# somebody made and a new one cannot join by accident. Local is still the safe
# answer when a fault genuinely sits in both paths - it loses a distinction
# rather than inventing one.
_LOCAL_FAULTS = (
    # This box's own link and hardware.
    "link_errors_live", "link_errors_historical", "link_flapping",
    "link_flapping_live", "link_flapping_logged", "nic_reset_logged",
    "optics_alarm", "optics_rx_low", "optics_rx_marginal", "optics_warning",
    "duplex_mismatch", "slow_link", "negotiated_below_capacity", "bond_degraded",
    "tunnel_mtu", "virtual_nic",
    "collisions", "link_saturated", "link_busy",
    "neigh_table_full", "neigh_table_near_limit",
    "no_ipv4", "duplicate_ip", "virtual_router_conflict", "mtu_nonstandard",
    "no_route_to_target",
    # This box failing to keep up, in both directions at once.
    "nic_drops_live", "nic_drops_historical", "drops_live", "rcv_buffer_pruned",
    "nic_ring_overruns", "frame_length_errors",
    "cpu_throttled_live", "cpu_throttled_historical", "fault_on_every_interface",
    "conntrack_drops_live", "conntrack_drops_historical", "conntrack_near_limit",
    "aborts_on_memory", "aborts_on_timeout",
    # Its own stack and clock.
    "tcp_retransmits", "tcp_checksum_errors", "syn_retrans_high",
    "retrans_spurious", "tcp_flow_loss_all_peers", "tcp_flow_loss_unclear",
    "tcp_flow_receiver_limited", "tcp_flow_sendbuf_limited",
    "clock_skewed", "clock_unsynced",
    # Housekeeping about the run itself.
    "interfaces_unreadable", "routes_unreadable", "regression_since_baseline",
)

FINDING_SIDE = {code: "local" for code in _LOCAL_FAULTS}
FINDING_SIDE.update({
    # --- downstream: the way in ------------------------------------------
    # Clients cannot reach the service, or reach it and are turned away.
    "tcp_flow_loss_clients": "downstream",
    "no_clients_connected": "downstream",
    "no_traffic_at_all": "local",
    "queuing_delay_clients": "downstream",
    "path_jitter_clients": "downstream",
    "syncookies_live": "downstream",
    "syncookies_historical": "downstream",
    "syn_recv_backlog": "downstream",
    "reqq_full_drops": "downstream",
    "accept_overflow_live": "downstream",
    "accept_overflow_historical": "downstream",
    # A file descriptor ceiling stops this box *accepting*. Its twin below
    # stops it *opening* - the same shortage, breaking opposite directions.
    "fd_pressure": "downstream",
    "close_wait_backlog": "downstream",
    # The certificate this box serves is only ever seen by whoever connects.
    "own_tls_expired": "downstream",
    "own_service_silent": "downstream",
    "own_service_erroring": "downstream",
    "own_service_not_http": "downstream",
    # Answered by this box, but it is a report about what lies beyond it.
    "own_service_upstream_error": "upstream",
    "own_tls_expiring": "downstream",
    "own_tls_untrusted": "downstream",
    "own_tls_handshake_failed": "downstream",

    # --- upstream: the way out -------------------------------------------
    "tcp_flow_loss_backends": "upstream",
    "path_jitter_backends": "upstream",
    "queuing_delay_backends": "upstream",
    "queuing_delay": "upstream",
    "tcp_flow_loss_some_peers": "upstream",
    "tcp_flow_loss_one_peer": "upstream",
    "ephemeral_ports_low": "upstream",      # cannot open outbound connections
    "connect_failures_high": "upstream",
    "syn_sent_backlog": "upstream",
    "egress_blocked": "upstream",
    "inet_unreachable": "upstream",
    "destination_unresponsive": "upstream",
    "inet_partial_loss": "upstream",
    "inet_loss_unmeasured": "upstream",
    "inet_icmp_filtered": "upstream",
    "path_loss": "upstream",
    "path_loss_cosmetic": "upstream",
    "port_host_unreachable": "upstream",
    "path_admin_prohibited": "upstream",
    "latency_wall": "upstream",
    "trace_stalls": "upstream",
    "loop": "upstream",
    "cgnat": "upstream",
    "double_nat": "upstream",
    "pmtu_blackhole": "upstream",
    "pmtu_unmeasurable": "upstream",
    "latency_high": "upstream",
    "resets_sent_high": "local",
    "udp_recv_buffer_full": "local",
    "tcp_orphans_high": "local",
    "udp_datagrams_corrupt": "upstream",
    "fragments_lost": "upstream",
    "connections_reset_by_peer": "upstream",
    "call_quality_bad": "upstream",
    "call_quality_degraded": "upstream",
    "uplink_saturated": "upstream",
    "uplink_busy": "upstream",
    "saturation_bursts": "upstream",
    "dns_fail": "upstream",
    "dns_no_resolvers": "upstream",
    "dns_all_resolvers_down": "upstream",
    "dns_resolver_down": "upstream",
    "dns_resolver_slow": "upstream",
    "dns_disagree": "upstream",
    "dns_hijack": "upstream",
    "resolvers_unreadable": "upstream",
    "port_refused": "upstream",
    "port_timeout": "upstream",
    "family_unreachable": "upstream",
    "tls_expired": "upstream",
    "tls_expiring": "upstream",
    "tls_not_yet_valid": "upstream",
    "tls_handshake_failed": "upstream",
    "tls_handshake_slow": "upstream",
    "tls_intercepted": "upstream",
    "tls_untrusted": "upstream",
    "gw_unreachable": "upstream",
    "gw_partial_loss": "upstream",
    "gw_loss_unmeasured": "upstream",
    "gw_unknown": "upstream",
    "gw_icmp_filtered": "upstream",
    "no_gateway": "upstream",
})


def finding_side(code):
    """Which way a fault faces. Local unless the table says otherwise."""
    return FINDING_SIDE.get(code, "local")


PORT_RELEVANT_CODES = {
    "link_errors_live", "link_errors_historical", "duplex_mismatch",
    "collisions", "slow_link", "gw_unreachable", "gw_partial_loss", "bond_degraded",
    "link_saturated", "link_busy", "duplicate_ip", "no_ipv4",
    "negotiated_below_capacity",
    # Both flap verdicts send the reader to "the port's own log at the other
    # end" - the one place LLDP has already named.
    "link_flapping_live", "link_flapping", "link_flapping_logged",
    # "Suspect the switch port or the cable" - so name it.
    "tcp_flow_loss_all_peers",
}


# ---------------------------------------------------------------------------
# Stage strip. The findings carry the detail; this is the one-glance summary a
# handheld tester gives you - each stage of the chain, pass or fail - which is
# what actually gets pasted into a ticket.
# ---------------------------------------------------------------------------

# stage -> (codes that fail it, codes that only warn)
STAGE_RULES = [
    # Optics belong to the link stage for the same reason the error counters
    # do: a fibre outside its rated range is the physical link failing, and
    # leaving the strip all-green during an optical alarm is exactly the
    # "everything looks fine" that sends someone hunting upstream.
    ("link", {"link_errors_live", "duplex_mismatch", "tcp_flow_loss_all_peers",
              "optics_alarm", "optics_rx_low", "link_flapping_live", "nic_drops_live",
              "rcv_buffer_pruned", "link_flapping_logged", "nic_reset_logged",
              "nic_ring_overruns", "frame_length_errors", "cpu_throttled_live",
              "fault_on_every_interface"},
     {"slow_link", "negotiated_below_capacity", "bond_degraded",
      "collisions", "link_errors_historical", "drops_live", "link_saturated",
      "link_busy",
      "optics_rx_marginal", "optics_warning", "link_flapping", "nic_drops_historical",
      "cpu_throttled_historical"}),
    ("address", {"no_ipv4", "no_gateway", "duplicate_ip", "virtual_router_conflict"},
     {"interfaces_unreadable", "routes_unreadable",
      "neigh_table_full", "neigh_table_near_limit"}),
    ("gateway", {"gw_unreachable"},
     {"gw_partial_loss", "gw_unknown", "gw_loss_unmeasured"}),
    # A routing loop means traffic never arrives, so it fails the stage rather
    # than merely warning it.
    ("internet", {"inet_unreachable", "destination_unresponsive", "loop",
                  "conntrack_drops_live"},
     {"inet_partial_loss", "inet_loss_unmeasured", "path_loss", "trace_stalls",
      "latency_wall", "latency_high", "tcp_retransmits", "path_admin_prohibited",
      # The uplink is this site's internet stage, whoever owns the congestion.
      "uplink_saturated", "saturation_bursts", "uplink_busy", "egress_blocked",
      "tcp_flow_loss_some_peers", "tcp_flow_loss_one_peer", "tcp_flow_loss_unclear",
      "tcp_flow_loss_backends", "tcp_flow_loss_clients",
      "queuing_delay", "queuing_delay_backends", "queuing_delay_clients",
      "path_jitter_backends", "path_jitter_clients",
      "syn_retrans_high", "tcp_checksum_errors", "connect_failures_high",
      "resets_sent_high", "connections_reset_by_peer",
      "udp_recv_buffer_full", "udp_datagrams_corrupt", "fragments_lost",
      "tcp_orphans_high",
      "retrans_spurious",
      # Listed as warnings, but build_stages promotes a critical to fail, so
      # "degraded" warns the stage and "unusable" fails it without a second rule.
      "call_quality_degraded", "call_quality_bad",
      "conntrack_near_limit", "conntrack_drops_historical",
      # Local ceilings that stop this box accepting or opening connections.
      "no_clients_connected", "no_traffic_at_all",
      "syncookies_live", "syncookies_historical", "ephemeral_ports_low",
      "fd_pressure", "syn_recv_backlog", "aborts_on_memory", "reqq_full_drops",
      "aborts_on_timeout"}),
    ("dns", {"dns_fail", "dns_all_resolvers_down", "dns_no_resolvers"},
     {"dns_resolver_down", "dns_resolver_slow", "dns_hijack", "dns_disagree",
      "resolvers_unreadable"}),
    ("mtu", {"pmtu_blackhole"}, {"pmtu_unmeasurable", "mtu_nonstandard"}),
    ("ports", {"no_route_to_target", "port_host_unreachable",
               "tls_handshake_failed", "tls_expired", "tls_not_yet_valid",
               "own_tls_expired", "own_tls_handshake_failed",
               "own_service_silent", "own_service_erroring",
               "own_service_upstream_error"},
     {"port_refused", "port_timeout", "ports_truncated", "tls_expiring", "tls_handshake_slow", "family_unreachable",
      "own_tls_expiring", "own_tls_untrusted", "own_service_not_http",
      "tls_intercepted", "tls_untrusted"}),
]


# Which stage of the chain each captured command belongs to. The compact
# export keeps the evidence behind the stages that are not passing and drops
# the rest, and this is how it knows which is which.
#
# A key with no stage - the clock, and the run's own provenance - is always
# kept. It is a short list of small things, and dropping evidence because
# nothing here could classify it would be the wrong way round.
RAW_STAGE = {
    "interfaces": "link", "link_stats": "link", "link_modes": "link",
    "bonds": "link", "kernel_log": "link", "kernel_drops": "link",
    "lldp": "link", "optics": "link",
    "ipv4": "address", "routes": "address", "arp": "address",
    "neigh_table": "address",
    "ping_gateway": "gateway",
    "ping_internet": "internet", "path_trace": "internet",
    "tcp_flows": "internet", "tcp_health": "internet",
    # The fallback when ping is filtered: reaching the target the way an
    # application would, before calling a site's uplink down.
    "reachability_tcp": "internet",
    # Kept when the TCP path is used instead, so both attempts are on record.
    "path_trace_icmp": "internet",
    "path_mtu": "mtu",
    "dns_lookup": "dns", "dns_health": "dns",
    "sockets": "ports", "ports": "ports",
    # This box's own service and the certificate it serves, both read from the
    # outside in. They belong to the ports stage for the same reason the port
    # checks do: they answer whether what is listening here actually works.
    "own_service": "ports", "own_tls": "ports",
    # Not a stage of the chain, and deliberately so - see _check_clock.
    "clock": None,
    # Provenance for everything else, and a few bytes each.
    "target": None, "target_kind": None,
}

# One raw entry per checked port, named for the port, so it cannot be a key in
# the map above. On a run with --check-ports common these are the largest thing
# in the export by a wide margin.
RAW_STAGE_PREFIXES = (("port_", "ports"), ("tls_", "ports"))


def raw_stage(key):
    """Which stage a captured command belongs to, or None if it belongs to no
    stage and must therefore always be kept."""
    if key in RAW_STAGE:
        return RAW_STAGE[key]
    for prefix, stage in RAW_STAGE_PREFIXES:
        if key.startswith(prefix):
            return stage
    return None


def compact_report(report):
    """The same report with the evidence for everything that passed removed.

    A full export is mostly captured command output - on a real box the port
    probes alone can be half of it - and all of it is kept so a conclusion can
    be audited later. That is the right default and the wrong thing to carry
    off a locked-down box through a console, which is the case this tool was
    written for.

    What survives is everything the report *concluded*: the verdict, the
    findings, the stage strip, the hop-by-hop path, the direction panel, call
    quality. All of it is derived and all of it is small, so the picture is
    the same one - the hops, the colours, the layers - with the raw material
    behind the parts that were fine left on the box.

    Evidence is kept when its stage is not passing, and when a check could not
    run at all: a gap in coverage is a thing the reader has to be able to see,
    and a missing panel would look like a check that passed.
    """
    slim = {k: v for k, v in report.items() if k not in ("raw", "panel_help")}
    state = {s["stage"]: s["state"] for s in report.get("stages") or []}
    keep = {}
    for key, value in (report.get("raw") or {}).items():
        stage = raw_stage(key)
        ran = not isinstance(value, dict) or value.get("ok", True)
        if stage is None or state.get(stage) in ("fail", "warn") or not ran:
            keep[key] = value
    slim["raw"] = keep
    help_text = report.get("panel_help") or {}
    slim["panel_help"] = {k: v for k, v in help_text.items() if k in keep}
    slim["compact"] = True
    return slim


# How each finding stands to the verdict. The relationships already exist in
# the verdict - based_on, explains, unrelated - and the report showed them as a
# line of raw finding codes above a flat list, so a reader had to match
# "inet_partial_loss" against the entries below by eye to see which fault was
# the answer and which were its consequences. That structure is the whole
# product; leaving it as a comma-separated string is the one place the report
# does not say what the tool knows.
FINDING_RELATIONS = {
    "cause": "the cause",
    "corroborates": "backs it up",
    "explained": "caused by it",
    "unrelated": "separate problem",
}


def finding_relation(code, verdict):
    """Where `code` sits relative to the verdict, or None if nowhere."""
    if not code or not verdict:
        return None
    based = verdict.get("based_on") or []
    if based and code == based[0]:
        return "cause"
    if code in based[1:]:
        return "corroborates"
    if code in (verdict.get("explains") or []):
        return "explained"
    if code in {u.get("code") for u in (verdict.get("unrelated") or [])}:
        return "unrelated"
    return None


def build_stages(findings, raw=None, checked_ports=False, quick=False):
    """Reduce the findings to pass/warn/fail per stage of the chain."""
    raw = raw or {}
    codes = {f.get("code") for f in findings if f.get("severity") != "ok"}
    stages = []
    for name, fail_codes, warn_codes in STAGE_RULES:
        # Our own TLS listeners are checked on every run, so the ports stage
        # has something to say even when nobody asked for --check-ports.
        if (name == "ports" and not checked_ports
                and not (raw.get("own_tls") or {}).get("listeners")
                and not (raw.get("own_service") or {}).get("listeners")):
            state = "skip"
        elif name == "mtu" and not raw.get("path_mtu"):
            state = "skip"          # not measured (quick mode, or target silent)
        elif name == "link" and not (raw.get("link_stats") or {}).get("interfaces"):
            state = "skip"
        elif codes & fail_codes:
            state = "fail"
        elif codes & warn_codes:
            # A critical finding must not leave its stage reading "warn" - the
            # strip is the summary someone acts on, and it has to agree with
            # the severity beside it.
            critical = {f.get("code") for f in findings if f.get("severity") == "critical"}
            state = "fail" if critical & warn_codes else "warn"
        else:
            state = "pass"
        # Which findings put it in that state, and the lowest layer among them.
        # Derived here rather than in a renderer so the terminal and the page
        # can't drift, and so a stage never carries a layer nobody measured.
        driving = sorted(codes & (fail_codes | warn_codes)) if state in ("fail", "warn") else []
        layers = [f["layer"] for f in findings
                  if f.get("code") in driving and f.get("layer")]
        stages.append({"stage": name, "state": state,
                       "because": driving, "layer": min(layers) if layers else None})
    return stages


def build_sides(findings, raw=None):
    """Where the fault is, in the three places it can be.

    The stage strip walks one chain outward, which is the shape of a device
    that only talks. A box that answers requests has traffic coming the other
    way too, and "where is it" is the first question anyone asks - before which
    layer, before which check. Three boxes with one of them lit answers it
    without knowing what a layer is.
    """
    raw = raw or {}
    serving = _serves_traffic(raw)
    order = [
        ("downstream", "clients reaching this box",
         "the load balancer, the edge, and the path in"),
        ("local", "this box",
         "its link, its hardware, and its own limits"),
        ("upstream", "what this box depends on",
         "backends, DNS, and the path out"),
    ]
    rank = {"pass": 0, "warn": 1, "fail": 2}
    out = []
    for side, label, detail in order:
        mine = [f for f in findings
                if finding_side(f.get("code")) == side
                and f.get("severity") in ("warning", "critical")
                and f.get("code") not in VERDICT_EXEMPT]
        state = ("fail" if any(f["severity"] == "critical" for f in mine)
                 else "warn" if mine else "pass")
        # Nothing connects to this box, so there is no inbound path to report
        # on. Showing it green would claim something was checked.
        if side == "downstream" and not serving:
            state, mine = "skip", []
        entry = {"side": side, "label": label, "detail": detail, "state": state,
                 "because": sorted(f.get("code") for f in mine),
                 "worst": None}
        if mine:
            entry["worst"] = sorted(mine, key=lambda f: -rank.get(
                "fail" if f["severity"] == "critical" else "warn", 0))[0]["message"]
        if side == "downstream" and serving:
            lb = _dominant_client(raw)
            entry["via"] = lb
        if side == "upstream" and raw.get("target_kind") in ("backend", "dependency"):
            entry["via"] = raw.get("target")
        out.append(entry)
    return out


# Share of connections one address must carry, and a floor beneath which a
# share means nothing, before it counts as infrastructure rather than one of
# the crowd.
DOMINANT_PEER_PCT = 0.6
DOMINANT_PEER_MIN = 3


def dominant_peer(counts):
    """The address carrying most of a set of connections, if one stands out.

    One address carrying most of the inbound traffic is a load balancer. A
    spread of addresses is the public, and naming the busiest of those would be
    noise dressed as a finding. Ties break by address so the answer is the same
    on every run.

    One function because it is a judgement, not an expression: the zone panel
    and the inbound path leg both ask it, and two copies of a threshold means
    two panels that can disagree about the same connections.
    """
    if not counts:
        return None
    peer, count = max(sorted(counts.items()), key=lambda kv: kv[1])
    total = sum(counts.values())
    return peer if count >= max(DOMINANT_PEER_MIN, total * DOMINANT_PEER_PCT) else None


def _dominant_client(raw):
    """The address most client connections arrive from, if one stands out."""
    sockets = raw.get("sockets") or {}
    listening = set(sockets.get("listen_ports") or [])
    counts = {}
    for peer, local_port in (sockets.get("peers") or []):
        if peer and local_port in listening:
            counts[peer] = counts.get(peer, 0) + 1
    return dominant_peer(counts)


# ---------------------------------------------------------------------------
# Baseline comparison. A field tool can't keep history, but the operator keeps
# the reports - so "what changed since last visit" is a diff of two JSON files
# and needs no storage, no service and no network.
# ---------------------------------------------------------------------------

def looks_like_a_report(data):
    """Is this JSON one of ours, or just JSON?

    --baseline takes a file the operator names, and being handed the wrong one
    is ordinary: a truncated write, an mtr export, last week's inventory. The
    loader already rejects what will not parse. What got through was valid JSON
    with a foreign shape, which crashed the comparison half way through a run
    and lost the diagnosis - over a piece of optional context.
    """
    return (isinstance(data, dict)
            and isinstance(data.get("findings"), list)
            and isinstance(data.get("verdict"), dict))


def _dict(value):
    """A mapping, whatever arrived. A key present and null is not a key absent,
    and `.get(k, {})` returns the None rather than the default for it."""
    return value if isinstance(value, dict) else {}


# States the kernel reports for an interface. "unknown" is the awkward one and
# has to count as up: loopback, tun devices and several virtual drivers never
# call the operstate machinery at all, so they sit at "unknown" while working
# perfectly. "dormant" is a port waiting on something external - 802.1X
# authentication, most often - which is not up and is not a failure either.
UP_OPERSTATES = ("up", "unknown")


def _operationally_up(state):
    return (state or "").strip().lower() in UP_OPERSTATES


def _iface_map(report, key):
    ifaces = _dict(_dict(_dict(report).get("raw")).get(key)).get("interfaces")
    return {i["name"]: i for i in (ifaces or []) if isinstance(i, dict) and i.get("name")}


def compare_reports(current, baseline):
    """Differences between two reports of the same site. Each entry says which
    direction it moved, so the caller can raise the ones that got worse."""
    if not isinstance(baseline, dict):
        return []
    changes = []

    def note(what, before, after, direction="neutral"):
        # If either side is missing, the two runs measured different things -
        # a quick run, or a tool that wasn't installed last time. Reporting
        # that as a change would manufacture regressions out of coverage gaps.
        if before is None or after is None:
            return
        if before != after:
            changes.append({"what": what, "before": before, "after": after,
                            "direction": direction})

    # Not a fault, but it explains a difference that isn't the network's doing.
    note("faultone version", baseline.get("version"), current.get("version"))
    note("python", baseline.get("python"), current.get("python"))

    # Everything measured *to the target* is only comparable when both runs
    # went to the same one. Since --target auto picks a backend off this box's
    # own connections, the target can change between visits without anyone
    # touching a flag: a box with no clients on the first visit and clients on
    # the second aims somewhere else entirely. Comparing call quality to
    # 8.8.8.8 against call quality to a database two racks away then reported
    # "something changed, and not for the better" on a network where nothing
    # had changed at all.
    same_target = (baseline.get("target") == current.get("target"))
    note("target", baseline.get("target"), current.get("target"))

    note("default gateway", baseline.get("detected_gateway"),
         current.get("detected_gateway"), "worse")
    # The address staying put while the hardware behind it changes is a
    # failover, and it is the only view of one this box gets: two routers in a
    # VRRP group share a virtual MAC, so a split brain is invisible in a
    # neighbour table at any single moment. Between two moments it is not.
    # Neutral, not "worse" - a redundancy pair failing over is the pair doing
    # its job, and the reader is the one who knows whether it should have.
    note("gateway hardware address", baseline.get("gateway_mac"),
         current.get("gateway_mac"))
    note("path measured with", baseline.get("path_source"), current.get("path_source"))

    # Switch port / VLAN: a device that moved, or a re-patched port, explains a
    # great deal on its own.
    def nb_map(rep):
        return {n["iface"]: n for n in (_dict(rep).get("neighbours") or [])
                if isinstance(n, dict) and n.get("iface")}
    cur_nb, base_nb = nb_map(current), nb_map(baseline)
    for iface in sorted(set(cur_nb) | set(base_nb)):
        c, b = cur_nb.get(iface, {}), base_nb.get(iface, {})
        note(f"{iface} switch", b.get("switch"), c.get("switch"), "worse")
        note(f"{iface} switch port", b.get("port") or b.get("port_descr"),
             c.get("port") or c.get("port_descr"), "worse")
        note(f"{iface} VLAN", b.get("vlan"), c.get("vlan"), "worse")

    cur_modes, base_modes = _iface_map(current, "link_modes"), _iface_map(baseline, "link_modes")
    for iface in sorted(set(cur_modes) & set(base_modes)):
        c, b = cur_modes[iface], base_modes[iface]
        cs, bs = c.get("speed_mbps"), b.get("speed_mbps")
        if cs != bs and cs is not None and bs is not None:
            direction = "worse" if (cs or 0) < (bs or 0) else "better"
            changes.append({"what": f"{iface} link speed", "before": bs, "after": cs,
                            "direction": direction})
        note(f"{iface} duplex", b.get("duplex"), c.get("duplex"),
             "worse" if c.get("duplex") == "half" else "better")
        note(f"{iface} MTU", b.get("mtu"), c.get("mtu"), "worse")
        # A link that was up on the last visit and is down on this one. The
        # live checks deliberately say nothing about an interface being down,
        # because from one visit there is no way to tell a failed link from a
        # spare NIC nobody ever plugged in - and calling an unused port a fault
        # is the kind of noise that gets a tool ignored. A baseline settles
        # that: this one was up when somebody last looked.
        #
        # No rate discipline here, unlike the counters below. A link state is
        # not a share of anything - it changed or it did not - so there is
        # nothing for a floor to protect against.
        before_state, after_state = b.get("operstate"), c.get("operstate")
        if before_state and after_state and before_state != after_state:
            was_up, now_up = _operationally_up(before_state), _operationally_up(after_state)
            changes.append({
                "what": f"{iface} link state", "before": before_state, "after": after_state,
                "direction": ("worse" if was_up and not now_up
                              else "better" if now_up and not was_up else "neutral")})

    # An interface that was there last time and is not now. A NIC that has been
    # renamed, removed, or failed to come back after a reboot is a change of
    # the same kind as one that went down, and the loop above cannot see it -
    # it only walks the interfaces both visits have.
    for iface in sorted(set(base_modes) - set(cur_modes)):
        changes.append({"what": f"{iface} interface", "before": "present",
                        "after": "no longer present", "direction": "worse"})

    cur_stats, base_stats = _iface_map(current, "link_stats"), _iface_map(baseline, "link_stats")
    for iface in sorted(set(cur_stats) & set(base_stats)):
        c, b = cur_stats[iface], base_stats[iface]
        # Counters reset on reboot, so a lower value means the box restarted -
        # reporting that as "-4000 errors" would be nonsense.
        if (c.get("packets") or 0) < (b.get("packets") or 0):
            changes.append({"what": f"{iface} counters", "before": "higher",
                            "after": "reset (device rebooted since the baseline)",
                            "direction": "neutral"})
            continue
        gained = (c.get("errors") or 0) - (b.get("errors") or 0)
        if gained > 0:
            # A change measured against a baseline still has to be worth
            # something in its own right. One new error between two visits is
            # a relative deterioration of infinity and an absolute nothing,
            # and it used to raise regression_since_baseline every time - so a
            # healthy box re-checked next week reported that it had got worse.
            #
            # The bar is the one the live check already applies to the same
            # counter: a rate, over enough traffic to be a rate. Below it the
            # change is still reported, because it did happen and somebody
            # hunting an intermittent fault wants to see it - just not as a
            # regression.
            moved = (c.get("packets") or 0) - (b.get("packets") or 0)
            ppm = (gained * 1_000_000.0 / moved) if moved else None
            material = (ppm is not None and ppm >= ERR_PPM_WARN
                        and moved >= MIN_PACKETS_FOR_RATE)
            changes.append({"what": f"{iface} errors since baseline", "before": b.get("errors"),
                            "after": c.get("errors"),
                            "direction": "worse" if material else "neutral",
                            "delta": gained,
                            "per_million": round(ppm, 1) if ppm is not None else None})

    cq, bq = current.get("call_quality") or {}, baseline.get("call_quality") or {}
    if (same_target and cq.get("mos") is not None and bq.get("mos") is not None
            and abs(cq["mos"] - bq["mos"]) >= 0.2):
        # Same rule as the counters above. A score that fell from 4.5 to 4.2
        # moved in the wrong direction and is still a call nobody would
        # complain about, so it is reported and not called a regression.
        fell = cq["mos"] < bq["mos"]
        changes.append({"what": "call quality (MOS)", "before": bq["mos"], "after": cq["mos"],
                        "direction": ("worse" if fell and cq["mos"] < MOS_WARN
                                      else "better" if not fell else "neutral")})

    def resolver_set(rep):
        return sorted(r["server"] for r in (_dict(_dict(_dict(rep).get("raw")).get("dns_health"))
                                            .get("resolvers") or []))
    note("DNS resolvers", ", ".join(resolver_set(baseline)) or None,
         ", ".join(resolver_set(current)) or None)

    def answer_set(rep):
        """What the probe name resolved to, across every resolver that answered."""
        answers = set()
        for r in (_dict(_dict(_dict(rep).get("raw")).get("dns_health")).get("resolvers") or []):
            answers.update(r.get("answers") or [])
        return sorted(answers)

    # Which resolvers are configured is one question; what they answer is
    # another, and only the second changes when a service moves - or when
    # something between here and them starts answering differently.
    # Neutral, not "worse". Any load-balanced or CDN-fronted name hands out a
    # different address run to run, and only "worse" changes raise
    # regression_since_baseline - so calling this a deterioration made a
    # healthy repeat visit report a regression, intermittently, for nothing.
    # Worth telling the operator; not worth calling a fault.
    note("resolves to", ", ".join(answer_set(baseline)) or None,
         ", ".join(answer_set(current)) or None)

    if same_target:
        note("hops to target", len(baseline.get("hops") or []) or None,
             len(current.get("hops") or []) or None)
        note("site edge at hop", baseline.get("demarc_hop"), current.get("demarc_hop"), "worse")

    cv, bv = current.get("verdict") or {}, baseline.get("verdict") or {}
    # The verdict is built from these findings, so during a live run it doesn't
    # exist yet - diagnose adds this row afterwards. Only compare when both
    # sides actually have one (i.e. two saved reports).
    if cv.get("headline") and bv.get("headline") and cv["headline"] != bv["headline"]:
        rank = {"ok": 0, "warning": 1, "critical": 2}
        direction = ("worse" if rank.get(cv.get("severity"), 0) > rank.get(bv.get("severity"), 0)
                     else "better" if rank.get(cv.get("severity"), 0) < rank.get(bv.get("severity"), 0)
                     else "neutral")
        changes.append({"what": "verdict", "before": bv.get("headline"),
                        "after": cv.get("headline"), "direction": direction})
    return changes


def collection_coverage(raw):
    """(collections that returned data, collections attempted).

    Not every check runs everywhere - ss is Linux-only, optics need a fibre
    module, the counters need /proc. That is handled honestly per finding, and
    then ignored entirely when stating how sure we are of the conclusion drawn
    from what did run. This is the number that was missing.

    A check that *cannot* apply here is not a check that failed, and counting
    it as one punishes the wrong boxes: a cloud instance has no fibre optics,
    no switch neighbour and no ethtool, so it scored low coverage and had every
    verdict marked down in confidence for running on the hardware it runs on.
    Those are excluded from the denominator entirely - the figure is meant to
    say how much of what could have run did.
    """
    attempted = [v for v in (raw or {}).values()
                 if isinstance(v, dict) and ("ok" in v or "error" in v)
                 and v.get("applicable") is not False]
    return sum(1 for v in attempted if v.get("ok")), len(attempted)


def _same_scope(a, b):
    """Are two findings about the same thing?

    Interface findings carry the interface they came from. Two that name
    different ones are separate faults however alike they look. A finding with
    no scope is about the box rather than one of its interfaces, and can
    corroborate anything - the softnet backlog belongs to all of them.
    """
    one, two = a.get("scope"), b.get("scope")
    return one is None or two is None or one == two


def _sides_can_agree(a, b):
    """Can a fault facing `a` explain, or corroborate, one facing `b`?

    Only if they face the same way, or one of them is local - this box and its
    own link sit in both paths, so a fault there explains symptoms in either
    direction. Two faults facing opposite ways are two faults.
    """
    return a == b or "local" in (a, b)


# Findings whose code does not say which check they came from. The heuristic
# below splits on the first word, which is right for four port results and
# wrong for these: the call score is computed from the same round trip that
# latency_high reports and the wall is that delay located on the path, so
# treating them as separate families let one number read as three agreeing
# opinions and put a slow path at high confidence on a single measurement.
# Which check a finding came from, where the first word of its code does not
# say. The heuristic below splits on that word, which is right for four port
# results and wrong in two directions - it can put one check's outputs in
# different families, and it can merge two checks that happen to share a
# prefix. Both are corrected here.
SHARED_FAMILY = {
    # "own_" marks whose service it is, not which check looked at it. Reading
    # the certificate this box serves and making an HTTP request to it are two
    # separate checks of two separate things, and grouping them meant an
    # expired certificate could not corroborate the service erroring - two
    # independent signals counted as one, which understates a real fault.
    "own_tls_expired": "own_cert",
    "own_tls_expiring": "own_cert",
    "own_tls_handshake_failed": "own_cert",
    "own_tls_untrusted": "own_cert",
    "own_service_erroring": "own_service",
    "own_service_not_http": "own_service",
    "own_service_silent": "own_service",
    "own_service_upstream_error": "own_service",
    # This box failing to take delivery, counted in two places. The kernel's
    # own backlog and the adapter's ring are the same complaint at two depths,
    # so neither is independent evidence for the other.
    "nic_drops_live": "backlog",
    "nic_drops_historical": "backlog",
    "nic_ring_overruns": "backlog",
    "udp_recv_buffer_full": "backlog",
    # One link running below par, said two ways. slow_link owns the absolute
    # case and this owns the relative one, so they are the same check and must
    # not confirm each other.
    "slow_link": "link_speed",
    "negotiated_below_capacity": "link_speed",
    "latency_high": "latency",
    "latency_wall": "latency",
    "call_quality_bad": "latency",
    "call_quality_degraded": "latency",
}


def _finding_family(code):
    """Which check a finding came from. Four port results are four instances of
    one check, not four independent signals - counting them as corroboration
    let a speculative port sweep read as 'high confidence'."""
    return SHARED_FAMILY.get(code) or (code or "").split("_")[0]


def _retarget_verdict(verdict, raw):
    """Re-attribute a target verdict when the target was a backend."""
    if (raw or {}).get("target_kind") != "backend":
        return
    code = (verdict.get("based_on") or [None])[0]
    override = BACKEND_TARGET_VERDICTS.get(code)
    if not override:
        return
    verdict["owner"], verdict["headline"], verdict["next_step"] = override


def build_verdict(findings, quick=False, raw=None):
    """Pick the most likely root cause from the findings and say who owns it."""
    by_code = {}
    for f in findings:
        by_code.setdefault(f.get("code"), []).append(f)

    # Codes that describe the run rather than the network don't count as
    # something being wrong - otherwise a truncated port list reads as an
    # unexplained failure.
    real = [f for f in findings
            if f["severity"] != "ok" and f.get("code") not in VERDICT_EXEMPT]
    if not real:
        clear_ran, clear_attempted = collection_coverage(raw)
        clear_pct = (round(100.0 * clear_ran / clear_attempted)
                     if clear_attempted else None)
        return {
            "headline": ("No fault found - this device looks healthy from here"
                         if clear_pct is None or clear_pct >= COVERAGE_GOOD_PCT else
                         f"Nothing wrong in the {clear_ran} check(s) that ran - but "
                         f"{clear_attempted - clear_ran} could not run"),
            "owner": ("nobody - nothing is failing" if clear_pct is None
                      or clear_pct >= COVERAGE_GOOD_PCT else
                      "unclear - this is not a clean bill of health"),
            # Only suggest dropping --quick when it was actually used - otherwise
            # the advice is for checks this run already did.
            "next_step": ("If a problem is still being reported, it's above the network "
                          "layer (the application, or something off this path)."
                          + (" This was a quick run - drop --quick to also check the "
                             "hop-by-hop path and path MTU." if quick else
                             " The path and MTU checks also came back clean.")),
            # Coverage matters most here, not least. "Nothing is wrong" from a
            # box where half the checks could not run is the most dangerous
            # thing this tool can say, and it used to say it with hardcoded
            # high confidence. The fault verdicts below were taught to account
            # for coverage; this path was missed.
            "confidence": ("high" if clear_pct is None or clear_pct >= COVERAGE_GOOD_PCT
                           else "low" if clear_pct < COVERAGE_THIN_PCT else "medium"),
            "coverage": {"ran": clear_ran, "attempted": clear_attempted},
            "corroborated_by": [],
            "unrelated": [],
            "unrelated_total": 0,
            "based_on": [f.get("code") for f in findings],
            "severity": "ok",
        }

    # Anything actively failing right now, ignoring the latent conditions -
    # those describe a risk, not a cause.
    live_critical = any(f["severity"] == "critical" and f.get("code") not in LATENT
                        for f in real)
    for code, owner, headline, next_step in VERDICT_RULES:
        matches = by_code.get(code)
        if not matches:
            continue
        if code in LATENT and live_critical:
            # Still reported, and still eligible to be the answer when nothing
            # is actively broken - just not the headline over a live outage.
            continue
        # Corroboration: an independent second fault at the same or lower layer
        # makes the call stronger; a lone historical signal makes it weaker.
        layer = matches[0].get("layer") or 9
        family = _finding_family(code)
        side = finding_side(code)
        corroborating = [f.get("code") for f in findings
                         if _finding_family(f.get("code")) != family
                         and f["severity"] != "ok"
                         and f.get("code") not in WEAK_EVIDENCE
                         and (f.get("layer") or 9) <= layer
                         # A fault facing the other way is not agreement. A
                         # local one faces both, so it corroborates either.
                         and _sides_can_agree(side, finding_side(f.get("code")))
                         # Nor is a fault on a different cable. Errors on one
                         # interface and collisions on another are two
                         # problems, and counting them as one confirmed twice
                         # made a two-NIC box read as high confidence in
                         # whichever happened to be named.
                         and _same_scope(matches[0], f)]
        if code in WEAK_EVIDENCE:
            confidence = "low"
        elif corroborating:
            confidence = "high"
        else:
            confidence = "medium"
        # How much of the tool actually ran. A conclusion drawn from a third of
        # the checks is not as well supported as one drawn from all of them,
        # and until now the two read identically.
        ran, attempted = collection_coverage(raw)
        pct = round(100.0 * ran / attempted) if attempted else None
        if pct is not None and pct < COVERAGE_THIN_PCT:
            confidence = "low"
        elif pct is not None and pct < COVERAGE_GOOD_PCT and confidence == "high":
            confidence = "medium"
        # Faults this cause cannot explain: a different check, at a higher
        # layer, that fixing this one will leave exactly where it is. The layer
        # rule assumes a chain; where there isn't one it discards the rest.
        # A fault the verdict cannot explain. Higher up the same chain, or -
        # and this is the case a layer number cannot express - facing the
        # opposite way. Client-side loss and loss on the path to a backend are
        # both layer 3, so before this the tool named one and presented the
        # other as its consequence, which it cannot be. Fixing the first would
        # have left the second exactly where it was.
        # Findings above the cause that are the shape a fault below produces.
        # These are its consequences, and saying so is most of the product: a
        # full link reported the loss it was causing as "also, unrelated -
        # suggests upstream congestion", which sends someone to a carrier over
        # a fault on their own box.
        def _above_and_facing_the_same_way(f):
            return ((f.get("layer") or 0) > layer
                    and _sides_can_agree(side, finding_side(f.get("code"))))

        candidates = [f for f in findings
                      if f.get("code") != code
                      and f["severity"] in ("warning", "critical")
                      and f.get("code") not in VERDICT_EXEMPT
                      and _finding_family(f.get("code")) != family]
        explains = [f for f in candidates
                    if f.get("code") in TRANSPORT_SYMPTOMS
                    and _above_and_facing_the_same_way(f)]
        explained = {id(f) for f in explains}
        unrelated = [f for f in candidates
                     if id(f) not in explained
                     and ((f.get("layer") or 0) > layer
                          or not _sides_can_agree(side, finding_side(f.get("code"))))]
        return {
            "headline": headline,
            "owner": owner,
            "next_step": next_step,
            "confidence": confidence,
            "coverage": {"ran": ran, "attempted": attempted},
            "corroborated_by": corroborating,
            # Capped: the point is to stop hiding a second fault, not to hand
            # the findings list back a second time.
            "unrelated": [{"code": f.get("code"), "message": f["message"]}
                          for f in unrelated[:2]],
            # A field that exists so a second fault is not hidden must not
            # quietly hide the third: two shown out of four reads as two.
            "unrelated_total": len(unrelated),
            # The other half of the same question, and the one that was never
            # answered: not what this cause fails to account for, but what it
            # does. Uncapped - a cause that explains six findings has earned
            # the right to say so, and the list is codes rather than messages
            # because they are already printed in full below.
            "explains": [f.get("code") for f in explains],
            "based_on": [code] + corroborating,
            "severity": matches[0]["severity"],
            "detail": matches[0]["message"],
        }

    worst = next((f for f in findings if f["severity"] == "critical"),
                 next((f for f in findings if f["severity"] == "warning"), None))
    return {
        "headline": "Something is failing, but it doesn't match a known pattern",
        "owner": "unclear - read the findings below",
        "next_step": "The findings below are still accurate; this is only the summary "
                     "declining to guess.",
        "confidence": "low",
        # Third path, and the third time this was missed. The targeted fixes
        # each covered the branch in front of them; a test asserting that no
        # path omits coverage is what found this one.
        "coverage": dict(zip(("ran", "attempted"), collection_coverage(raw))),
        "corroborated_by": [],
        "unrelated": [],
        "unrelated_total": 0,
        "based_on": [f.get("code") for f in findings if f["severity"] != "ok"],
        "severity": worst.get("severity", "warning") if worst else "warning",
        "detail": worst.get("message", "") if worst else "",
    }

def _per_day_since_boot(total):
    """(events per day, days of uptime), or (None, None) if that can't be said.

    A lifetime counter needs a denominator. Forty transitions across two years
    is somebody rebooting a switch twice a year; the same forty in a day is a
    dying cable. Under an hour of uptime any rate is an artefact of the box
    having just started, so it reports nothing rather than extrapolating.

    Written once because it had been written three times, each slightly
    differently - one inverted the guard, and one borrowed a threshold named
    after a different check.
    """
    uptime = _uptime_seconds()
    if not total or not uptime or uptime < 3600:
        return None, None
    days = uptime / 86400.0
    return total / days, days


def _check_nic_backlog(stats, findings, counter_window):
    """Packets the kernel dropped because its receive backlog was full."""
    delta = stats.get("delta") or {}
    live_ppm = stats.get("drop_ppm_live")
    live_drops = delta.get("softnet_dropped", 0)

    if live_drops and live_ppm is not None and live_ppm >= SOFTNET_DROP_PPM:
        findings.append({
            "severity": "critical",
            "layer": 2,
            "code": "nic_drops_live",
            "message": f"This device discarded {live_drops:,} incoming packet(s) in the last "
                       f"{counter_window}s because its own receive backlog was full "
                       f"({live_ppm}/million). That is the box failing to pick packets up, "
                       f"not the cable and not the network - but it makes every destination "
                       f"retransmit equally, so it reads exactly like a bad link. Check load "
                       f"and net.core.netdev_max_backlog before touching anything physical."
                       + _load_context(),
        })
    elif stats.get("drop_ppm_lifetime") and stats["drop_ppm_lifetime"] >= SOFTNET_DROP_PPM:
        lifetime = stats.get("lifetime", {})
        findings.append({
            "severity": "warning",
            "layer": 2,
            "code": "nic_drops_historical",
            "message": f"This device has discarded {lifetime.get('softnet_dropped', 0):,} "
                       f"incoming packet(s) since boot because its receive backlog filled "
                       f"({stats['drop_ppm_lifetime']}/million), though none during this run. "
                       f"Worth knowing before blaming the network for loss that comes and "
                       f"goes with load on this box.",
        })


def _check_conntrack_table(stats, findings, counter_window):
    """Connection tracking: how full the table is, and whether it has refused."""
    delta = stats.get("delta") or {}
    # Connection tracking: pressure, and whether it has already refused.
    ct_refused = delta.get("ct_insert_failed", 0) + delta.get("ct_drop", 0)
    lifetime = stats.get("lifetime") or {}
    ct_count, ct_max = lifetime.get("ct_count"), lifetime.get("ct_max")
    ct_pct = round(100.0 * ct_count / ct_max, 1) if ct_count is not None and ct_max else None
    if ct_refused:
        findings.append({
            "severity": "critical",
            "layer": 4,
            "code": "conntrack_drops_live",
            "message": f"The connection tracking table refused {ct_refused} new connection(s) "
                       f"in the last {counter_window}s"
                       + (f" - it is {ct_pct}% full ({ct_count:,} of {ct_max:,})" if ct_pct
                          else "")
                       + f". Traffic isn't leaving this device, so it will look like the "
                         f"network dropping connections at random while every check here "
                         f"passes. Raise nf_conntrack_max, or stop tracking what doesn't "
                         f"need it." + _load_context(),
        })
    elif ct_pct is not None and ct_pct >= CONNTRACK_WARN_PCT:
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "conntrack_near_limit",
            "message": f"The connection tracking table is {ct_pct}% full ({ct_count:,} of "
                       f"{ct_max:,}). Nothing has been refused yet. At 100% new connections "
                       f"start failing for no visible reason, so this is worth raising "
                       f"before it is the thing someone is calling about." + _load_context(),
        })
    else:
        past = (lifetime.get("ct_insert_failed") or 0) + (lifetime.get("ct_drop") or 0)
        per_day, _days = _per_day_since_boot(past)
        if per_day is not None:
            if per_day >= CONNTRACK_REFUSAL_PER_DAY:
                findings.append({
                    "severity": "warning",
                    "layer": 4,
                    "code": "conntrack_drops_historical",
                    "message": f"The connection tracking table has refused {past:,} connection(s) "
                               f"since boot - about {per_day:.0f} a day, none during this run"
                               + (f", and it is {ct_pct}% full now" if ct_pct else "")
                               + f". It fills under load, so this explains failures that "
                                 f"cluster at busy times and never reproduce afterwards.",
                })


def _check_connection_setup(stats, findings, counter_window):
    """Is it connection setup that's failing, or traffic once it's up?

    A SYN is one packet sent before anything has warmed up - no window, no
    congestion state, nothing to recover from. Losing it repeatedly while
    established traffic flows fine is not general loss; it points at something
    that treats connection setup differently. A stateful firewall out of
    session slots, SYN-flood protection, or a middlebox dropping what it can't
    place. The existing retransmit rate mixes this in with everything else and
    cannot tell you which.
    """
    delta = stats.get("delta") or {}
    lifetime = stats.get("lifetime") or {}
    live_syn, live_opens = delta.get("TCPSynRetrans", 0), delta.get("ActiveOpens", 0)
    if live_opens >= 20 and live_syn:
        pct = round(100.0 * live_syn / live_opens, 1)
        if pct >= SYN_RETRANS_PCT:
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "syn_retrans_high",
                "message": f"{pct}% of the connections this device opened in the last "
                           f"{counter_window}s needed their SYN sent again "
                           f"({live_syn} of {live_opens}). A SYN is a single packet sent "
                           f"before anything has warmed up, so losing it repeatedly while "
                           f"established traffic is fine points at something treating "
                           f"connection setup differently - a stateful firewall out of "
                           f"session slots, or flood protection in the path.",
            })
    live_fails = delta.get("AttemptFails", 0)
    if live_opens >= 20 and live_fails:
        pct = round(100.0 * live_fails / live_opens, 1)
        if pct >= ATTEMPT_FAIL_PCT:
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "connect_failures_high",
                "message": f"{pct}% of the connections this device tried to open in the last "
                           f"{counter_window}s never established at all ({live_fails} of "
                           f"{live_opens}). Not a retransmitted SYN that eventually got "
                           f"through - these gave up. Measured on this box's real traffic, "
                           f"so it covers destinations no check here probes.",
            })

    # Resets this box sent. Collected for a while before anything read them:
    # on a box that answers requests these are the wire-level shape of every
    # refusal it makes, and a client on the end of one sees a connection
    # dropped rather than a slow one - which is reported as the network and is
    # not the network.
    live_rsts = delta.get("OutRsts", 0)
    live_conns = delta.get("PassiveOpens", 0) + live_opens
    if live_rsts and live_conns >= 20:
        pct = round(100.0 * live_rsts / live_conns)
        if pct >= RESETS_PER_CONN_PCT:
            estab = delta.get("EstabResets", 0)
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "resets_sent_high",
                "message": f"This device sent {live_rsts:,} TCP reset(s) in the last "
                           f"{counter_window}s against {live_conns:,} connection(s) it "
                           f"opened or accepted ({pct}%). The resets are coming from here, "
                           f"not arriving here"
                           + (f", and {estab:,} of the connections torn down were already "
                              f"established rather than refused at the door"
                              if estab else
                              ", and none of them were established connections, so this is "
                              "refusal at the door rather than sessions dying")
                           + ". A listener that has stopped, a port nothing is bound to, or "
                             "an application aborting instead of closing all look like this. "
                             "Whoever is on the other end sees a connection dropped, not a "
                             "slow one, and reports it as the network.",
            })

    # Connections that were up and were then killed. The counter cannot say
    # which end sent the reset - it counts the transition, not the direction -
    # but this box knows how many resets *it* sent, and when that is a small
    # part of the total the rest arrived from outside. Said as an inference
    # rather than a measurement, because that is what it is.
    live_estab = delta.get("EstabResets", 0)
    if live_estab and live_conns >= 20:
        pct = round(100.0 * live_estab / live_conns)
        ours = delta.get("OutRsts", 0)
        if pct >= ESTAB_RESET_PCT and ours < live_estab:
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "connections_reset_by_peer",
                "message": f"{live_estab:,} connection(s) that had been established were "
                           f"torn down abruptly in the last {counter_window}s rather than "
                           f"closed - {pct}% of the {live_conns:,} this device opened or "
                           f"accepted. This box sent {ours:,} reset(s) of its own, so most "
                           f"of these came from the other end or from something in the "
                           f"middle. The counter records the teardown and not who sent it, "
                           f"so that last part is inference rather than measurement. A "
                           f"session-tracking firewall timing connections out, a load "
                           f"balancer recycling them, or a backend restarting all look "
                           f"like this from here.",
            })

    # How much of the retransmission was unnecessary. A DSACK is the far end
    # saying "I already had that" - direct evidence the data was not lost, only
    # late. Every retransmit-based finding here reads as loss without this.
    live_dsack = delta.get("TCPDSACKRecv", 0) + delta.get("TCPDSACKOfoRecv", 0)
    live_retrans = delta.get("RetransSegs", 0)
    if live_dsack and live_retrans:
        pct = round(100.0 * live_dsack / live_retrans, 1)
        if pct >= SPURIOUS_RETRANS_PCT:
            reorder = delta.get("TCPSACKReorder", 0) + delta.get("TCPOFOQueue", 0)
            findings.append({
                "severity": "warning",
                "layer": 3,
                "code": "retrans_spurious",
                "message": f"{pct}% of this device's retransmissions in the last "
                           f"{counter_window}s were unnecessary - the far end acknowledged "
                           f"data it already had ({live_dsack} of {live_retrans}). That is "
                           f"not a lossy path: the packets arrived, out of order or late "
                           f"enough for TCP to give up waiting"
                           + (f", and {reorder} reordering event(s) were seen alongside"
                              if reorder else "")
                           + f". Read the retransmit and per-destination loss figures below "
                             f"with that in mind - they count these too. Per-packet load "
                             f"balancing across a bundle is the usual cause.",
            })

    # Segments that arrived corrupted. Ethernet's CRC catches damage on the
    # wire, so anything reaching here failed a check the link layer passed -
    # which means it was corrupted somewhere that re-framed the packet.
    live_csum, live_in = delta.get("InCsumErrors", 0), delta.get("InSegs", 0)
    if live_csum and live_in:
        ppm = round(live_csum * 1_000_000.0 / live_in, 1)
        if ppm >= CSUM_ERR_PPM:
            findings.append({
                "severity": "warning",
                "layer": 3,
                "code": "tcp_checksum_errors",
                # The rate is quoted only when there were enough segments for
                # it to be one. This finding is deliberately count-based - a
                # bad checksum should never happen, so one is worth saying -
                # but one error in two segments is 500,000 per million, and
                # printing that reads as a catastrophe rather than as a single
                # packet on a nearly idle box.
                "message": f"{live_csum} segment(s) arrived with a bad TCP checksum in the "
                           f"last {counter_window}s"
                           + (f" ({ppm} per million received)"
                              if live_in >= MIN_WINDOW_PACKETS_FOR_RATE else
                              f" (out of {live_in:,} received - too few for a rate)")
                           + f". Ethernet "
                           f"has its own CRC, so these passed the link layer and failed "
                           f"here - the corruption happened somewhere that re-framed the "
                           f"packet after that check, which means a device in the path or "
                           f"an offload engine on this one, not the cable into it. TCP "
                           f"recovers by retransmitting, so it reads as unexplained "
                           f"slowness rather than as an error.",
            })

    # Packets the kernel threw away because it could not find memory for them.
    pruned = delta.get("RcvPruned", 0) + delta.get("PruneCalled", 0)
    if pruned:
        findings.append({
            "severity": "critical",
            "layer": 4,
            "code": "rcv_buffer_pruned",
            "message": f"The kernel discarded data from {pruned} received packet(s) in the "
                       f"last {counter_window}s because it could not allocate socket memory "
                       f"for them. That is this device running out of buffer, not the "
                       f"network losing anything - and it produces retransmits that look "
                       f"exactly like a lossy path." + _load_context(),
        })


# Share of the ephemeral range in use before outbound connections are at risk.
# A proxy holding this many sockets is close to being unable to open another,
# and the failure looks exactly like the far end refusing it.
EPHEMERAL_PRESSURE_PCT = 80

# Share of the system-wide file descriptor ceiling in use before a box serving
# traffic is in danger of not being able to accept.
FD_PRESSURE_PCT = 80

# SYN_RECV sockets before half-open connections are worth reporting. A busy
# server always has some; a queue full of them is a backlog that cannot drain
# or something opening connections it never completes.
SYN_RECV_HIGH = 256

# Share of the connections this box handled that ended with the peer having
# stopped answering. Some of this is normal on any public service - clients
# walk away, laptops close - so the bar is where it stops looking like people
# and starts looking like a path.
ABORT_TIMEOUT_PCT = 2.0


def _check_server_limits(stats, findings, counter_window, raw):
    """Local ceilings that a service hits and that present as network faults.

    Nothing here is the network. Each is a limit on this box that, from the
    outside and from every other check in this tool, is indistinguishable from
    the path being broken - which is exactly why they belong in a tool whose
    job is deciding which it is.
    """
    life, delta = stats.get("lifetime") or {}, stats.get("delta") or {}
    sock = raw.get("sockets") or {}
    states = sock.get("states") or {}

    # Syncookies: the kernel saying the accept queue overflowed, in words.
    cookies = delta.get("SyncookiesSent") if delta else None
    if cookies:
        findings.append({
            "severity": "critical",
            "layer": 4,
            "code": "syncookies_live",
            "message": f"The kernel sent {cookies:,} SYN cookie(s) in the last "
                       f"{counter_window}s. That is it telling you outright that a listen "
                       f"queue overflowed: connections arrived faster than the service "
                       f"accepted them, and the kernel fell back to cookies to avoid "
                       f"dropping them outright. Either the backlog is too small, the "
                       f"service is too slow to accept, or something is flooding it."
                       + _load_context(),
        })
    elif life.get("SyncookiesSent"):
        per_day, days = _per_day_since_boot(life["SyncookiesSent"])
        if per_day is not None and per_day >= 1:
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "syncookies_historical",
                "message": f"{life['SyncookiesSent']:,} SYN cookie(s) sent over {days:.1f} "
                           f"days of uptime - about {per_day:.0f} a day. None during this "
                           f"run, so the accept queue is not overflowing right now, but it "
                           f"has been. This is the signature of a listen backlog that is too "
                           f"small for the peaks this box actually sees.",
            })

    # Ephemeral ports. The pressure is per destination, not global: a source
    # port is only required to be unique within the four-tuple, so the same one
    # can serve any number of different destinations at once. Counting every
    # outbound socket against the range - which this did - reports exhaustion
    # on a box that brokers traffic to thousands of places and has enormous
    # headroom, because its connections are spread across all of them.
    total = life.get("ephemeral_total")
    worst = sock.get("outbound_worst_count") or 0
    if total and worst:
        dests = sock.get("outbound_destinations") or 1
        where = sock.get("outbound_worst_dest") or "one destination"
        pct = round(worst * 100.0 / total, 1)
        if pct >= EPHEMERAL_PRESSURE_PCT:
            findings.append({
                "severity": "critical" if pct >= 95 else "warning",
                "layer": 4,
                "code": "ephemeral_ports_low",
                "message": f"{worst:,} connections are open to {where} alone - {pct}% of the "
                           f"{total:,} ports in {life['ephemeral_low']}-"
                           f"{life['ephemeral_high']}. A source port only has to be unique "
                           f"per destination, so this is the number that matters rather than "
                           f"the {sock.get('outbound') or worst:,} outbound connections "
                           f"spread across {dests:,} destination(s). When the range is "
                           f"exhausted for that destination this box cannot open another "
                           f"connection to it, and the failure looks exactly like the far "
                           f"end refusing it. Widen ip_local_port_range, or find what is "
                           f"holding the sockets (TIME_WAIT is "
                           f"{states.get('TIME_WAIT', 0):,}).",
            })

    # File descriptors: at the ceiling a service simply stops accepting.
    fd_used, fd_max = life.get("fd_used"), life.get("fd_max")
    if fd_used and fd_max:
        pct = round(fd_used * 100.0 / fd_max, 1)
        if pct >= FD_PRESSURE_PCT:
            findings.append({
                "severity": "critical" if pct >= 95 else "warning",
                "layer": 4,
                "code": "fd_pressure",
                "message": f"{fd_used:,} of {fd_max:,} file descriptors are allocated "
                           f"system-wide ({pct}%). A box at this ceiling stops accepting "
                           f"connections, and from the client's side that is "
                           f"indistinguishable from the network being down. Nothing on the "
                           f"wire is wrong.",
            })

    # Out of socket memory. Unambiguous, and never normal.
    if (delta or {}).get("TCPAbortOnMemory"):
        findings.append({
            "severity": "critical",
            "layer": 4,
            "code": "aborts_on_memory",
            "message": f"This box tore down {delta['TCPAbortOnMemory']:,} connection(s) in "
                       f"the last {counter_window}s because it had no memory for them. That "
                       f"is not the network refusing anything - it is this box running out "
                       f"of socket memory and killing established connections to cope. "
                       f"Check tcp_mem and how much the service is buffering."
                       + _load_context(),
        })

    # SYNs dropped before they ever reached a queue.
    if (delta or {}).get("TCPReqQFullDrop"):
        findings.append({
            "severity": "critical",
            "layer": 4,
            "code": "reqq_full_drops",
            "message": f"{delta['TCPReqQFullDrop']:,} incoming connection attempt(s) were "
                       f"dropped in the last {counter_window}s because the SYN queue was "
                       f"full. The client sees a connection that never opens and retries, "
                       f"which is indistinguishable from packet loss on the path - and there "
                       f"is none. Raise tcp_max_syn_backlog and the service's own backlog.",
        })

    # Peers that stopped answering, as a share of what this box handled.
    aborts = (delta or {}).get("TCPAbortOnTimeout") or 0
    handled = ((delta or {}).get("PassiveOpens") or 0) + ((delta or {}).get("ActiveOpens") or 0)
    if aborts and handled >= 100:
        pct = round(aborts * 100.0 / handled, 1)
        if pct >= ABORT_TIMEOUT_PCT:
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "aborts_on_timeout",
                "message": f"{aborts:,} of {handled:,} connection(s) in the last "
                           f"{counter_window}s ({pct}%) were torn down because the other end "
                           f"stopped answering. Some of that is ordinary on a public "
                           f"service - people close laptops - but at this share it is a path "
                           f"that is dropping traffic mid-connection rather than users "
                           f"leaving. The per-destination split says which side.",
            })

    # Half-open connections piling up.
    syn_recv = states.get("SYN_RECV", 0)
    if syn_recv >= SYN_RECV_HIGH:
        somaxconn = life.get("somaxconn")
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "syn_recv_backlog",
            "message": f"{syn_recv:,} connection(s) are half-open in SYN_RECV"
                       + (f", against a somaxconn of {somaxconn:,}" if somaxconn else "")
                       + ". Clients started a handshake this box never finished. Either the "
                         "accept queue is not draining, or connections are being opened and "
                         "abandoned - the two look identical here, and the syncookie counter "
                         "above tells them apart.",
        })


def _check_accept_queues(stats, findings, counter_window):
    """Connections a service here turned away with a full accept queue."""
    delta = stats.get("delta") or {}
    live_overflow = delta.get("ListenOverflows", 0)
    if live_overflow:
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "accept_overflow_live",
            "message": f"A service on this device turned away {live_overflow} connection(s) in "
                       f"the last {counter_window}s because its accept queue was full. Clients "
                       f"see a refusal or a hang and report the network - but nothing here "
                       f"reached the network. The application isn't accepting fast enough, or "
                       f"its listen backlog is too small." + _load_context(),
        })
    else:
        total = (stats.get("lifetime") or {}).get("ListenOverflows")
        per_day, _days = _per_day_since_boot(total)
        if per_day is not None:
            if per_day >= ACCEPT_OVERFLOW_PER_DAY:
                findings.append({
                    "severity": "warning",
                    "layer": 4,
                    "code": "accept_overflow_historical",
                    "message": f"Services on this device have turned away {total:,} connection(s) "
                               f"since boot with a full accept queue - about {per_day:.0f} a day, "
                               f"none during this run. That is a load problem on this box that "
                               f"gets reported as the network being unreliable.",
                })


def _check_kernel_drops(raw, findings, counter_window, baseline):
    """Loss this box causes itself.

    Every other check here measures the network. These three measure the device
    failing to pick traffic up - and because that makes every destination fail
    equally, they wear the same signature as a bad link. Reported above the
    per-flow split for exactly that reason.
    """
    raw["kernel_drops"] = cmd_kernel_drops(counter_window if baseline else 0,
                                           baseline=baseline)
    stats = raw["kernel_drops"]
    if not stats.get("ok"):
        return
    _check_nic_backlog(stats, findings, counter_window)
    _check_conntrack_table(stats, findings, counter_window)
    _check_accept_queues(stats, findings, counter_window)
    _check_connection_setup(stats, findings, counter_window)
    _check_server_limits(stats, findings, counter_window, raw)
    _check_thermal(stats, findings, counter_window)
    _check_udp(stats, findings, counter_window)
    _check_fragments(stats, findings, counter_window)
    _check_orphans(stats, findings, counter_window)


def _check_udp(stats, findings, counter_window):
    """Datagrams this box did not take delivery of.

    Nothing else here looks at UDP, and DNS is UDP. A box overflowing its
    receive buffers loses resolver answers while every TCP check in this tool
    passes - so the report reads as a slow or failing resolver, and the fault
    is on this side of the wire.
    """
    delta = stats.get("delta") or {}
    got = delta.get("udp_InDatagrams", 0)
    rcvbuf = delta.get("udp_RcvbufErrors", 0)
    errors = delta.get("udp_InErrors", 0)
    if rcvbuf >= UDP_DROP_FLOOR and got:
        pct = round(100.0 * rcvbuf / (got + rcvbuf), 1)
        if pct >= UDP_DROP_PCT:
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "udp_recv_buffer_full",
                "message": f"This device dropped {rcvbuf:,} incoming datagram(s) in the last "
                           f"{counter_window}s because the receiving socket had no room "
                           f"({pct}% of the {got + rcvbuf:,} that arrived). UDP has no "
                           f"retransmission and no window, so a datagram dropped here is "
                           f"gone and the sender is never told. DNS runs over UDP: this "
                           f"presents as a resolver that is slow or flaky while every other "
                           f"check here passes, and the resolver is fine." + _load_context(),
            })

    # InErrors contains RcvbufErrors one for one. What is left over arrived and
    # failed before any socket saw it - a bad checksum, a truncated header -
    # which is damage in the path rather than this box failing to keep up, and
    # a different thing to go and look at.
    other = errors - rcvbuf
    if other >= UDP_DROP_FLOOR and got:
        pct = round(100.0 * other / (got + errors), 1)
        if pct >= UDP_DROP_PCT:
            findings.append({
                "severity": "warning",
                "layer": 3,
                "code": "udp_datagrams_corrupt",
                "message": f"{other:,} incoming datagram(s) were discarded in the last "
                           f"{counter_window}s for something other than a full buffer "
                           f"({pct}% of arrivals). This box had room for them; they failed "
                           f"a checksum or arrived malformed, so they were damaged on the "
                           f"way here. Ethernet has its own CRC, so whatever re-framed them "
                           f"after that did it - a device in the path or an offload engine "
                           f"on this one, not the cable.",
            })


def _check_fragments(stats, findings, counter_window):
    """Fragments that arrived and never came back together.

    The path-MTU probe measures this from the sending side. This is the same
    problem seen from the receiving side, and it is evidence the probe cannot
    produce: it is about traffic other people sent to this box.
    """
    delta = stats.get("delta") or {}
    tried, failed = delta.get("ip_ReasmReqds", 0), delta.get("ip_ReasmFails", 0)
    if failed >= REASM_FAIL_FLOOR and tried:
        pct = round(100.0 * failed / tried, 1)
        if pct >= REASM_FAIL_PCT:
            findings.append({
                "severity": "warning",
                "layer": 3,
                "code": "fragments_lost",
                "message": f"{failed:,} of {tried:,} fragmented packet(s) failed to "
                           f"reassemble in the last {counter_window}s ({pct}%). The pieces "
                           f"arrived and the whole never did, which means some of them did "
                           f"not turn up inside the reassembly timeout. Something on the "
                           f"path is fragmenting traffic to this box and losing part of it "
                           f"- the usual cause is an MTU step somewhere with the ICMP that "
                           f"would report it filtered, so the sender never learns to send "
                           f"smaller packets.",
            })


def _check_orphans(stats, findings, counter_window):
    """Connections torn down without being closed, against the ceiling."""
    live = stats.get("lifetime") or {}
    count, limit = live.get("tcp_orphans"), live.get("tcp_max_orphans")
    if not count or not limit:
        return
    pct = round(100.0 * count / limit)
    if pct >= ORPHAN_WARN_PCT:
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "tcp_orphans_high",
            "message": f"{count:,} orphaned TCP socket(s) against a ceiling of {limit:,} "
                       f"({pct}%). An orphan is a connection with no file descriptor left "
                       f"to close it, still holding kernel memory. The kernel counts them "
                       f"at two to four times their weight when it decides whether it is "
                       f"under pressure, so the ceiling bites sooner than the number looks "
                       f"- and past it the kernel stops being polite and resets them, which "
                       f"arrives at the far end as a connection dropped for no reason "
                       f"visible from there.",
        })


def _check_thermal(stats, findings, counter_window):
    """A CPU clocking itself down, which every network check reads as the network.

    Throttling costs cycles exactly where a box that moves packets needs them:
    the softnet backlog fills, latency spikes, retransmits climb, and every one
    of those is a finding here that points somewhere else. None of them is
    wrong - they are all downstream of a box that is too hot to run at speed.
    """
    delta, lifetime = stats.get("delta") or {}, stats.get("lifetime") or {}
    live = max(delta.get("core_throttles", 0), delta.get("package_throttles", 0))
    total = max(lifetime.get("core_throttles", 0), lifetime.get("package_throttles", 0))
    if live:
        findings.append({
            "severity": "critical",
            "layer": 1,
            "code": "cpu_throttled_live",
            "message": f"This device's CPU was thermally throttled {live:,} time(s) in the "
                       f"last {counter_window}s ({total:,} since boot). It is clocking itself "
                       f"down to survive, right now, and the cycles it loses are the ones "
                       f"that move packets - a full receive backlog, latency that spikes for "
                       f"no reason on the wire, and retransmits are all downstream of this "
                       f"rather than faults of their own. Check airflow, intake dust and fan "
                       f"health before anything on the network." + _load_context(),
        })
    elif total:
        findings.append({
            "severity": "warning",
            "layer": 1,
            "code": "cpu_throttled_historical",
            "message": f"This device's CPU has been thermally throttled {total:,} time(s) "
                       f"since boot, but not during this {counter_window}s check. Cooling "
                       f"that is marginal rather than failed: it happens under load and "
                       f"stops when the load does, which is exactly the shape of a problem "
                       f"that only appears at the busiest time of day and never reproduces "
                       f"afterwards.",
        })

def _check_clock(raw, findings):
    """A clock that has drifted, which is a device fault reported as a service one.

    Deliberately a warning even at five minutes out, rather than critical.
    Everything this tool calls critical is the network chain being broken, and
    a wrong clock breaks nothing on the wire - it breaks authentication,
    certificate validation and log correlation, none of which the stage strip
    models. It ranks above the certificate findings instead, because if the
    clock is wrong then those readings are measuring the clock.
    """
    raw["clock"] = cmd_clock_sync()
    clock = raw["clock"]
    if not clock.get("ok"):
        return
    offset, synced = clock.get("offset_ms"), clock.get("synced")
    if offset is not None and abs(offset) >= CLOCK_SKEW_WARN_MS:
        bad = abs(offset) >= CLOCK_SKEW_BAD_MS
        direction = "ahead of" if offset > 0 else "behind"
        findings.append({
            "severity": "warning",
            "layer": 7,
            "code": "clock_skewed",
            "message": f"This device's clock is {abs(offset) / 1000:.0f}s {direction} its time "
                       f"source (per {clock.get('source')})."
                       + (" That is past the five minutes Kerberos allows, so domain "
                          "authentication will be failing, and certificate validity "
                          "windows start to bite."
                          if bad else
                          " Not enough to break authentication, but enough to make logs "
                          "from this box impossible to line up with anything else.")
                       + " Every certificate result in this report is measured against "
                         "this clock.",
        })
    elif synced is False:
        findings.append({
            "severity": "warning",
            "layer": 7,
            "code": "clock_unsynced",
            "message": f"This device is not synchronised to any time source "
                       f"({clock.get('source')} reports no usable peer). The clock may be "
                       f"right now and will drift. When it does, it breaks authentication "
                       f"and certificate checks in ways that look like the service is at "
                       f"fault rather than this box.",
        })


def _fmt_span(seconds):
    """"40s", "11 minutes", "3 hours" - a field engineer's units, no decimals."""
    if seconds is None:
        return None
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 5400:
        return f"{int(round(seconds / 60))} minutes"
    if seconds < 172800:
        return f"{int(round(seconds / 3600))} hours"
    return f"{int(round(seconds / 86400))} days"


def _fmt_ago(seconds):
    span = _fmt_span(seconds)
    return f"{span} ago" if span else "at an unknown time"


def _check_kernel_log(raw, findings):
    """Faults the kernel timestamped, which the counters can only average.

    The counter checks answer "how much, since boot". This answers "when", and
    the difference decides whether something is history or an outage. It runs
    before _check_link_flaps so the flap check can see what it found and stay
    quiet rather than reporting the same link twice at two different urgencies.
    """
    raw["kernel_log"] = cmd_kernel_log()
    klog = raw["kernel_log"]
    if not klog.get("ok"):
        return

    resets = [e for e in klog["recent"] if e["kind"] == "reset"]
    if resets:
        ifaces = sorted({e["iface"] for e in resets if e["iface"]})
        where = f" on {', '.join(ifaces)}" if ifaces else ""
        findings.append({
            "severity": "critical",
            "layer": 1,
            "code": "nic_reset_logged",
            "message": f"The kernel reset this device's network hardware "
                       f"{len(resets)} time(s){where} in the last hour, most recently "
                       f"{_fmt_ago(min(e['age_seconds'] for e in resets))}: "
                       f"\"{resets[-1]['text'][:120]}\". Every packet in flight is lost "
                       f"each time, and no interface counter records that it happened - "
                       f"the driver or the adapter is failing, not the network.",
        })

    carrier = [e for e in klog["recent"] if e["kind"] == "carrier"]
    if len(carrier) >= KLOG_FLAPS_RECENT:
        oldest = max(e["age_seconds"] for e in carrier)
        newest = min(e["age_seconds"] for e in carrier)
        ifaces = sorted({e["iface"] for e in carrier if e["iface"]})
        raw["kernel_log"]["flapping_ifaces"] = ifaces
        findings.append({
            "severity": "critical",
            "layer": 1,
            "code": "link_flapping_logged",
            "message": f"{', '.join(ifaces) or 'This device'} lost and regained carrier "
                       f"{len(carrier)} time(s) in the last {_fmt_span(oldest)}, most "
                       f"recently {_fmt_ago(newest)} - the kernel logged each one. It is up "
                       f"now, which is why every other check here looks clean, and the "
                       f"lifetime counter averages this away to nothing on a box that has "
                       f"been up a while. This is a physical fault: the cable, the "
                       f"transceiver, or the switch port.",
        })


def _check_link_flaps(raw, findings):
    """Has the link been dropping and coming back?

    Every other link check measures the state the port is in. This one measures
    how often it has left that state - which is the only way a snapshot catches
    a fault that is intermittent by definition. The counter is cumulative since
    boot, so it costs nothing to read and carries months of history into a
    seven-second run.
    """
    # The kernel log has already reported these transitions with their times,
    # which is strictly better evidence. Reporting the same interface twice -
    # once as a critical fault with timestamps, once as a warning about a
    # lifetime average - reads as two problems and buries the first.
    logged = set((raw.get("kernel_log") or {}).get("flapping_ifaces") or [])
    for iface in (raw.get("link_stats") or {}).get("interfaces", []):
        name = iface.get("name", "?")
        if name.startswith("lo") or name in logged:
            continue
        live = iface.get("delta_carrier_changes")
        window = iface.get("sample_seconds")
        if live:
            findings.append({
                "severity": "critical",
                "layer": 1,
                "code": "link_flapping_live", "scope": name,
                "message": f"{name} lost carrier and regained it {live} time(s) in the "
                           f"{window}s this run was watching. A link that drops while you "
                           f"are looking at it is a physical fault - the cable, the "
                           f"transceiver, or the switch port - and every check above this "
                           f"one is measuring a connection that keeps disappearing.",
            })
            continue        # a live flap makes the historical rate a footnote
        total = iface.get("carrier_changes")
        if not isinstance(total, int):
            continue          # no counter is unknown, not "never flapped"
        flaps = max(0, total - LINK_FLAP_BASELINE)
        per_day, days = _per_day_since_boot(flaps)
        if per_day is not None and per_day >= LINK_FLAP_PER_DAY:
            findings.append({
                "severity": "warning",
                "layer": 1,
                "code": "link_flapping", "scope": name,
                "message": f"{name} has lost and regained carrier {flaps} time(s) over "
                           f"{days:.1f} days of uptime - about {per_day:.1f} a day. It is "
                           f"up now, so nothing else here will show it, but a link that "
                           f"keeps dropping explains complaints that come and go and never "
                           f"reproduce while someone is watching. Try --soak to catch it "
                           f"in the act.",
            })


# A site uplink is called full lower than a NIC is. Queues on a CPE are small
# and the line is shared with everything else at the site, so latency and loss
# start well before the last few percent - 70% sustained on a WAN link is
# already the reason someone is complaining.
UPLINK_FULL_PCT = 70

# Below this, the traffic this device is putting through the uplink is too
# small to be filling any line a site would plausibly be sold, so an upstream
# verdict doesn't need the "check your own uplink first" caveat. Above it, the
# tool cannot tell the site's congestion from the carrier's without being told
# the line rate.
UPLINK_UNKNOWN_FLOOR_MBPS = 5

# Verdicts a full site uplink counterfeits exactly: loss, latency, jitter and
# retransmits that hit every destination equally, beyond a locally clean link.
# Each of these blames the path or the provider on evidence that a saturated
# line at the site produces just as well.
CONGESTION_MASQUERADE = {
    "inet_partial_loss", "tcp_flow_loss_all_peers", "tcp_retransmits",
    "call_quality_bad", "call_quality_degraded", "latency_wall",
    "latency_high",
}

# A single hop has to add this many milliseconds, and this share of the whole
# round trip, before it is a wall rather than one hop on a long path. Both are
# needed and the share is the one that makes the finding's own sentence true -
# it says a single hop adds *most* of the delay, so "most" is what it must
# measure. A rule that under-fires on a path with two equal walls is the right
# trade: naming one of them would be a claim that is not true of either.
LATENCY_WALL_MS = 100
LATENCY_WALL_SHARE = 0.5

# Round trip past which the distance explanation runs out. Light in fibre
# covers about 200,000 km/s, so the far side of the planet and back is roughly
# 250ms and the longest real terrestrial paths measure 250-300ms. 400ms leaves
# room for a genuinely long route and still catches delay that is not distance.
# One threshold rather than a warn/critical pair on purpose: the verdict takes
# its severity from the finding that headlines it, so a warning-level rule
# sitting above a critical one would quietly downgrade the whole run.
LATENCY_HIGH_MS = 400

# Utilisation below which a queue overflowing has to be explained by the shape
# of the traffic rather than its volume.
BURST_UTIL_PCT = 25


def _burst_note(raw, iface):
    """Why a queue overflowed on a link the averages say is quiet.

    Throughput here is bytes over the counter window - seconds, not
    milliseconds - so a link that fills completely for fifty milliseconds at a
    time and idles in between averages out to nothing. That is exactly what
    flow tools measure and this cannot: the reading is right and the
    conclusion drawn from it alone would be wrong. Drops on an apparently idle
    link are the one piece of evidence for it available from counters.
    """
    speeds = {i.get("name"): i.get("speed_mbps")
              for i in ((raw.get("link_modes") or {}).get("interfaces") or [])}
    speed = speeds.get(iface.get("name"))
    busiest = max(iface.get("rx_mbps") or 0, iface.get("tx_mbps") or 0)
    if not speed or not busiest:
        return ""
    util = round(100.0 * busiest / speed, 1)
    if util >= BURST_UTIL_PCT:
        return ""
    return (f" The link averaged only {util}% of {speed} Mbps across the window, so the "
            f"queue did not fill from sustained volume - it filled in bursts the average "
            f"cannot show. Throughput here is measured over seconds; a link can be full "
            f"for fifty milliseconds at a time and still read as idle.")


def _check_counters(raw, findings, duplex_by_iface):
    """Error, drop and collision counters, per interface that carries traffic."""
    for iface in raw["link_stats"].get("interfaces", []):
        name = iface["name"]
        # Skip loopback and interfaces that have never passed traffic - every
        # box has a pile of idle virtual interfaces and they're all noise here.
        if name.startswith("lo") or not iface["packets"]:
            continue
        bits = [f"{iface[k]:,} {lbl}" for k, lbl in
                (("crc", "CRC"), ("frame", "frame"), ("overruns", "overrun"),
                 ("collisions", "collision")) if iface[k]]
        detail = f" ({', '.join(bits)})" if bits else ""
        secs = iface["sample_seconds"]

        # Which sub-counter moved decides the owner. rx_errors is an
        # aggregate, and blaming all of it on the cable sent someone to a
        # switch port over a box that could not drain its own ring buffer.
        # rx_errors is the aggregate; these are shares of it. A driver that
        # reports a share larger than the whole is a driver being inconsistent,
        # not evidence - so the shares are capped at the total and what is left
        # over is the link's, never a negative number.
        total_errs = iface["delta_errors"] or 0
        host_errs = min(iface.get("delta_host_errors") or 0, total_errs)
        length_errs = min(iface.get("delta_length_errors") or 0, total_errs - host_errs)
        link_errs = max(total_errs - host_errs - length_errs, 0)
        if iface["delta_errors"] and host_errs > max(link_errs, length_errs):
            findings.append({
                "severity": "critical",
                "code": "nic_ring_overruns", "scope": name,
                "layer": 2,
                "message": f"{name}: {host_errs:,} of {iface['delta_errors']:,} new error(s) in "
                           f"the last {secs}s were the receiver overflowing or the host having "
                           f"no buffer ready. The frames arrived intact and this device failed "
                           f"to take delivery, so nothing about the cable, the optic or the "
                           f"switch port explains it - the ring buffer, the driver, or the CPU "
                           f"that services it does." + _burst_note(raw, iface),
            })
        elif iface["delta_errors"] and length_errs > max(link_errs, host_errs):
            findings.append({
                "severity": "critical",
                "code": "frame_length_errors", "scope": name,
                "layer": 2,
                "message": f"{name}: {length_errs:,} of {iface['delta_errors']:,} new error(s) in "
                           f"the last {secs}s were frames of an invalid length - runts and "
                           f"giants. Frames arriving the wrong size point at something on this "
                           f"segment disagreeing about how big a frame may be, which is an MTU "
                           f"or VLAN-tagging mismatch rather than a damaged link.",
            })
        elif iface["delta_errors"]:
            findings.append({
                "severity": "critical",
                "code": "link_errors_live", "scope": name,
                "layer": 1,
                "message": f"{name}: {iface['delta_errors']:,} new error(s) in the last {secs}s - "
                           f"{iface['errors']:,} total across {iface['packets']:,} packets "
                           f"({iface['err_ppm']}/million){detail}. Errors are incrementing right "
                           f"now, which points at the physical link into this device: cable, "
                           f"connector/SFP, or a duplex mismatch on the switch port.",
            })
        elif (iface["errors"] and iface["err_ppm"] >= ERR_PPM_WARN
                and iface["packets"] >= MIN_PACKETS_FOR_RATE):
            findings.append({
                "severity": "warning",
                "code": "link_errors_historical", "scope": name,
                "layer": 1,
                "message": f"{name}: {iface['errors']:,} errors across {iface['packets']:,} packets "
                           f"({iface['err_ppm']}/million){detail}"
                           + (f", but not incrementing during this {secs}s check" if secs else "")
                           + ". Historical - relevant if the fault is intermittent, but not proof "
                             "of a problem happening now.",
            })

        # Only meaningful on a full-duplex link. If the interface actually
        # negotiated half duplex, collisions are expected for that mode and the
        # duplex finding below is the real story - don't say both.
        if (iface["collisions"] and iface.get("coll_ppm", 0) >= COLL_PPM_WARN
                and iface["packets"] >= MIN_PACKETS_FOR_RATE
                and duplex_by_iface.get(name) != "half"):
            findings.append({
                "severity": "warning",
                "code": "collisions", "scope": name,
                "layer": 1,
                "message": f"{name}: {iface['collisions']:,} collisions across {iface['packets']:,} "
                           f"packets ({iface['coll_ppm']}/million). On a full-duplex link - which "
                           f"nearly all modern switch ports are - collisions shouldn't happen at "
                           f"all, so this is the classic signature of a duplex mismatch between "
                           f"this interface and the switch port it's plugged into.",
            })

        # A discard is not an error. Errors should never happen and are worth
        # reporting on a single occurrence; discards happen every day on a busy
        # box - buffer pressure, traffic it was never going to deliver upwards
        # - and firing on one of them made this the finding that was always
        # present, corroborating whatever else was found and lifting the
        # confidence of conclusions it had nothing to do with.
        window = iface.get("delta_packets") or 0
        drop_pct = (100.0 * iface["delta_drops"] / window
                    if iface["delta_drops"] and window else 0)
        if window >= MIN_WINDOW_PACKETS_FOR_RATE and drop_pct >= DROP_PCT_WARN:
            findings.append({
                "severity": "warning",
                "code": "drops_live", "scope": name,
                "layer": 2,
                "message": f"{name}: {iface['delta_drops']:,} of {window:,} packet(s) discarded in "
                           f"the last {secs}s ({drop_pct:.1f}%, {iface['drops']:,} total). A few "
                           f"discards are normal on any busy interface; this is a share large "
                           f"enough to be losing real traffic. Frames are arriving and this "
                           f"device isn't keeping up - CPU, ring buffer, or driver, rather than "
                           f"the network." + _burst_note(raw, iface),
            })

def _check_link_modes(raw, findings):
    """Negotiated speed, duplex and MTU per interface.

    Returns the primary interface MTU, which the path-MTU probe starts from.
    """
    active_names = {i["name"] for i in raw["link_stats"].get("interfaces", [])
                    if i["packets"] and not i["name"].startswith("lo")}
    collisions_by_iface = {i["name"]: i["collisions"]
                           for i in raw["link_stats"].get("interfaces", [])}
    primary_mtu = None
    for mode in raw["link_modes"].get("interfaces", []):
        name = mode["name"]
        if name not in active_names:
            continue
        if primary_mtu is None and mode.get("mtu"):
            primary_mtu = mode["mtu"]

        if mode.get("duplex") == "half":
            # Half duplex on a switched link is nearly always a failed
            # negotiation rather than a deliberate choice.
            coll = collisions_by_iface.get(name, 0)
            findings.append({
                "severity": "critical" if coll else "warning",
                "code": "duplex_mismatch", "scope": name,
                "layer": 1,
                "message": f"{name}: negotiated HALF duplex"
                           + (f" at {mode['speed_mbps']} Mbps" if mode.get("speed_mbps") else "")
                           + (f", with {coll:,} collisions recorded" if coll else "")
                           + ". On a switched link this is almost always a failed "
                             "auto-negotiation or a hard-coded mismatch: one side forced, the "
                             "other negotiating. Throughput collapses under load while pings "
                             "stay fine. Check the duplex setting on both this interface and "
                             "the switch port.",
            })

        speed = mode.get("speed_mbps")
        if speed is not None and speed <= 100:
            findings.append({
                "severity": "warning",
                "code": "slow_link", "scope": name,
                "layer": 1,
                "message": f"{name}: link negotiated at only {speed} Mbps. If this port and "
                           f"switch are gigabit-capable, that usually means a damaged cable "
                           f"(gigabit needs all four pairs; 100 Mbps needs two, so a broken "
                           f"pair silently drops you to 100), or a speed forced on one end.",
            })

        # The same fault the check above catches, for a port fast enough that
        # no absolute number finds it. A 10G NIC sitting at 1G is not slow by
        # any threshold worth writing down and is still a tenth of the port.
        # Only above where slow_link already speaks, so one condition does not
        # produce two findings: its sentence is the right one below 100.
        capacity = mode.get("max_mbps")
        if speed is not None and capacity and 100 < speed < capacity:
            findings.append({
                "severity": "warning",
                "code": "negotiated_below_capacity", "scope": name,
                "layer": 1,
                "message": f"{name}: the port can do {capacity:,} Mbps and negotiated "
                           f"{speed:,}. Nothing is failing and nothing will look wrong until "
                           f"the traffic needs the rest of it - the ceiling every throughput "
                           f"figure in this report is measured against is a fraction of the "
                           f"one that was bought. A cable or optic rated below the port, or a "
                           f"speed forced at one end, is the usual reason.",
            })

        # What the physical-layer checks on this interface are worth. On a
        # paravirtual adapter every one of them is hardwired to zero, so their
        # silence says nothing - and a stage strip reading "link PASS" on a box
        # where the link could not have failed the check is the most misleading
        # thing this tool can print.
        kind = VIRTUAL_NIC_DRIVERS.get((mode.get("driver") or "").lower())
        if kind:
            findings.append({
                "severity": "ok",
                "code": "virtual_nic", "scope": name,
                "layer": 1,
                "message": f"{name} is {kind} ({mode['driver']}). Its CRC, frame, collision "
                           f"and optical counters are hardwired to zero by the driver - "
                           f"there is no cable to damage and no duplex to mismatch - so a "
                           f"clean physical layer here is not evidence that anything is "
                           f"well. It means the question cannot be asked from inside this "
                           f"guest. If the physical link is genuinely suspect, it has to be "
                           f"read on the host.",
            })

        mtu = mode.get("mtu")
        if mtu and mtu != STANDARD_MTU and is_tunnel(name):
            # Context, not a fault, and exempt from the verdict. The reader
            # still sees the number - it is the one that decides whether the
            # traffic inside the tunnel fits - but a tunnel being smaller than
            # a wire is the tunnel working.
            findings.append({
                "severity": "ok",
                "code": "tunnel_mtu", "scope": name,
                "layer": 2,
                "message": f"{name}: MTU {mtu}, on what looks like a tunnel. Smaller than "
                           f"{STANDARD_MTU} is expected here - the difference is the header "
                           f"overhead of whatever is wrapping the traffic. It matters when "
                           f"something inside the tunnel assumes {STANDARD_MTU} and sends "
                           f"packets that will not fit, which shows up as large transfers "
                           f"stalling while small ones are fine.",
            })
        elif mtu and mtu != STANDARD_MTU:
            findings.append({
                "severity": "warning",
                "code": "mtu_nonstandard", "scope": name,
                "layer": 2,
                "message": f"{name}: MTU is {mtu}, not the standard {STANDARD_MTU}."
                           + (" Smaller than standard usually means a tunnel (VPN/PPPoE) or a "
                              "manual override; if the far end expects 1500, large packets get "
                              "fragmented or dropped."
                              if mtu < STANDARD_MTU else
                              " Jumbo frames only work if every device along the path agrees - "
                              "one switch at 1500 in the middle silently drops them."),
            })

    # Link utilization. Needs a sampling window to mean anything, so it only
    # runs under --soak (or the default 2s sample, which is noisy but honest).
    return primary_mtu


def _check_neighbours_and_optics(raw, findings):
    """Which switch port this device is on, and the health of a fibre module.

    Returns the LLDP/CDP neighbours.
    """
    lldp = cmd_lldp()
    neighbours = []
    if lldp:
        raw["lldp"] = lldp
        neighbours = lldp["neighbours"]
        for n in neighbours:
            where = ", ".join(filter(None, [
                f"switch {n['switch']}" if n.get("switch") else None,
                f"port {n.get('port') or n.get('port_descr')}" if (n.get("port") or n.get("port_descr")) else None,
                f"VLAN {n['vlan']}" if n.get("vlan") else None,
                f"management IP {n['mgmt_ip']}" if n.get("mgmt_ip") else None,
            ]))
            findings.append({
                "severity": "ok",
                "layer": 2,
                "code": "switch_port",
                "message": f"{n['iface']} is connected to {where}"
                           + (f" (learned via {n['via']})" if n.get("via") else "")
                           + ". Anything below about the cable or switch port refers to this one.",
            })

    # Optical power, where the interface is fibre.
    optics = {}
    for iface in raw["link_stats"].get("interfaces", []):
        name = iface["name"]
        if name.startswith("lo") or not iface["packets"]:
            continue
        o = cmd_optics(name)
        if not o:
            continue
        optics[name] = o["parsed"]
        p = o["parsed"]
        rx = p.get("rx_dbm")
        desc = " ".join(filter(None, [p.get("vendor"), p.get("part")])) or "module"
        if p.get("alarms"):
            findings.append({
                "severity": "critical",
                "layer": 1,
                "code": "optics_alarm", "scope": name,
                "message": f"{name}: the optical module is raising its own alarms "
                           f"({', '.join(p['alarms'][:3])})"
                           + (f", receiving {rx} dBm" if rx is not None else "")
                           + f". These thresholds come from the {desc} itself, so they beat any "
                             f"generic figure - the link is outside what this optic is rated for.",
            })
        elif p.get("rx_dark"):
            findings.append({
                "severity": "critical",
                "layer": 1,
                "code": "optics_rx_low", "scope": name,
                "message": f"{name}: the optical module reports no received light at all "
                           f"(-inf dBm). This is not a weak signal to be cleaned up - nothing "
                           f"is arriving. The fibre is unplugged, broken, or patched to a port "
                           f"whose laser is off or dead. Check the receive strand specifically: "
                           f"the pair can be crossed so that this end transmits fine and hears "
                           f"nothing back.",
            })
        elif rx is not None and rx <= OPTIC_RX_CRIT_DBM:
            findings.append({
                "severity": "critical",
                "layer": 1,
                "code": "optics_rx_low", "scope": name,
                "message": f"{name}: optical receive power is {rx} dBm, below the "
                           f"{OPTIC_RX_CRIT_DBM} dBm most receivers can work with. The link may "
                           f"still show up while corrupting frames. Usual causes are a dirty or "
                           f"loose connector, a tight bend, or a failing laser at the far end.",
            })
        elif rx is not None and rx <= OPTIC_RX_WARN_DBM:
            findings.append({
                "severity": "warning",
                "layer": 1,
                "code": "optics_rx_marginal", "scope": name,
                "message": f"{name}: optical receive power is {rx} dBm - working, but with "
                           f"little margin left. Clean the connectors and check the patching "
                           f"before it starts dropping frames.",
            })
        elif p.get("warnings"):
            findings.append({
                "severity": "warning",
                "layer": 1,
                "code": "optics_warning", "scope": name,
                "message": f"{name}: the optical module reports {', '.join(p['warnings'][:3])}"
                           + (f" while receiving {rx} dBm" if rx is not None else "")
                           + ". Not failing yet, but it's the module's own warning threshold.",
            })
    if optics:
        raw["optics"] = {"ok": True, "cmd": "ethtool -m", "code": 0, "stderr": "",
                         "stdout": "\n".join(
                             f"{n:<10} rx {v.get('rx_dbm', '?')} dBm  tx {v.get('tx_dbm', '?')} dBm"
                             f"  {v.get('vendor', '')} {v.get('part', '')}".rstrip()
                             for n, v in optics.items()),
                         "interfaces": optics}
    return neighbours


def _check_own_tls(raw, findings, quick=False):
    """The certificate this box serves, which nothing here was ever looking at.

    Every other TLS check points outward at something this device connects to.
    A box terminating HTTPS is the opposite case, and its own certificate is
    the one that takes the site down when it expires.

    Only ports this box is already listening on, and only ones conventionally
    used for TLS - so this never probes anything, it opens a handshake against
    a service already accepting them.
    """
    if quick:
        return
    sockets = raw.get("sockets") or {}
    seen, listening = set(), []
    for addr, port in (sockets.get("bound") or []):
        if port.isdigit() and int(port) in TLS_PORTS and port not in seen:
            seen.add(port)
            listening.append((_listener_address(addr), int(port)))
    if not listening:
        return
    results = []
    for addr, port in listening[:OWN_TLS_MAX_PORTS]:
        res = cmd_own_tls(port, address=addr)
        results.append(res)
        _own_tls_findings(res, port, findings)
    if results:
        raw["own_tls"] = {
            "ok": any(r.get("ok") for r in results), "cmd": "tls handshake (own listeners)",
            "stderr": "", "code": 0, "listeners": results,
            "stdout": "\n".join(
                f"{r['port']:<6} " + (
                    f"{r.get('tls_version', '?')}  {r.get('verified_as', '?')}  "
                    f"expires {r.get('expires', '?')}"
                    + (f"  ({r['days_left']}d)" if r.get("days_left") is not None else "")
                    if r.get("ok") else
                    f"not listening on {r['host']}" if r.get("unreachable_locally")
                    else f"handshake failed: {r.get('error', '?')}")
                for r in results),
        }


def _check_own_service(raw, findings, quick=False):
    """Does the service answer, or only accept?

    Runs against the ports this box already listens on that are conventionally
    HTTP, so this never probes anything - it asks a service already taking
    requests for one response.
    """
    if quick:
        return
    sockets = raw.get("sockets") or {}
    seen, targets = set(), []
    for addr, port in (sockets.get("bound") or []):
        if port in SERVING_PORTS and port not in seen:
            seen.add(port)
            targets.append((_listener_address(addr), int(port)))
    if not targets:
        return
    results = []
    for addr, port in targets[:OWN_TLS_MAX_PORTS]:
        res = cmd_own_http(port, address=addr, tls=int(port) in TLS_PORTS)
        results.append(res)
        _own_service_findings(res, port, findings)
    if results:
        raw["own_service"] = {
            "ok": any(r.get("ok") for r in results), "cmd": "HEAD / (own listeners)",
            "stderr": "", "code": 0, "listeners": results,
            "stdout": "\n".join(
                f"{r['port']:<6} " + (str(r.get("status") or r.get("status_line")
                                          or ("no answer" if r.get("silent") else
                                              r.get("unreachable_locally")
                                              or r.get("error") or "?")))
                for r in results),
        }


def _own_service_timing(res, port, findings):
    """Which part of the answer took the time.

    "The service answered in 900ms" is true and useless. Getting a connection,
    finishing a handshake and waiting for the application to think are three
    different things with three different owners - and this connection is to a
    listener on this same box, so the first two should be almost nothing. That
    makes the split unusually easy to read: whatever is left is the service
    itself, and no part of it is the network.

    Context rather than a fault. What counts as slow depends entirely on what
    the service does, and a number picked here would be wrong for most of them.
    """
    phases = res.get("phases") or {}
    wait, connect = phases.get("wait_ms"), phases.get("connect_ms")
    if wait is None or connect is None:
        return
    tls = phases.get("tls_ms")
    parts = [("waiting for the service to answer", wait),
             ("getting a connection", connect)]
    if tls is not None:
        parts.append(("finishing the TLS handshake", tls))
    lead = max(parts, key=lambda pair: pair[1])
    findings.append({
        "severity": "ok",
        "layer": 7,
        "code": "own_service_timing",
        "message": f"Port {port} answered in {res.get('ms', 0):.0f}ms, of which "
                   f"{connect:.0f}ms was getting a connection"
                   + (f", {tls:.0f}ms was the TLS handshake" if tls is not None else "")
                   + f", and {wait:.0f}ms was waiting for the service itself. Mostly "
                   f"{lead[0]}. The connection is to a listener on this box, so the "
                   f"first parts should be close to nothing - whatever is left is the "
                   f"service thinking, and none of it is the network.",
    })


def _own_service_findings(res, port, findings):
    """One listener's answer, or its refusal to give one."""
    if res.get("unreachable_locally"):
        return                      # bound elsewhere; nothing was asked
    _own_service_timing(res, port, findings)
    if res.get("silent"):
        findings.append({
            "severity": "critical",
            "layer": 7,
            "code": "own_service_silent",
            "message": f"The service on port {port} accepted a connection, took a request "
                       f"and answered nothing"
                       + (f" in {res['ms']:.0f}ms" if res.get("ms") else "")
                       + ". Every check above this one passes - the port is open, the "
                         "handshake completes, the certificate is valid - and no client "
                         "gets a reply. That is the most common way a service is down "
                         "while the box it runs on looks entirely healthy.",
        })
        return
    if res.get("not_http"):
        findings.append({
            "severity": "warning",
            "layer": 7,
            "code": "own_service_not_http",
            "message": f"Port {port} answered, but not with HTTP: "
                       f"{res.get('status_line', '')!r}. Either something other than the "
                       f"expected service is bound to this port, or it speaks a protocol "
                       f"this check cannot read - worth confirming which before trusting "
                       f"anything else here about it.",
        })
        return
    status = res.get("status")
    if status in GATEWAY_ERRORS:
        findings.append({
            "severity": "critical",
            "layer": 7,
            "code": "own_service_upstream_error",
            "message": f"The service on port {port} answered {status} - it is running and "
                       f"telling you that what it depends on is not. This box is not the "
                       f"fault; whatever it proxies to, or the path to it, is. Every "
                       f"network check here can pass while this is true.",
        })
    elif status and status >= 500:
        findings.append({
            "severity": "critical",
            "layer": 7,
            "code": "own_service_erroring",
            "message": f"The service on port {port} answered {status} to a plain request "
                       f"for its root path. It is accepting connections and failing to "
                       f"serve them, which is the service itself rather than anything on "
                       f"the network.",
        })


def _own_tls_findings(res, port, findings):
    """Turn one listener's handshake into findings, if it deserves any."""
    if res.get("unreachable_locally"):
        return          # bound elsewhere; nothing was checked and nothing is wrong
    if not res.get("ok"):
        findings.append({
            "severity": "critical",
            "layer": 7,
            "code": "own_tls_handshake_failed",
            "message": f"This box is listening on {port} but a TLS handshake against it "
                       f"failed: {res.get('error', 'no detail')}. Every client trying to "
                       f"reach this service over TLS is getting the same thing, and no "
                       f"check that looks outward from here would ever show it.",
        })
        return
    days = res.get("days_left")
    if res.get("expired") or (days is not None and days < 0):
        findings.append({
            "severity": "critical",
            "layer": 7,
            "code": "own_tls_expired",
            "message": f"The certificate this box serves on port {port} has expired"
                       + (f" ({abs(days)} day(s) ago)" if days is not None else "")
                       + ". Browsers are refusing it now. Nothing about the network is "
                         "wrong and no amount of looking at the network will find it.",
        })
    elif days is not None and days <= CERT_EXPIRY_WARN_DAYS:
        findings.append({
            "severity": "warning",
            "layer": 7,
            "code": "own_tls_expiring",
            "message": f"The certificate this box serves on port {port} expires in "
                       f"{days} day(s), on {res.get('expires', '?')}"
                       + (f" (issued to {res['verified_as']})" if res.get("verified_as") else "")
                       + ". Renew it before it becomes an outage nobody can diagnose from "
                         "the network side.",
        })
    elif res.get("verified") is False:
        findings.append({
            "severity": "warning",
            "layer": 7,
            "code": "own_tls_untrusted",
            "message": f"The certificate this box serves on port {port} does not verify as "
                       f"a client would see it: {res.get('verify_error', 'no detail')}. "
                       f"This was checked against the name on the certificate itself"
                       + (f" ({res['verified_as']})" if res.get("verified_as") else "")
                       + ", so an incomplete chain shows up here even though the service "
                         "works from a machine that already trusts the issuer - which is "
                         "exactly the failure that reaches customers and not you."
                       + (" " + (own_cert_trust_note(res.get("verify_error")) or "")).rstrip(),
        })


def _check_neigh_table(raw, findings):
    """The ceiling on how many neighbours this box can talk to at once."""
    if OS_NAME != "Linux":
        raw["neigh_table"] = {"applicable": False}
        return
    table = _read_neigh_table()
    raw["neigh_table"] = table
    limit, entries = table.get("gc_thresh3"), table.get("entries")
    if table.get("table_fulls"):
        findings.append({
            "severity": "warning",
            "layer": 3,
            "code": "neigh_table_full",
            "message": f"The neighbour table has hit its ceiling "
                       f"{table['table_fulls']:,} time(s) since boot"
                       + (f" (limit {limit:,})" if limit else "")
                       + ". Past it the kernel stops resolving addresses, so this box "
                         "cannot talk to some of its neighbours while everything that does "
                         "not need one of them keeps working. That is why it presents as the "
                         "network failing at random and never reproduces on demand. It is a "
                         "setting on this box, not a fault on the wire - raise "
                         "net.ipv4.neigh.default.gc_thresh3 and the two thresholds below it.",
        })
    elif limit and entries and round(100.0 * entries / limit) >= NEIGH_TABLE_WARN_PCT:
        findings.append({
            "severity": "warning",
            "layer": 3,
            "code": "neigh_table_near_limit",
            "message": f"The neighbour table holds {entries:,} of the {limit:,} entries it "
                       f"is allowed ({round(100.0 * entries / limit)}%). It has not refused "
                       f"anything yet. When it does the kernel stops resolving addresses "
                       f"rather than queuing, so the first symptom is this box losing "
                       f"neighbours at random on a segment that is working - raise "
                       f"net.ipv4.neigh.default.gc_thresh3 before that rather than after.",
        })


def _check_bonds(raw, findings):
    """A bond that is carrying traffic on fewer cables than it was given."""
    if OS_NAME != "Linux":
        raw["bonds"] = {"applicable": False}
        return
    bonds = _bond_members_linux()
    raw["bonds"] = bonds
    for name in sorted(bonds):
        bond = bonds[name]
        down, members = bond["down"], bond["members"]
        if not down or len(down) >= len(members):
            # All of them down is not a degraded bond, it is an interface with
            # no carrier, and the link checks already say so in better words.
            continue
        findings.append({
            "severity": "warning",
            "code": "bond_degraded", "scope": name,
            "layer": 1,
            "message": f"{name}: {len(down)} of {len(members)} bonded member(s) are down "
                       f"({', '.join(down)}"
                       + (f", mode {bond['mode']}" if bond.get("mode") else "")
                       + f"). The bond is still up and nothing is failing, which is the "
                         f"whole problem - a bond is built to hide exactly this, so no "
                         f"address moved and no alarm fired. What has gone is the redundancy "
                         f"it was built for: the next member to fail takes this box off the "
                         f"network, and the capacity it can carry is already reduced.",
        })


def _check_arp(raw, findings):
    """Duplicate addresses on the local segment.

    Returns the parsed entries, which the passive inventory reuses rather than
    parsing - or probing - anything again.
    """
    raw["arp"] = cmd_arp()
    arp_entries = parse_arp_table(raw["arp"].get("stdout", "")) if raw["arp"].get("ok") else []
    for conflict in find_arp_conflicts(arp_entries):
        virtual = [(m, virtual_router_mac(m)) for m in conflict["macs"]]
        virtual = [(m, v) for m, v in virtual if v]
        if len(virtual) >= 2:
            # Always different groups. Two routers in the *same* group share
            # one virtual MAC - that is what VRRP is for - so a same-group
            # split brain is invisible here and this branch cannot see it. It
            # is worth saying plainly rather than implying coverage: the
            # signal that is available for that is the address changing hands
            # between visits, which --baseline reports.
            groups = sorted({f"{p} {g}" for _m, (p, g) in virtual})
            findings.append({
                "severity": "critical",
                "layer": 2,
                "code": "virtual_router_conflict",
                "message": (
                    f"{conflict['ip']} is answered by {len(virtual)} different redundancy "
                    f"addresses: {', '.join(m for m, _v in virtual)}. Those are different "
                    f"groups ({', '.join(groups)}), so two separate virtual routers have "
                    f"been configured onto one address - commonly a CARP vhid and a VRRP "
                    f"vrid colliding, since both live in the same MAC range. Traffic for "
                    f"this address lands on whichever the switch learned last, so symptoms "
                    f"move between them with no pattern."),
            })
            continue
        findings.append({
            "severity": "critical",
            "layer": 2,
            "code": "duplicate_ip",
            "message": f"{conflict['ip']} is claimed by more than one MAC address "
                       f"({', '.join(conflict['macs'])}). Two devices are using the same IP, "
                       f"so traffic for it lands wherever the switch learned that address last. "
                       f"Symptoms come and go with no pattern - the classic signature of a "
                       f"duplicate address.",
        })

    # What this device's own sockets are doing. Zeek reads these states off the
    # wire; the kernel already knows them here, with no capture involved.
    # Already read at the top of diagnose(), because the target choice needed
    # it. Re-read only when something else called this directly.
    if "sockets" not in raw:
        raw["sockets"] = cmd_socket_states()
    sock_states = raw["sockets"].get("states", {}) if raw["sockets"].get("ok") else {}
    pending = raw["sockets"].get("pending", {}) if raw["sockets"].get("ok") else {}
    syn_sent = sock_states.get("SYN_SENT", 0)
    if syn_sent >= SYN_SENT_WARN:
        peers = pending.get("SYN_SENT", {})
        worst = max(peers.items(), key=lambda kv: kv[1])[0] if peers else None
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "syn_sent_backlog",
            "message": f"{syn_sent} connection(s) from this device are stuck waiting for a reply"
                       + (f", mostly to {worst}" if worst else "")
                       + ". The device is trying and nothing is answering, which is traffic being "
                         "filtered rather than a slow network - a dropped SYN looks identical to "
                         "a slow server from the application's side.",
        })
    close_wait = sock_states.get("CLOSE_WAIT", 0)
    if close_wait >= CLOSE_WAIT_WARN:
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "close_wait_backlog",
            "message": f"{close_wait} sockets are in CLOSE_WAIT: the far end hung up and the "
                       f"local application never closed its side. That is an application holding "
                       f"sockets open, not a network fault - and it ends with the process running "
                       f"out of file descriptors.",
        })

    # Retransmissions on this box's real traffic - loss that probes can miss.
    return arp_entries

def _check_utilization(raw, findings, counter_window, uplink_mbps=None):
    """How full the link is - only meaningful once the sample window has run.

    Two denominators, and the difference is the whole point. The NIC's
    negotiated speed is the one this box can read; the site's uplink is the one
    that is actually the bottleneck almost everywhere this tool gets used. A
    branch appliance with a 1 Gbps port on a 50 Mbps line reads 5% full while
    the line is at 96%, and every symptom that produces - loss, jitter, stalled
    transfers - then gets attributed to the carrier. There is no way to measure
    the uplink from here without generating load on a customer's connection, so
    --uplink-mbps takes it as an input instead.
    """
    speed_by_iface = {m["name"]: m.get("speed_mbps")
                      for m in raw["link_modes"].get("interfaces", [])}
    egress = _default_route_iface(raw)
    # A full line is only a fault when something broke while it was full.
    # Computed once here and used by both denominators - see the note on
    # _harm_during_window for why it is never derived from the throughput.
    harm = _harm_during_window(raw, findings)
    for iface in raw["link_stats"].get("interfaces", []):
        name = iface["name"]
        if name.startswith("lo") or not iface["packets"]:
            continue
        speed = speed_by_iface.get(name)
        busiest = max(iface.get("rx_mbps") or 0, iface.get("tx_mbps") or 0)
        if not busiest or not counter_window:
            continue
        iface["busiest_mbps"] = busiest

        # The uplink first: it is the smaller number, so it is the one that
        # fills, and it is the one whose owner is the site rather than the NIC.
        if uplink_mbps and (egress is None or name == egress):
            up = round(busiest * 100.0 / uplink_mbps, 1)
            iface["uplink_utilization_pct"] = up
            if up >= UPLINK_FULL_PCT and harm:
                findings.append({
                    "severity": "critical" if up >= 95 else "warning",
                    "layer": 3,
                    "code": "uplink_saturated",
                    "message": f"This device moved {busiest} Mbps over {counter_window}s on a "
                               f"site uplink given as {uplink_mbps} Mbps - {up}% of it - and "
                               f"{harm}. A full uplink produces exactly the symptoms of a bad "
                               f"carrier: loss on every destination, latency that climbs under "
                               f"load, transfers that stall. It is not the carrier. Either the "
                               f"line is undersized for what the site is doing, or something "
                               f"here is using more of it than it should - check what is "
                               f"running before opening a ticket.",
                })
            elif up >= UPLINK_FULL_PCT:
                findings.append({
                    "severity": "warning",
                    "layer": 3,
                    "code": "uplink_busy",
                    "message": f"This device moved {busiest} Mbps over {counter_window}s on a "
                               f"site uplink given as {uplink_mbps} Mbps - {up}% of it - with "
                               f"nothing failing while it did. That is a line being used, not "
                               f"a fault: a backup, a sync, a large transfer. Worth knowing if "
                               f"the site has grown into its circuit, and worth ruling out "
                               f"first if anyone reports trouble at this time of day.",
                })

        # Bursts, against whichever capacity is the real one. Checked after
        # the sustained readings so it only speaks when the mean stayed quiet -
        # a line that is full throughout is already reported above.
        capacity = uplink_mbps if (uplink_mbps and (egress is None or name == egress)) else speed
        _check_saturation_bursts(iface, findings, capacity, uplink_mbps, raw, counter_window)

        if not speed:
            continue
        util = round(busiest * 100.0 / speed, 1)
        iface["utilization_pct"] = util
        if util >= 80 and harm:
            findings.append({
                "severity": "critical" if util >= 95 else "warning",
                "layer": 2,
                "code": "link_saturated", "scope": name,
                "message": f"{name} is running at {busiest} Mbps on a {speed} Mbps link "
                           f"({util}% utilization over {counter_window}s). A full link looks "
                           f"exactly like a broken one from the application's side - latency "
                           f"climbs and transfers stall - but nothing here is faulty. Either "
                           f"the link is undersized for the traffic, or something is using more "
                           f"than it should. Note this is the NIC's own negotiated speed; if "
                           f"the site's uplink is slower, pass --uplink-mbps to measure "
                           f"against the link that actually fills. Something was failing "
                           f"while it was full: {harm}.",
            })
        elif util >= 80:
            findings.append({
                "severity": "warning",
                "layer": 2,
                "code": "link_busy", "scope": name,
                "message": f"{name} ran at {busiest} Mbps of a {speed} Mbps link "
                           f"({util}% over {counter_window}s) with nothing failing while it "
                           f"did. A link being used to capacity is not a fault - but if the "
                           f"site's uplink is slower than this NIC, pass --uplink-mbps, "
                           f"because the number that matters is how full the line was, not "
                           f"the port.",
            })

# Codes that mean this device or its path was actually dropping traffic during
# the window. A link running flat out is not a fault - that is a link being
# used for what it was bought for - so a burst only becomes a finding when
# something broke while it was happening.
HARM_IN_WINDOW = {
    "nic_drops_live", "conntrack_drops_live", "rcv_buffer_pruned",
    "accept_overflow_live", "drops_live",
}


def _harm_during_window(raw, findings):
    """Did anything actually break while we were sampling?

    Two independent signals: packets this device dropped on the floor, and
    probes that never came back. Either is enough; neither is inferred from
    the throughput itself, which would make the test circular.
    """
    codes = {f.get("code") for f in findings}
    if codes & HARM_IN_WINDOW:
        return "this device was dropping packets at the same time"
    ping = raw.get("ping_internet") or {}
    loss = parse_ping_loss(ping)
    sent, _lost = parse_ping_counts(ping)
    if loss and (sent or 0) >= MIN_PROBES_FOR_LOSS:
        return (f"{loss:g}% of {sent} probes to the target went unanswered over "
                f"the same window")
    return None


def _check_saturation_bursts(iface, findings, capacity, uplink_mbps, raw, counter_window):
    """A line that fills in bursts, which no average over the window can show.

    The counters used to be read at each end of the window and divided, and a
    mean is the wrong statistic for the fault --soak exists to find: full for
    twenty seconds of every minute averages to a third and reads as quiet while
    calls break three times a minute. Per-second sampling makes the peak
    visible; harm makes it a finding.
    """
    series = iface.get("rate_series")
    if not series or not capacity or len(series) < 3:
        return
    full = capacity * UPLINK_FULL_PCT / 100.0
    over = [r for r in series if r >= full]
    mean = sum(series) / len(series)
    if not over or mean >= full:
        return          # never full, or full throughout and already reported
    harm = _harm_during_window(raw, findings)
    if not harm:
        return
    peak = max(series)
    # The interface's own window, not the one passed alongside it: the series
    # and sample_seconds are set together in _finish_link_sample, so deriving
    # the span from that pair keeps them from drifting apart.
    # The span the series covers, not the nominal window: the sampler only
    # runs through the part of the window left after the checks finish, and
    # dividing by the larger number would overstate how long the line was full.
    window = iface.get("series_seconds") or iface.get("sample_seconds") or counter_window
    span = _fmt_span(len(over) * (window / len(series))) or f"{len(over)}s"
    what = ("the site uplink" if capacity == uplink_mbps and uplink_mbps
            else f"{iface['name']}")
    findings.append({
        "severity": "critical" if len(over) * 4 >= len(series) else "warning",
        "layer": 3 if capacity == uplink_mbps and uplink_mbps else 2,
        "code": "saturation_bursts",
        "message": f"{what} hit {peak} Mbps of {round(capacity)} Mbps in bursts - full for "
                   f"about {span} of the {window}s window, while averaging only "
                   f"{round(mean * 100.0 / capacity)}% across it. That average is why nothing "
                   f"else here shows it, and it is the difference between a line that is busy "
                   f"and one that is too small: {harm}. Traffic that arrives while the line is "
                   f"full is delayed or dropped, which is what breaks calls and stalls "
                   f"transfers a few times a minute.",
    })


def _check_tcp(raw, findings, counter_window, tcp_baseline):
    """Retransmit rate on this device's own traffic."""
    raw["tcp_health"] = cmd_tcp_health(counter_window if tcp_baseline else 0,
                                       baseline=tcp_baseline)
    live_retrans = raw["tcp_health"].get("retrans_pct_live")
    life_retrans = raw["tcp_health"].get("retrans_pct_lifetime")
    retrans = live_retrans if live_retrans is not None else life_retrans
    if retrans is not None and retrans >= 2:
        window = (f"over the last {counter_window}s" if live_retrans is not None
                  else "since boot, so this is history rather than a live rate")
        findings.append({
            "severity": "critical" if retrans >= 5 else "warning",
            "layer": 3,
            "code": "tcp_retransmits",
            "message": f"{retrans}% of this device's TCP segments were retransmitted {window}. "
                       f"That's measured on real traffic rather than probes, so it counts loss "
                       f"that ICMP tests can miss - anything above a few percent will be felt "
                       f"as slowness by every application on this box.",
        })

def _check_flows(raw, findings):
    """Split the retransmit picture by destination, and name what's blocking.

    This runs after _check_tcp on purpose: the host-wide rate is the headline,
    and these say which destination it belongs to. Both share the `tcp` finding
    family, so two views of the same retransmits can't corroborate each other
    into false confidence.
    """
    raw["tcp_flows"] = cmd_tcp_flows((raw.get("sockets") or {}).get("listen_ports"))
    stats = raw["tcp_flows"]
    if not stats.get("ok"):
        return
    if stats.get("truncated"):
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "tcp_flow_sample_partial",
            "message": (f"This box has more open connections than one report can carry, so "
                        f"only the first {stats['flows_seen']} were read. The per-destination "
                        f"split below is drawn from that sample rather than every connection."),
        })
    shape = stats.get("shape")
    worst = stats.get("worst_loss_pct")
    basis = "segment counts" if stats.get("basis") == "segments" else "byte counts"
    peers = ", ".join(stats.get("lossy_peers") or [])

    # On a box that accepts connections, which side the loss is on decides who
    # owns it, and that is a different question from how many destinations are
    # affected. Answered first, because the direction-blind shapes below would
    # otherwise call an internal segment "the provider or upstream".
    side = stats.get("lossy_side")
    if side in ("backend", "client"):
        if side == "backend":
            findings.append({
                "severity": "critical" if (worst or 0) >= 5 else "warning",
                "layer": 3,
                "code": "tcp_flow_loss_backends",
                "message": (f"Loss is on the connections this box opened, not on the ones "
                            f"clients opened to it: {stats['backends_lossy']} backend "
                            f"connection(s) losing traffic (worst {worst}% by {basis}, to "
                            f"{peers}) while every client connection is clean. That puts it "
                            f"between this box and what it depends on - an internal segment, "
                            f"not the internet, and not the carrier."),
            })
            return
        findings.append({
            "severity": "critical" if (worst or 0) >= 5 else "warning",
            "layer": 3,
            "code": "tcp_flow_loss_clients",
            "message": (f"Loss is on the connections clients opened to this box, not on the "
                        f"ones it opened to its backends: {stats['clients_lossy']} client "
                        f"connection(s) losing traffic (worst {worst}% by {basis}) while "
                        f"everything this box depends on is clean. The service and its "
                        f"dependencies are fine; the path between here and the people using "
                        f"it is not."),
        })
        return

    # Queuing, before the loss shapes below. Latency that is queue rather than
    # distance has a different owner and a different fix, and every other
    # latency reading here - the ping, the per-hop deltas - can only say how
    # long the trip took, never how much of it was spent waiting.
    #
    # Written out per side rather than looped, because every guard in the suite
    # discovers finding codes by scanning for them as literals. A loop emitting
    # `"code": code` hides them from the scenario check, the side table and the
    # counts all at once.
    sides = stats.get("by_side") or {}
    if sides.get("backend", {}).get("queued"):
        findings.append({
            "severity": "warning", "layer": 3, "code": "queuing_delay_backends",
            "message": _queue_message(sides["backend"],
                                      "between this box and what it depends on"),
        })
    elif sides.get("client", {}).get("queued"):
        findings.append({
            "severity": "warning", "layer": 3, "code": "queuing_delay_clients",
            "message": _queue_message(sides["client"],
                                      "between this box and the people using it"),
        })
    elif not sides and (stats.get("queue") or {}).get("queued"):
        findings.append({
            "severity": "warning", "layer": 3, "code": "queuing_delay",
            "message": _queue_message(stats["queue"], "on the path out of this box"),
        })

    # Delay that will not sit still, from TCP's own variance on the
    # connections this box is carrying. Every other jitter figure here comes
    # from probes, which a router is free to deprioritise; this one is the
    # traffic. Written out per side rather than looped for the same reason as
    # the block above - a loop hides the codes from every guard in the suite.
    def _jitter_bad(side):
        var, rtt = side.get("jitter_ms"), side.get("rtt_ms")
        return bool(var and rtt and var >= JITTER_MS and var >= rtt * JITTER_SHARE)

    def _jitter_message(side, where):
        return (f"The round trip {where} is moving about as much as it lasts: "
                f"{side['jitter_ms']:.0f}ms of variance on a {side['rtt_ms']:.0f}ms "
                f"trip, across {side['connections']} connection(s). This is TCP's own "
                f"measurement of the traffic rather than a probe, so it is what the "
                f"connections are actually experiencing. Nothing has to be lost for it "
                f"to hurt - a retransmit timer sized for the worst case is a timer that "
                f"waits, so recovery stalls and throughput falls while every loss "
                f"figure here stays clean.")

    if _jitter_bad(sides.get("backend") or {}):
        findings.append({
            "severity": "warning", "layer": 3, "code": "path_jitter_backends",
            "message": _jitter_message(sides["backend"],
                                       "between this box and what it depends on"),
        })
    elif _jitter_bad(sides.get("client") or {}):
        findings.append({
            "severity": "warning", "layer": 3, "code": "path_jitter_clients",
            "message": _jitter_message(sides["client"],
                                       "between this box and the people using it"),
        })

    # Which of the three is holding throughput back, on the traffic this box is
    # actually carrying. Context rather than a fault: a transfer limited by the
    # path is usually TCP working correctly, and the value is in being able to
    # say which of the three it is when somebody asks why something is slow.
    limits = stats.get("limits") or {}
    if limits:
        lead = max((("the path between them", limits["path_pct"]),
                    ("the far end, which stopped reading", limits["receiver_pct"]),
                    ("this box's own send buffer", limits["sender_pct"])),
                   key=lambda pair: pair[1])
        findings.append({
            "severity": "ok",
            "layer": 4,
            "code": "throughput_limited_by",
            "message": f"Across {limits['connections']} connection(s) that were actually "
                       f"sending, throughput was held back mostly by {lead[0]} "
                       f"({lead[1]:.0f}% of the time they spent busy). The full split is "
                       f"{limits['path_pct']:.0f}% waiting on the path, "
                       f"{limits['receiver_pct']:.0f}% on the far end having no window left, "
                       f"and {limits['sender_pct']:.0f}% on this box having nothing queued to "
                       f"send. This is measured on real traffic rather than a probe, and it "
                       f"is the question behind \"why is it slow\" - the three answers have "
                       f"three different owners.",
        })

    if shape == "all_peers":
        findings.append({
            "severity": "critical",
            "layer": 2,
            "code": "tcp_flow_loss_all_peers",
            "message": (f"Every network this device is talking to is losing traffic "
                        f"({stats['networks_lossy']} of them, worst {worst}% by {basis}). "
                        f"Loss that follows every destination equally is not out in the "
                        f"network - it's this device's own link or the segment it sits on."),
        })
    elif shape == "unclear":
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "tcp_flow_loss_unclear",
            "message": (f"Every connection that could be read is losing traffic (worst "
                        f"{worst}% by {basis}), but this box has more connections open than "
                        f"the sample could cover. Calling that this device's own link means "
                        f"showing no destination is clean, and a partial sample can't show "
                        f"that - so the loss is reported and the owner is left open."),
        })
    elif shape == "one_peer":
        findings.append({
            "severity": "warning",
            "layer": 3,
            "code": "tcp_flow_loss_one_peer",
            "message": (f"{worst}% of traffic to {peers} is being retransmitted (by {basis}), "
                        f"and it's the only destination measured. Either that path is damaged "
                        f"or that host is struggling; there's nothing here to compare it "
                        f"against, so this device's own link isn't ruled out."),
        })
    elif shape == "some_peers":
        findings.append({
            "severity": "warning",
            "layer": 3,
            "code": "tcp_flow_loss_some_peers",
            "message": (f"{stats['networks_lossy']} of "
                        f"{stats['networks_lossy'] + stats['networks_clean']} networks are "
                        f"losing traffic (worst {worst}% by {basis}, to {peers}), while the "
                        f"rest are clean. This device's link is carrying the clean traffic "
                        f"fine, so the fault is on the path to those destinations."
                        + (f" Round trip to the worst of them is "
                           f"{stats['worst_rtt_ms']}ms." if stats.get("worst_rtt_ms") else "")),
        })
    if stats.get("receiver_limited"):
        findings.append({
            "severity": "warning",
            "layer": 7,
            "code": "tcp_flow_receiver_limited",
            "message": (f"{stats['receiver_limited']} connection(s) spent up to "
                        f"{stats['receiver_limited_pct']}% of their active time waiting on the "
                        f"far end's receive window. The remote application is reading slower "
                        f"than the network can deliver - if this is the 'slow network' "
                        f"complaint, the network isn't the constraint."),
        })
    if stats.get("sendbuf_limited"):
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "tcp_flow_sendbuf_limited",
            "message": (f"{stats['sendbuf_limited']} connection(s) spent up to "
                        f"{stats['sendbuf_limited_pct']}% of their active time blocked on this "
                        f"device's own send buffer. That's a local socket or memory limit "
                        f"rather than anything on the network."),
        })


def _qualify_upstream_verdict(verdict, raw, uplink_mbps):
    """Don't blame the carrier at high confidence for something we can't rule out.

    Every symptom in CONGESTION_MASQUERADE is produced just as well by the
    site filling its own uplink as by the carrier dropping traffic, and the
    tool cannot tell the two apart without knowing the line rate. When the
    device was itself moving real traffic during the window and nobody told us
    what the line is, that is an unexamined alternative explanation - so the
    verdict says so and stops calling itself high confidence. With
    --uplink-mbps supplied there is nothing to qualify: either the uplink
    finding fired and outranks this, or the line had headroom.
    """
    if uplink_mbps or not verdict.get("based_on"):
        return
    if (raw or {}).get("target_kind") == "backend":
        return          # the loss is on an internal segment; the WAN is not in it
    if verdict["based_on"][0] not in CONGESTION_MASQUERADE:
        return
    busiest = max((i.get("busiest_mbps") or 0
                   for i in (raw.get("link_stats") or {}).get("interfaces", [])
                   if not i["name"].startswith("lo")), default=0)
    if busiest < UPLINK_UNKNOWN_FLOOR_MBPS:
        return
    verdict["next_step"] += (
        f" First, rule out the site's own line: this device was moving "
        f"{busiest} Mbps during the check, and a full uplink produces exactly "
        f"this pattern. Re-run with --uplink-mbps <the site's rate> to settle "
        f"it before escalating.")
    if verdict.get("confidence") == "high":
        verdict["confidence"] = "medium"
    verdict["uplink_unknown_mbps"] = busiest


def _finish_link_checks(raw, findings, counter_window, link_sample, tcp_baseline,
                        duplex_by_iface, slot, progress=None, drops_baseline=None,
                        uplink_mbps=None):
    """Close the counter window and emit everything that depended on it.

    Findings are spliced in at `slot` - the position these occupied when the
    sampling happened up front - so the report reads in the same order it
    always did.
    """
    raw["link_stats"] = cmd_link_stats(counter_window, sample=link_sample,
                                       progress=progress)
    late = []
    _check_counters(raw, late, duplex_by_iface)
    _check_kernel_log(raw, late)
    _check_link_flaps(raw, late)
    _check_clock(raw, late)
    _check_kernel_drops(raw, late, counter_window, drops_baseline)
    _check_utilization(raw, late, counter_window, uplink_mbps)
    _check_tcp(raw, late, counter_window, tcp_baseline)
    _check_flows(raw, late)
    findings[slot:slot] = late


def _check_device_and_link(raw, findings, counter_window, soak, quick, link_sample):
    """Everything about this device and the wire into it: error counters, link
    mode, utilization, switch neighbour, optics, ARP and TCP health.

    Appends its findings to `findings` and its raw output to `raw`, and returns
    what the rest of the diagnosis needs: the switch neighbours and the primary
    interface MTU.
    """
    # Provisional read: interface names and lifetime totals, no deltas yet. The
    # window keeps running while the network checks work, and the real figures
    # land in _finish_link_checks() at the end.
    raw["link_stats"] = _finish_link_sample(link_sample["first"], link_sample["source"], 0)
    # Collected before the counter findings because how to read a collision
    # depends on the negotiated duplex.
    raw["link_modes"] = cmd_link_modes()
    duplex_by_iface = {m["name"]: m.get("duplex")
                       for m in raw["link_modes"].get("interfaces", [])}


    # Speed / duplex / MTU. Reported per interface, but only interfaces that
    # carry traffic produce findings - see the counter loop above for why.
    primary_mtu = _check_link_modes(raw, findings)

    # Which switch port this device is on. Reported as an ok-severity finding
    # because it's context rather than a fault - but it's the context that
    # makes every "check the switch port" instruction actionable.
    neighbours = _check_neighbours_and_optics(raw, findings)

    # Duplicate IP: Wireshark's classic ARP finding, from the table this box
    # already keeps rather than from a capture.
    _check_bonds(raw, findings)
    _check_neigh_table(raw, findings)
    arp_entries = _check_arp(raw, findings)
    return neighbours, primary_mtu, duplex_by_iface, arp_entries


def _check_dns(raw, findings, target, inet_loss, quick):
    """Name resolution, both the single lookup and each configured resolver.

    Returns whether resolution failed, which the all-clear message needs.
    """
    raw["dns_lookup"] = cmd_dns("google.com")
    dns_out = raw["dns_lookup"].get("stdout", "") if raw["dns_lookup"].get("ok") else ""
    # A missing dig/nslookup is not a DNS failure. When the tool isn't there,
    # fall back to the resolver queries this program makes itself, which need
    # nothing installed - otherwise a stripped box gets told its DNS is broken
    # when it is fine.
    tool_missing = (not raw["dns_lookup"].get("ok")
                    and "no DNS lookup utility" in str(raw["dns_lookup"].get("error", "")))
    if tool_missing:
        probe = cmd_dns_health(check_hijack=False)
        raw["dns_health"] = probe
        answered = [r for r in probe.get("resolvers", []) if r.get("ok") and r.get("answers")]
        dns_failed = bool(probe.get("resolvers")) and not answered
        raw["dns_lookup"] = {
            "ok": True, "cmd": "built-in resolver query (no dig/nslookup on this box)",
            "stdout": probe.get("stdout", ""), "stderr": "", "code": 0,
        }
    else:
        dns_failed = (
            not raw["dns_lookup"].get("ok")
            or "NXDOMAIN" in dns_out
            or "SERVFAIL" in dns_out
            or "can't find" in dns_out.lower()
            or not dns_out.strip()
        )
    if dns_failed and inet_loss is not None and inet_loss < 100:
        findings.append({
            "severity": "critical",
            "code": "dns_fail",
            "layer": 7,
            "message": "Internet connectivity works by IP address, but DNS resolution for google.com "
                       "failed. Check the configured DNS server(s), or whether the DNS server itself "
                       "is reachable/responding.",
        })

    # Resolver-level DNS. The single lookup above answers "does DNS work at
    # all"; this asks the harder question of whether each configured resolver
    # works, how fast, and whether they agree.
    if "dns_health" not in raw:
        raw["dns_health"] = cmd_dns_health(check_hijack=not quick)
    resolvers = raw["dns_health"].get("resolvers", [])
    if not raw["dns_health"].get("ok") and not resolvers:
        unreadable = raw["dns_health"].get("unreadable")
        if unreadable:
            findings.append({
                "severity": "warning",
                "layer": 7,
                "code": "resolvers_unreadable",
                "message": f"Couldn't read which DNS resolvers this device is configured to use "
                           f"({unreadable}), so the per-resolver checks were skipped. This is not "
                           f"the same as having none configured - whether names actually resolve "
                           f"is reported separately below.",
            })
        else:
            findings.append({
                "severity": "critical",
                "layer": 7,
                "code": "dns_no_resolvers",
                "message": "No DNS resolvers are configured on this device, so no name will ever "
                           "resolve here regardless of how healthy the network is. Check DHCP or "
                           "the static resolver configuration.",
            })
    elif resolvers:
        working = [r for r in resolvers if r["ok"]]
        dead = [r for r in resolvers if not r["ok"]]
        if dead and not working:
            findings.append({
                "severity": "critical",
                "layer": 7,
                "code": "dns_all_resolvers_down",
                "message": f"None of the {len(resolvers)} configured resolver(s) answered "
                           f"({', '.join(r['server'] for r in dead)}). Nothing will resolve, "
                           f"though anything addressed by IP will still work.",
            })
        elif dead:
            # The nastiest DNS fault: it works, then doesn't, depending on which
            # resolver the stub picks - and a single lookup usually passes.
            findings.append({
                "severity": "warning",
                "layer": 7,
                "code": "dns_resolver_down",
                "message": f"{len(dead)} of {len(resolvers)} configured resolvers aren't "
                           f"answering ({', '.join(r['server'] for r in dead)}), while "
                           f"{', '.join(r['server'] for r in working)} is fine. Lookups will "
                           f"work or hang depending on which resolver gets picked, which is why "
                           f"this shows up as things being intermittently slow rather than as a "
                           f"DNS outage.",
            })
        slow = [r for r in working if (r.get("elapsed_ms") or 0) >= DNS_SLOW_MS]
        if slow:
            findings.append({
                "severity": "warning",
                "layer": 7,
                "code": "dns_resolver_slow",
                "message": f"Resolver {slow[0]['server']} answered in "
                           f"{slow[0]['elapsed_ms']:.0f}ms. Every new connection waits on this "
                           f"before it starts, so the whole site feels slow while every "
                           f"connectivity check passes.",
            })
        hijacked = [r for r in resolvers if r.get("hijacks_nxdomain")]
        if hijacked:
            findings.append({
                "severity": "warning",
                "layer": 7,
                "code": "dns_hijack",
                "message": f"Resolver {hijacked[0]['server']} returned an address for a name "
                           f"that cannot exist ({NXDOMAIN_PROBE}, in the reserved .invalid "
                           f"domain). Something is intercepting DNS and inventing answers - a "
                           f"captive portal, or an ISP redirect service. Software that relies "
                           f"on a lookup failing will misbehave in ways that look unrelated.",
            })
        answer_sets = {tuple(r["answers"]) for r in working if r["answers"]}
        if len(answer_sets) > 1:
            findings.append({
                "severity": "warning",
                "layer": 7,
                "code": "dns_disagree",
                "message": f"The configured resolvers disagree about {raw['dns_health']['probe']}: "
                           # sorted, not raw set order: string hashing is
                           # randomised per process, so the same disagreement
                           # was being written two different ways from one run
                           # to the next - which reads as a change on the next
                           # --baseline, and makes a pasted report unrepeatable.
                           + " vs ".join(", ".join(a) or "(none)" for a in sorted(answer_sets))
                           + ". Usually a stale cache on one of them, or a middlebox answering "
                             "for some queries but not others.",
            })

    return dns_failed


def _check_ports(raw, findings, target, check_ports, quick, speculative=False):
    """TCP reachability for the requested ports. Returns the per-port results."""
    port_results = []
    if len(check_ports) > MAX_CHECK_PORTS:
        findings.append({
            "severity": "warning",
            "layer": 4,
            "code": "ports_truncated",
            "message": f"{len(check_ports)} ports were requested; only the first "
                       f"{MAX_CHECK_PORTS} were checked. Each check is a TCP connect with a "
                       f"timeout, so an unbounded list would take far longer than a diagnosis "
                       f"should.",
        })
        check_ports = check_ports[:MAX_CHECK_PORTS]
    # Checked concurrently: five dead ports cost one timeout rather than five.
    # Bounded, because a burst of simultaneous connects to one host looks more
    # like a scan than a diagnostic to whatever is watching the site's
    # network. Results keep the order the ports were given in.
    timeout = 2 if quick else 5
    if len(check_ports) > 1:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(PORT_CHECK_WORKERS, len(check_ports))) as pool:
            results = list(pool.map(lambda p: cmd_check_port(target, p, timeout=timeout),
                                    check_ports))
    else:
        results = [cmd_check_port(target, p, timeout=timeout) for p in check_ports]
    for port_spec, port_result in zip(check_ports, results):
        port_results.append(port_result)
        raw[f"port_{target}_{port_spec}"] = port_result
        # A name with records for both families, where one of them doesn't
        # work, costs every client a timeout before it falls back - on every
        # connection. It is invisible from a machine that only has the working
        # family, and it is why something is "slow for some people" rather
        # than down for everyone.
        if port_result.get("family_mismatch"):
            dead = ", ".join(f"IPv{v}" for v in port_result["family_mismatch"])
            findings.append({
                "severity": "warning",
                "layer": 3,
                "code": "family_unreachable",
                "message": f"{target}:{port_spec} answers over "
                           f"IPv{port_result.get('ip_version')} but not over {dead}, and it "
                           f"publishes an address for both. Clients try the broken one first "
                           f"and wait for it to time out before falling back, on every "
                           f"connection - which is why this reads as slow rather than down.",
            })
        # A TLS port that answered deserves the harder question: does the
        # service behind it actually work, and is anything re-signing it.
        try:
            port_num = int(port_spec)
        except (TypeError, ValueError):
            continue
        if port_result.get("ok") and port_num in TLS_PORTS:
            tls = cmd_tls_check(target, port_num)
            if not tls:
                continue
            raw[f"tls_{target}_{port_num}"] = tls
            port_result["tls"] = {k: tls.get(k) for k in
                                  ("tls_version", "subject", "issuer", "expires",
                                   "days_left", "starts", "not_yet_valid_days",
                                   "verified", "verify_error",
                                   "tcp_ms", "tls_ms")}
            # Where the time went. The connect is a round trip and belongs to
            # the path; the handshake beyond that is the server's own work, and
            # "it's slow" gets sent to the wrong team without the split.
            tcp_ms, tls_ms = tls.get("tcp_ms"), tls.get("tls_ms")
            if (tls_ms is not None and tcp_ms is not None
                    and tls_ms >= TLS_HANDSHAKE_FLOOR_MS
                    and tcp_ms > 0 and tls_ms / tcp_ms >= TLS_HANDSHAKE_RATIO):
                findings.append({
                    "severity": "warning",
                    "layer": 7,
                    "code": "tls_handshake_slow",
                    "message": f"Reaching {target}:{port_num} took {tcp_ms + tls_ms:.0f}ms, and "
                               f"{tls_ms:.0f}ms of that was the TLS handshake against "
                               f"{tcp_ms:.0f}ms to connect. A handshake is one or two round "
                               f"trips, so the difference is the server doing work rather than "
                               f"distance - it is busy, or fetching something mid-handshake. "
                               f"The network delivered the connection in {tcp_ms:.0f}ms.",
                })
            if not tls.get("ok"):
                findings.append({
                    "severity": "warning",
                    "layer": 4,
                    "code": "tls_handshake_failed",
                    "message": f"Port {port_num} on {target} accepts connections but the TLS "
                               f"handshake doesn't complete ({tls.get('error', 'no detail')}). "
                               f"Something is listening; whatever it is isn't serving TLS. A "
                               f"port check alone would have called this healthy.",
                })
                continue
            issuer = (tls.get("issuer") or "").lower()
            if tls.get("verified") is False:
                # Two separate findings rather than one with a computed code:
                # the coverage test greps for literal codes, and a code it
                # cannot see is a code with no verdict rule.
                preamble = (f"The certificate returned by {target}:{port_num} doesn't verify "
                            f"({tls.get('verify_error', 'unknown reason')})"
                            + (f", and was issued by {tls.get('issuer')}"
                               if tls.get("issuer") else "") + ". ")
                if tls.get("intercepted_by") or any(h in issuer for h in INTERCEPTION_HINTS):
                    findings.append({
                        "severity": "warning",
                        "layer": 7,
                        "code": "tls_intercepted",
                        "message": preamble + "That issuer is an inspection product, so traffic "
                                              "is being intercepted and re-signed somewhere in "
                                              "the path - anything that pins or verifies "
                                              "certificates fails while ping and port checks "
                                              "look perfect.",
                    })
                else:
                    findings.append({
                        "severity": "warning",
                        "layer": 7,
                        "code": "tls_untrusted",
                        "message": preamble + "Either the certificate is genuinely bad, or "
                                              "something in the path is re-signing traffic. "
                                              "Anything that verifies certificates refuses to "
                                              "connect either way.",
                    })
            ahead = tls.get("not_yet_valid_days")
            if ahead:
                findings.append({
                    "severity": "critical",
                    "layer": 7,
                    "code": "tls_not_yet_valid",
                    "message": f"The certificate on {target}:{port_num} does not become valid "
                               f"for another {ahead} day(s) (from {tls.get('starts')}). A "
                               f"certificate issued for the future is rare; a clock that is "
                               f"behind is common, and this device's clock is the first thing "
                               f"to check. If it is wrong, every TLS result in this report is "
                               f"measuring the clock rather than the service.",
                })
            days = tls.get("days_left")
            if tls.get("expired"):
                findings.append({
                    "severity": "critical",
                    "layer": 7,
                    "code": "tls_expired",
                    "message": f"The certificate on {target}:{port_num} has expired. Clients "
                               f"refuse the connection outright while the network is perfect - "
                               f"which is why this looks like a network fault and isn't one.",
                })
            elif days is not None and days < 0:
                findings.append({
                    "severity": "critical",
                    "layer": 7,
                    "code": "tls_expired",
                    "message": f"The certificate on {target}:{port_num} expired "
                               f"{abs(days)} day(s) ago ({tls.get('expires')}). Clients will "
                               f"refuse the connection outright; the network is fine.",
                })
            elif days is not None and days <= CERT_EXPIRY_WARN_DAYS:
                findings.append({
                    "severity": "warning",
                    "layer": 7,
                    "code": "tls_expiring",
                    "message": f"The certificate on {target}:{port_num} expires in {days} day(s) "
                               f"({tls.get('expires')}). Not a fault yet, and much cheaper to fix "
                               f"now than during the outage it becomes.",
                })
        if not port_result.get("ok"):
            reason = port_result.get("reason", "unknown")
            # A port from the 'common' preset was a look, not a claim. Naming a
            # port is asserting you expect it open; a preset asserts nothing, so
            # a closed one there is context rather than a fault.
            severity = "ok" if speculative else "warning"
            suffix = (" This came from the 'common' preset rather than a port you named, so "
                      "plenty of hosts legitimately don't answer here." if speculative else "")
            if reason == "refused":
                findings.append({
                    "severity": severity,
                    "code": "port_refused",
                    "layer": 4,
                    "message": f"Port {port_spec} on {target} is closed or filtered: "
                               f"{port_result.get('error', 'connection refused')}. The service "
                               f"may not be running, or a firewall is blocking it." + suffix,
                })
            elif reason == "no_route":
                findings.append({
                    # Never speculative: a missing route is this box's own
                    # configuration whichever port asked the question, and a
                    # preset port finding one is the preset doing its job.
                    "severity": "critical",
                    "code": "no_route_to_target",
                    "layer": 3,
                    "message": f"This device has no route to {target} at all - the kernel "
                               f"refused port {port_spec} instantly rather than sending "
                               f"anything and waiting. Nothing was put on the wire, so no "
                               f"part of the network had the chance to fail. Read this "
                               f"device's routing table: either the destination is not "
                               f"covered by any route, or the route that should cover it "
                               f"points at an interface that is down.",
                })
            elif reason == "host_unreachable":
                findings.append({
                    "severity": severity,
                    "code": "port_host_unreachable",
                    "layer": 3,
                    "message": f"A router on the way to {target} reported that it cannot "
                               f"reach the host, for port {port_spec}. That is different "
                               f"from silence: something forwarded the traffic partway and "
                               f"then told us the destination is not reachable from there. "
                               f"The router that answered knows why - the trace names the "
                               f"hop." + suffix,
                })
            else:  # timeout
                findings.append({
                    "severity": severity,
                    "code": "port_timeout",
                    "layer": 4,
                    "message": f"Port {port_spec} on {target} timed out: "
                               f"{port_result.get('error', 'no response')}. Likely a routing or "
                               f"packet-loss issue rather than a firewall rule." + suffix,
                })

    return port_results


def collect_trace(target, mtr_cycles):
    """Run the trace and parse it. Separated from the interpretation so it can
    be started alongside the pings - it is the single slowest thing here, and
    nothing else needs to wait for it."""
    mtr_res = cmd_mtr(target, mtr_cycles)
    if mtr_res:
        return {"raw": mtr_res, "hops": mtr_res["hops"], "source": "mtr", "mtr": mtr_res}
    res = cmd_traceroute(target)
    hops = parse_traceroute_hops(res.get("stdout", "")) if res.get("ok") else []
    return {"raw": res, "hops": hops, "source": "traceroute", "mtr": None}


def collect_probes(target, gw, ping_count, ping_wait, quick, mtr_cycles, parallel=True):
    """Gateway ping, target ping and the trace.

    These don't depend on each other, so by default they run together and the
    run costs about as long as the trace alone. Under --soak they run one at a
    time: when someone has deliberately asked to sample for a minute, probes
    perturbing each other's latency matters more than the seconds saved.
    """
    jobs = {}
    if gw:
        jobs["ping_gateway"] = (cmd_ping, (gw, ping_count, ping_wait))
    jobs["ping_internet"] = (cmd_ping, (target, ping_count, ping_wait))
    if not quick:
        jobs["trace"] = (collect_trace, (target, mtr_cycles))

    if not parallel or len(jobs) < 2:
        return {name: fn(*args) for name, (fn, args) in jobs.items()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {name: pool.submit(fn, *args) for name, (fn, args) in jobs.items()}
        return {name: f.result() for name, f in futures.items()}


def _check_path(raw, findings, target, gw, inet_loss, quick, mtr_cycles, primary_mtu,
                trace=None):
    """The path to the target: trace it, read what the shape of it means, and
    check whether full-size packets survive it.

    Returns the hops, the derived path insight, and which tool produced them.
    """
    if quick:
        # The trace is the expensive part - skip it, and say so in the report
        # so the UI and the text output don't imply an empty path was measured.
        hops = []
        path_source = None
        path_insight = {"demarc_hop": None, "worst_jump": None,
                        "networks_crossed": [], "double_nat": [], "loop_at": None,
                        "cgnat_hop": None}
    else:
        # mtr sends many cycles per hop, so it yields real per-hop loss where
        # traceroute yields a single sample. Use it when present; the hop shape
        # is identical either way, so everything downstream is unchanged.
        trace = trace or collect_trace(target, mtr_cycles)
        raw["path_trace"] = trace["raw"]
        hops = trace["hops"]
        path_source = trace["source"]
        mtr_res = trace["mtr"]
        # If the probes stopped short but the target answers ping, the path is
        # probably fine and the probes are being filtered. A TCP trace to a
        # port that's actually open usually walks straight through, and the
        # difference between "the path is broken" and "the probes are dropped"
        # is worth the extra few seconds.
        if (not trace_reached(hops, target) and inet_loss is not None and inet_loss < 100
                and not quick):
            tcp_res = cmd_traceroute_tcp(target)
            if tcp_res and trace_reached(tcp_res["hops"], target):
                raw["path_trace_icmp"] = raw["path_trace"]
                raw["path_trace"] = tcp_res
                stalled_at = hops[-1]["hop"] if hops else "the first hop"
                hops = tcp_res["hops"]
                path_source = f"{tcp_res['tool']} (TCP/{tcp_res['port']})"
                findings.append({
                    "severity": "ok",
                    "layer": 3,
                    "code": "icmp_filtered",
                    "message": f"The standard trace stopped at hop {stalled_at}, but a TCP probe "
                               f"to port {tcp_res['port']} reached {target} - so the path is "
                               f"fine and something along it simply doesn't answer traceroute "
                               f"probes. Worth knowing before escalating a path that isn't "
                               f"actually broken.",
                })
            elif tcp_res:
                path_source += " (TCP probe also stopped short)"

        path_insight = annotate_hops(hops, gw, target)

        # Per-hop loss is only meaningful with mtr's repeated probes. Read it
        # from the destination backwards: loss at an intermediate hop that
        # clears later is ICMP rate limiting on that router, not a fault.
        lossy = [h for h in hops if (h.get("loss_pct") or 0) >= 5]
        final_loss = hops[-1].get("loss_pct") if hops else None
        if lossy and final_loss is not None and final_loss >= 5:
            first = lossy[0]
            findings.append({
                "severity": "critical" if final_loss >= 20 else "warning",
                "layer": 3,
                "code": "path_loss",
                "message": f"Packet loss along the path to {target}: {final_loss:.0f}% at the "
                           f"destination, first appearing at hop {first['hop']} "
                           f"({first.get('display')}) over {mtr_res['cycles'] if mtr_res else '?'} probes "
                           f"per hop. "
                           f"Loss that persists to the final hop is real loss, not a router "
                           f"declining to answer probes.",
            })
        elif lossy and final_loss is not None and final_loss < 5:
            findings.append({
                "severity": "ok",
                "layer": 3,
                "code": "path_loss_cosmetic",
                "message": f"Some intermediate hops report loss but the destination shows "
                           f"{final_loss:.0f}%, so the path is fine - those routers are rate-"
                           f"limiting ICMP replies rather than dropping traffic.",
            })
    # A hop that refused and said why. The distinction that matters is whether
    # the path still completed: a policy device that declines traceroute probes
    # while forwarding traffic is normal and common, and the same annotation on
    # the hop where the path stops is a firewall standing in the way. Only the
    # second is a fault, and it has an owner a silent path does not - somebody
    # configured this, so there is a person to ask rather than a carrier.
    refused = [h for h in hops
               if any(f in TRACE_PROHIBITED for f in (h.get("flags") or []))]
    if refused and not trace_reached(hops, target):
        hop = refused[-1]
        reasons = sorted({TRACE_ANNOTATIONS.get(f, f) for f in hop["flags"]
                          if f in TRACE_PROHIBITED})
        findings.append({
            "severity": "critical",
            "layer": 3,
            "code": "path_admin_prohibited",
            "message": f"The path stops at hop {hop['hop']} ({hop['display']}), and that hop "
                       f"said why: {', '.join(reasons)}. This is not a broken path or a "
                       f"router that has stopped answering - it is a device that received "
                       f"the traffic, decided against forwarding it, and reported the "
                       f"decision. Somebody configured that, so there is a policy to read "
                       f"and a person to ask rather than a carrier to open a ticket with.",
        })
    stalled = [h for h in hops if h["timed_out"]] if not quick else []
    if stalled and hops and not stalled[-1]["hop"] == hops[-1]["hop"]:
        # a timeout in the middle of the path, with hops succeeding after it, usually just
        # means that hop doesn't reply to traceroute probes (common/benign) - only flag a
        # run of timeouts that goes all the way to the last hop we saw.
        pass
    if hops and all(h["timed_out"] for h in hops[-3:]) and len(hops) >= 3:
        findings.append({
            "severity": "warning",
            "code": "trace_stalls",
            "layer": 3,
            "message": f"The path to {target} stops responding around hop {hops[-3]['hop']} and never "
                       "reaches the destination in the trace. The break is likely at or just after that "
                       "hop (could also be a router that silently drops traceroute probes but still "
                       "forwards real traffic - check the ping result above to tell them apart).",
        })

    # Path MTU. Skipped in quick mode (it's several more pings) and pointless
    # if the target never answered at all.
    if not quick and inet_loss is not None and inet_loss < 100:
        raw["path_mtu"] = cmd_path_mtu(target, primary_mtu or STANDARD_MTU)
        pm = raw["path_mtu"]
        if pm.get("path_mtu") is None:
            findings.append({
                "severity": "warning",
                "code": "pmtu_unmeasurable",
                "layer": 3,
                "message": f"No do-not-fragment probe reached {target} at any size, even though "
                           f"ordinary pings do. The target or a device in between is likely "
                           f"dropping DF-flagged packets, so path MTU can't be measured from "
                           f"here - not necessarily a fault in itself.",
            })
        elif pm.get("path_mtu") < pm.get("iface_mtu", STANDARD_MTU):
            findings.append({
                "severity": "critical",
                "code": "pmtu_blackhole",
                "layer": 3,
                "message": f"Path MTU to {target} is only {pm['path_mtu']} bytes, but this "
                           f"interface is set to {pm['iface_mtu']}. Full-size packets are being "
                           f"dropped silently somewhere along the path while small ones get "
                           f"through - so ping and SSH look fine while large transfers, file "
                           f"copies, TLS handshakes or VPN traffic stall. Classic PMTU "
                           f"blackhole: something in the path drops oversized packets without "
                           f"sending the ICMP message that would let the sender adapt. This "
                           f"measures the path to {target} in the outbound direction only - "
                           f"routing is often asymmetric, so a service elsewhere may see a "
                           f"different limit, and the return path is not tested at all.",
            })

    if path_insight.get("loop_at"):
        lp = path_insight["loop_at"]
        # Both ends of the circle, since the loop is the pair and marking one
        # of them would read as a single bad hop rather than traffic going
        # back where it came from.
        for hop in hops:
            if hop.get("hop") in lp["hops"]:
                hop["blame"] = {"code": "loop", "severity": "critical"}
        findings.append({
            "severity": "critical",
            "code": "loop",
            "layer": 3,
            "message": f"Routing loop: {lp['host']} answers at both hop {lp['hops'][0]} and hop "
                       f"{lp['hops'][1]}. Traffic is circling between routers instead of moving "
                       f"toward {target}, and will die when the TTL runs out. This is a routing "
                       f"misconfiguration upstream, not a fault on this device.",
        })

    if path_insight.get("double_nat"):
        subnets = path_insight["double_nat"]
        findings.append({
            "severity": "warning",
            "code": "double_nat",
            "layer": 3,
            "message": f"Two private networks before traffic leaves this site "
                       f"({', '.join(s + '.x' for s in subnets)}) - so there are at least two "
                       f"routers in series (double NAT). It usually still works, but it breaks "
                       f"inbound connections and port forwarding, and makes intermittent faults "
                       f"much harder to place.",
        })

    if path_insight.get("cgnat_hop"):
        findings.append({
            "severity": "warning",
            "code": "cgnat",
            "layer": 3,
            "message": f"This site sits behind carrier-grade NAT (hop "
                       f"{path_insight['cgnat_hop']} is in 100.64.0.0/10, the provider's own "
                       f"shared range). There is no public address on this connection, so "
                       f"nothing can reach it from outside regardless of local configuration - "
                       f"worth knowing before chasing an inbound-access problem on the device.",
        })

    wj = path_insight.get("worst_jump")
    end_to_end = max((h.get("avg_ms") or 0) for h in hops) if hops else 0
    wall_share = (wj["delta_ms"] / end_to_end) if (wj and end_to_end) else 0
    if wj and wj["delta_ms"] >= LATENCY_WALL_MS and wall_share >= LATENCY_WALL_SHARE:
        # 100ms in a single hop is well past normal inter-city routing, so it's
        # worth naming - and which side of the demarc it lands on is the point.
        #
        # The share test is what makes the sentence true. On a uniformly graded
        # path every hop adds the same amount, and the milliseconds alone fired
        # this and named a hop no worse than its neighbours - while claiming a
        # single hop added most of the delay. Where no hop does, nothing is
        # claimed: the per-hop deltas are in the path panel either way.
        # CGNAT space is private-range but belongs to the carrier, so a jump
        # there is on their side of the demarc, not inside the site.
        if wj.get("cgnat"):
            side = ("in the provider's carrier-NAT layer, just outside this site - their "
                    "access network rather than anything here")
        elif wj.get("private"):
            side = "inside the local network - so the delay starts before traffic leaves the site"
        else:
            side = "out on the provider's side of the network, past this site's edge"
        # Mark the hop on the way past. The chain scored its nodes on loss and
        # timeouts alone, which are the only things it could see for itself -
        # so on a latency wall the one hop this finding names was the one thing
        # on the path drawn as unremarkable, and the verdict pointed at a hop
        # the picture showed as clean. The conclusion travels with the hop
        # rather than being worked out a second time from the timings, because
        # a second derivation is a second set of thresholds to drift.
        for hop in hops:
            if hop.get("hop") == wj["hop"]:
                hop["blame"] = {"code": "latency_wall", "severity": "warning"}
                break
        findings.append({
            "severity": "warning",
            "code": "latency_wall",
            "layer": 3,
            "message": (
                (f"The very first hop is already {wj['delta_ms']:.0f}ms "
                 f"({wj['host']}), {side}. "
                 if wj["hop"] == 1 else
                 f"Latency jumps {wj['delta_ms']:.0f}ms at hop {wj['hop']} "
                 f"({wj['host']}), {side}. ")
                + "Everything past that hop inherits the delay, so the hops after it "
                  "looking slow is expected rather than separate."),
        })
    return hops, path_insight, path_source


def _check_call_quality(raw, findings, target, inet_loss):
    """What the round trip costs: on its own, and reduced to a call score.

    Two statements from one measurement, because a box serving requests and a
    box carrying calls are hurt by the same milliseconds in different words.
    The MOS finding used to be the only one, so an 800ms path to a database
    reported that voice and video would be unusable - true, and no use at all
    to whoever runs the database. It also needs a loss figure to compute, so a
    run that could not measure loss said nothing about latency whatsoever.
    """
    ping_stats = parse_ping_stats(raw.get("ping_internet", {}))
    avg = ping_stats.get("avg_ms")
    if avg is not None and avg >= LATENCY_HIGH_MS:
        findings.append({
            "severity": "critical",
            "layer": 3,
            "code": "latency_high",
            "message": f"The round trip to {target} averages {avg:.0f}ms. Light in "
                       f"fibre crosses the planet and comes back in about 250ms, so "
                       f"distance stops explaining a path this long - unless this link "
                       f"is satellite, where a geostationary hop is 500-650ms by itself "
                       f"and nothing is wrong. Every request pays it before any data "
                       f"moves, and a new TLS connection pays it three times over, so "
                       f"anything that makes several calls is seconds slower no matter "
                       f"how much bandwidth the line has.",
        })
    call_quality = None
    if ping_stats.get("avg_ms") is not None and inet_loss is not None:
        mos, r = mos_score(ping_stats["avg_ms"], ping_stats.get("stdev_ms"), inet_loss)
        if mos is not None:
            call_quality = {"mos": mos, "r_factor": r, "target": target,
                            "avg_ms": ping_stats["avg_ms"],
                            "jitter_ms": ping_stats.get("stdev_ms"),
                            "loss_pct": inet_loss}
            if mos < MOS_BAD:
                findings.append({
                    "severity": "critical",
                    "layer": 3,
                    "code": "call_quality_bad",
                    "message": f"Estimated call quality to {target} is MOS {mos} "
                               f"({ping_stats['avg_ms']:.0f}ms latency, "
                               f"{ping_stats.get('stdev_ms', 0):.0f}ms jitter, {inet_loss:.0f}% "
                               f"loss). Below {MOS_BAD} most people call a line unusable - "
                               f"words drop and people talk over each other. Video and "
                               f"screen-sharing degrade the same way.",
                })
            elif mos < MOS_WARN:
                findings.append({
                    "severity": "warning",
                    "layer": 3,
                    "code": "call_quality_degraded",
                    "message": f"Estimated call quality to {target} is MOS {mos} "
                               f"({ping_stats['avg_ms']:.0f}ms latency, "
                               f"{ping_stats.get('stdev_ms', 0):.0f}ms jitter, {inet_loss:.0f}% "
                               f"loss). Calls will be audible but rough. Jitter hurts a call "
                               f"more than steady latency does, so a stable slow link beats an "
                               f"erratic fast one.",
                })
    return call_quality


# Interfaces carrying the same fault before it stops being about a cable. Two
# is a coincidence worth nothing - a box with two bad patch leads is a box with
# two bad patch leads. Three of them, and every active interface, is a common
# factor.
SHARED_FAULT_INTERFACES = 3


def _check_every_interface(findings, raw):
    """The same fault on every interface is not a fault of any of them.

    This is the reasoning the flow checks already do for peers - loss to one
    destination is that destination, loss to all of them is the local link -
    applied to the cables instead, where it was missing. A box with eight NICs
    all reporting errors produced eight findings, and the verdict picked
    whichever happened to be first and called it that cable, at medium
    confidence, on a box where the cable was demonstrably not the thing they
    had in common.
    """
    active = {i["name"] for i in (raw.get("link_stats") or {}).get("interfaces", [])
              if i.get("packets") and not i["name"].startswith("lo")}
    if len(active) < SHARED_FAULT_INTERFACES:
        return
    by_code = {}
    for f in findings:
        if f.get("scope") and f["severity"] in ("warning", "critical"):
            by_code.setdefault(f["code"], set()).add(f["scope"])
    for code in sorted(by_code):
        scopes = by_code[code] & active
        if len(scopes) < SHARED_FAULT_INTERFACES or scopes != active:
            continue
        findings.append({
            "severity": "critical",
            "layer": 2,
            "code": "fault_on_every_interface",
            "message": f"Every active interface on this device is reporting the same "
                       f"problem - {code} on all {len(scopes)} of them "
                       f"({', '.join(sorted(scopes))}). Whatever they have in common is "
                       f"the cause, and it is not a cable: they do not share one. Look at "
                       f"what they do share - the driver, the NIC or its firmware, the "
                       f"power or heat around it, or the one switch they all land in.",
        })
        return


def _all_clear(raw, findings, check_ports, dns_failed):
    """When nothing failed, say what was actually verified - an all-clear that
    lists its evidence is worth more than one that just says 'fine'."""
    if not any(f["severity"] != "ok" for f in findings):
        # Only claim what was measured. On a box with no IPv4 the gateway and
        # target were never reached - they could not be - and an all-clear that
        # says they were is the exact overclaim this sentence exists to avoid.
        unmeasured = {f.get("code") for f in findings} & {
            "gw_unmeasurable_v4", "inet_unmeasurable_v4"}
        if unmeasured:
            msg = "No fault found in what could be checked here: the interface has an address"
        else:
            msg = ("No obvious issues detected: the interface has an IP address, the "
                   "gateway and the internet are reachable")
        if dns_failed:
            pass  # Already flagged above
        else:
            msg += ", DNS resolution succeeded"
        if check_ports:
            msg += f", all {len(check_ports)} port(s) checked are reachable"
        # Clean counters are the evidence that it *isn't* this device, which is
        # the whole question on a call - say it explicitly.
        active = [i for i in raw["link_stats"].get("interfaces", [])
                  if i["packets"] and not i["name"].startswith("lo")]
        if active and all(not i["errors"] and not i["drops"] for i in active):
            # Only claim a clean link for counters we actually read. A driver
            # that exports nothing would otherwise look identical to a perfect
            # link, and this sentence gets repeated to sites.
            core = ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
            missing = {k for i in active for k in i.get("unknown_counters", []) if k in core}
            if missing:
                msg += (f", and the {len(active)} active interface(s) report no errors or drops "
                        "(though this driver doesn't expose every counter, so that's not a "
                        "complete picture of the physical link)")
            else:
                msg += (f", and the {len(active)} active interface(s) show no error or drop counters "
                        "at all - the physical link into this device is clean")
        if unmeasured:
            msg += (". The gateway and the target were never reached - see above for why - "
                    "so nothing here is a claim about them")
        msg += "."
        findings.append({
            "severity": "ok",
            "code": "all_clear",
            "message": msg,
        })

def _check_addressing(raw, findings):
    """Does this device have an address at all?

    The two outcomes are deliberately different in kind: a tool that wouldn't
    run leaves a warning that the question is open, while an interface list
    that ran and showed nothing is a critical fault. Reporting a missing
    command as "no IP address" would be a diagnosis invented from a gap, which
    is exactly what a stripped-down appliance provokes.
    """
    # Always set, both ways. It was written only when it was False, so its
    # absence meant the opposite of the only value ever stored - which reads
    # correctly today because both callers test `is False`, and breaks the
    # first time anyone writes `if raw["ipv4"]`. A key should mean one thing.
    raw["ipv4"] = bool(has_ipv4(raw["interfaces"]))
    if not raw["interfaces"].get("ok"):
        findings.append({
            "severity": "warning",
            "code": "interfaces_unreadable",
            "layer": 1,
            "message": f"Couldn't read the interface list "
                       f"({raw['interfaces'].get('error', 'command failed')}), so this run "
                       f"can't say whether the device has an address. Everything below assumes "
                       f"it does.",
        })
    elif not has_ip_address(raw["interfaces"]):
        findings.append({
            "severity": "critical",
            "code": "no_ipv4",
            "layer": 1,
            "message": "No active interface has an address of either family - no IPv4, and no "
                       "IPv6 beyond the link-local one every interface gets whether or not "
                       "anything configured it. Check the physical connection (cable seated / "
                       "Wi-Fi associated) and whether DHCP or SLAAC is completing.",
        })
    elif not has_ipv4(raw["interfaces"]):
        # On the network by IPv6 and not by IPv4. Ordinary on mobile carriers
        # and in plenty of datacentres outside the US - and every IPv4 check
        # below is now measuring something this box cannot do, rather than
        # something that is broken.
        findings.append({
            "severity": "ok",
            "code": "ipv6_only",
            "layer": 3,
            "message": "This box has a global IPv6 address and no IPv4 one. That is a working "
                       "configuration, not a fault - but every check below that reaches an "
                       "IPv4 address cannot run here, and is reported as unavailable rather "
                       "than as a failure. Point --target at an IPv6 address or a name with "
                       "an AAAA record to diagnose the path this box actually uses.",
        })


# Tried in order to prove a host is reachable when ICMP gets nowhere. Three
# ports on the one host the operator named - not a scan, and the same thing
# --check-ports already does on request.
REACHABILITY_PORTS = ("443", "80", "53")


# Live inbound connections before a box counts as serving traffic. One is a
# health check or this SSH session; a handful is clients.
SERVING_INBOUND_MIN = 3


# Connections to one peer before it counts as a dependency rather than a
# passing conversation. A proxy holds many to each backend; one connection to
# somewhere is a DNS lookup or a webhook, not the thing the service runs on.
BACKEND_MIN_CONNECTIONS = 2

# And the share of this box's outbound connections it has to hold. A count
# alone cannot tell a dependency from a busy destination: a box that forwards
# traffic on behalf of other people opens connections to hundreds of places it
# does not depend on at all, and the most-connected of those is whichever site
# is popular this minute. A handful of real backends each hold a large slice;
# one destination out of hundreds holds almost none.
BACKEND_MIN_SHARE = 0.15

# Distinct outbound destinations above which a box is forwarding traffic rather
# than consuming a few services. Well clear of an application talking to a
# dozen or so of its own dependencies.
FORWARDER_DESTINATIONS = 50

# At or below this many outbound destinations, a box with no listening ports is
# holding a deliberate handful of connections rather than browsing. A connector
# that carries traffic over a few long-lived links to an edge looks exactly
# like this, and its edge is the dependency worth aiming at.
CONNECTOR_DESTINATIONS = 6


def pick_backend(sockets):
    """The peer this box depends on most, or None.

    Outbound connections from a box that accepts connections are, by
    definition, the things it needs in order to answer. The busiest of them is
    the dependency worth pointing a diagnosis at - 8.8.8.8 tells a proxy
    nothing it needs to know, and its database tells it everything.

    Counted by number of connections rather than bytes: a pool of twenty
    connections to a database is a harder dependency than one long transfer to
    an object store, and pools are what proxies keep.
    """
    if not sockets or not sockets.get("ok"):
        return None
    listening = set(sockets.get("listen_ports") or [])
    serving = listening and (sockets.get("inbound") or 0) >= SERVING_INBOUND_MIN
    # Listening is not serving: almost every machine has something bound to a
    # port, and on a laptop the busiest peer is whatever application is open.
    # But a box with no listeners at all can still have real dependencies - a
    # connector that holds a few long-lived connections out to an edge and
    # carries traffic over them opens no inbound ports by design. What both
    # cases have in common is concentration, which the share test below
    # measures, so the gate is "serving, or holding a concentrated handful"
    # rather than "listening".
    concentrated = (not listening
                    and 0 < (sockets.get("outbound_destinations") or 0) <= CONNECTOR_DESTINATIONS
                    and (sockets.get("outbound") or 0) >= BACKEND_MIN_CONNECTIONS)
    if not serving and not concentrated:
        return None
    ssh_peer, _ssh_port = _own_ssh_peer()
    counts = {}
    for peer, local_port in (sockets.get("peers") or []):
        if not peer or local_port in listening:
            continue                # a client's connection, not one of ours
        if peer == ssh_peer or _flow_is_local(peer):
            continue                # our own way in, or not the network
        counts[peer] = counts.get(peer, 0) + 1
    if not counts:
        return None
    # Ties broken by address so the choice is the same on every run - a target
    # that moves between runs makes two reports impossible to compare.
    peer, count = max(sorted(counts.items()), key=lambda kv: kv[1])
    if count < BACKEND_MIN_CONNECTIONS:
        return None
    if count < sum(counts.values()) * BACKEND_MIN_SHARE:
        return None      # forwarding, not depending - see BACKEND_MIN_SHARE
    return peer


def _choose_target(requested, sockets, findings):
    """(target, kind) - what to point the diagnosis at, and what it is.

    8.8.8.8 answers "can this box reach the internet", which is the whole
    question on a branch appliance and close to irrelevant on a box whose job
    is to answer requests. What matters there is whether it can reach the
    things it depends on. Those are visible: the connections it opened itself.

    Only ever chosen when nobody said otherwise, and always reported - a target
    that changes silently makes two runs impossible to compare.
    """
    asked = (requested or "").strip().lower()
    if requested and asked != "auto":
        # Converted once, here, so nothing downstream has to think about it:
        # every command this runs and every socket it opens sees the ASCII form
        # the DNS actually carries, and the report records what was reached
        # rather than what was typed.
        requested = idna_host(requested) or requested
        return requested, "internet" if not _flow_is_local(requested) else "local"
    backend = pick_backend(sockets)
    forwarding = (not backend and (sockets or {}).get("outbound_destinations", 0)
                  >= FORWARDER_DESTINATIONS)
    # A dependency on a public address is a real dependency - a managed
    # database, an external API - and worth aiming at. But the verdicts that
    # say "the segment between here and that backend" are only true of an
    # internal one, so the two kinds are named apart and only the internal kind
    # re-owns anything.
    kind = "backend" if backend and is_private_ip(backend) else "dependency"
    if forwarding:
        findings.append({
            "severity": "ok",
            "layer": 3,
            "code": "target_is_forwarded",
            "message": f"This box has connections open to "
                       f"{sockets['outbound_destinations']:,} distinct destinations with no "
                       f"single one holding a meaningful share, which is a box forwarding "
                       f"traffic on behalf of other people rather than one depending on a "
                       f"few services. Aiming at the busiest of them would diagnose the "
                       f"path to whichever destination is popular this minute, so "
                       f"{DEFAULT_TARGET} is used instead. Pass --target explicitly for the "
                       f"path you actually care about - the service this box reports to, or "
                       f"one destination its users are complaining about.",
        })
        return DEFAULT_TARGET, "internet"
    if not backend:
        if asked == "auto":
            findings.append({
                "severity": "ok",
                "layer": 3,
                "code": "target_auto_failed",
                "message": "--target auto found no backend to aim at: this box is not "
                           "accepting connections, or it has opened none of its own. "
                           f"Falling back to {DEFAULT_TARGET}, which answers whether it can "
                           "reach the internet rather than whether it can reach anything it "
                           "depends on.",
            })
        return DEFAULT_TARGET, "internet"
    findings.append({
        "severity": "ok",
        "layer": 3,
        "code": "target_is_a_backend",
        "message": f"Aimed at {backend} rather than {DEFAULT_TARGET}: this box is serving "
                   f"clients and {backend} is the peer it has opened the most connections "
                   f"to, which makes it a dependency rather than a passing conversation. "
                   + ("Reachability, path and latency below are about the segment between "
                      "here and that backend, not about the internet. "
                      if kind == "backend" else
                      "That is a public address, so the path to it does leave this site - "
                      "the readings below are about reaching that dependency rather than "
                      "about the internet in general. ")
                   + "Pass --target explicitly to aim somewhere else.",
    })
    return backend, kind


# Ports whose purpose is answering clients. Gated to these deliberately:
# almost every machine listens on something - sshd, a metrics endpoint, a
# database bound to the LAN - and "listening with nobody connected" is only
# interesting when the thing listening exists to be connected to. Without this
# the check fired on any box with sshd running, which is all of them.
SERVING_PORTS = {"80", "443", "8000", "8080", "8443", "3000", "9443"}


LOCAL_RESOLVERS = {
    "127.0.0.53": "systemd-resolved",
    "127.0.0.54": "systemd-resolved (delegated)",
    "127.0.1.1": "dnsmasq or a NetworkManager stub",
}


def _check_dns_cache(raw, findings):
    """Are we asking a cache on this box, or a server on the network?

    It changes what every DNS answer here means. A stale entry in a cache on
    this box is invisible from anywhere else, will not reproduce from the next
    machine somebody tries, and outlives the upstream being fixed - which is
    exactly the shape of "it works for me". Worth saying before any resolver
    result below is read as the network's answer.
    """
    health = raw.get("dns_health") or {}
    if not health.get("ok"):
        return
    local = [(r.get("server"), LOCAL_RESOLVERS.get((r.get("server") or "").strip()))
             for r in health.get("resolvers") or []
             if _flow_is_local((r.get("server") or "").strip())]
    if not local:
        return
    named = ", ".join(f"{s} ({n})" if n else str(s) for s, n in local)
    findings.append({
        "severity": "ok",
        "layer": 7,
        "code": "dns_local_cache",
        "message": f"{len(local)} of the configured resolver(s) is on this box itself: "
                   f"{named}. Every DNS answer below came from that cache rather than "
                   f"from a server on the network - so a stale or poisoned entry here is "
                   f"invisible from anywhere else, will not reproduce from the next "
                   f"machine somebody tries, and outlives the upstream being fixed. Flush "
                   f"it before concluding anything about DNS from these results.",
    })


def _check_idle(raw, findings):
    """Neither listening for anyone nor talking to anything.

    A box that carries traffic over links it opens itself - a connector to some
    edge, an agent that registers upward - has no inbound ports at all, so
    every "is anything reaching it" check here stays silent by design. When its
    links are gone there is nothing left to see: no listeners, no connections,
    and every other check passes because there is nothing for them to find a
    fault in. It reported "no fault found - this device looks healthy".

    Our own session is excluded. We arrived over it, so counting it would mean
    this could never fire from the place it is run.
    """
    sock = raw.get("sockets") or {}
    if not sock.get("ok"):
        return
    # "No peers listed" and "the peer list was never produced" are different
    # answers, and only the first is evidence. A parse that predates this key,
    # or a platform whose socket table it cannot read, must not be reported as
    # a box with nothing connected to it.
    if "peers" not in sock or "listen_ports" not in sock:
        return
    if sock.get("listen_ports"):
        return                  # something is bound; _check_rotation covers it
    ssh_peer, _port = _own_ssh_peer()
    others = [peer for peer, _local in (sock.get("peers") or [])
              if peer and peer != ssh_peer and not _flow_is_local(peer)]
    if others:
        return
    findings.append({
        "severity": "warning",
        "layer": 4,
        "code": "no_traffic_at_all",
        "message": "This box is listening on nothing and has no connections open to "
                   "anywhere"
                   + (" except the session this was run over" if ssh_peer else "")
                   + ". Every other check here passes, because a box doing nothing has "
                     "nothing wrong with its network. If it is meant to be carrying "
                     "traffic over links it opens itself - a connector to some edge, an "
                     "agent registering upward - those links are gone, and that is the "
                     "fault. Check the service is running and can reach what it "
                     "registers with before looking at anything below.",
    })


def _check_rotation(raw, findings):
    """Listening, healthy, and nobody is talking to it.

    The failure a load balancer produces looks like nothing at all from the
    box it happened to: the service is up, the port is open, the certificate
    is fine, and no traffic arrives. Every check in this tool passes. It is
    the most common way a proxy is "down" and the least visible from here.
    """
    sock = raw.get("sockets") or {}
    if not sock.get("ok"):
        return
    ports = [p for p in (sock.get("listen_ports") or []) if p in SERVING_PORTS]
    if not ports:
        return                      # nothing here exists to be connected to
    inbound = sock.get("inbound") or 0
    if inbound >= SERVING_INBOUND_MIN:
        return                      # clients are connected; whatever else is wrong
    # Named directly rather than through dominant_peer: that asks whether one
    # address carries *most* of the traffic, and here there is barely any
    # traffic to carry. With one or two connections the peer is the whole
    # picture, and saying which address is still probing is the useful part.
    listening = set(ports)
    who = sorted({peer for peer, local in (sock.get("peers") or [])
                  if peer and local in listening})
    findings.append({
        "severity": "warning",
        "layer": 4,
        "code": "no_clients_connected",
        "message": (
            f"This box is listening on {', '.join(ports[:4])} and "
            + (f"only {inbound} connection(s) are open inbound"
               if inbound else "nothing is connected to it")
            + (f", from {', '.join(who[:3])} - which at that volume is a health check "
               f"rather than traffic" if who and inbound else "")
            + ". The service is up and nothing is reaching it, which is what being "
              "taken out of a load balancer's pool looks like from the inside - "
              "along with a firewall in front, DNS pointing somewhere else, or a "
              "genuinely quiet period. Every other check here will pass while this "
              "is true, so check the balancer's view of this box before its own."),
    })


def _serves_traffic(raw):
    """Is this box being connected *to* right now?

    Clients holding open connections to it prove its network works, from the
    only direction that matters for a service. That is a different question
    from whether the box can reach the internet itself, and conflating the two
    is how a proxy with no egress by design reads as a carrier outage.
    """
    sock = raw.get("sockets") or {}
    if not sock.get("ok"):
        return None
    inbound, ports = sock.get("inbound") or 0, sock.get("listen_ports") or []
    if ports and inbound >= SERVING_INBOUND_MIN:
        return {"inbound": inbound, "ports": ports}
    return None


def _trace_got_there(probes, target):
    """Did the path carry probes all the way to the target?

    The difference between a destination that is down and a path that is
    broken. Without a trace - a --quick run, or a tool that could not run -
    nothing is concluded and the older, vaguer finding stands.
    """
    trace = (probes or {}).get("trace") or {}
    hops = trace.get("hops") or []
    return bool(hops) and trace_reached(hops, target)


def _is_ipv6_literal(host):
    return ":" in (host or "")


def _reachable_over_tcp(host, timeout=3):
    """Did anything reach `host` and come back, ICMP aside?

    A refusal proves it as well as an accept does: an RST is a completed round
    trip, so the packets got there and the replies got back. Only a timeout is
    inconclusive. Returns (port, how) or (None, None).

    This exists because blocking ICMP is ordinary hardening, and a box that
    serves traffic all day was being reported as a critical uplink outage
    purely for not answering ping.
    """
    for port in REACHABILITY_PORTS:
        res = cmd_check_port(host, port, timeout=timeout)
        if res.get("ok"):
            return port, "answered"
        if res.get("reason") == "refused":
            return port, "refused the connection"
    return None, None


def _gateway_answers_arp(arp_entries, gw):
    """Is the gateway in the neighbour table with a real MAC?

    Definitive for the question the ping was asked: ARP does not cross a dead
    cable or a down switch port, so an entry with a hardware address means the
    local link is up whatever ICMP says. States are the kernel's own - anything
    but FAILED/INCOMPLETE means it has been heard from.
    """
    for e in arp_entries or []:
        if e.get("ip") == gw and e.get("mac"):
            if (e.get("state") or "") not in ("failed", "incomplete"):
                return e
    return None


def _check_gateway(raw, findings, gw, probes, arp_entries=None):
    """Is a gateway configured, and does it answer?

    Same shape as the address check: an unreadable routing table leaves the
    question open, no default route is a fault, and only when there is a
    gateway to ping does its reachability mean anything.
    """
    if not raw["routes"].get("ok"):
        findings.append({
            "severity": "warning",
            "code": "routes_unreadable",
            "layer": 3,
            "message": f"Couldn't read the routing table "
                       f"({raw['routes'].get('error', 'command failed')}), so whether a default "
                       f"gateway exists is unknown - not established as missing.",
        })
    elif not gw:
        findings.append({
            "severity": "critical",
            "code": "no_gateway",
            "layer": 3,
            "message": "No default gateway is configured in the routing table. This device can "
                       "likely only reach hosts on its own local subnet.",
        })
    else:
        raw["ping_gateway"] = probes["ping_gateway"]
        loss = parse_ping_loss(raw["ping_gateway"])
        if loss is None:
            findings.append({
                "severity": "warning",
                "code": "gw_unknown",
                "layer": 3,
                "message": f"Could not determine reachability of the gateway ({gw}).",
            })
        elif loss >= 100 and not raw.get("ipv4", True):
            findings.append({
                "severity": "ok",
                "code": "gw_unmeasurable_v4",
                "layer": 2,
                "message": f"The IPv4 gateway {gw} did not answer, and this box has no IPv4 "
                           f"address to reach it from. Nothing is concluded from that - it is "
                           f"a check that could not run, not a gateway that is down.",
            })
        elif loss >= 100:
            neighbour = _gateway_answers_arp(arp_entries, gw)
            if neighbour:
                findings.append({
                    "severity": "ok",
                    "code": "gw_icmp_filtered",
                    "layer": 2,
                    "message": f"Gateway {gw} did not answer a single ping, but it is in this "
                               f"device's neighbour table at {neighbour['mac']}"
                               + (f" ({neighbour['state']})" if neighbour.get("state") else "")
                               + ". ARP does not cross a dead cable or a down switch port, so "
                                 "the local link is up and the gateway is simply not answering "
                                 "ICMP - which is ordinary on a hardened or cloud network. "
                                 "Reported so nothing below reads as an outage.",
                })
            else:
                findings.append({
                    "severity": "critical",
                    "code": "gw_unreachable",
                    "layer": 2,
                    "message": f"Gateway {gw} is unreachable (100% packet loss) and it is not in "
                               "the neighbour table either. Points to a local link problem: bad "
                               "cable, weak/no Wi-Fi signal, a down switch/AP port, or the "
                               "gateway device itself being offline.",
                })
        elif loss > 0:
            sent, lost = parse_ping_counts(raw["ping_gateway"])
            if sent and sent < MIN_PROBES_FOR_LOSS and lost == 1:
                findings.append({
                    "severity": "warning",
                    "code": "gw_loss_unmeasured",
                    "layer": 2,
                    "message": f"One of {sent} probes to the gateway ({gw}) went unanswered. "
                               f"At {sent} probes that reads as {loss:.0f}% because nothing "
                               f"smaller can be expressed, and a gateway busy routing will "
                               f"deprioritise an echo reply. Worth a --soak before calling "
                               f"the local link unstable.",
                })
            else:
                findings.append({
                    "severity": "warning",
                    "code": "gw_partial_loss",
                    "layer": 2,
                    "message": f"Intermittent packet loss ({loss:.0f}%"
                               + (f", {lost} of {sent} probes" if sent else "")
                               + f") to the gateway ({gw}). Possible unstable cabling, "
                                 f"Wi-Fi interference, or an overloaded switch/AP.",
                })


def _check_internet(raw, findings, target, probes):
    """Does traffic get off the site, and is the gateway ruled out first?

    "The internet is unreachable" is only worth saying when the gateway itself
    answered - otherwise it's the same fault reported twice, one layer up.
    Returns the loss figure, which the path, MTU and DNS checks all read.
    """
    gw_loss = parse_ping_loss(raw.get("ping_gateway", {})) if "ping_gateway" in raw else None
    raw["ping_internet"] = probes["ping_internet"]
    inet_loss = parse_ping_loss(raw["ping_internet"])
    gw_ok = gw_loss is None or gw_loss < 100 or any(
        f.get("code") in ("gw_icmp_filtered", "gw_unmeasurable_v4") for f in findings)
    # An IPv4 target on a box with no IPv4 is unreachable by design.
    if not raw.get("ipv4", True) and not _is_ipv6_literal(target):
        findings.append({
            "severity": "ok",
            "code": "inet_unmeasurable_v4",
            "layer": 3,
            "message": f"{target} is an IPv4 destination and this box has no IPv4 address, so "
                       f"it was never reachable from here and nothing follows from that. Give "
                       f"--target an IPv6 address, or a name with an AAAA record.",
        })
        return None
    if inet_loss is not None and inet_loss >= 100 and gw_ok:
        # Ping is one protocol, and the one most likely to be dropped on
        # purpose. Before calling a site's uplink down, try to reach the target
        # the way an application would.
        port, how = _reachable_over_tcp(target)
        raw["reachability_tcp"] = {"ok": bool(port), "cmd": f"tcp connect {target}",
                                   "port": port, "how": how,
                                   "stdout": (f"{target}:{port} {how}" if port else
                                              f"no TCP reply from {target} on "
                                              f"{', '.join(REACHABILITY_PORTS)}"),
                                   "stderr": "", "code": 0}
        if port:
            findings.append({
                "severity": "ok",
                "code": "inet_icmp_filtered",
                "layer": 3,
                "message": f"{target} did not answer a single ping, but TCP reached it - "
                           f"port {port} {how}. The path out of this site works; ICMP is "
                           f"being filtered somewhere along it, which is ordinary on a "
                           f"hardened network and routine in a cloud VPC. Nothing here is "
                           f"an outage, and the loss figures below are about ICMP only.",
            })
            inet_loss = None
        else:
            serving = _serves_traffic(raw)
            if serving:
                findings.append({
                    "severity": "warning",
                    "code": "egress_blocked",
                    "layer": 3,
                    "message": f"Nothing reaches {target} from here - no ping, no TCP on "
                               f"{', '.join(REACHABILITY_PORTS)}. But this box is serving "
                               f"{serving['inbound']} live connection(s) inbound on port(s) "
                               f"{', '.join(serving['ports'][:4])}, so its network is working "
                               f"in the direction that matters for a service. This is outbound "
                               f"internet access, which on a server is usually absent on "
                               f"purpose. Only a fault if this box is supposed to reach the "
                               f"internet - check the egress rules before the carrier.",
                })
            elif _trace_got_there(probes, target):
                # The path carried probes all the way there and the host itself
                # said nothing. Nagios has drawn this line for twenty years:
                # a host that is DOWN and a host that is UNREACHABLE because
                # something in front of it failed are different states with
                # different owners, and calling both "the provider" sends
                # someone to a carrier about their own server.
                findings.append({
                    "severity": "critical",
                    "code": "destination_unresponsive",
                    "layer": 3,
                    "message": f"The path to {target} works - the trace reached it - and "
                               f"{target} itself answers nothing, on ICMP or on TCP. The "
                               f"network between here and there is carrying traffic; what is "
                               f"not answering is the destination, or something filtering "
                               f"immediately in front of it. Nothing upstream of this site "
                               f"explains it.",
                })
            else:
                findings.append({
                    "severity": "critical",
                    "code": "inet_unreachable",
                    "layer": 3,
                    "message": f"The gateway is reachable but {target} is not - no ping replies, "
                               f"and no TCP reply on {', '.join(REACHABILITY_PORTS)} either."
                               + (" That is a backend this box depends on, so this is an "
                                  "internal path or a backend that is down - not the internet."
                                  if raw.get("target_kind") == "backend" else
                                  " The router's internet uplink may be down, or an upstream "
                                  "firewall/ISP outage is blocking traffic."),
                })
    elif inet_loss is not None and 0 < inet_loss < 100:
        sent, lost = parse_ping_counts(raw["ping_internet"])
        if sent and sent < MIN_PROBES_FOR_LOSS and lost == 1:
            # One unanswered probe out of a handful. The percentage it produces
            # is an artefact of the sample size, and hosts rate-limit ICMP
            # replies as a matter of course, so this is not a rate.
            findings.append({
                "severity": "warning",
                "code": "inet_loss_unmeasured",
                "layer": 3,
                "message": f"One of {sent} probes to {target} went unanswered. That reads as "
                           f"{inet_loss:.0f}% only because {sent} probes cannot express "
                           f"anything smaller - and hosts rate-limit ICMP replies as a "
                           f"matter of course, this one included. It is not established as "
                           f"loss. Run --soak to send enough probes to measure a rate.",
            })
        else:
            findings.append({
                "severity": "warning",
                "code": "inet_partial_loss",
                "layer": 3,
                "message": f"Packet loss ({inet_loss:.0f}%"
                           + (f", {lost} of {sent} probes" if sent else "")
                           + f") reaching {target} even though some replies get through. "
                             f"Suggests upstream congestion or an unstable WAN link.",
            })
    return inet_loss


def diagnose(target=None, check_ports=None, quick=False, soak=0, baseline=None,
             progress=None, inventory=False, ports_speculative=False,
             uplink_mbps=None):
    """Run the checks and turn them into findings.

    quick=True trims the two slow parts - it drops the traceroute entirely
    (that's most of the runtime) and pings with 2 packets instead of 4. You
    lose the hop-by-hop path; everything else still runs. Meant for a fast
    "is it us or them" answer while someone is waiting on the phone.
    """
    check_ports = check_ports or []
    findings = []
    raw = {}
    # The socket table has to be read before the target is chosen rather than
    # with the rest of the device checks, because choosing a backend to aim at
    # is the first thing that depends on it. Read once and reused below.
    raw["sockets"] = cmd_socket_states()
    target, target_kind = _choose_target(target, raw["sockets"], findings)
    raw["target_kind"] = target_kind
    # Kept beside the kind so anything reading raw can name what was aimed at
    # without being handed the report as well.
    raw["target"] = target
    # soak: sample over a window instead of taking a snapshot. Intermittent
    # faults - a marginal cable, a hop dropping 3% - are invisible in one pass
    # and obvious over a minute, so the window drives every timed measurement.
    soak = max(0, int(soak or 0))
    if soak:
        quick = False
        counter_window = soak
        ping_count = max(4, min(soak // 2, 60))
        ping_wait = 2
        mtr_cycles = max(10, min(soak, 300))
    else:
        counter_window = 0 if quick else 2
        ping_count = 2 if quick else 4
        ping_wait = 1 if quick else 2
        mtr_cycles = 10

    # Start the counter window immediately: it then covers the whole run rather
    # than costing a dedicated two-second pause that measures nothing else.
    say = progress or (lambda _msg: None)
    say("reading interfaces and routes")
    link_sample = start_link_sample()
    tcp_baseline = _read_tcp_counters() if counter_window else None
    drops_baseline = _read_kernel_drops() if counter_window else None

    raw["interfaces"] = cmd_interfaces()
    raw["routes"] = cmd_routes()

    _check_addressing(raw, findings)

    # Interface error counters. Runs before the reachability checks because if
    # frames are arriving corrupted, that's the answer - everything downstream
    # is a symptom. Sampled twice (except in quick mode) to tell a link that is
    # failing now from one that collected errors months ago.
    # Baseline before the link counters sleep, so both rates come from the same
    # window rather than costing two of them.
    say("checking link mode, switch port and neighbours")
    link_findings_slot = len(findings)
    neighbours, primary_mtu, duplex_by_iface, arp_entries = _check_device_and_link(
        raw, findings, counter_window, soak, quick, link_sample)

    gw = guess_default_gateway(raw["routes"])

    # Passive inventory of the segment, if asked for. Built from the neighbour
    # table already collected above - nothing new is probed.
    inventory_data = None
    if inventory:
        say("listing neighbours already known to this device")
        inventory_data = build_inventory(arp_entries, list_resolvers())
        raw["inventory"] = {
            "ok": True, "cmd": "neighbour table (passive - nothing was probed)",
            "code": 0, "stderr": "",
            "stdout": "\n".join(
                f"{h['ip']:<16}{(h['name'] or '-')[:30]:<32}{h['mac'] or '-'}"
                for h in inventory_data["hosts"]) or "(no neighbours known)",
        }

    say(f"probing gateway and {target}" + ("" if quick else ", tracing the path"))
    # Collected together: the gateway ping, the target ping and the trace don't
    # depend on each other, and the trace is the long pole. Serial under --soak,
    # where measurement isolation is the point.
    probes = collect_probes(target, gw, ping_count, ping_wait, quick, mtr_cycles,
                            parallel=not soak)
    _check_gateway(raw, findings, gw, probes, arp_entries)

    inet_loss = _check_internet(raw, findings, target, probes)

    say("reading the path and measuring MTU")
    hops, path_insight, path_source = _check_path(
        raw, findings, target, gw, inet_loss, quick, mtr_cycles, primary_mtu,
        trace=probes.get("trace"))

    # Overall call quality to the target: latency, jitter and loss reduced to
    # one number people recognise. Uses the ping we already ran.
    call_quality = _check_call_quality(raw, findings, target, inet_loss)

    # What this device is listening on. Pairs with the port checks: those ask
    # whether something answers from outside, this shows what is bound here at
    # all - and on which interface rather than just loopback.
    raw["ports"] = cmd_listen_ports()
    _check_rotation(raw, findings)
    _check_idle(raw, findings)
    _check_own_tls(raw, findings, quick)
    _check_own_service(raw, findings, quick)

    say("querying each configured DNS resolver")
    dns_failed = _check_dns(raw, findings, target, inet_loss, quick)
    # After the resolvers are probed, not before: this reads what that check
    # collected, and running it first meant it read an empty dict and said
    # nothing, on every box, silently.
    _check_dns_cache(raw, findings)
    # Check specific ports if requested
    if check_ports:
        say(f"checking {len(check_ports)} port(s) on {target}")
    port_results = _check_ports(raw, findings, target, check_ports, quick,
                                speculative=ports_speculative)

    # Everything else is done; close the counter window and report on it.
    if counter_window:
        waited = time.monotonic() - link_sample["started"]
        left = max(0, round(max(counter_window, MIN_COUNTER_WINDOW) - waited))
        say(f"closing the {max(counter_window, MIN_COUNTER_WINDOW)}s counter window"
            + (f" ({left}s left)" if left else " (already elapsed)"))
    _finish_link_checks(raw, findings, counter_window, link_sample, tcp_baseline,
                        duplex_by_iface, link_findings_slot, progress=say,
                        drops_baseline=drops_baseline, uplink_mbps=uplink_mbps)
    _all_clear(raw, findings, check_ports, dns_failed)

    # What changed since a previous visit. Regressions become findings so they
    # can't be missed; everything else is reported as context.
    # The hardware currently answering for the gateway, and what kind of thing
    # it is. Both are context on their own and evidence once there are two
    # visits to compare.
    gateway_mac = next((e.get("mac") for e in (arp_entries or [])
                        if e.get("ip") == gw and e.get("mac")), None)
    virtual = virtual_router_mac(gateway_mac)
    if virtual:
        findings.append({
            "severity": "ok",
            "layer": 2,
            "code": "gateway_is_virtual",
            "message": f"The gateway {gw} answers from {gateway_mac}, which is a "
                       f"{virtual[0]} address for group {virtual[1]}. It is a redundancy "
                       f"pair rather than one router, so \"the gateway is down\" here would "
                       f"more often mean a failover that did not complete than a box that "
                       f"stopped. Two masters in one group share this address, so nothing "
                       f"from a single run can tell them apart - compare against a "
                       f"--baseline to see the address change hands.",
        })
    comparison = compare_reports({"detected_gateway": gw, "path_source": path_source,
                                  "neighbours": neighbours, "raw": raw, "hops": hops,
                                  "call_quality": call_quality,
                                  # Without this the comparison could not tell
                                  # whether both visits measured the same
                                  # thing, and every target-dependent reading
                                  # was silently dropped on every run.
                                  "target": target,
                                  "gateway_mac": gateway_mac,
                                  "demarc_hop": path_insight.get("demarc_hop"),
                                  # These two are compared and were being left
                                  # out, so a version or interpreter change
                                  # between visits could never be reported.
                                  "version": __version__,
                                  "python": platform.python_version(),
                                  "verdict": None}, baseline) if baseline else []
    worse = [c for c in comparison if c["direction"] == "worse"]
    if worse:
        summary = "; ".join(f"{c['what']}: {c['before']} -> {c['after']}" for c in worse[:4])
        findings.append({
            "severity": "warning",
            "layer": 2,
            "code": "regression_since_baseline",
            "message": f"{len(worse)} thing(s) got worse since the baseline report - {summary}"
                       + ("; ..." if len(worse) > 4 else "")
                       + ". A change since the last visit is usually a better lead than any "
                         "absolute reading, because it dates the fault.",
        })
    elif comparison:
        findings.append({
            "severity": "ok",
            "layer": 2,
            "code": "baseline_changes",
            "message": f"{len(comparison)} difference(s) from the baseline, none of them a "
                       f"regression. See the comparison section.",
        })

    _check_every_interface(findings, raw)

    verdict = build_verdict(findings, quick=quick, raw=raw)
    for f in findings:
        relation = finding_relation(f.get("code"), verdict)
        if relation:
            f["relation"] = relation
        if f.get("code") in HARDWARE_FINDINGS:
            f["kind"] = "hardware"
    _retarget_verdict(verdict, raw)
    _qualify_upstream_verdict(verdict, raw, uplink_mbps)
    if neighbours and verdict.get("based_on") and verdict["based_on"][0] in PORT_RELEVANT_CODES:
        n = neighbours[0]
        port = n.get("port") or n.get("port_descr")
        if n.get("switch") or port:
            where = " ".join(filter(None, [n.get("switch"), port and f"port {port}"]))
            verdict["next_step"] += f" This device is connected to {where}."
            verdict["switch_port"] = where

    if baseline and (baseline.get("verdict") or {}).get("headline") \
            and verdict.get("headline") != baseline["verdict"]["headline"]:
        rank = {"ok": 0, "warning": 1, "critical": 2}
        comparison.append({
            "what": "verdict",
            "before": baseline["verdict"]["headline"],
            "after": verdict["headline"],
            "direction": ("worse" if rank.get(verdict.get("severity"), 0)
                          > rank.get(baseline["verdict"].get("severity"), 0)
                          else "better" if rank.get(verdict.get("severity"), 0)
                          < rank.get(baseline["verdict"].get("severity"), 0) else "neutral"),
        })

    return {
        "verdict": verdict,
        "stages": build_stages(findings, raw, checked_ports=bool(check_ports), quick=quick),
        "sides": build_sides(findings, raw),
        "comparison": comparison,
        "findings": findings,
        "raw": raw,
        "detected_gateway": gw,
        # Stored, not only compared: a baseline that does not carry it can
        # never be compared against, which is how the target comparison was
        # silently dead before it was noticed.
        "gateway_mac": gateway_mac,
        "os": OS_NAME,
        "os_label": os_label(),
        "target": target,
        "hops": hops,
        "demarc_hop": path_insight.get("demarc_hop"),
        "worst_jump": path_insight.get("worst_jump"),
        "networks_crossed": path_insight.get("networks_crossed") or [],
        "double_nat": path_insight.get("double_nat") or [],
        "loop_at": path_insight.get("loop_at"),
        "cgnat_hop": path_insight.get("cgnat_hop"),
        "port_results": port_results,
        "quick": quick,
        "soak_seconds": soak or None,
        "path_source": path_source,
        "call_quality": call_quality,
        "neighbours": neighbours,
        "inventory": inventory_data,
        # Shipped with the report so an exported JSON stays self-describing:
        # index.html can label layer badges without knowing this table itself.
        "layers": {str(n): meta for n, meta in LAYERS.items()},
        # Attached to each finding rather than worked out again in the
        # viewer: the browser would need a second copy of the rule, and two
        # copies of a rule are two chances to disagree.
        "panel_help": PANEL_HELP,
        "lowest_broken_layer": min(
            (f["layer"] for f in findings if f.get("layer") and f["severity"] != "ok"),
            default=None,
        ),
        "version": __version__,
        "python": platform.python_version(),
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# The report viewer. Kept here rather than beside the script so faultone.py is
# the whole tool on the box being diagnosed - nothing else has to travel with
# it. `static/index.html` in the repo is this same template with the island
# left empty, and a test fails if the two drift apart.
# ---------------------------------------------------------------------------

REPORT_PLACEHOLDER = "__FAULTONE_" + "REPORT__"

VIEWER_TEMPLATE = r"""<!doctype html>
<!-- FaultOne report viewer. Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
     SPDX-License-Identifier: MIT -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FaultOne console</title>
<!-- Inline so a report stays one file: the icon is recoloured from the
     verdict once a report loads, and a tab that has been squeezed too narrow
     to show its title still shows its state. -->
<link rel="icon" id="favicon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ccircle cx='8' cy='8' r='6' fill='%236b7785'/%3E%3C/svg%3E">
<style>
  :root{
    --bg: #0a0e13;
    --panel: #10151c;
    --panel-2: #151b23;
    --border: #232b35;
    --text: #dce4ec;
    --text-dim: #6b7785;
    /* Same role as --text-dim, lifted until it clears 4.5:1 against the
       verdict's tinted backgrounds. "owner:" and "confidence:" are among the
       most load-bearing words in the report and were the dimmest text on it. */
    --text-dim-lift: #8b97a5;
    --accent: #4fd1c5;
    --accent-dim: #2a5b56;
    --ok: #3fb950;
    --warn: #d9a02b;
    --crit: #e5534b;
    /* The last colours the stylesheet was carrying inline. A hardcoded hex
     is invisible to a palette: these five stayed at their dark-theme values
     under the light one, which put the pill reading "the cause" at 3.2:1 on
     white and the hardware pill at 2.2:1 - the two chips that say what a
     finding is. Declared here so every palette has to answer for them. */
  --cause: #e0705a;
  --cause-edge: #c2553c;
  --hardware: #d3a83a;
  --hardware-edge: #8a6d1f;
  --node-edge: #333d47;
  /* The drop overlay dims the page behind it, so it has to dim toward the
     page's own ground: a near-black scrim under a light palette left the
     accent-coloured prompt on it at 2.4:1. */
  --scrim: rgba(10,14,19,0.88);
  --topbar-a: #0d1218;
  --topbar-b: #0a0e13;
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", "JetBrains Mono", Consolas, monospace;
    --sans: -apple-system, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif;
  }
  *{box-sizing:border-box}
  body{
    margin:0; background:var(--bg); color:var(--text);
    font-family:var(--sans); font-size:14px; line-height:1.5;
  }
  .topbar{
    display:flex; align-items:center; gap:14px;
    padding:14px 20px; border-bottom:1px solid var(--border);
    background:linear-gradient(180deg, var(--topbar-a), var(--topbar-b));
    position:sticky; top:0; z-index:5;
  }
  .brand{display:flex; align-items:center; gap:10px;}
  .brand .dot{
    width:10px; height:10px; border-radius:50%;
    background:var(--accent); box-shadow:0 0 8px var(--accent);
  }
  .brand h1{
    font-family:var(--mono); font-size:15px; font-weight:600;
    margin:0; letter-spacing:0.02em; color:var(--text);
  }
  .brand h1 .sub{color:var(--text-dim); font-weight:400;}
  .badge{
    font-family:var(--mono); font-size:11px; color:var(--text-dim);
    border:1px solid var(--border); border-radius:4px; padding:3px 8px;
    margin-left:auto;
  }
  .layout{
    display:grid; grid-template-columns:280px 1fr; gap:0; min-height:calc(100vh - 53px);
  }
  @media (max-width:820px){ .layout{grid-template-columns:1fr;} }

  .sidebar{
    border-right:1px solid var(--border); padding:18px; background:var(--panel);
  }
  .field-label{
    font-family:var(--mono); font-size:11px; color:var(--text-dim);
    text-transform:uppercase; letter-spacing:0.08em; margin-bottom:6px; display:block;
  }

  .viewer-hint{
    margin-top:12px; padding:10px 12px; border-radius:6px;
    background:var(--panel-2); border:1px solid var(--border);
    color:var(--text-dim); font-size:12px; line-height:1.55;
  }
  .viewer-hint code{
    font-family:var(--mono); font-size:11px; color:var(--accent);
    word-break:break-all;
  }
  /* Drop a report anywhere on the page. */
  body.dragging::after{
    content:'Drop report.json to load it';
    position:fixed; inset:0; z-index:100;
    display:flex; align-items:center; justify-content:center;
    background:var(--scrim); border:2px dashed var(--accent);
    color:var(--accent); font-family:var(--mono); font-size:15px;
    pointer-events:none;
  }


  .leds{margin-top:22px;}
  .led-row{display:flex; align-items:center; gap:8px; padding:4px 0; font-family:var(--mono); font-size:12px; color:var(--text-dim);}
  .led-name{flex:1 1 auto;}
  /* A skipped stage is dimmed rather than coloured: "not measured" is not a
     result, and showing it green would be a claim the run never made. */
  .led-row.skip{opacity:.55;}
  .led-layer{font-size:10px; color:var(--text-dim); border:1px solid var(--border); border-radius:3px; padding:0 4px;}
  .led-state{font-size:10px; letter-spacing:.06em; text-transform:uppercase; opacity:.8;}
  .led-row.warn .led-state{color:var(--warn);}
  .led-row.crit .led-state{color:var(--crit);}
  /* Set apart from the chain above it: this is the conclusion, not a stage. */
  .verdict-row{border-top:1px solid var(--border); margin-top:6px; padding-top:8px;}
  .led{width:8px; height:8px; border-radius:50%; background:var(--node-edge); flex-shrink:0;}
  .led.ok{background:var(--ok); box-shadow:0 0 6px var(--ok);}
  .led.warn{background:var(--warn); box-shadow:0 0 6px var(--warn);}
  .led.crit{background:var(--crit); box-shadow:0 0 6px var(--crit);}
  .led.skip{background:var(--node-edge); box-shadow:none;}

  .main{padding:24px; max-width:1080px; overflow-x:hidden;}
  .empty-state{
    color:var(--text-dim); font-family:var(--mono); font-size:13px;
    padding:40px 10px; text-align:center; border:1px dashed var(--border); border-radius:8px;
  }

  /* The verdict: what to look at first. Sits above everything because reading
     eight findings to work out the culprit is the thing it exists to spare you. */
  .verdict{
    border:1px solid var(--border); border-left:4px solid var(--text-dim);
    background:var(--panel); border-radius:8px; padding:16px 24px; margin-bottom:16px;
    box-shadow:0 6px 20px rgba(0,0,0,.35);
  }
  /* The most important block on the page shared its background with every
     panel and stage chip, so severity showed only as a 4px stripe on one edge
     and the block read as generic. The tint is mixed from the same variables
     the lamps and the tab icon use, so the three can't drift apart. The plain
     background and border are declared first: a browser too old for color-mix
     (pre-2023) ignores the line after and is left with today's appearance
     rather than a broken one.
     On a dark page this has to be a wash of the severity colour over the panel,
     not a pastel - a light tint over #10151c goes muddy rather than soft. */
  .verdict.critical{
    border-color:var(--border);
    border-color:color-mix(in srgb, var(--crit) 35%, var(--border));
    border-left-color:var(--crit);
    background:var(--panel);
    background:color-mix(in srgb, var(--crit) 8%, var(--panel));
  }
  .verdict.warning{
    border-color:var(--border);
    border-color:color-mix(in srgb, var(--warn) 35%, var(--border));
    border-left-color:var(--warn);
    background:var(--panel);
    background:color-mix(in srgb, var(--warn) 8%, var(--panel));
  }
  /* No wash when nothing is wrong: it would shout with nothing to say, and
     compete with the lamps that are already green. */
  .verdict.ok{border-left-color:var(--ok);}
  .verdict .vlabel{
    font-family:var(--mono); font-size:11px; text-transform:uppercase;
    letter-spacing:0.08em; color:var(--text-dim-lift); margin-bottom:8px;
  }
  .verdict .vhead{font-size:20px; font-weight:600; line-height:1.3; margin-bottom:12px;}
  .verdict .vmeta{
    font-family:var(--mono); font-size:12px; color:var(--text-dim-lift);
    display:flex; flex-wrap:wrap; gap:16px; margin-bottom:12px;
  }
  /* Where the fault is. Deliberately the largest thing on the page after the
     verdict itself: someone who does not know what a layer is can still read
     three boxes and an arrow. State is a word as well as a colour, because a
     colour alone is not readable to everyone and does not survive a printout
     or a screenshot pasted into a ticket. */
  .zones{display:flex; align-items:stretch; gap:0; margin:14px 0 4px; flex-wrap:wrap;}
  .zarrow{display:flex; align-items:center; padding:0 10px; color:var(--text-dim);
          font-size:18px;}
  .zone{flex:1 1 180px; min-width:150px; padding:10px 12px; border-radius:8px;
        border:1px solid var(--border); background:var(--panel-2);}
  .zone .zname{font-size:12px; color:var(--text-dim-lift); line-height:1.35;}
  .zone .zvia{font-family:var(--mono); font-size:11px; color:var(--text-dim);
              margin-top:2px; word-break:break-all;}
  .zone .zstate{font-size:15px; font-weight:700; letter-spacing:.04em; margin-top:6px;}
  .zone .zwhy{font-size:12px; color:var(--text-dim-lift); margin-top:6px; line-height:1.45;}
  .zone.pass{border-color:var(--ok);} .zone.pass .zstate{color:var(--ok);}
  .zone.warn{border-color:var(--warn);} .zone.warn .zstate{color:var(--warn);}
  /* Washed over the card, not painted over the page. background: on a
     semi-transparent colour replaces the card's own, so the tint composited
     against the page behind it and came out darker than the zones either
     side - the broken direction rendered quieter than the healthy ones, in
     the panel whose only job is to say which way is broken. Same wash the
     verdict uses, over the same surface the zone already has. */
  .zone.fail{
    border-color:var(--crit);
    background:var(--panel-2);
    background:color-mix(in srgb, var(--crit) 8%, var(--panel-2));
  }
  .zone.fail .zstate{color:var(--crit);}
  .zone.skip{opacity:.5;} .zone.skip .zstate{color:var(--text-dim);}
  @media (max-width: 640px){
    .zones{flex-direction:column;}
    .zarrow{padding:2px 0; transform:rotate(90deg); align-self:center;}
  }
  /* The inbound leg. One hop, because one hop is all that is true - drawn in
     the same shape as the path below it so the two read as two directions of
     one picture rather than two unrelated panels. */
  .inbound{margin-bottom:16px; padding-bottom:14px; border-bottom:1px dashed var(--border);}
  .inbound-title{font-family:var(--mono); font-size:12px; color:var(--text-dim);
                 margin-bottom:8px;}
  .inbound-note{font-size:12px; color:var(--text-dim-lift); margin-top:8px;
                line-height:1.45; max-width:70ch;}
  .verdict .vnext{font-size:13px; color:var(--text); line-height:1.55;}
  .verdict .vnext b{color:var(--accent); font-weight:600;}
  /* Stage strip: the whole chain at a glance, the way a handheld tester shows
     it. Detail lives in the findings below. */
  .stages{display:flex; flex-wrap:wrap; gap:8px; margin-bottom:24px;}
  .stage{
    font-family:var(--mono); font-size:11px; padding:4px 8px; border-radius:6px;
    border:1px solid var(--border); background:var(--panel); color:var(--text-dim);
    display:flex; gap:6px; align-items:center;
  }
  .stage b{font-weight:600;}
  .stage.pass b{color:var(--ok);}
  .stage.warn b{color:var(--warn);}
  .stage.fail b{color:var(--crit);}
  .stage.skip{opacity:0.5;}
  .changes{
    border:1px solid var(--border); border-radius:8px; background:var(--panel);
    padding:11px 14px; margin-bottom:16px; font-size:12.5px;
  }
  .changes h4{margin:0 0 7px; font-family:var(--mono); font-size:10px;
    text-transform:uppercase; letter-spacing:0.08em; color:var(--text-dim); font-weight:600;}
  .changes .row{display:flex; gap:8px; padding:2px 0; font-family:var(--mono); font-size:11.5px;}
  .changes .row.worse{color:var(--warn);}
  .changes .row.better{color:var(--ok);}
  .changes .row.neutral{color:var(--text-dim);}
  .findings{display:flex; flex-direction:column; gap:8px; margin-bottom:24px;}
  .finding{
    display:flex; gap:12px; padding:12px; border-radius:6px;
    border:1px solid var(--border); background:var(--panel);
  }
  .finding .sev{width:8px; height:8px; border-radius:50%; margin-top:5px; flex-shrink:0;}
  .finding.ok .sev{background:var(--ok); box-shadow:0 0 6px var(--ok);}
  .finding.warning .sev{background:var(--warn); box-shadow:0 0 6px var(--warn);}
  .finding.critical .sev{background:var(--crit); box-shadow:0 0 6px var(--crit);}
  .finding .msg{font-size:13px; line-height:1.55;}
  .finding .tag{
    font-family:var(--mono); font-size:11px; text-transform:uppercase;
    letter-spacing:0.06em; color:var(--text-dim); margin-bottom:3px;
  }
  .finding .tagline{display:flex; align-items:center; gap:7px; margin-bottom:3px;}
  /* Where a finding stands to the verdict: the answer, something backing it
     up, one of its consequences, or a separate problem. Deliberately quiet -
     the severity colour is the thing to see first, and this is the structure
     underneath it. The cause is the one that gets weight, because on a long
     report it is the line the reader is looking for. */
  .finding .rel{
    font-family:var(--mono); font-size:11px; text-transform:uppercase;
    letter-spacing:0.06em; padding:1px 6px; border-radius:9px;
    border:1px solid var(--border); color:var(--text-dim); white-space:nowrap;
  }
  .finding .rel-cause{border-color:var(--cause-edge); color:var(--cause); font-weight:600;}
  .finding .rel-unrelated{border-style:dashed;}
  /* A fix that means somebody in the room rather than somebody at a keyboard.
     Given its own colour because it is a different kind of answer, not a
     different severity. */
  .finding .rel-hardware{border-color:var(--hardware-edge); color:var(--hardware);}
  /* Layer badge: which OSI layer a finding implicates. Deliberately monochrome
     so it never competes with the severity color for attention. */
  .layer{
    font-family:var(--mono); font-size:11px; letter-spacing:0.04em;
    padding:1px 6px; border-radius:9px; white-space:nowrap;
    border:1px solid var(--border); color:var(--text-dim); background:var(--panel-2);
  }
  .layer.low{border-color:var(--warn); color:var(--warn);}
  .layer-note{
    font-size:12px; color:var(--text-dim); margin:-8px 0 16px;
    padding:8px 11px; border-left:2px solid var(--warn);
    background:var(--panel); border-radius:0 5px 5px 0;
  }

  .panel{
    background:var(--panel); border:1px solid var(--border); border-radius:6px;
    margin-bottom:12px; overflow:hidden;
  }
  .panel-head{
    display:flex; align-items:center; gap:12px; padding:8px 12px;
    background:var(--panel-2); border-bottom:1px solid var(--border);
    font-family:var(--mono); font-size:12px; cursor:pointer; user-select:none;
  }
  /* A control that can be reached by keyboard and does not say where the
     keyboard is has only moved the problem. Drawn inside the edge, because the
     panel clips its own overflow and an outline outside it would be cut off. */
  .panel-head:focus-visible{outline:2px solid var(--accent); outline-offset:-2px;}
  .panel-head .prompt{color:var(--accent);}
  .panel-head .cmdtxt{color:var(--text-dim); flex:1;}
  .panel-head .chev{color:var(--text-dim); transition:transform .15s;}
  .panel.collapsed .chev{transform:rotate(-90deg);}
  .panel.collapsed .panel-body{display:none;}
  .panel.collapsed .panel-desc{display:none;}
  .panel-body{padding:12px;}
  /* What this panel checked. Inline rather than on hover: the sidebar is a list
     you scan before clicking, but this is a result you read - and screenshot. */
  .panel-desc{
    padding:8px 14px; border-bottom:1px solid var(--border); background:var(--panel);
    color:var(--text-dim); font-size:12px; line-height:1.5;
    display:flex; gap:8px; align-items:flex-start;
  }
  .panel-desc .layer{flex:0 0 auto; margin-top:1px;}
  pre{
    margin:0; font-family:var(--mono); font-size:12.5px; white-space:pre-wrap;
    word-break:break-word; color:var(--text); max-height:400px; overflow:auto;
  }
  .err{color:var(--crit); font-family:var(--mono); font-size:12.5px;}
  .loading{color:var(--text-dim); font-family:var(--mono); font-size:12.5px;}

  .divider{border:none; border-top:1px solid var(--border); margin:18px 0;}
  .file-input{
    width:100%; background:var(--panel-2); border:1px solid var(--border);
    color:var(--text-dim); font-family:var(--sans); font-size:12px;
    padding:8px 9px; border-radius:6px;
  }
  .report-meta{
    font-family:var(--mono); font-size:11px; color:var(--text-dim);
    margin-top:8px; line-height:1.5;
  }

  .section-title{
    font-family:var(--mono); font-size:11px; color:var(--text-dim);
    text-transform:uppercase; letter-spacing:0.08em; margin:0 0 12px;
  }
  /* Wrap rather than scroll: a 12-hop trace with long PTR names ran several
     screens wide, so the end of the path - the part that matters - sat off
     the right edge. Wrapping keeps the whole path visible at any width. */
  .hop-chain{
    display:flex; flex-wrap:wrap; align-items:stretch; gap:8px 0;
    padding:0; margin:0 0 24px;
  }
  .hop-node{
    flex:0 1 auto; min-width:110px; max-width:230px;
    background:var(--panel); border:1px solid var(--border);
    border-left:3px solid var(--node-edge); border-radius:6px; padding:12px 11px;
  }
  /* A path is read for one thing: which hop the fault lands on. Every node was
     drawn at the same weight with a different coloured edge, so the answer had
     to be looked for rather than seen. The clean hops recede into context and
     the faulting one carries a wash of its own severity - same cards, same
     layout, the emphasis moved onto the hop that is being reported. The plain
     background is declared first so a browser too old for color-mix gets the
     previous appearance rather than a broken one. */
  .hop-node.ok{border-left-color:var(--ok);}
  /* The clean hops recede only when there is something to recede against.
     Applied unconditionally it faded the whole chain on the great majority of
     reports - most paths have no individually faulty hop, so every node went
     to 55% and nothing was emphasised, which is dimmer than what it replaced
     and says the opposite of what the fade is for. Scoped to the chain rather
     than the page so the inbound panel, which scores its one node on its own
     thresholds, decides separately. A browser without :has() drops the rule
     and gets the flat chain, which is the safe direction to fail in. */
  .hop-chain:has(.hop-node.warn, .hop-node.crit) .hop-node.ok{
    background:transparent; opacity:0.55;
  }
  .hop-node.warn{
    padding:16px 12px;
    background:var(--panel);
    background:color-mix(in srgb, var(--warn) 9%, var(--panel));
    border-color:color-mix(in srgb, var(--warn) 40%, var(--border));
    border-left-color:var(--warn);
  }
  .hop-node.crit{
    padding:16px 12px;
    background:var(--panel);
    background:color-mix(in srgb, var(--crit) 11%, var(--panel));
    border-color:color-mix(in srgb, var(--crit) 50%, var(--border));
    border-left-color:var(--crit);
    box-shadow:0 8px 22px -12px rgba(229,83,75,0.75);
  }
  /* The dim greys sit at about 4:1 on the flat panel and a tint takes them
     under it, so the text on a reported hop uses the lifted grey instead. */
  .hop-node.warn .hop-meta, .hop-node.crit .hop-meta{color:var(--text-dim-lift);}
  .hop-node.warn .hop-label{color:color-mix(in srgb, var(--warn) 75%, var(--text));}
  .hop-node.crit .hop-label{color:color-mix(in srgb, var(--crit) 75%, var(--text));}
  .hop-label{font-family:var(--mono); font-size:11px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.04em;}
  .hop-sub{font-family:var(--mono); font-size:13px; margin-top:4px; word-break:break-word;}
  .hop-arrow{flex:0 0 auto; display:flex; align-items:center; padding:0 8px; color:var(--text-dim); font-family:var(--mono);}
  .hop-meta{font-family:var(--mono); font-size:11px; color:var(--text-dim); margin-top:4px;}
  .hop-meta .jump{color:var(--warn);}
  /* Where traffic stops being the site's network and becomes their ISP's -
     the most useful single boundary on the whole diagram. */
  .hop-arrow.demarc{
    flex-direction:column; justify-content:center; gap:2px; padding:0 10px;
    color:var(--accent); border-left:1px dashed var(--accent-dim);
    margin-left:6px; padding-left:14px;
  }
  .hop-arrow.demarc span{font-size:9px; letter-spacing:0.06em; text-transform:uppercase;}
  /* Entering a different operator's network - the same kind of boundary as the
     site edge, one level out. Dimmer, so the site edge stays the loudest. */
  .hop-arrow.handoff{
    flex-direction:column; justify-content:center; gap:2px;
    color:var(--text-dim); border-left:1px dashed var(--border);
    margin-left:6px; padding-left:14px;
  }
  .hop-arrow.handoff span{font-size:9px; letter-spacing:0.04em;}

  /* Proportional digits change width as they change value, so a column of
     latencies shifts sideways every time one of them ticks over - the numbers
     are the reading, and they were the least steady thing on the page. Tabular
     figures fix the advance width; slashed zero keeps a zero from reading as a
     capital O in an interface name or a hex address. Applied only where digits
     are load-bearing, since tabular figures in prose are worse than neither. */
  .hop-sub, .hop-meta, .verdict .vmeta, .stage, .led-row, .report-meta,
  .finding .tag, .changes .row, pre{
    font-variant-numeric:tabular-nums;
    font-feature-settings:"tnum" 1, "zero" 1;
  }
  body{-webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;}

  /* A dark console is right for the box it was run on and wrong for where the
     report ends up - a laptop in a meeting, a ticket read on a phone. Rather
     than ship a theme switch nobody would find, the page follows the reader's
     own system setting, which is the answer they already gave. Dark stays the
     default, so a terminal-shaped audience sees no change. The glows go: a
     halo around a lamp reads as depth on black and as a printing fault on
     white, which is the same reason the print block drops them. */
  @media (prefers-color-scheme: light){
    :root{
      --bg:#f6f8fa; --panel:#ffffff; --panel-2:#eef1f5; --border:#d5dbe2;
      --text:#0f1720; --text-dim:#5a6572; --text-dim-lift:#48525d;
      --accent:#0f6f66; --accent-dim:#9fd4ce;
      --ok:#1a7f37; --warn:#8a5b00; --crit:#b3261e;
      --cause:#a3372a; --cause-edge:#a3372a;
      --hardware:#7a5c10; --hardware-edge:#7a5c10;
      --node-edge:#c7cdd4;
      --scrim:rgba(246,248,250,0.93);
      --topbar-a:#ffffff; --topbar-b:#f6f8fa;
    }
    .brand .dot, .led, .finding .sev{box-shadow:none;}
    .verdict{box-shadow:0 1px 3px rgba(16,24,40,.08);}
    .hop-node.crit{box-shadow:0 6px 16px -10px rgba(179,38,30,.55);}
  }

  /* A report often has to reach someone who will not open a file - it goes
     into a ticket, an email or a change record as a PDF. Printed as it stands,
     a dark page comes out as black ink or as nothing at all, depending on the
     browser's background-graphics setting. So print gets a light ground with
     the same palette inverted in place: the severity colours are darkened only
     as far as they need to hold 4.5:1 on white, and every rule below is a
     variable swap rather than a second stylesheet that could drift.
     The controls that produce a report are dropped, since a printed one has
     already been produced, and the evidence panels are forced open - a chevron
     the reader cannot click would otherwise hide the output on paper. */
  @media print{
    :root{
      --bg:#ffffff; --panel:#ffffff; --panel-2:#f5f6f8; --border:#c7cdd4;
      --text:#11161c; --text-dim:#59636f; --text-dim-lift:#454f5a;
      --accent:#0f6f66; --accent-dim:#9fd4ce;
      --ok:#1a7f37; --warn:#8a5b00; --crit:#b3261e;
      --cause:#a3372a; --cause-edge:#a3372a;
      --hardware:#7a5c10; --hardware-edge:#7a5c10;
      --node-edge:#c7cdd4;
    }
    .topbar, .sidebar, #reportControls, .file-input{display:none !important;}
    .layout{display:block; min-height:0;}
    .main{padding:0;}
    .panel.collapsed .panel-body, .panel.collapsed .panel-desc{display:block !important;}
    .panel-head .chev{display:none;}
    pre{max-height:none; overflow:visible;}
    /* A hop or a finding split across a page break is the one thing on the
       page that has to be read whole. */
    .verdict, .finding, .hop-node, .zone, .panel{box-shadow:none; break-inside:avoid;}
    /* On paper there is no glow to carry a lamp, so the dot needs its edge. */
    .led, .finding .sev{box-shadow:none; border:1px solid var(--border);}
    /* The recede-and-emphasise pass reads as ink density on screen; on paper a
       55% grey hop just looks badly printed. */
    .hop-node.ok, .zone.skip{opacity:1;}
  }
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">
    <div class="dot" id="brandDot"></div>
    <h1>FaultOne <span class="sub">// diagnostics console</span></h1>
  </div>
  <div class="badge" id="osBadge">report viewer</div>
</div>

<div class="layout">
  <div class="sidebar">
    <div class="leds" id="leds"></div>

    <hr class="divider" id="sidebarDivider">

    <div id="reportControls">
      <label class="field-label" for="reportFile" id="reportFileLabel">Load exported report</label>
      <input type="file" id="reportFile" class="file-input" accept="application/json,.json">
      <div class="report-meta" id="reportMeta"></div>
      <div class="viewer-hint" id="viewerHint">
        Choose a <code>report.json</code> above, or drop one anywhere on this page.
        <br><br>
        Produce one with:<br><code>python3 faultone.py --export report.json</code>
        <br><br>
        Or skip this viewer entirely:<br><code>python3 faultone.py --export report.html</code><br>
        gives you a single file that opens on its own.
      </div>
    </div>
  </div>

  <div class="main">
    <div class="section-title" id="pathTitle" style="display:none;">Path</div>
    <div id="hopChainWrap"></div>
    <div id="findingsWrap"></div>
    <div id="output">
      <div class="empty-state" id="emptyState">Load a report exported with <code>--export</code> — choose the file on the left, or drop it anywhere on this page.</div>
    </div>
  </div>
</div>

<!-- A self-contained report drops its data in here; the viewer leaves it
     empty and waits for a file instead. -->
<script id="faultone-report" type="application/json">__FAULTONE_REPORT__</script>
<script>
const output = document.getElementById('output');
const findingsWrap = document.getElementById('findingsWrap');
const osBadge = document.getElementById('osBadge');
const ledsEl = document.getElementById('leds');

let panelSeq = 0;
let panelHelp = {}; // raw-report key -> {desc, layer}

function escapeHtml(s){
  return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function clearEmptyState(){
  const empty = output.querySelector('.empty-state');
  if(empty) empty.remove();
}

// A div with an onclick is a control to a mouse and scenery to everything
// else: no focus, no key handling, and nothing announced. The evidence panels
// were the only interactive thing on the page, so a reader without a mouse
// could not open a single one of them. Enter and Space are what a button
// answers to, and space is stopped from scrolling the page under it.
function togglePanel(id, head){
  const open = !document.getElementById(id).classList.toggle('collapsed');
  head.setAttribute('aria-expanded', open ? 'true' : 'false');
}

function addPanel(label, cmdText, help){
  clearEmptyState();
  const id = 'panel-' + (panelSeq++);
  const div = document.createElement('div');
  div.className = 'panel';
  div.id = id;
  const desc = help && help.desc ? `
    <div class="panel-desc">
      ${help.layer ? `<span class="layer">L${escapeHtml(String(help.layer))}</span>` : ''}
      <span>${escapeHtml(help.desc)}</span>
    </div>` : '';
  div.innerHTML = `
    <div class="panel-head" role="button" tabindex="0" aria-expanded="true"
         onclick="togglePanel('${id}', this)"
         onkeydown="if(event.key === 'Enter' || event.key === ' '){ event.preventDefault(); togglePanel('${id}', this); }">
      <span class="prompt">$</span>
      <span class="cmdtxt">${escapeHtml(cmdText || label)}</span>
      <span class="chev">▾</span>
    </div>
    ${desc}
    <div class="panel-body"><div class="loading">running…</div></div>
  `;
  output.prepend(div);
  return div.querySelector('.panel-body');
}

function renderResult(body, result){
  if(!result){
    body.innerHTML = '<div class="err">no response</div>';
    return;
  }
  if(result.error){
    body.innerHTML = `<div class="err">${escapeHtml(result.error)}</div>`;
    return;
  }
  let html = '';
  if(result.stdout && result.stdout.trim()){
    html += `<pre>${escapeHtml(result.stdout)}</pre>`;
  }
  if(result.stderr && result.stderr.trim()){
    html += `<pre style="color:var(--warn); margin-top:8px;">${escapeHtml(result.stderr)}</pre>`;
  }
  if(!html){
    html = '<div class="loading">(no output)</div>';
  }
  body.innerHTML = html;
}

const STAGE_LAMP = {pass: 'ok', warn: 'warn', fail: 'crit', skip: 'skip'};
const VERDICT_LAMP = {ok: 'ok', warning: 'warn', critical: 'crit'};

function verdictRow(v){
  // The stages above describe getting traffic out and back. Some faults sit
  // outside that chain entirely - an application at either end, the site's
  // inbound topology, a change since the last visit - and those left seven
  // green lamps sitting beside a verdict that named an owner. This row is the
  // verdict itself, so the panel cannot disagree with the conclusion it
  // summarises.
  if(!v) return '';
  const lamp = VERDICT_LAMP[v.severity] || 'skip';
  const why = v.owner ? ` title="${escapeHtml(v.headline || '')} — ${escapeHtml(v.owner)}"` : '';
  return `<div class="led-row verdict-row ${lamp}"${why}><div class="led ${lamp}"></div>` +
         `<span class="led-name">verdict</span>` +
         `<span class="led-state">${escapeHtml(v.severity === 'ok' ? 'clear' : v.severity)}</span></div>`;
}

function ledRow(st){
  const lamp = STAGE_LAMP[st.state] || 'skip';
  // The layer is only present when a finding put the stage in that state, so
  // a passing stage carries no layer rather than a guessed one.
  const layer = st.layer ? `<span class="led-layer">L${escapeHtml(String(st.layer))}</span>` : '';
  const why = (st.because && st.because.length)
    ? ` title="${escapeHtml(st.because.join(', '))}"` : '';
  return `<div class="led-row ${lamp}"${why}><div class="led ${lamp}"></div>` +
         `<span class="led-name">${escapeHtml(st.stage)}</span>${layer}` +
         `<span class="led-state">${escapeHtml(st.state)}</span></div>`;
}

function hopSeverity(h, probes){
  // A hop the report has already blamed outranks anything worked out here. The
  // rest of this function is what the chain can see for itself - loss and
  // timeouts - and a latency wall is neither, so the hop the verdict named was
  // being drawn as clean. The severity travels with the blame so a code that
  // is critical does not arrive here and get demoted to a warning.
  if(h.blame) return h.blame.severity === 'critical' ? 'crit' : 'warn';
  if(h.timed_out) return 'crit';
  // With mtr we have a real loss percentage; use it. Counting timings is a
  // traceroute-only heuristic (three probes per hop) and mtr reports one
  // representative timing, which would make every hop look lossy.
  if(h.loss_pct != null){
    if(h.loss_pct >= 20) return 'crit';
    if(h.loss_pct >= 5) return 'warn';
    return 'ok';
  }
  // Fewer timings than the path is getting elsewhere means probes went
  // missing at this hop. Comparing against a hardcoded three assumed every
  // source sends three and reported them all: where a source gives one
  // representative timing per hop, every hop had fewer than three and the
  // whole path came out marked - a parsing shape drawn as a fault, and enough
  // yellow to bury the hop the verdict was actually naming. Measured against
  // what the rest of the path returned, and only where that is a real sample,
  // so a path that reports one timing throughout says nothing either way.
  if(probes >= 3 && h.times_ms && h.times_ms.length && h.times_ms.length < probes){
    return 'warn';
  }
  return 'ok';
}

function avgMs(times){
  if(!times || !times.length) return null;
  return times.reduce((a,b)=>a+b,0) / times.length;
}

function renderHopChain(data){
  const hops = data.hops || [];
  const pathTitle = document.getElementById('pathTitle');
  if(hops.length === 0){
    pathTitle.style.display = 'none';
    document.getElementById('hopChainWrap').innerHTML = '';
    return;
  }
  pathTitle.style.display = 'block';

  // Path summary stats
  // The most timings any hop on this path reported - the sample size the
  // per-hop counts are judged against.
  const probes = hops.reduce((n,h) => Math.max(n, (h.times_ms || []).length), 0);
  const timeouts = hops.filter(h => h.timed_out).length;
  const validTimes = hops.flatMap(h => h.times_ms || []);
  const avgLatency = validTimes.length ? (validTimes.reduce((a,b)=>a+b,0) / validTimes.length).toFixed(1) : null;
  const summaryParts = [`${hops.length} hops`];
  if(timeouts) summaryParts.push(`${timeouts} timeout${timeouts > 1 ? 's' : ''}`);
  if(avgLatency) summaryParts.push(`avg ${avgLatency}ms`);
  if(data.demarc_hop != null) summaryParts.push(`leaves this site at hop ${data.demarc_hop}`);
  const wj = data.worst_jump;
  if(wj && wj.delta_ms >= 10){
    // The share turns "+65ms" into "is this hop worth chasing".
    const share = wj.share_pct != null ? ` (${wj.share_pct}% of the path)` : '';
    summaryParts.push(`biggest jump +${wj.delta_ms}ms at hop ${wj.hop}${share}`);
  }
  const nets = (data.networks_crossed || []).map(n => n.network);
  if(nets.length) summaryParts.push(`crosses ${nets.join(' → ')}`);
  // summary is escaped at render; nets/hops come from the report file
  const summary = summaryParts.join(' · ');

  const nodes = [{label:'source', sub:'this device', sev:'ok'}];
  hops.forEach(h => {
    const avg = h.avg_ms != null ? h.avg_ms : avgMs(h.times_ms);
    // zone: inside the site vs out on the provider's network
    const zone = h.cgnat ? 'cgnat' : (h.private === true ? 'lan' : (h.private === false ? 'wan' : ''));
    const roles = (h.roles || []).join(' ');
    const meta = [];
    if(h.delta_ms) meta.push(`<span class="jump">+${escapeHtml(String(h.delta_ms))}ms</span>`);
    const jit = h.jitter_ms != null ? h.jitter_ms : h.stdev_ms;   // mtr reports stdev, traceroute a spread
    if(jit != null && jit >= 5) meta.push(`jitter ${escapeHtml(String(jit))}ms`);
    nodes.push({
      label: `hop ${h.hop}${zone ? ` · ${zone}` : ''}${roles ? ` · ${roles}` : ''}`,
      sub: h.timed_out ? 'timeout' : `${h.display}${avg != null ? ' · ' + Number(avg).toFixed(1) + 'ms' : ''}`,
      meta: meta.join(' · '),
      sev: hopSeverity(h, probes),
      demarcBefore: data.demarc_hop != null && h.hop === data.demarc_hop,
      entersNetwork: h.enters_network || null,
      cgnat: !!h.cgnat,
    });
  });
  nodes.push({label:'target', sub: data.target || '', sev:'ok'});

  // The other direction, as far as it can honestly be drawn: one hop. A
  // traceroute goes one way, and nothing here can observe the route a client's
  // packets took to arrive - so there is no inbound chain, and inventing one
  // would be worse than leaving it out. What is drawn instead is the kernel's
  // own measurement of the connections clients actually have open.
  const inbound = ((data.raw || {}).tcp_flows || {}).by_side || {};
  const cin = inbound.client;
  const inboundHtml = cin ? `
    <div class="inbound">
      <div class="inbound-title">clients in — measured on their own connections, not probed</div>
      <div class="hop-chain">
        <div class="hop-node ${(cin.worst_loss_pct >= 5) ? 'crit'
                              : (cin.worst_loss_pct >= 2) ? 'warn' : 'ok'}">
          <div class="hop-label">clients${cin.via ? ' · via ' + escapeHtml(cin.via) : ''}</div>
          <div class="hop-sub">${cin.connections} connection${cin.connections === 1 ? '' : 's'}</div>
          <div class="hop-meta">${[cin.rtt_ms != null ? cin.rtt_ms + 'ms rtt' : '',
              cin.worst_loss_pct != null ? cin.worst_loss_pct + '% loss' : '']
              .filter(Boolean).join(' · ')}</div>
        </div>
        <div class="hop-arrow">→</div>
        <div class="hop-node ok"><div class="hop-label">this box</div>
          <div class="hop-sub">${escapeHtml(data.hostname || 'here')}</div></div>
      </div>
      <div class="inbound-note">${cin.via
        ? `This box cannot see past ${escapeHtml(cin.via)} to the client. A clean reading here means clean as far as ${escapeHtml(cin.via)} — not clean to whoever is complaining.`
        : 'Connections arrive from many addresses, so this is the spread of real clients rather than one balancer in front.'}</div>
    </div>` : '';

  document.getElementById('hopChainWrap').innerHTML = inboundHtml +
    `<div style="font-family:var(--mono); font-size:12px; color:var(--text-dim); margin-bottom:8px;">${
      escapeHtml(cin ? 'path out — ' + summary : summary)}</div>` +
    '<div class="hop-chain">' + nodes.map((n,i) => `
      ${n.demarcBefore ? '<div class="hop-arrow demarc">→<span>site edge</span></div>'
        : (n.entersNetwork ? `<div class="hop-arrow handoff">→<span>${escapeHtml(n.entersNetwork)}</span></div>` : '')}
      <div class="hop-node ${n.sev}">
        <div class="hop-label">${escapeHtml(n.label)}</div>
        <div class="hop-sub">${escapeHtml(n.sub)}</div>
        ${n.meta ? `<div class="hop-meta">${n.meta}</div>` : ''}
      </div>
      ${i < nodes.length - 1 && !(nodes[i+1] && (nodes[i+1].demarcBefore || nodes[i+1].entersNetwork)) ? '<div class="hop-arrow">→</div>' : ''}
    `).join('') + '</div>';
}

// Where each finding stands to the verdict. The words come from the report so
// the page and the terminal say the same thing.
const RELATION_LABEL = {cause: 'the cause', corroborates: 'backs it up',
                        explained: 'caused by it', unrelated: 'separate problem'};

function renderDiagnosis(data, opts){
  opts = opts || {};
  output.innerHTML = '';
  panelSeq = 0;

  osBadge.textContent = [(data.os_label || data.os) && `${data.os_label || data.os} report`,
                         data.version && `v${data.version}`].filter(Boolean).join(' · ')
                        || 'report viewer';

  renderHopChain(data);

  const findings = data.findings || [];
  const layers = data.layers || {};
  if(data.panel_help) panelHelp = data.panel_help;
  const lowest = data.lowest_broken_layer || null;
  const layerBadge = f => {
    if(!f.layer) return '';
    const meta = layers[String(f.layer)] || {};
    const isLowest = f.layer === lowest && f.severity !== 'ok';
    return `<span class="layer${isLowest ? ' low' : ''}" title="${escapeHtml(meta.hint || '')}">L${f.layer}${meta.name ? ' · ' + escapeHtml(meta.name) : ''}</span>`;
  };
  const v = data.verdict;
  const verdictHtml = v ? `
    <div class="verdict ${v.severity || 'warning'}">
      <div class="vlabel">likely root cause</div>
      <div class="vhead">${escapeHtml(v.headline)}</div>
      <div class="vmeta">
        <span>owner: ${escapeHtml(v.owner)}</span>
        <span>confidence: ${escapeHtml(v.confidence)}${v.coverage && v.coverage.attempted
          ? ` (${v.coverage.ran} of ${v.coverage.attempted} checks ran)` : ''}</span>
      </div>
      ${(v.explains || []).length ? `<div class="vnext"><b>This also accounts for:</b> `
        + escapeHtml((v.explains || []).join(', ')) + `</div>` : ''}
      ${(v.unrelated || []).map(u =>
        `<div class="vnext"><b>Also, unrelated:</b> ${escapeHtml(u.message)}</div>`).join('')}
      ${((v.unrelated_total || 0) - (v.unrelated || []).length) > 0
        ? `<div class="vnext">and ${(v.unrelated_total - v.unrelated.length)} more unrelated finding(s) below</div>` : ''}
      <div class="vnext"><b>Next:</b> ${escapeHtml(v.next_step)}</div>
    </div>` : '';

  // Where the fault is, before which layer. The strip below walks one chain
  // outward, which is the shape of a device that only talks; a box that
  // answers requests has traffic coming the other way too. Three boxes with
  // one of them lit answers "where" without knowing what a layer is, which is
  // the first thing anyone wants and the last thing a layer number gives them.
  // Shown on every box, including one nothing connects to, where the inbound
  // zone greys out. Hiding it there restated the strip for a reader who can
  // already read the strip, and withheld it from the one who cannot.
  const sides = data.sides || [];
  const ZONE_NAME = {downstream: 'clients reaching this box', local: 'this box',
                     upstream: 'what this box depends on'};
  const ZONE_WORD = {pass: 'OK', warn: 'DEGRADED', fail: 'FAULT',
                     // The socket table was read and nothing was coming in.
                     // That is an answer, not a gap.
                     skip: 'none connected'};
  const sidesHtml = sides.length ? `
    <div class="zones">
      ${sides.map((z, i) => `
        ${i ? '<div class="zarrow" aria-hidden="true">→</div>' : ''}
        <div class="zone ${z.state}">
          <div class="zname">${escapeHtml(ZONE_NAME[z.side] || z.side)}</div>
          ${z.via ? `<div class="zvia">via ${escapeHtml(z.via)}</div>` : ''}
          <div class="zstate">${ZONE_WORD[z.state] || z.state}</div>
          ${z.worst ? `<div class="zwhy">${escapeHtml(z.worst)}</div>` : ''}
        </div>`).join('')}
    </div>` : '';

  const stages = data.stages || [];
  const stageHtml = stages.length ? '<div class="stages">' + stages.map(st =>
    `<span class="stage ${st.state}">${escapeHtml(st.stage)} <b>${
      {pass:'PASS', warn:'WARN', fail:'FAIL', skip:'—'}[st.state] || ''}</b></span>`).join('') + '</div>' : '';

  const changes = data.comparison || [];
  const changesHtml = changes.length ? `<div class="changes">
      <h4>changes since baseline</h4>
      ${changes.map(c => `<div class="row ${escapeHtml(c.direction || 'neutral')}">
        <span>${escapeHtml(String(c.what))}:</span>
        <span>${escapeHtml(String(c.before))} → ${escapeHtml(String(c.after))}</span>
      </div>`).join('')}
    </div>` : '';

  findingsWrap.innerHTML = verdictHtml + sidesHtml + stageHtml + changesHtml + '<div class="findings">' + findings.map(f => `
    <div class="finding ${f.severity}">
      <div class="sev"></div>
      <div>
        <div class="tagline"><span class="tag">${f.severity}</span>${layerBadge(f)}${
          f.relation ? `<span class="rel rel-${f.relation}">${escapeHtml(RELATION_LABEL[f.relation] || f.relation)}</span>` : ''}${
          f.kind === 'hardware' ? `<span class="rel rel-hardware">needs hands on it</span>` : ''}</div>
        <div class="msg">${escapeHtml(f.message)}</div>
      </div>
    </div>
  `).join('') + '</div>' + (lowest ? `
    <div class="layer-note">Lowest layer showing a problem: <strong>L${lowest}${(layers[String(lowest)]||{}).name ? ' · ' + escapeHtml(layers[String(lowest)].name) : ''}</strong>
    — ${escapeHtml((layers[String(lowest)]||{}).hint || '')}. Start there; findings at higher layers may just be downstream symptoms.</div>` : '');

  // Every stage the report computed, in path order, from the report's own
  // stage data. This used to substring-match the finding text for four
  // keywords, which left a critical CRC fault showing all-green and lit the
  // gateway lamp for a finding that said the gateway was reachable.
  ledsEl.innerHTML = (data.stages || []).map(ledRow).join('') + verdictRow(data.verdict);

  const raw = data.raw || {};
  const order = ['lldp', 'optics', 'dns_health', 'inventory', 'ports', 'sockets', 'link_stats', 'link_modes', 'tcp_health', 'arp', 'path_mtu', 'ping_gateway', 'ping_internet', 'path_trace', 'dns_lookup', 'routes', 'interfaces'];
  order.forEach(key => {
    if(!raw[key]) return;
    const labelMap = {
      ping_gateway: `ping ${data.detected_gateway || ''}`.trim(),
      ping_internet: `ping ${data.target || ''}`.trim(),
      path_trace: `traceroute ${data.target || ''}`.trim(),
      dns_lookup: 'dns lookup google.com',
      lldp: 'switch port (lldp/cdp)',
      optics: 'optical module (sfp)',
      dns_health: 'dns resolvers',
      ports: 'listening ports',
      sockets: 'socket states',
      inventory: 'neighbours (passive)',
      link_stats: 'interface error counters',
      tcp_health: 'tcp retransmissions',
      arp: 'arp / neighbour table',
      link_modes: 'link speed / duplex / mtu',
      path_mtu: 'path mtu probe',
      routes: 'routing table',
      interfaces: 'interfaces',
    };
    const body = addPanel(labelMap[key], raw[key].cmd || labelMap[key], (data.panel_help || {})[key]);
    renderResult(body, raw[key]);
  });

  // Port check results
  const portResults = data.port_results || [];
  portResults.forEach(pr => {
    if(!pr || !pr.cmd) return;
    const body = addPanel(pr.cmd, pr.cmd, (data.panel_help || panelHelp || {}).port_check);
    renderResult(body, pr);
  });

  if(opts.imported){
    document.getElementById('reportMeta').textContent =
      `loaded: ${data.generated_at || 'unknown time'}`;
  }

  // A self-contained export is a finished report, not a tool waiting for
  // input. The standalone viewer keeps its picker - loading another report is
  // the whole point of it - so this turns on only for the embedded copy.
  if(opts.embedded){
    ['reportFileLabel', 'reportFile', 'viewerHint'].forEach(id => {
      const el = document.getElementById(id);
      if(el) el.style.display = 'none';
    });
  }

  // Name the tab after the report. Several of these get opened side by side -
  // two sites, or a before and after - and identical titles make you click
  // each one to find out which is which. It is also the filename a browser
  // offers when the page is saved.
  const state = (data.verdict || {}).severity === 'ok' ? 'clear'
              : (data.verdict || {}).severity || 'report';
  document.title = ['FaultOne', data.target, state].filter(Boolean).join(' \u00b7 ');
  setFavicon(state);
}

const FAVICON_VAR = {clear: '--ok', warning: '--warn', critical: '--crit'};

function setFavicon(state){
  // Read the colour from the stylesheet rather than repeating the hex here,
  // so the tab dot and the lamps can't drift apart.
  const css = getComputedStyle(document.documentElement);
  const colour = (css.getPropertyValue(FAVICON_VAR[state] || '--text-dim') || '#6b7785').trim();
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">`
            + `<circle cx="8" cy="8" r="6" fill="${colour}"/></svg>`;
  const link = document.getElementById('favicon');
  // encodeURIComponent also escapes the '#' of the colour, which would
  // otherwise truncate the data URI at the fragment.
  if(link) link.href = 'data:image/svg+xml,' + encodeURIComponent(svg);
}

function loadReportFile(file){
  if(!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try{
      const data = JSON.parse(reader.result);
      renderDiagnosis(data, {imported:true});
    }catch(err){
      alert('Could not parse this file as a FaultOne report: ' + err);
    }
  };
  reader.readAsText(file);
}

document.getElementById('reportFile').addEventListener('change', (e) => {
  loadReportFile(e.target.files[0]);
});

// Drag a report anywhere onto the page - in viewer mode that's the whole job,
// so it shouldn't require aiming at a file input.
document.addEventListener('dragover', (e) => {
  e.preventDefault();
  document.body.classList.add('dragging');
});
document.addEventListener('dragleave', (e) => {
  if(e.relatedTarget === null) document.body.classList.remove('dragging');
});
document.addEventListener('drop', (e) => {
  e.preventDefault();
  document.body.classList.remove('dragging');
  loadReportFile(e.dataTransfer && e.dataTransfer.files[0]);
});


// A self-contained export leaves its data in the island above; the standalone
// viewer leaves the placeholder in place and waits for a dropped file.
(function () {
  const el = document.getElementById('faultone-report');
  const raw = el && el.textContent.trim();
  if (!raw || raw === '__FAULTONE_' + 'REPORT__') return;
  try {
    renderDiagnosis(JSON.parse(raw), {imported: true, embedded: true});
  } catch (err) {
    document.getElementById('findingsWrap').innerHTML =
      '<div class="err">this file\'s embedded report could not be read: ' +
      escapeHtml(String(err)) + '</div>';
  }
})();
</script>
</body>
</html>
"""


def json_safe(value):
    """Replace non-finite floats with None.

    json.dumps writes bare NaN and Infinity, which Python re-reads happily and
    every browser's JSON.parse rejects - so one stray value would make a
    self-contained report fail to open, with nothing to explain why.
    """
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value


def render_report_html(report):
    """A single file that opens in a browser and shows the whole report.

    The data rides inside the page as a JSON island, so there is nothing to
    load, no viewer to keep in sync and no second file to copy. `</` is escaped
    because an unescaped one inside the island would end the script block early
    and take the rest of the page with it.
    """
    blob = json.dumps(json_safe(report), separators=(",", ":")).replace("</", "<\\/")
    return VIEWER_TEMPLATE.replace(REPORT_PLACEHOLDER, blob, 1)


def extract_embedded_report(text):
    """Pull the report back out of a self-contained page, so an old
    report.html still works as a --baseline."""
    m = re.search(r'<script id="faultone-report" type="application/json">(.*?)</script>',
                  text or "", re.S)
    if not m:
        return None
    body = m.group(1).strip().replace("<\\/", "</")
    if not body or body == REPORT_PLACEHOLDER:
        return None            # the empty viewer, not a report
    try:
        return json.loads(body)
    except ValueError:
        return None


def load_report_file(path):
    """Read a report from either format - JSON, or a self-contained page."""
    with open(path) as fh:
        text = fh.read()
    if path.lower().endswith((".html", ".htm")):
        report = extract_embedded_report(text)
        if report is None:
            raise ValueError("no embedded report found in this page")
        return report
    return json.loads(text)


# ---------------------------------------------------------------------------
# Terminal rendering. This is the primary output path when you're logged into
# the box over SSH: no browser to point anywhere, nothing to copy off first.
# ---------------------------------------------------------------------------

SEV_TAG = {"critical": "CRIT", "warning": "WARN", "ok": " OK "}
SEV_COLOR = {"critical": "\033[31m", "warning": "\033[33m", "ok": "\033[32m"}
RESET = "\033[0m"


class Progress:
    """Live "what it's doing now" line on stderr.

    stderr on purpose: stdout carries the JSON for `--export -`, and a progress
    line mixed into that would corrupt it. Overwrites one line on a terminal;
    when stderr is redirected it stays quiet rather than filling a log with
    half-finished lines.
    """

    def __init__(self, stream=None, enabled=None):
        self.stream = stream or sys.stderr
        if enabled is None:
            enabled = bool(getattr(self.stream, "isatty", lambda: False)())
        self.enabled = enabled
        self.started = time.monotonic()
        self._width = 0

    def __call__(self, message):
        if not self.enabled:
            return
        elapsed = time.monotonic() - self.started
        line = f"  [{elapsed:4.1f}s] {message}"
        # pad to erase whatever the previous, possibly longer, line left behind
        self.stream.write("\r" + line.ljust(self._width))
        self.stream.flush()
        self._width = max(self._width, len(line))

    def done(self):
        if self.enabled and self._width:
            self.stream.write("\r" + " " * self._width + "\r")
            self.stream.flush()
            self._width = 0


def use_color(stream):
    """Color only for a real terminal, and honor NO_COLOR - output gets pasted
    into tickets and piped into files, where escape codes are just noise."""
    return bool(
        getattr(stream, "isatty", lambda: False)()
        and os.environ.get("NO_COLOR") is None
        and OS_NAME != "Windows"
    )


def worst_by_scope(findings):
    """The worst severity anything said about each interface.

    Read off the findings rather than worked out again from the counters. The
    tables below would otherwise need their own copy of every threshold - what
    counts as an error rate, a drop rate, a slow link - and a second copy of a
    rule is a second chance to disagree with the first. Anything with a scope
    has already been judged; this only asks what the answer was.
    """
    rank = {"ok": 0, "warning": 1, "critical": 2}
    worst = {}
    for f in findings or []:
        scope = f.get("scope")
        if not scope:
            continue
        sev = f.get("severity", "ok")
        if rank.get(sev, 0) > rank.get(worst.get(scope, "ok"), 0):
            worst[scope] = sev
    return worst


def _render_inbound(report, out, tint, width):
    """The other direction, as far as it can honestly be drawn: one hop.

    A traceroute goes one way. No probe from this box can observe the route a
    client's packets took to arrive, so there is no inbound path to draw and
    inventing one would be worse than leaving it out. What there is instead is
    better evidence than a probe: the kernel's own measurement of every
    connection a client actually has open, which is what TCP_INFO carries.
    """
    flows = (report.get("raw") or {}).get("tcp_flows") or {}
    side = (flows.get("by_side") or {}).get("client")
    if not side:
        return
    out.append("")
    out.append("CLIENTS IN (measured on their own connections, not probed)")
    via = f" via {side['via']}" if side.get("via") else ""
    loss = side.get("worst_loss_pct")
    sev = "critical" if (loss or 0) >= 5 else "warning" if (loss or 0) >= 2 else "ok"
    bits = [f"{side['connections']} connection(s){via}"]
    if side.get("rtt_ms") is not None:
        bits.append(f"rtt {side['rtt_ms']}ms")
    if loss is not None:
        bits.append(tint(f"loss {loss}%", sev))
    out.append("  " + "   ".join(bits))
    if side.get("via"):
        out.append(_wrap_note(
            f"this box cannot see past {side['via']} to the client, so a clean "
            f"reading here means clean as far as {side['via']} - not clean to "
            f"whoever is complaining.", width))
    else:
        out.append(_wrap_note(
            "connections arrive from many addresses, so this is the spread of "
            "real clients rather than one balancer in front.", width))


def _wrap_note(text, width):
    return "\n".join(textwrap.wrap("  -> " + text, width=max(width - 4, 40),
                                    subsequent_indent="     "))


def _render_path(report, out, tint, width):
    """The hop-by-hop path, with the site edge, handoffs and per-hop insight."""
    _render_inbound(report, out, tint, width)
    out.append("")
    hops = report.get("hops", [])
    # Named as a direction, not as "the path". On a box that answers requests
    # this is one of two, and the other one is above it.
    kind = ((report.get("raw") or {}).get("target_kind"))
    what = {"backend": " - what this box depends on",
            "dependency": " - what this box depends on"}.get(kind, "")
    serving = bool(((report.get("raw") or {}).get("tcp_flows") or {})
                   .get("by_side", {}).get("client"))
    out.append(f"PATH OUT TO {report.get('target', '?')}{what}"
               if serving else f"PATH TO {report.get('target', '?')}")
    if report.get("quick"):
        out.append("  (skipped in --quick mode; drop --quick for the hop-by-hop path)")
    elif not hops:
        out.append("  (no hops parsed - traceroute may be unavailable or blocked)")
    demarc = report.get("demarc_hop")
    for h in hops:
        times = [t for t in (h.get("times_ms") or []) if t is not None]
        if h.get("timed_out"):
            latency = "* * *  no reply"
        elif times:
            avg = sum(times) / len(times)
            # Only meaningful for traceroute, which sends three probes per hop.
            # mtr reports loss directly, so counting its timings proves nothing.
            partial = h.get("loss_pct") is None and len(times) < 3
            latency = f"{avg:6.1f} ms" + ("   (partial reply loss)" if partial else "")
        else:
            latency = ""
        name = h.get("display") or h.get("host") or "*"
        alt = h.get("also") or []
        if alt:
            latency += f"   (+{len(alt)} other router{'s' if len(alt) > 1 else ''} at this hop)"
        zone = "lan" if h.get("private") else ("wan" if h.get("private") is False else "  ?")
        extra = []
        if h.get("loss_pct"):
            extra.append(f"loss {h['loss_pct']}%")
        if h.get("mos"):
            extra.append(f"MOS {h['mos']}")
        if h.get("delta_ms"):
            extra.append(f"+{h['delta_ms']}ms")
        # mtr reports a standard deviation over many cycles, traceroute the
        # spread of three probes. The MOS calculation already treats either as
        # the jitter estimate; the display was gated on the traceroute one
        # alone, so the better measurement was scored and then hidden.
        jitter = h.get("jitter_ms")
        if jitter is None:
            jitter = h.get("stdev_ms")
        if jitter is not None and jitter >= 5:
            extra.append(f"jitter {jitter}ms")
        if h.get("roles"):
            extra.append("/".join(h["roles"]))
        if demarc is not None and h.get("hop") == demarc:
            out.append("       ----- site edge: past here is the provider's network -----")
        elif h.get("enters_network"):
            frm = f" (from {h['handoff_from']})" if h.get("handoff_from") else ""
            out.append(f"       ----- enters {h['enters_network']}{frm} -----")
        out.append(f"  {str(h.get('hop', '?')):>3} {zone:<4}{name:<30} {latency}"
                   + (f"   {', '.join(extra)}" if extra else ""))
    nets = [n["network"] for n in (report.get("networks_crossed") or [])]
    if nets:
        out.append(f"  -> networks crossed: {' -> '.join(nets)}")
    if report.get("cgnat_hop"):
        out.append(f"  -> behind carrier NAT at hop {report['cgnat_hop']} "
                   f"(100.64/10) - no public address on this connection")
    wj = report.get("worst_jump")
    if wj and wj.get("delta_ms", 0) >= 10:
        where = ("in the provider's carrier-NAT layer" if wj.get("cgnat")
                 else "inside this site" if wj.get("private")
                 else "on the provider's side")
        share_pct = wj.get("share_pct")
        total = wj.get("total_ms")
        # Naming a hop is a claim that it is the one to go and look at, and on
        # an evenly graded path it is not. latency_wall already declines to
        # fire below this share - it is the test that makes its own sentence
        # true - and the summary was naming a hop anyway, sending the reader
        # to hop 8 of ten hops that each add about the same.
        dominates = share_pct is None or share_pct >= LATENCY_WALL_SHARE * 100
        if not dominates and total:
            out.append(f"  -> no single hop adds most of the delay: the {total:.0f}ms "
                       f"builds up across the path, the largest step being "
                       f"{wj['share_pct']}% of it at hop {wj['hop']}")
        else:
            share = (f", {share_pct}% of the {total:.0f}ms end to end"
                     if share_pct is not None and total else "")
            out.append(f"  -> biggest latency jump: +{wj['delta_ms']}ms at hop {wj['hop']} "
                       f"({wj['host']}){share}, {where}")

def _render_neighbours(report, out, tint, width):
    """Which switch port this device is on."""
    neighbours = report.get("neighbours") or []
    if neighbours:
        out.append("")
        out.append("SWITCH PORT (LLDP/CDP)")
        for n in neighbours:
            bits = [f"{n['iface']} ->"]
            if n.get("switch"):
                bits.append(n["switch"])
            port = n.get("port") or n.get("port_descr")
            if port:
                bits.append(f"port {port}")
            if n.get("vlan"):
                bits.append(f"vlan {n['vlan']}")
            if n.get("mgmt_ip"):
                bits.append(f"({n['mgmt_ip']})")
            out.append("  " + " ".join(bits))

def _render_link_tables(report, out, tint, width):
    """Call quality, error counters, optical modules and link mode."""
    cq = report.get("call_quality")
    if cq:
        rating = ("excellent" if cq["mos"] >= 4.3 else "good" if cq["mos"] >= 4.0
                  else "fair" if cq["mos"] >= 3.6 else "poor")
        sev = "ok" if cq["mos"] >= MOS_WARN else ("warning" if cq["mos"] >= MOS_BAD else "critical")
        out.append("")
        out.append("CALL QUALITY (estimated, to " + str(cq.get("target", "?")) + ")")
        out.append(f"  MOS {tint(str(cq['mos']), sev)} ({rating})   "
                   f"latency {cq['avg_ms']:.0f}ms · jitter {(cq.get('jitter_ms') or 0):.0f}ms · "
                   f"loss {cq['loss_pct']:.0f}%")

    ifaces = [i for i in ((report.get("raw", {}).get("link_stats") or {}).get("interfaces") or [])
              if i.get("packets") and not i["name"].startswith("lo")]
    if ifaces:
        out.append("")
        iface_speed = {m.get("name"): m.get("speed_mbps")
                       for m in ((report.get("raw", {}).get("link_modes") or {})
                                 .get("interfaces") or [])}
        # Which row to look at first, on a box with eight of them. The colour
        # says the same thing here as everywhere else in the report - it is the
        # severity of what was found about that interface, not a second opinion
        # formed in the renderer.
        scope_sev = worst_by_scope(report.get("findings"))
        out.append("INTERFACE ERROR COUNTERS")
        out.append(f"  {'iface':<10}{'packets':>14}{'errors':>9}{'drops':>8}{'err/M':>8}   live")
        for i in ifaces:
            if i["delta_errors"] is None:
                live = "(not sampled)"
            elif i["delta_errors"] or i["delta_drops"]:
                live = f"+{i['delta_errors']} err / +{i['delta_drops']} drop in {i['sample_seconds']}s"
            else:
                live = f"steady over {i['sample_seconds']}s"
            rate = ""
            if i.get("rx_mbps") is not None:
                rate = f"   {i['rx_mbps']}/{i['tx_mbps']} Mbps rx/tx"
                if i.get("utilization_pct") is not None:
                    # Name the denominator. This percentage is against the
                    # NIC, and the saturation findings measure against the
                    # site uplink when one was given - so the same interface
                    # could read "2% of link" here and "full" three lines
                    # above, with nothing on the page reconciling them.
                    speed = iface_speed.get(i["name"])
                    against = f" of the {speed:g}M link" if speed else " of link"
                    rate += f" ({i['utilization_pct']}%{against})"
                # The average alone is what lets a line that fills in bursts
                # read as quiet - see saturation_bursts, which exists because
                # of it. Where the peak says something different, say it.
                peak, mean = i.get("peak_mbps"), max(i.get("rx_mbps") or 0,
                                                     i.get("tx_mbps") or 0)
                if peak and peak >= max(mean, 0.01) * PEAK_WORTH_SHOWING:
                    rate += f", peak {peak:g}"
            row = (f"  {i['name']:<10}{i['packets']:>14,}{i['errors']:>9,}"
                   f"{i['drops']:>8,}{i['err_ppm']:>8}   {live}{rate}")
            out.append(tint(row, scope_sev[i["name"]]) if i["name"] in scope_sev else row)

    optics = ((report.get("raw", {}) or {}).get("optics") or {}).get("interfaces") or {}
    if optics:
        out.append("")
        out.append("OPTICAL MODULES")
        for name, o in optics.items():
            bits = [f"  {name:<10}"]
            if o.get("rx_dbm") is not None:
                bits.append(f"rx {o['rx_dbm']:>7.2f} dBm")
            if o.get("tx_dbm") is not None:
                bits.append(f"tx {o['tx_dbm']:>7.2f} dBm")
            if o.get("alarms"):
                bits.append(f"ALARM: {', '.join(o['alarms'][:2])}")
            elif o.get("warnings"):
                bits.append(f"warning: {', '.join(o['warnings'][:2])}")
            desc = " ".join(filter(None, [o.get("vendor"), o.get("part")]))
            if desc:
                bits.append(f"  {desc}")
            sev = "critical" if o.get("alarms") or (o.get("rx_dbm") or 0) <= OPTIC_RX_CRIT_DBM \
                else ("warning" if (o.get("rx_dbm") or 0) <= OPTIC_RX_WARN_DBM else "ok")
            out.append(tint(" ".join(bits), sev))

    modes = [m for m in ((report.get("raw", {}).get("link_modes") or {}).get("interfaces") or [])
             if m["name"] in {i["name"] for i in ifaces}]
    if modes:
        out.append("")
        out.append("LINK MODE")
        out.append(f"  {'iface':<10}{'speed':>10}{'duplex':>9}{'mtu':>7}")
        scope_sev = worst_by_scope(report.get("findings"))
        for m in modes:
            speed = f"{m['speed_mbps']}M" if m.get("speed_mbps") else "-"
            row = (f"  {m['name']:<10}{speed:>10}{(m.get('duplex') or '-'):>9}"
                   f"{(m.get('mtu') or '-'):>7}")
            out.append(tint(row, scope_sev[m["name"]]) if m["name"] in scope_sev else row)

def _render_services(report, out, tint, width):
    """Path MTU, resolvers, retransmits and port checks."""
    pm = report.get("raw", {}).get("path_mtu") or {}
    if pm.get("attempts"):
        out.append("")
        out.append(f"PATH MTU TO {pm.get('target', '?')}")
        for a in pm["attempts"]:
            out.append(f"  {a['mtu']:>5} bytes   {'passes' if a['ok'] else 'blocked'}")
        if pm.get("path_mtu"):
            same = pm["path_mtu"] == pm.get("iface_mtu")
            out.append(f"  -> largest that gets through: {pm['path_mtu']}"
                       + ("  (matches the interface MTU)" if same
                          else f"  (interface is set to {pm.get('iface_mtu')})"))

    dnsh = (report.get("raw", {}) or {}).get("dns_health") or {}
    if dnsh.get("resolvers"):
        out.append("")
        out.append(f"DNS RESOLVERS (probe: {dnsh.get('probe', '?')})")
        for r in dnsh["resolvers"]:
            status = r.get("rcode") or ("ok" if r["ok"] else "no reply")
            line = f"  {r['server']:<22}{status:<10}{str(r.get('elapsed_ms') or '-'):>7} ms"
            if r.get("hijacks_nxdomain"):
                line += "   [invents NXDOMAIN answers]"
            out.append(tint(line, "ok" if r["ok"] else "warning"))

    inv = report.get("inventory") or {}
    if inv.get("hosts"):
        out.append("")
        out.append(f"NEIGHBOURS ({inv['count']} known to this device, nothing was probed)")
        show_names = any(h.get("name") for h in inv["hosts"])
        for host in inv["hosts"][:20]:
            name_col = f"{(host.get('name') or '-')[:30]:<32}" if show_names else ""
            out.append(f"  {host['ip']:<16}{name_col}{host.get('mac') or '-'}")
        if inv["count"] > 20:
            out.append(f"  ... and {inv['count'] - 20} more")
        if len(inv.get("subnets", {})) > 1:
            out.append("  subnets: " + ", ".join(f"{net}.0/24 x{n}"
                                                 for net, n in sorted(inv["subnets"].items())))

    socks = (report.get("raw", {}) or {}).get("sockets") or {}
    if socks.get("states"):
        interesting = ["ESTABLISHED", "LISTEN", "SYN_SENT", "CLOSE_WAIT", "TIME_WAIT"]
        cells = [f"{name.lower()} {socks['states'][name]}"
                 for name in interesting if socks["states"].get(name)]
        if cells:
            out.append("")
            out.append("SOCKETS (this device)")
            out.append("  " + "   ".join(cells))

    tcp = (report.get("raw", {}) or {}).get("tcp_health") or {}
    live = tcp.get("retrans_pct_live") if tcp.get("ok") else None
    life = tcp.get("retrans_pct_lifetime") if tcp.get("ok") else None
    if live is not None or life is not None:
        out.append("")
        out.append("TCP RETRANSMITS (this device's own traffic)")
        if live is not None:
            out.append(f"  {live}% over the last {tcp.get('sample_seconds')}s"
                       f"   ({life}% since boot)")
        else:
            out.append(f"  {life}% since boot (lifetime figure - run --soak for a live rate)")
    elif tcp:
        # Say so rather than leaving the section out. A reader who doesn't see
        # the heading assumes retransmits were checked and were clean, which is
        # the opposite of what happened.
        out.append("")
        out.append("TCP RETRANSMITS (this device's own traffic)")
        out.append(f"  not measured - {tcp.get('error') or 'the counters read as unavailable'}")

    ports = report.get("port_results", [])
    if ports:
        out.append("")
        out.append("PORT CHECKS")
        for p in ports:
            label = (p.get("cmd", "") or "").replace("tcp connect ", "")
            if p.get("ok"):
                extra = ""
                tls = p.get("tls") or {}
                if tls.get("tls_version"):
                    extra = f"   {tls['tls_version']}"
                    if tls.get("issuer"):
                        extra += f", issued by {tls['issuer']}"
                    if tls.get("days_left") is not None:
                        extra += f", {tls['days_left']}d left"
                    if tls.get("verified") is False:
                        extra += "   [does not verify]"
                elif p.get("banner"):
                    extra = f"   {p['banner'][:60]}"
                out.append(f"  {label:<24} {tint('open', 'ok')}{extra}")
                # Where the time went. The connect is a round trip and belongs
                # to the path; the handshake beyond it is the server's own
                # work, and "it's slow" goes to the wrong team without this.
                tcp_ms, tls_ms = tls.get("tcp_ms"), tls.get("tls_ms")
                if tcp_ms is not None and tls_ms is not None:
                    out.append(f"  {'':<24} {tcp_ms:.0f}ms connect + {tls_ms:.0f}ms "
                               f"handshake = {tcp_ms + tls_ms:.0f}ms")
                elif p.get("connect_ms") is not None:
                    out.append(f"  {'':<24} {p['connect_ms']:.0f}ms to connect")
            else:
                reason = p.get("reason", "failed")
                # Indent continuation lines to the real prefix width - measured
                # uncolored, since ANSI codes take columns the terminal doesn't show.
                pad = len(f"  {label:<24} {reason} - ")
                detail = textwrap.wrap(p.get("error", ""), width=max(width - pad, 30)) or [""]
                out.append(f"  {label:<24} {tint(reason, 'warning')} - {detail[0]}")
                for extra in detail[1:]:
                    out.append(" " * pad + extra)

def _render_comparison(report, out, tint, width):
    """What changed since the baseline report."""
    comparison = report.get("comparison") or []
    if comparison:
        out.append("")
        out.append("CHANGES SINCE BASELINE")
        for c in comparison:
            arrow = {"worse": "!", "better": "+", "neutral": " "}.get(c["direction"], " ")
            line = f"  {arrow} {c['what']}: {c['before']} -> {c['after']}"
            if c.get("delta"):
                line += f"  (+{c['delta']})"
            out.append(tint(line, {"worse": "warning", "better": "ok"}.get(c["direction"], "ok")))

    out.append("")

def render_text_report(report, color=False, width=None):
    """Render a diagnosis as plain text for a terminal. Returns a string."""
    if width is None:
        width = min(shutil.get_terminal_size((80, 24)).columns, 100)
    out = []
    tint = (lambda s, sev: f"{SEV_COLOR.get(sev, '')}{s}{RESET}") if color else (lambda s, sev: s)
    # Reports arrive from files now (--baseline, and pages opened later), so a
    # wrong shape shouldn't take the whole render down.
    if not isinstance(report.get("raw"), dict):
        report = dict(report, raw={})

    gw = report.get("detected_gateway") or "not found"
    version = report.get("version")
    py = report.get("python")
    # Reports written before os_label existed carry only the raw name, and
    # translating it on the way out costs nothing - the mapping is fixed.
    shown_os = report.get("os_label") or os_label(report.get("os")) or "?"
    out.append(f"FaultOne{' ' + version if version else ''} - {shown_os}"
               f"{' - python ' + py if py else ''}"
               f" - {report.get('generated_at', '')}")
    mode = ""
    if report.get("quick"):
        mode = "    [quick mode]"
    elif report.get("soak_seconds"):
        mode = f"    [soak: {report['soak_seconds']}s window]"
    src = report.get("path_source")
    out.append(f"target: {report.get('target', '?')}    gateway: {gw}" + mode
               + (f"    path via {src}" if src else ""))
    out.append("")

    v = report.get("verdict")
    if v:
        bar = "=" * min(width, 72)
        out.append(bar)
        for line in textwrap.wrap(f"LIKELY ROOT CAUSE: {v['headline']}", width=min(width, 72)):
            out.append(tint(line, v.get("severity", "warning")))
        # Show what the confidence is made of. "medium" on its own hides its
        # own reasoning, which is what makes a percentage tempting - and a
        # percentage would be a formula's output wearing a decimal point.
        # These are countable instead.
        cov = v.get("coverage") or {}
        basis = []
        if cov.get("attempted"):
            basis.append(f"{cov['ran']} of {cov['attempted']} checks ran")
        n = len(v.get("corroborated_by") or [])
        if n:
            basis.append(f"{n} corroborating")
        n = len(v.get("explains") or [])
        if n:
            basis.append(f"{n} explained by it")
        hands = sum(1 for f in report.get("findings", [])
                    if f.get("kind") == "hardware" and f.get("severity") != "ok")
        if hands:
            basis.append(f"{hands} needing hands on it")
        out.append(f"  owner: {v['owner']}   confidence: {v['confidence']}"
                   + (f" ({', '.join(basis)})" if basis else ""))
        for line in textwrap.wrap(f"next: {v['next_step']}", width=min(width, 72) - 2):
            out.append(f"  {line}")
        # What this cause accounts for. Without it every finding below reads
        # as its own problem, and the longest reports - the ones where one
        # fault has knocked over five things - were the hardest to act on.
        if v.get("explains"):
            for line in textwrap.wrap(
                    "this also accounts for: " + ", ".join(v["explains"]),
                    width=min(width, 72) - 2):
                out.append(f"  {line}")
        # A fault the cause above cannot explain. Fixing the cause leaves this
        # exactly where it is, and the layer rule would otherwise bury it.
        shown = v.get("unrelated") or []
        for other in shown:
            for i, line in enumerate(textwrap.wrap(
                    f"also, unrelated: {other['message']}", width=min(width, 72) - 2)):
                out.append(f"  {line}")
        more = (v.get("unrelated_total") or len(shown)) - len(shown)
        if more:
            out.append(f"  and {more} more unrelated finding(s) below")
        out.append(bar)
        out.append("")

    # Where, before which layer. "Which of the three places is it" is the
    # question anyone asks first, and it can be answered without knowing what
    # a layer is - which is the whole reason this is above the stage strip
    # rather than instead of it.
    #
    # Shown on every box, including one that nothing connects to. It was
    # hidden there at first, on the grounds that two boxes and an arrow
    # restate a seven-stage strip that says the same thing more precisely.
    # That optimises for a reader who can already read the strip. Boxes that
    # only talk outward are the common case, so hiding it there meant the
    # panel written for someone who cannot read the strip was the one they
    # would almost never be shown.
    sides = report.get("sides") or []
    if sides:
        sev = {"pass": "ok", "warn": "warning", "fail": "critical", "skip": "ok"}
        word = {"pass": "ok", "warn": "degraded", "fail": "FAULT",
                # Not "not checked": the socket table was read and there was
                # nothing coming in. That is an answer, not a gap.
                "skip": "none connected"}
        cells = []
        for zone in sides:
            name = {"downstream": "clients in", "local": "this box",
                    "upstream": "depends on"}[zone["side"]]
            via = f" ({zone['via']})" if zone.get("via") else ""
            cells.append(f"{name}{via} {tint(word[zone['state']], sev[zone['state']])}")
        out.append("  " + tint("  ->  ", "ok").join(cells))
        out.append("")

    stages = report.get("stages") or []
    if stages:
        symbols = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "skip": "-"}
        sev = {"pass": "ok", "warn": "warning", "fail": "critical", "skip": "ok"}
        cells = [f"{st['stage']} {tint(symbols[st['state']], sev[st['state']])}" for st in stages]
        out.append("  " + "   ".join(cells))
        out.append("")

    out.append("FINDINGS")
    findings = report.get("findings", [])
    layers = report.get("layers", {})
    if not findings:
        out.append("  (none)")
    for f in findings:
        sev = f.get("severity", "ok")
        tag = tint(f"[{SEV_TAG.get(sev, sev.upper()[:4])}]", sev)
        lname = (layers.get(str(f.get("layer")), {}) or {}).get("name", "")
        lcol = f"L{f['layer']} {lname}" if f.get("layer") else ""
        head = f"  {tag} {lcol:<16} "
        # Which of these is the answer, and which are its consequences. Without
        # it the list is ordered by layer and says nothing about what explains
        # what, which is the one thing this tool exists to work out.
        relation = finding_relation(f.get("code"), report.get("verdict"))
        # Indent wrapped lines under the message, not under the tag, so the
        # severity column stays scannable on a narrow terminal.
        body = textwrap.wrap(f.get("message", ""), width=max(width - 26, 30)) or [""]
        out.append(head + body[0])
        for extra in body[1:]:
            out.append(" " * 26 + extra)
        marks = []
        if relation:
            marks.append(FINDING_RELATIONS[relation])
        if f.get("kind") == "hardware":
            marks.append("needs hands on it")
        if marks:
            out.append(" " * 26 + tint("^ " + " · ".join(marks),
                                       "critical" if relation == "cause" else "ok"))

    low = report.get("lowest_broken_layer")
    if low:
        lmeta = layers.get(str(low), {}) or {}
        out.append("")
        out.append(f"  -> lowest layer showing a problem: L{low} {lmeta.get('name', '')}"
                   f" ({lmeta.get('hint', '')})")
        out.append("     start there - higher layers may just be downstream symptoms.")

    _render_path(report, out, tint, width)

    _render_neighbours(report, out, tint, width)

    _render_link_tables(report, out, tint, width)

    _render_services(report, out, tint, width)

    _render_comparison(report, out, tint, width)
    out.append("Raw command output is not shown here - use --export to capture it.")
    return "\n".join(out)


def build_parser():
    """Every flag the tool takes.

    Split out of main() so the flags can be read - and tested - without
    running a diagnosis; main() is then the dispatch it always meant to be.
    """
    ap = argparse.ArgumentParser(
        description=f"FaultOne {__version__} - field triage for a box you're logged into: "
                    f"is the fault this device, the network it's plugged into, or upstream?")
    ap.add_argument("--version", action="version",
                     version=f"FaultOne {__version__} (python {platform.python_version()})")
    ap.add_argument("--report", action="store_true",
                     help="run the diagnosis once and print the findings to this terminal, then "
                          "exit (no web server, no open port, nothing to copy off the box)")
    ap.add_argument("--emit-viewer", metavar="FILE", nargs="?", const="static/index.html",
                     help="write the standalone report viewer (the embedded template with an "
                          "empty slot) to FILE, default static/index.html. Only needed when "
                          "regenerating the copy kept in the repo")
    ap.add_argument("--inventory", action="store_true",
                     help="list the neighbours this device already knows about, from its own "
                          "ARP/neighbour table. Passive - nothing is probed or scanned, so it "
                          "is safe on a network you don't own")
    ap.add_argument("--quiet", action="store_true",
                     help="don't show the progress line while the checks run (it is already "
                          "hidden when output is redirected)")
    ap.add_argument("--baseline", metavar="FILE",
                     help="a previously exported report from this site, in either format. The "
                          "run is compared against it and anything that changed is reported - "
                          "a dated change is usually a better lead than an absolute reading")
    ap.add_argument("--soak", type=int, metavar="SECONDS",
                     help="sample over a window instead of taking a snapshot (try 60 or 120). "
                          "Uses mtr for per-hop loss where available, watches the error "
                          "counters for the whole window, and pings for longer - which is how "
                          "you catch an intermittent fault a single pass misses")
    ap.add_argument("--uplink-mbps", type=float, metavar="MBPS",
                     help="the site's WAN line rate, from the ticket or the contract. This "
                          "box can only read its own NIC speed, which on a branch appliance "
                          "is 20x the line behind it - so a site filling a 50 Mbps uplink "
                          "reads as 5%% busy and its loss gets blamed on the carrier. Give "
                          "the real number and the tool measures against the link that "
                          "actually fills. Needs --soak to have a window to measure over")
    ap.add_argument("--quick", action="store_true",
                     help="skip the traceroute and use 2 ping packets instead of 4 - a few "
                          "seconds instead of ~15, at the cost of the hop-by-hop path")
    ap.add_argument("--export", metavar="FILE",
                     help="run the diagnosis once, write a report to FILE, and exit. A '.html' "
                          "name gives a single self-contained page that opens in a browser; any "
                          "other name gives JSON, which is smaller to paste and is what "
                          "--baseline reads. Use - for stdout")
    ap.add_argument("--export-compact", metavar="FILE",
                     help="like --export, without the captured command output behind "
                          "the checks that passed. Same verdict, findings, hop diagram "
                          "and stage strip - on a healthy box it is around a "
                          "twentieth of the size, which is the difference between "
                          "pasting a report off a console and not. Evidence is kept "
                          "for stages that are not passing, and for checks that could "
                          "not run at all")
    ap.add_argument("--target", default="auto",
                     help="host to ping/traceroute for the full diagnosis. Default 'auto': on "
                          "a box that accepts connections this picks the backend it has "
                          "opened the most connections to, because whether a service can "
                          "reach its dependencies matters more than whether it can reach "
                          f"{DEFAULT_TARGET}. Falls back to {DEFAULT_TARGET} on a box with no "
                          "backends. The choice is always named in the report")
    ap.add_argument("--check-ports", metavar="PORTS",
                     help="comma-separated ports to check on the target "
                          "(e.g. 53,443,8080), or 'common' for 22, 53, 80, 443, 8080")
    return ap


def main():
    """Parse the flags and run whichever single action was asked for."""
    ap = build_parser()
    args = ap.parse_args()

    if args.emit_viewer:
        with open(args.emit_viewer, "w") as f:
            f.write(VIEWER_TEMPLATE)
        print(f"Wrote the viewer to {args.emit_viewer} "
              f"({len(VIEWER_TEMPLATE):,} bytes). Open it and drop a report.json on it.")
        return

    # One path for both, so a compact export cannot drift into behaving
    # differently from a full one. Only what gets written differs.
    if args.export and args.export_compact:
        print("Use --export or --export-compact, not both.", file=sys.stderr)
        raise SystemExit(EXIT_UNKNOWN)
    export_path = args.export or args.export_compact
    if export_path or args.report:
        if args.target.strip().lower() != "auto" and not valid_target(args.target):
            print(f"Invalid --target: {args.target!r}", file=sys.stderr)
            raise SystemExit(EXIT_UNKNOWN)
        check_ports = []
        ports_speculative = False
        if args.check_ports:
            if args.check_ports.strip().lower() == "common":
                check_ports = list(COMMON_PORTS)
                ports_speculative = True
            else:
                check_ports = [p.strip() for p in args.check_ports.split(",") if p.strip()]
        uplink_mbps = args.uplink_mbps
        if uplink_mbps is not None and uplink_mbps <= 0:
            print(f"Invalid --uplink-mbps: {uplink_mbps}", file=sys.stderr)
            raise SystemExit(EXIT_UNKNOWN)
        soak = min(max(int(args.soak or 0), 0), MAX_SOAK_SECONDS)
        if args.soak and soak != args.soak:
            print(f"Note: --soak capped at {MAX_SOAK_SECONDS}s.", file=sys.stderr)
        baseline = None
        if args.baseline:
            try:
                baseline = load_report_file(args.baseline)
            except (OSError, ValueError) as e:
                print(f"Could not read baseline {args.baseline}: {e}", file=sys.stderr)
                raise SystemExit(EXIT_UNKNOWN)
            if not looks_like_a_report(baseline):
                print(f"{args.baseline} parsed, but it is not a FaultOne report - "
                      f"no findings or verdict in it.", file=sys.stderr)
                raise SystemExit(EXIT_UNKNOWN)
        progress = Progress(enabled=False if args.quiet else None)
        try:
            report = diagnose(args.target, check_ports, quick=args.quick, soak=soak,
                              baseline=baseline, progress=progress,
                              inventory=args.inventory,
                              ports_speculative=ports_speculative,
                              uplink_mbps=uplink_mbps)
        finally:
            progress.done()

        # With --export -, the JSON owns stdout so it can be piped or pasted
        # cleanly; everything human-readable goes to stderr instead.
        to_stdout = export_path == "-"
        msg = sys.stderr if to_stdout else sys.stdout

        wants_html = bool(export_path) and export_path.lower().endswith((".html", ".htm"))
        # The report that gets written. The one printed to the terminal is
        # always the full one - the reader is already on the box, so there is
        # nothing to save by showing them less.
        written = compact_report(report) if args.export_compact else report
        # A diagnosis that can't be written must not be a diagnosis that is
        # lost. The run has already happened - seven seconds, or two minutes
        # under --soak, on a box someone had to reach - so a full disk or a
        # wrong path prints the report rather than a traceback, and says the
        # write failed. Exit 3, because the check ran and could not deliver,
        # which is not the same as a warning about the network.
        export_error = None
        if export_path:
            if to_stdout:
                if wants_html:
                    sys.stdout.write(render_report_html(written))
                else:
                    json.dump(json_safe(written), sys.stdout, indent=2)
                    sys.stdout.write("\n")
            else:
                try:
                    # 0600: the report contains internal addressing, MAC
                    # addresses and listening ports - not for other users of a
                    # shared box.
                    fd = os.open(export_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w") as f:
                        if wants_html:
                            f.write(render_report_html(written))
                        else:
                            json.dump(json_safe(written), f, indent=2)
                except OSError as e:
                    export_error = e

        if args.report or export_error:
            # Printed even when --report wasn't asked for, if the file couldn't
            # be written: the alternative is doing the work and handing back
            # nothing.
            print(render_text_report(report, color=use_color(msg)), file=msg)

        if export_error:
            print(f"\nCould not write {export_path}: {export_error}. The report is above.",
                  file=sys.stderr)
            raise SystemExit(EXIT_UNKNOWN)

        if export_path and not to_stdout:
            crit = sum(1 for x in report["findings"] if x["severity"] == "critical")
            warn = sum(1 for x in report["findings"] if x["severity"] == "warning")
            size = os.path.getsize(export_path) if os.path.exists(export_path) else 0
            kind = "compact report" if args.export_compact else "report"
            print(f"Wrote {kind} to {export_path} ({size:,} bytes, "
                  f"{crit} critical, {warn} warning finding(s)).",
                  file=msg)
            if not args.report:
                # --report already printed this; don't say it twice.
                low = report.get("lowest_broken_layer")
                if low:
                    print(f"Lowest layer showing a problem: {layer_label(low)} "
                          f"({LAYERS[low]['hint']}) - start there, higher layers may just be "
                          f"downstream symptoms.", file=msg)
                if check_ports:
                    print(f"Checked {len(check_ports)} port(s) on {args.target}.", file=msg)
            if wants_html:
                print("Copy this file to any machine and open it in a browser - the report "
                      "travels inside it, so nothing else is needed.", file=msg)
            else:
                print("Copy this file to any machine and open static/index.html, then drop "
                      "the report on it - no server or network access needed. Export to a "
                      "'.html' name instead for a single file that opens on its own.",
                      file=msg)

        # Exit non-zero when something is actually broken, so this can be used
        # in a scripted health check without parsing the output.
        raise SystemExit(exit_status(report))

    # No server mode: with --report and --export there is nothing to serve, and
    # a listening port on someone else's network was never worth its risk.
    ap.error("nothing to do - use --report for the terminal, or --export FILE "
             "(.html for a page that opens on its own, .json to load into the viewer)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl-C during a --soak window is a decision, not a fault.
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(EXIT_UNKNOWN)
    except SystemExit:
        raise
    except Exception:
        # An unexpected crash exits 1 by default, and 1 now means WARNING - so
        # a scheduled check would read a broken tool as a mild network finding.
        # The traceback is still printed, because a bug report needs it.
        import traceback
        traceback.print_exc()
        print("\nFaultOne failed before it could finish. That is a bug in the tool, "
              "not a finding about the network.", file=sys.stderr)
        raise SystemExit(EXIT_UNKNOWN)
