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
It opens no port and listens for nothing. There is no server here and so
nothing to authenticate to: every command above writes to your terminal or
to a file and exits. That whole category of risk is absent rather than
defended, which is why there is nothing here about binding addresses or
putting it behind a proxy.

What it does do is execute real system commands (ping, traceroute, ss and
so on) with whatever privileges you run it as, typically root, because
some of them need that on some systems. It connects outward - to its own
listeners, to the target, to resolvers - and never accepts a connection.
Hostnames and addresses you supply are strictly validated and commands run
without a shell, so classic "; rm -rf" injection is not possible.

The output is the thing to be careful with. A report is a map of the
network it was taken on: internal addressing, MAC addresses, switch names,
resolvers, listening ports. --export writes 0600 for that reason. Treat
one the way you would treat a network diagram - fine in a ticket, fine with
the people who own that network, not committed to a public repository.

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
import ipaddress
import socket
import ssl
import tempfile
import struct
import subprocess
import sys
import time
import textwrap

# Reports carry this, so a page opened months later, or a --baseline from a
# previous visit, can be read in the light of what produced it.
__version__ = "1.19.0"

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

# The address every probe leaves from, when one was asked for. None means the
# kernel chooses, which is right for a box with one address and wrong for the
# box this exists for.
#
# A proxy holding a service address alongside its own has two different paths
# off it, and the faults worth finding are exactly the ones that tell them
# apart: policy routing, a return path that differs by source, an upstream
# filter or NAT keyed on the source address, reverse-path filtering. Every one
# of those works from the box's primary address and fails from the service
# address, so a run that lets the kernel choose measures the wrong path and
# reports it clean.
#
# A global rather than an argument threaded through thirty call sites, for the
# same reason OS_NAME is one: it is a property of the run, fixed before any
# check starts, and read in places too far apart to pass it between.
SOURCE_ADDRESS = None
# Ask every global-scope address whether it can reach the target, rather
# than whichever one the kernel picks. Set by `--source all`.
PROBE_EVERY_SOURCE = False

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

def _answered(result):
    """Did this command actually say something?

    run() reports ok for anything it managed to execute, so a daemon that is
    installed and failing looked identical to one that answered. In a chain of
    utilities that each need their own parsing, that ended the chain on the
    first one present rather than the first one working, and the two behind it
    were never asked.
    """
    return bool(result.get("ok")) and not result.get("code") \
        and bool((result.get("stdout") or "").strip())


def run_first_usable(variants, fallback=None, timeout=None):
    """Run candidates that read the same thing until one answers usefully.

    Different from run_first_understood, and the difference is what counts as
    an answer. There, one command was asked twice and a failure was a result to
    report. Here several unrelated commands describe the same state, so nothing
    is an answer until one of them produces output: a trimmed `ip` that exits
    non-zero says nothing about the box, and `ifconfig` beside it may say
    everything.

    Choosing on which() alone is what made that a critical fault. The binary
    existed, the subcommand did not, and a working machine was told it had no
    IP address on any interface while ifconfig sat there unread.

    `fallback` is a reader that needs no userland at all, tried once every
    command has failed. On a custom OS none of these names may mean anything,
    and the kernel still knows the answer.

    What a failure returns matters as much as which command wins. run() reports
    ok for anything it managed to execute, so a command that ran and exited 127
    with nothing to say arrived downstream as a successful read of an empty
    machine - which is how a box whose whole userland was foreign got told it
    had no address and no gateway, both critical, instead of being told its
    userland could not be read. A non-zero exit is now a failed read. An exit of
    zero with no output is not: an empty neighbour table is a real answer, and
    the only honest one on a box that has spoken to nobody.
    """
    result = None
    for cmd in variants:
        if not which(cmd[0]):
            continue
        result = run(cmd, timeout=timeout) if timeout else run(cmd)
        if result.get("code") == 0 and (result.get("stdout") or "").strip():
            return result
    if fallback is not None:
        from_kernel = fallback()
        if from_kernel is not None:
            return from_kernel
    names = ", ".join(sorted({c[0] for c in variants}))
    if result is None:
        return {"ok": False, "cmd": " ".join(variants[0]) if variants else "",
                "error": "none of %s is installed" % names}
    if result.get("code") != 0:
        return {"ok": False, "cmd": result.get("cmd", ""),
                "error": "%s exited %s - none of %s could read this"
                         % (result.get("cmd", "").split(" ")[0],
                            result.get("code"), names)}
    return result


# ---------------------------------------------------------------------------
# Reading the network without a userland.
#
# Every command above is a program somebody chose to ship. An appliance, a
# container built from scratch, a vendor's own OS - any of them may ship none
# of them, or ship names that mean something else. The facts are not in those
# programs though, they are in the kernel, and on Linux the kernel publishes
# them as files. These read those files and hand back exactly what the parsers
# upstairs already understand, so a box with no userland is diagnosed by the
# same rules as any other rather than by a second, thinner set.
#
# They return None, not a failure, when they cannot answer. None means "this
# reader had nothing to add" and leaves the command's own failure to be
# reported; a failure here would overwrite the real reason with this one.
# ---------------------------------------------------------------------------

def read_proc(path):
    """A file under /proc as text, or None if it is not there to read."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (IOError, OSError):
        return None


def _le_hex_ipv4(word):
    """One little-endian hex word from /proc as a dotted quad.

    /proc/net/route prints addresses in host byte order, which on everything
    this runs on means the quad is reversed: 0101A8C0 is 192.168.1.1, not
    1.1.168.192. Reading it the obvious way produces a gateway address that
    looks plausible and is wrong.
    """
    try:
        n = int(word, 16)
    except (TypeError, ValueError):
        return None
    return "%d.%d.%d.%d" % (n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff,
                            (n >> 24) & 0xff)


def kernel_routes():
    """The default route from /proc/net/route, worded as `ip route` words it.

    Rendered into the format the richest command produces rather than into a
    format of its own, because the gateway parser has four dialects to handle
    already and this would have been a fifth for no gain.
    """
    text = read_proc("/proc/net/route")
    if text is None:
        return None
    lines = []
    for line in text.splitlines()[1:]:            # first line is the header
        parts = line.split()
        if len(parts) < 3 or parts[1] != "00000000":
            continue                              # not the default route
        hop = _le_hex_ipv4(parts[2])
        if hop and hop != "0.0.0.0":
            lines.append("default via %s dev %s" % (hop, parts[0]))
    if not lines:
        return None
    return {"ok": True, "cmd": "/proc/net/route", "stdout": "\n".join(lines) + "\n",
            "stderr": "", "code": 0}


def kernel_neighbours():
    """The neighbour table from /proc/net/arp, worded as `ip neigh` words it.

    Flags is a bitmask and 0x2 is the completed bit. An entry without it is one
    the box asked about and never heard back on, which is not the same as no
    entry and is why it is passed up as INCOMPLETE rather than dropped - an
    unanswered gateway is a finding of its own.
    """
    text = read_proc("/proc/net/arp")
    if text is None:
        return None
    lines = []
    for line in text.splitlines()[1:]:            # first line is the header
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, flags, mac, dev = parts[0], parts[2], parts[3], parts[5]
        try:
            complete = int(flags, 16) & 0x2
        except (TypeError, ValueError):
            complete = False
        if complete and mac != "00:00:00:00:00:00":
            lines.append("%s dev %s lladdr %s REACHABLE" % (ip, dev, mac))
        else:
            lines.append("%s dev %s INCOMPLETE" % (ip, dev))
    if not lines:
        return None
    return {"ok": True, "cmd": "/proc/net/arp", "stdout": "\n".join(lines) + "\n",
            "stderr": "", "code": 0}


def kernel_source_address():
    """The address this box would use to reach off itself, or None.

    No command and no packets. connect() on a UDP socket sends nothing - it
    fixes a destination - so this is a routing lookup with a socket for a
    mouth, and it works wherever Python does, Windows and BSD included.

    The destinations are the documentation ranges, so nothing here depends on
    a host being up, or reachable, or existing.

    What it answers is "this box has an address and a way off itself", which is
    the question the missing-address finding asks. What it cannot answer is
    which interface holds what, and it says nothing on a box with an address
    but no route - that box has no way off itself either, so the finding it
    would suppress is one worth leaving up.
    """
    for family, probe in ((socket.AF_INET, "192.0.2.1"),
                          (socket.AF_INET6, "2001:db8::1")):
        try:
            # A socket is its own context manager and closes on the way out,
            # which is what the hand-written try/finally here was doing by
            # hand, twice, in two functions written on the same afternoon.
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.0)
                sock.connect((probe, 9))
                addr = sock.getsockname()[0]
            # _flow_is_local rather than a loopback test written here, and not
            # only to keep one copy of that list. It rejects link-local too,
            # and a box that self-assigned 169.254 is a box that never got on
            # the network - the address it would leave from is exactly the
            # evidence this must not offer.
            if addr and not _flow_is_local(addr):
                return addr
        except (OSError, socket.error):
            continue
    return None


def cmd_interfaces():
    if OS_NAME == "Windows":
        return run(["ipconfig", "/all"])
    return run_first_usable([["ip", "addr", "show"], ["ifconfig", "-a"]])


def cmd_routes():
    if OS_NAME == "Windows":
        return run(["route", "print"])
    return run_first_usable([["ip", "route"], ["netstat", "-rn"]],
                            fallback=kernel_routes)


def cmd_arp():
    if OS_NAME == "Windows":
        return run(["arp", "-a"])
    return run_first_usable([["ip", "neigh"], ["arp", "-a"]],
                            fallback=kernel_neighbours)


def cmd_listen_ports():
    if OS_NAME == "Windows":
        return run(["netstat", "-an"])
    return run_first_usable([["ss", "-tuln"], ["netstat", "-an"]])


# A command can be present and still not understand us. Busybox, toybox and the
# trimmed userlands on appliances ship a ping that takes -c and not -W, an ip
# that knows a subset of the real one. which() sees the name and says yes, the
# flags come back rejected, and a check that would have worked without its
# tuning argument is lost instead.
#
# The distinction that keeps this honest: a command that ran and returned a bad
# result is an answer, and must not be retried. Only a command that did not
# understand the request earns a second attempt with less of it.
_DID_NOT_UNDERSTAND = re.compile(
    r"invalid option|unrecognized option|illegal option|unknown option"
    r"|invalid argument|bad option|^usage:|^BusyBox ", re.I | re.M)


def run_first_understood(variants, timeout=15):
    """Run the first variant the system understands.

    `variants` goes from most informative to most portable. A non-zero exit is
    only a reason to try the next one when the output says the command did not
    know what we asked - otherwise the failure is the answer and gets returned.
    """
    result = None
    for cmd in variants:
        result = run(cmd, timeout=timeout)
        if result.get("code") == 0:
            return result
        text = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
        if not _DID_NOT_UNDERSTAND.search(text):
            return result
    return result


def _source_flag(tool, source=None):
    """The flag this tool takes for "leave from this address", as a list.

    `source` overrides the global for one call. Asking every address on a box
    whether it can reach the target means several probes in flight at once, and
    a global that each of them would have to set in turn is the one shape that
    cannot be done in parallel. Nothing mutates: the caller says which address
    it is asking about, and the run-wide setting stays the default.

    Three spellings for one idea, and they are not interchangeable. Linux ping
    takes -I, which also accepts an interface name; BSD and macOS ping take -S
    and mean only an address; both traceroutes take -s. Windows ping has no
    equivalent at all, so a bound run there is carried by the socket probes
    alone, which do support it.

    Empty when no source was asked for, so the command built is byte for byte
    the one that was built before this existed.
    """
    source = source or SOURCE_ADDRESS
    if not source:
        return []
    if tool == "ping":
        if OS_NAME == "Windows":
            return []
        return ["-S" if OS_NAME == "Darwin" else "-I", source]
    return ["-s", source]


def cmd_ping(target, count=4, wait=2, source=None):
    if not valid_target(target):
        return bad_target()
    src = _source_flag("ping", source)
    if OS_NAME == "Windows":
        return run(["ping", "-n", str(count), target])
    # -W is seconds on Linux but milliseconds on BSD/macOS - passing "2" there
    # means 2ms, which marks every reply "out of wait time".
    wait_arg = str(wait * 1000) if OS_NAME == "Darwin" else str(wait)
    # Without -W a ping that gets no reply waits on its own default, so the
    # timeout on run() is what stops it, not the missing flag.
    #
    # The source flag rides on both forms rather than being dropped with -W.
    # Dropping it would silently answer a different question than the one
    # asked, and a wrong answer to "can this address reach the target" is worse
    # than no answer.
    return run_first_understood([
        ["ping", "-c", str(count), "-W", wait_arg] + src + [target],
        ["ping", "-c", str(count)] + src + [target],
    ])


def cmd_traceroute(target):
    if not valid_target(target):
        return bad_target()
    # Every branch asks whether the command exists before running it. Windows
    # did not, and tracert is the one that costs a minute when the path does
    # not answer: on a Server Core box without it, that was an exception where
    # every other system returns "no utility found" and carries on.
    src = _source_flag("traceroute")
    if OS_NAME == "Windows":
        if which("tracert"):
            return run(["tracert", "-h", "20", target], timeout=60)
        return {"ok": False, "error": "no traceroute/tracepath utility found on this system"}
    # traceroute first, tracepath behind it, and behind rather than instead:
    # choosing on which() alone meant a traceroute that exists and fails took
    # the whole path with it while tracepath sat unread. tracepath has no
    # source option, so a bound run falls back to an unbound hop list rather
    # than to no hop list, which is the better of the two.
    res = run_first_usable([["traceroute", "-m", "20", "-w", "2"] + src + [target],
                            ["tracepath", target]], timeout=60)
    if not res.get("ok") and "is installed" in (res.get("error") or ""):
        return {"ok": False, "error": "no traceroute/tracepath utility found on this system"}
    return res


# ---------------------------------------------------------------------------
# A trace that keeps the flow identifier constant.
#
# Classic traceroute varies the destination port on every probe, because that is
# how it tells which reply belongs to which probe. That port is part of the
# five-tuple a per-flow load balancer hashes on, so under ECMP the probes are
# sprayed across branches and the numbered list is a sample of several paths
# written out as one. Paris traceroute exists to fix that.
#
# Paris keeps the five-tuple fixed and encodes the probe number in the UDP
# checksum, by choosing payload bytes that make the checksum come out right.
# That needs the sender to build its own IP header. This does the same thing the
# other way round: keep everything fixed, including the source port, and send
# one probe at a time so ordering is the identifier. Serial where Paris is
# parallel, which costs seconds and no correctness, and needs no crafted header.
#
# The send side needs no privilege at all - a UDP socket with IP_TTL set. Only
# the socket that catches the ICMP replies does. A box that will not give us one
# falls back to the traceroute binary, which is what every box did until now.
# ---------------------------------------------------------------------------

TRACE_MAX_HOPS = 20
# The port classic traceroute starts at. Kept fixed rather than incremented,
# which is the entire point: this is the field the balancer hashes on.
TRACE_FLOW_PORT = 33434
TRACE_PROBE_TIMEOUT = 2.0
ICMP_TIME_EXCEEDED = 11
ICMP_UNREACHABLE = 3
ICMP_PORT_UNREACHABLE = 3


def quoted_packet(inner):
    """What an ICMP error says the packet it is complaining about looked like.

    An ICMP error carries the IP header of the packet that provoked it plus the
    first eight bytes after it, which for UDP is the whole header. That quote is
    the router repeating our packet back to us as it saw it, which is worth more
    than the matching it is here for.
    """
    if len(inner) < 20:
        return None
    ihl = (inner[0] & 0x0F) * 4
    out = {"ip_id": struct.unpack("!H", inner[4:6])[0],
           "src": socket.inet_ntoa(inner[12:16]),
           "dst": socket.inet_ntoa(inner[16:20]),
           "src_port": None, "dst_port": None}
    udp = inner[ihl:ihl + 4]
    if len(udp) == 4:
        out["src_port"], out["dst_port"] = struct.unpack("!HH", udp)
    return out


def read_icmp_reply(packet):
    """(what it means, what it quoted) from one raw IPv4 packet.

    "expired" is a router saying the TTL ran out, which is a hop. "arrived" is
    the target itself saying nothing is listening on that port, which is how a
    UDP trace knows it has got there and is a success rather than a fault.
    """
    if len(packet) < 20:
        return None, None
    icmp = packet[(packet[0] & 0x0F) * 4:]
    if len(icmp) < 8:
        return None, None
    quoted = quoted_packet(icmp[8:])
    if icmp[0] == ICMP_TIME_EXCEEDED:
        return "expired", quoted
    if icmp[0] == ICMP_UNREACHABLE and icmp[1] == ICMP_PORT_UNREACHABLE:
        return "arrived", quoted
    if icmp[0] == ICMP_UNREACHABLE:
        return "blocked", quoted
    return None, quoted


def _ours(quoted, address):
    """Is this ICMP complaining about a packet we sent?

    Matched on where the packet was going, never on where it came from. A
    translating router rewrites the source address and port on the way out, so
    a router past a NAT quotes a packet whose source is not ours and never was.
    Requiring the source to match drops every reply from beyond the first NAT,
    which is the half of the path worth having, and it throws away the
    difference this is about to be asked to notice.

    Destination address and port together are specific enough to be ours: this
    port is not a service anybody runs, and the address is the one we picked.
    """
    if not quoted:
        return False
    return (quoted.get("dst_port") == TRACE_FLOW_PORT
            and quoted.get("dst") == address)


def trace_constant_flow(target, max_hops=TRACE_MAX_HOPS,
                        timeout=TRACE_PROBE_TIMEOUT):
    """Walk the TTL out to `target` without ever changing the flow.

    Returns hops in the same shape the text parsers produce, with the router's
    quote kept alongside. None when the receiving socket cannot be opened,
    which is the ordinary case on a box this is not run as root on.
    """
    if not valid_target(target):
        return None
    try:
        address = socket.gethostbyname(target)
    except (OSError, UnicodeError):
        return None
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (OSError, AttributeError):
        return None                 # no privilege, or a platform without them
    hops, arrived, sent_from = [], False, None
    try:
        listener.settimeout(timeout)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Bound once, before the first probe, so every probe leaves from
            # the same port. An unbound socket gets a fresh ephemeral port per
            # send, which would vary the flow exactly as the tool we are
            # replacing does.
            sender.bind((SOURCE_ADDRESS or "", 0))
            sent_from = sender.getsockname()
            for ttl in range(1, max_hops + 1):
                sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                hop = _one_ttl(listener, sender, address, ttl, timeout)
                hops.append(hop)
                if hop.pop("_done", False):
                    arrived = True
                    break
        finally:
            sender.close()
    except OSError:
        return None
    finally:
        listener.close()
    return {"hops": hops, "target": address, "arrived": arrived,
            "sent_from": sent_from, "dest_port": TRACE_FLOW_PORT}


def _one_ttl(listener, sender, address, ttl, timeout):
    """One probe, and whatever answers it before the clock runs out.

    Replies that are not about our packet are read past rather than counted as
    silence: on a box carrying real traffic the ICMP socket sees every error
    the kernel receives, and the first one to arrive is usually somebody
    else's.
    """
    hop = {"hop": ttl, "host": None, "display": "*", "times_ms": [],
           "timed_out": True, "flags": None, "quoted": None}
    started = time.time()
    sender.sendto(b"", (address, TRACE_FLOW_PORT))
    while True:
        left = timeout - (time.time() - started)
        if left <= 0:
            return hop
        try:
            listener.settimeout(left)
            packet, peer = listener.recvfrom(1500)
        except (socket.timeout, OSError):
            return hop
        kind, quoted = read_icmp_reply(packet)
        if kind is None or not _ours(quoted, address):
            continue
        hop.update({"host": peer[0], "display": peer[0], "timed_out": False,
                    "times_ms": [round((time.time() - started) * 1000, 1)],
                    "quoted": quoted})
        if kind == "blocked":
            hop["flags"] = ["!X"]
        hop["_done"] = kind in ("arrived", "blocked")
        return hop


def cmd_dns(target):
    if not valid_target(target):
        return bad_target()
    # Three utilities that answer the same question, tried in order of how much
    # they say. On a box with a dig that exists and rejects a flag, choosing on
    # which() alone lost resolution entirely and the run reported DNS as
    # unreadable - on a machine with two other working lookup tools installed.
    res = run_first_usable([
        ["dig", "+noall", "+answer"]
        + (["-b", SOURCE_ADDRESS] if SOURCE_ADDRESS else []) + [target],
        ["nslookup", target],
        ["host", target],
    ])
    if not res.get("ok") and "is installed" in (res.get("error") or ""):
        return {"ok": False,
                "error": "no DNS lookup utility (dig/nslookup/host) found on this system"}
    return res


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
        # A module prints its own limits beside its readings, and every limit
        # repeats the name of the reading it belongs to: "Laser output power
        # high alarm threshold" carries a dBm figure in exactly the shape
        # "Laser output power" does. Read as readings they win by coming last
        # in the dump, so a healthy module reported its lowest warning
        # threshold as its transmit power.
        if key.endswith("threshold"):
            continue
        # The flags repeat those names too, and are matched before the readings
        # for the same reason. "Module temperature high alarm" begins with the
        # name of the temperature reading, so the branch below used to take the
        # line, store "Off" as the temperature, and drop the alarm - on the one
        # check whose whole point is that the module's own thresholds beat any
        # generic number we pick.
        if value.lower() in ("on", "off") and ("alarm" in key or "warning" in key):
            if value.lower() == "on":
                (out["alarms"] if "alarm" in key else out["warnings"]).append(m.group(1).strip())
            continue
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
        attempts.append(["tcptraceroute", "-m", "20", "-w", "2"] + _source_flag("traceroute")
                        + [target, str(port)])
    if which("traceroute") and OS_NAME != "Windows":
        attempts.append(["traceroute", "-T", "-p", str(port), "-m", "20", "-w", "2"]
                        + _source_flag("traceroute") + [target])
    if which("mtr"):
        attempts.append(["mtr", "--tcp", "-P", str(port), "--json", "-c", "5", "-b"]
                        + (["-a", SOURCE_ADDRESS] if SOURCE_ADDRESS else []) + [target])
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
            # Resolution is a path like any other, and a resolver reached from
            # one address is not proof about another: an upstream filter or a
            # split-horizon view keyed on source is exactly the fault a bound
            # run exists to find.
            source = _source_for(family)
            if source:
                sock.bind(source)
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
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
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


# Listeners of our own to test, at most, counted per address-and-port rather
# than per port. Each costs a handshake or a request against a service that is
# probably logging connections, so this stays small on purpose.
#
# Three was right while this counted ports, because a box with more than a
# couple of TLS ports is unusual. Counting instances it was far too low: a front
# end terminating several services on 443 has one entry per address, and the
# old limit checked the first and said nothing about the rest. Twelve covers
# that shape and still bounds the cost; whatever is past it is reported as not
# checked rather than dropped.
OWN_TLS_MAX_LISTENERS = 12


def _cert_names_from_fields(der):
    """The names a certificate actually carries, or None if they cannot be read.

    Read out of SubjectAltName and the common name, which are the fields that
    hold names, rather than guessed from the bytes around them. Unverified on
    purpose: this runs before anything has been trusted, which is the whole
    reason the scan below existed.

    Costs, both real and both why the scan is kept behind this. The decoder
    takes a path rather than bytes, so a certificate is written to a temporary
    file and removed again - a tool that leaves nothing behind should own that
    plainly. And it is a private entry point in the ssl module: long-lived, not
    contracted, and absent on a build that ships without it. Every one of those
    routes returns None and falls through.
    """
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None or not der:
        return None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
    except (ValueError, TypeError):
        return None
    path = None
    try:
        handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False,
                                             encoding="utf-8")
        path = handle.name
        with handle:
            handle.write(pem)
        info = decode(path)
    except (OSError, ValueError, TypeError, ssl.SSLError):
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

    names = []
    for kind, value in info.get("subjectAltName") or ():
        if kind == "DNS" and value and value not in names:
            names.append(value)
    for rdn in info.get("subject") or ():
        for key, value in rdn:
            if key == "commonName" and value and value not in names:
                names.append(value)
    if not names:
        return None
    # A wildcard cannot be handed back as the name to verify against, and the
    # bare domain beneath one is not necessarily covered by it - so a concrete
    # entry is preferred where the certificate offers one, and the wildcard is
    # only reduced when it is all there is. That is what the scan did too.
    concrete = [n for n in names if not n.startswith("*.")]
    return concrete or [n.lstrip("*.") for n in names]


def _cert_names(der):
    """Hostnames a certificate is for, best first.

    Its own fields when they can be read, and the printable runs when they
    cannot. The scan is a good fallback and a poor primary: key material reads
    as text often enough that a random `v.RD` once became the name a box was
    verified against, and a seven-character `g-ev.ox` is indistinguishable in
    shape from a real `x9-k.io`, so no filter separates them. Tightening the
    pattern has already been tried once and only lowered the rate.
    """
    parsed = _cert_names_from_fields(der)
    if parsed:
        return parsed
    return _cert_names_scanned(der)


def _cert_names_scanned(der):
    """Hostnames a certificate appears to be for, guessed from its bytes.

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


class SourceAddressUnavailable(OSError):
    """The address this run was told to leave from is not on this box.

    Its own type because it is a diagnosis, not a failure to probe. Everything
    else that raises here means the far end did something; this means the near
    end never had the address, and the two must not be reported alike.
    """


def _source_for(family):
    """SOURCE_ADDRESS as a bind tuple, when it belongs to this socket's family.

    None rather than an error on a mismatch. A run bound to an IPv4 address
    still has to be able to reach an IPv6-only target, and refusing would turn
    "measure from this address" into "only measure things this address can
    reach", which is a different and much less useful instruction. The check
    that the box holds the address is separate and has already run by then.
    """
    if not SOURCE_ADDRESS:
        return None
    if (family == socket.AF_INET6) != (":" in SOURCE_ADDRESS):
        return None
    return (SOURCE_ADDRESS, 0)


def connect_from(address, port, timeout):
    """A TCP connection, leaving from SOURCE_ADDRESS when one was asked for.

    The bind is the cheapest real check in the tool. An address this box does
    not hold fails here with EADDRNOTAVAIL, in the kernel, before a packet is
    sent: no timeout, no waiting on a far end, and no ambiguity about whose
    fault it is.

    That case is worth the separate exception because of what it means on a
    redundant pair. A backup node does not hold the service address, so a run
    on it that lets the kernel choose measures the node's own address, finds
    the path healthy and says so, while the node serves nothing. "You are not
    holding this address" is the finding, and it is the one a clean report on
    the wrong box hides.
    """
    src = (SOURCE_ADDRESS, 0) if SOURCE_ADDRESS else None
    try:
        return socket.create_connection((address, port), timeout=timeout,
                                        source_address=src)
    except OSError as exc:
        if src and getattr(exc, "errno", None) in _NO_SUCH_ADDRESS:
            raise SourceAddressUnavailable(
                "%s is not an address on this box" % SOURCE_ADDRESS)
        raise


# EADDRNOTAVAIL is what every platform returns for "bind to an address that is
# not here". EINVAL joins it because Windows reports a bind to an address of
# the wrong family that way, which is the same mistake and reads identically to
# whoever typed it.
_NO_SUCH_ADDRESS = {errno.EADDRNOTAVAIL, errno.EINVAL}


def why_it_would_not_connect(exc):
    """Refused, timed out, or the address is not here.

    Three different faults that a single "could not connect" hides, and the
    distinction HAProxy grades every health check by: refused means nothing is
    listening, and timed out means something is and it is not completing. They
    send a reader to opposite places.

    Only the classification lives here. What each one means is decided where
    the listener is known, because a refusal on an address this box does not
    hold is a different sentence from one on an address it does.
    """
    if isinstance(exc, socket.timeout):
        return "timeout"
    code = getattr(exc, "errno", None)
    if code == errno.ECONNREFUSED:
        return "refused"
    if code in _NO_SUCH_ADDRESS:
        return "no such address"
    return None


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
        raw = connect_from(address, port, timeout)
        connected = time.monotonic()
    except (OSError, ValueError) as e:
        result["unreachable_locally"] = str(e)
        result["refusal"] = why_it_would_not_connect(e)
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
        raw = connect_from(address, port, timeout)
    except (OSError, ValueError) as e:
        result["unreachable_locally"] = str(e)
        result["refusal"] = why_it_would_not_connect(e)
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
        with connect_from(address, port, timeout) as raw:
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
        with connect_from(host, port, timeout) as raw:
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
            with connect_from(host, port, timeout) as raw:
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


def ports_in_order(ports):
    """Ports sorted as numbers, which they are not stored as.

    A port is carried as text everywhere here - peer_port returns the digits it
    matched, and the sets it is compared against are sets of strings - so the
    default sort puts 4500 before 500 before 53. That is wrong wherever a list
    is shown, and worse wherever one is cut short: a run of listeners trimmed
    to the first few kept 4500 and 1194 and dropped 53, which is the one that
    would have told a reader what the box was.
    """
    return sorted(ports, key=lambda p: (int(p) if str(p).isdigit() else 0, str(p)))


def parse_socket_states(text, own_access=(None, None)):
    """Count sockets by state, and note who the pending ones are talking to.

    Handles `ss -tan` (state first) and `netstat -an` (state last), which is
    why the peer is picked out by position rather than by column name.

    `own_access` is the way the operator got in, as (peer, local port), and
    sessions matching it are not counted as traffic this box is serving. They
    are real connections and they are not the box doing its job: a run over
    three admin windows used to read as three clients connected, which was
    enough to satisfy every "is anyone using this" threshold in the tool and
    invent a fault out of the diagnostic's own presence.

    Passed in rather than read from the environment here, so this stays a
    parser that can be handed a fixture and asked what it makes of it.
    """
    states = {}
    pending = {}
    # Which ports this box accepts on, and how many of its live connections
    # arrived rather than left. That split is what separates a server from a
    # client, and a server with clients connected to it right now has a working
    # network however little it can reach on its own.
    listening, established, bound, peers, outbound_dests = set(), [], [], [], []
    # Closed connections still holding their four-tuple. Kept apart from the
    # established ones because they are not connections this box has - they
    # must not reach the inbound and outbound totals, or the per-address
    # serving counts - and they do still occupy the port.
    waiting_dests = []
    # Which of this box's own addresses each live connection arrived on. The
    # port was already kept and the address thrown away, which answered "is
    # anyone connected" and could never answer "connected to what". On a box
    # holding a service address those are different questions: the address can
    # be up, listening and taking nothing, while the partner takes it all.
    local_ends = []
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
            if (peer_host(peer), peer_port(local)) == own_access:
                continue                # our own way in, not this box working
            established.append(peer_port(local))
            local_ends.append((peer_host(local), peer_port(local)))
            peers.append((peer_host(peer), peer_port(local)))
            # The local port travels with the destination because it is the
            # only thing that says which way the connection was opened, and it
            # cannot be judged here: `listening` is still being filled, and a
            # LISTEN line is free to arrive after the sockets it explains.
            outbound_dests.append((peer_host(peer), peer_port(peer), peer_port(local)))
        elif key == "TIME_WAIT" and local:
            # A connection that has closed still owns its four-tuple until
            # the timer expires, so the port it used cannot serve another
            # connection to the same destination yet. On a box that opens
            # short connections to a small set of places these outnumber the
            # established ones several times over, and leaving them out
            # understated the pressure by exactly that factor.
            if (peer_host(peer), peer_port(local)) != own_access:
                waiting_dests.append((peer_host(peer), peer_port(peer), peer_port(local)))
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
    # Which end decides that is the local port, not the remote one. Tested
    # against the remote port, every client of a busy server counted as a
    # place this box had been: a plain web server with sixty clients and no
    # outbound connections at all reported sixty destinations, said so in the
    # same breath as reporting zero outbound connections, and past fifty of
    # them was described to its owner as a box forwarding other people's
    # traffic and pointed at 8.8.8.8 instead of anything it depends on. A
    # client's ephemeral port is never one this box listens on, so the test
    # passed for every one of them. pick_backend draws the same line correctly
    # one screen down.
    dest_counts, waiting_counts = {}, {}
    for host, port, local_port in outbound_dests + waiting_dests:
        if host and port and local_port not in listening:
            dest_counts[(host, port)] = dest_counts.get((host, port), 0) + 1
    for host, port, local_port in waiting_dests:
        if host and port and local_port not in listening:
            waiting_counts[(host, port)] = waiting_counts.get((host, port), 0) + 1
    worst = max(dest_counts.items(), key=lambda kv: (kv[1], kv[0]), default=None)
    inbound = sum(1 for p in established if p and p in listening)
    # Counted per address, never listed per connection. Who is connected is the
    # peer list, which deliberately does not reach a report; which of this box's
    # own addresses they arrived on is a property of this box, and its addresses
    # are already in the report.
    served_on = {}
    # And the same counted per endpoint rather than per address, which is what
    # separates two instances sharing an address on different ports. Keys are
    # strings so this survives a round trip through the JSON export.
    served_endpoints = {}
    for host, port in local_ends:
        if host and port and port in listening:
            served_on[host] = served_on.get(host, 0) + 1
            key = "%s:%s" % (host, port)
            served_endpoints[key] = served_endpoints.get(key, 0) + 1
    return {"states": states, "pending": pending, "served_on": served_on,
            "served_endpoints": served_endpoints,
            "listen_ports": ports_in_order(listening), "bound": bound, "peers": peers,
            "outbound_destinations": len(dest_counts),
            "outbound_worst_dest": f"{worst[0][0]}:{worst[0][1]}" if worst else None,
            "outbound_worst_count": worst[1] if worst else 0,
            # How much of that is connections already closed. It changes the
            # advice rather than the number: these drain on their own, and
            # the fix is the churn making them, not a wider port range.
            "outbound_worst_waiting": waiting_counts.get(worst[0], 0) if worst else 0,
            "inbound": inbound, "outbound": len(established) - inbound}


_SKMEM_RB = re.compile(r"skmem:\([^)]*?\brb(\d+)")


def parse_udp_sockets(text):
    """`ss -uan` into the two things a datagram socket can honestly tell us.

    A datagram listener is not a connection table. One socket bound to a port
    can serve any number of peers without the kernel recording one of them, so
    counting sockets is not counting clients and must never be presented as
    though it were. What the table does say is that something is bound and
    willing to receive, and how much has piled up behind it unread.

    Recv-Q on a UDP socket is bytes the kernel is holding that the process has
    not taken. On a box whose user traffic is datagrams that is the closest
    thing there is to "this box cannot keep up with what is arriving" - the
    counterpart to an accept queue, for a plane that has no accept.
    """
    listeners, connected, queued = [], 0, 0
    for line in (text or "").splitlines():
        # skmem:(r0,rb212992,...) - rb is the socket's own receive buffer, and
        # the only thing here that can say whether a queue is large. Present
        # with `ss -m` and absent from netstat, so it is read where it is and
        # its absence is handled rather than assumed.
        buffered = _SKMEM_RB.search(line)
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() not in ("UNCONN", "ESTAB", "UDP"):
            continue
        try:
            recv_q, send_q = int(parts[1]), int(parts[2])
        except ValueError:
            continue
        local, peer = parts[3], parts[4]
        port = peer_port(local)
        if not port:
            continue
        if peer not in ("*:*", "0.0.0.0:*", "[::]:*", ":::*"):
            connected += 1
            continue
        if _is_loopback_socket(local):
            continue                    # bound for this box's own use, not serving
        listeners.append({"address": peer_host(local) or "", "port": port,
                          "recv_q": recv_q, "send_q": send_q,
                          "recv_buffer": int(buffered.group(1)) if buffered else None})
        queued += recv_q
    return {"listeners": listeners, "connected": connected, "queued_bytes": queued,
            "listen_ports": ports_in_order({l["port"] for l in listeners})}


def cmd_udp_sockets():
    """This box's datagram listeners, and what is waiting behind them.

    Read because a box can carry its user traffic over datagrams while its
    control plane is TCP, and every other socket reading here is TCP. Without
    this the whole data plane is absent from the report, and "nothing is
    connected" gets said about a box that is busy.
    """
    if OS_NAME == "Windows":
        res = run(["netstat", "-an", "-p", "UDP"], timeout=15)
    else:
        # -m for skmem, which carries the receive buffer size. Behind the
        # plain read rather than instead of it: a trimmed ss that rejects the
        # flag should cost the buffer, not the listener table.
        res = run_first_usable([["ss", "-uanm"], ["ss", "-uan"],
                                ["netstat", "-an", "-u"]], timeout=15)
    if not res.get("ok"):
        return res
    res.update(parse_udp_sockets(res.get("stdout", "")))
    return res


# What share of a datagram socket's own receive buffer can stand unread before
# it is worth saying so. A share rather than a byte count, because bytes cannot
# answer the question: 4 KB is a serious backlog on a small socket and one
# datagram on a large one, and a fixed floor firing on a flat 4 KB queue was
# what showed this up.
UDP_QUEUE_SHARE_PCT = 25
# And a floor underneath it, so a socket with a tiny buffer cannot reach that
# share on one datagram. Below this the queue is one or two datagrams in
# flight, which is what a working socket looks like at any instant.
UDP_QUEUE_FLOOR_BYTES = 8192


def udp_window(before, after, seconds):
    """Two readings of the listener queues, and which of them did not drain.

    Recv-Q is a level, not a counter, so the delta that works for every other
    sampled reading here is the wrong instrument: a queue that went from 8000
    to 0 and back to 8000 has a delta of nothing and never emptied. What two
    readings can say is narrower and is the whole finding - the queue was above
    the floor at both ends of the window and had not gone down.

    That is deliberately not proof of a persistent queue. Two samples cannot
    tell one standing backlog from two bursts, and the message says so rather
    than the code pretending otherwise. It is the strongest claim two readings
    support, and the reason there are two readings instead of one.

    The later read wins for everything else, so the listeners a report shows
    are the ones that were there at the end.
    """
    out = dict(after)
    if not (before.get("ok") and after.get("ok") and seconds):
        return out
    was = {(l["address"], l["port"]): l["recv_q"] for l in before.get("listeners") or []}
    standing = []
    for listener in after.get("listeners") or []:
        first = was.get((listener["address"], listener["port"]))
        if first is None:
            continue                # bound after the window opened; nothing to compare
        buffer = listener.get("recv_buffer")
        if not buffer:
            # Without the socket's own buffer there is nothing to be a share
            # of, and a byte count cannot tell a backlog from a datagram. Say
            # nothing rather than guess, the same way an unreadable kernel log
            # is never "nothing happened".
            continue
        share = round(100.0 * listener["recv_q"] / buffer, 1)
        # Written as the condition for saying something rather than as reasons
        # to stay quiet, so the bar reads the way it is documented: a real
        # share of its own buffer, over the floor, at both ends of the window,
        # and no lower at the end than at the start. A queue that went down is
        # a queue doing its job at whatever depth.
        if (share >= UDP_QUEUE_SHARE_PCT
                and first >= UDP_QUEUE_FLOOR_BYTES
                and listener["recv_q"] >= UDP_QUEUE_FLOOR_BYTES
                and listener["recv_q"] >= first):
            standing.append(dict(listener, first_recv_q=first, share_pct=share,
                                 window_seconds=seconds))
    out["standing_queues"] = sorted(standing, key=lambda l: -l["recv_q"])
    out["window_seconds"] = seconds
    return out


# ---------------------------------------------------------------------------
# What the proxy itself believes, where it will say.
#
# PROTOTYPE. This is the first thing here that knows the name of a product, and
# that is a decision about what this tool is, not just about what it reads. It
# is written so it can be deleted in one block if the answer is no.
#
# The case for it: a proxy knows things the kernel cannot. Which backends it
# has marked down, the check that failed, how long ago, and how many times it
# has flapped. None of that is derivable from sockets and counters, and on a
# box whose whole job is proxying it is the richest source on the machine.
#
# The case against: it is conditional on somebody having enabled the socket, so
# it can never be relied on; and naming a product in the source is exactly what
# the withheld-names guard exists to discourage, even though this particular
# name is not on that list.
#
# What keeps it honest meanwhile: a read-only command on a socket the operator
# chose to expose, never required, and a box without one produces the report it
# produced before.
# ---------------------------------------------------------------------------

HAPROXY_SOCKETS = ("/var/run/haproxy.sock", "/run/haproxy/admin.sock",
                   "/var/run/haproxy/admin.sock", "/var/lib/haproxy/stats",
                   "/var/run/haproxy/haproxy.sock")
# The states the proxy uses for a server it will not send traffic to. MAINT and
# DRAIN are somebody's decision rather than a fault, and are kept apart for it.
PROXY_IS_DOWN = ("DOWN",)
PROXY_ON_PURPOSE = ("MAINT", "DRAIN")


def read_stats_socket(path, command="show stat\n", timeout=2.0):
    """One read-only command to a local stats socket. None if there isn't one."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except (AttributeError, OSError):
        return None                 # a platform without unix sockets
    try:
        sock.settimeout(timeout)
        sock.connect(path)
        sock.sendall(command.encode())
        # Bounded by how many reads rather than by comparing a byte count, so
        # the cap stays a cap. Every number in the thresholds table is a
        # judgement somebody has to defend, and "stop reading eventually" is
        # not one of them.
        chunks = []
        for _ in range(PROXY_READ_CHUNKS):
            block = sock.recv(65536)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        sock.close()


# 64 reads of 64 KB. A stats socket answers in a few kilobytes on any
# ordinary box; this only exists so a wedged socket cannot hang the run.
PROXY_READ_CHUNKS = 64


def parse_proxy_stats(text):
    """`show stat` CSV into one row per server the proxy is balancing over.

    The header names the columns and the set of them varies by version, so
    everything is read by name. FRONTEND and BACKEND rows are the proxy's own
    totals rather than servers, and are dropped: a backend being down is a
    consequence of its servers being down, and reporting both is one fault
    twice.
    """
    lines = [l for l in (text or "").splitlines() if l.strip()]
    if not lines or not lines[0].startswith("#"):
        return []
    header = [h.strip() for h in lines[0].lstrip("#").strip().split(",")]
    out = []
    for line in lines[1:]:
        row = dict(zip(header, [c.strip() for c in line.split(",")]))
        if row.get("svname") in ("FRONTEND", "BACKEND") or not row.get("svname"):
            continue

        def number(name):
            value = row.get(name) or ""
            return int(value) if value.isdigit() else None

        # A row with no status is not a server anything can be said about, and
        # there are three ways to get one: a version whose CSV does not carry
        # the column, a field that is genuinely empty, and - the likely one -
        # the last row of a read that hit its chunk cap partway through a line.
        # Dropped rather than graded, and dropped rather than allowed to end the
        # run, which is what reading [0] off an empty split used to do: the
        # IndexError escaped parse, escaped diagnose, and cost the whole report
        # on the one kind of box that has a stats socket to read.
        status = (row.get("status") or "").split()
        if not status:
            continue

        out.append({"proxy": row.get("pxname"), "server": row.get("svname"),
                    "status": status[0].upper(),
                    "check_status": row.get("check_status") or None,
                    "since_s": number("lastchg"), "downtime_s": number("downtime"),
                    "times_down": number("chkdown"), "queued": number("qcur")})
    return out


def cmd_haproxy_stats():
    """The proxy's own view of its backends, if it is willing to give one."""
    if OS_NAME == "Windows":
        return {"ok": False, "cmd": "show stat", "applicable": False,
                "error": "stats sockets are not read on this platform"}
    for path in HAPROXY_SOCKETS:
        if not os.path.exists(path):
            continue
        text = read_stats_socket(path)
        if not text:
            continue
        servers = parse_proxy_stats(text)
        if not servers:
            continue
        return {"ok": True, "cmd": "show stat (%s)" % path, "socket": path,
                "servers": servers,
                "stdout": "\n".join(
                    "%s/%s  %s  %s" % (s["proxy"], s["server"], s["status"],
                                       s["check_status"] or "")
                    for s in servers)}
    # Not a failure. Almost no box has one, and a box without one is not a box
    # that could not be read - there is nothing there to read.
    return {"ok": False, "cmd": "show stat", "applicable": False,
            "error": "no proxy stats socket found here"}


def cmd_socket_states():
    """This device's own TCP sockets, by state."""
    if OS_NAME == "Windows":
        res = run(["netstat", "-an", "-p", "TCP"], timeout=15)
    else:
        # netstat behind ss rather than instead of it. This is the socket table
        # every client and serving finding is built from, so an ss that exists
        # and fails used to take all of them with it.
        res = run_first_usable([["ss", "-tan"], ["netstat", "-an"]], timeout=15)
    if not res.get("ok"):
        return res
    parsed = parse_socket_states(res.get("stdout", ""), _own_access_service())
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
# Which process holds a socket.
#
# Six findings name the thing at fault as "a service on this device" or "an
# application on this device" and then cannot say which one. On a box running a
# single service that is a shrug you can live with. On one running several
# instances it is the whole question, and the answer is sitting in a socket
# table this tool already reads twice.
#
# Opportunistic in the same way ethtool and the kernel log are: several commands
# that answer the same question, tried in order of how much they say, and a run
# where none of them work leaves every message exactly as it reads today. A
# socket with no name attached is "couldn't look", never "no process".
#
# Without the privilege to see other users' sockets this names only our own,
# which is a partial answer rather than a wrong one, so it is worth asking
# either way.
# ---------------------------------------------------------------------------

OWNER_READ_BYTES = 4_000_000

# ss prints every process holding the socket, which is what a pre-forking
# server looks like: ("nginx",pid=1234,fd=8),("nginx",pid=1235,fd=8).
_SS_PROC = re.compile(r'\("([^"]+)",pid=(\d+)')
# netstat's last column is PID/name, and the name can carry a space of its own
# ("1235/nginx: worker"), so the pair is matched rather than split off the end.
# No address in these rows contains a slash, so this cannot match one.
_NETSTAT_PROC = re.compile(r"\s(\d+)/(\S+)")
_LSOF_STATE = re.compile(r"\(([A-Z_]+)\)\s*$")
_PORT_TAIL = re.compile(r":(\d+)$")


def _port_of(address):
    m = _PORT_TAIL.search((address or "").strip())
    return int(m.group(1)) if m else None


def _norm_state(state):
    """ss says CLOSE-WAIT, netstat says CLOSE_WAIT, and the findings are keyed
    on one of them."""
    return (state or "").strip().upper().replace("-", "_")


def parse_ss_owners(text):
    """`ss -tanp` rows: state, queues, local, peer, then the process column."""
    out = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 5 or not _SS_PROC.search(line):
            continue
        state = _norm_state(fields[0])
        if not state or state == "STATE":
            continue
        seen = set()
        for name, pid in _SS_PROC.findall(line):
            # One row per process, not one per descriptor: a worker pool holding
            # one listening socket is one holder, and counting the descriptors
            # would report a server as leaking in proportion to its worker count.
            if (name, pid) in seen:
                continue
            seen.add((name, pid))
            out.append({"process": name, "pid": int(pid), "state": state,
                        "local_port": _port_of(fields[3]), "peer": fields[4]})
    return out


def parse_netstat_owners(text):
    """Linux `netstat -tanp`. A row whose process reads "-" was not readable by
    this user, and is skipped rather than counted as unowned."""
    out = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 6 or not fields[0].startswith("tcp"):
            continue
        m = _NETSTAT_PROC.search(line)
        if not m:
            continue
        out.append({"process": m.group(2).rstrip(":"), "pid": int(m.group(1)),
                    "state": _norm_state(fields[5]),
                    "local_port": _port_of(fields[3]), "peer": fields[4]})
    return out


def parse_lsof_owners(text):
    """`lsof -nP -iTCP`. One row per descriptor, with the endpoints as
    local->peer and the state in brackets at the end."""
    out = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 9 or fields[0] == "COMMAND" or "TCP" not in fields:
            continue
        where_at = fields.index("TCP") + 1
        if where_at >= len(fields):
            continue
        try:
            pid = int(fields[1])
        except ValueError:
            continue
        local, _, peer = fields[where_at].partition("->")
        state = _LSOF_STATE.search(line)
        out.append({"process": fields[0], "pid": pid,
                    "state": _norm_state(state.group(1)) if state else None,
                    "local_port": _port_of(local), "peer": peer or None})
    return out


def cmd_socket_owners():
    """The process behind each TCP socket, from whichever command can say.

    Richest first. ss names every process holding a socket, netstat names one,
    lsof is a row per descriptor and has to be folded back together. A command
    that exists and rejects the flags is passed over rather than believed, which
    is the same rule the rest of the collectors follow: a busybox netstat knows
    the name and not the option.
    """
    if OS_NAME == "Windows":
        # netstat -ano gives a PID and no name, and turning one into the other
        # is a second command and a second parser for a worse answer.
        return {"ok": False, "cmd": "ss -tanp", "applicable": False,
                "error": "naming the process behind a socket is not supported here"}
    attempts = []
    if OS_NAME == "Linux":
        attempts.append((["ss", "-tanp"], parse_ss_owners))
        # macOS netstat reads -p as "protocol" and takes an argument, so this
        # one is Linux-only by name rather than by accident.
        attempts.append((["netstat", "-tanp"], parse_netstat_owners))
    attempts.append((["lsof", "-nP", "-iTCP"], parse_lsof_owners))
    for cmd, parser in attempts:
        if not which(cmd[0]):
            continue
        res = run(cmd, timeout=15, limit=OWNER_READ_BYTES)
        # An exit code here means the flags were refused, not that the box has
        # no sockets, so the next command still gets its turn.
        if not res.get("ok") or res.get("code"):
            continue
        owners = parser(res.get("stdout") or "")
        if not owners:
            continue
        res["owners"] = owners
        res["stdout"] = _cap(res.get("stdout"))
        return res
    return {"ok": False, "cmd": "ss -tanp",
            "error": "no command here could name the process behind a socket "
                     "(tried ss, netstat, lsof)"}


# ---------------------------------------------------------------------------
# Which firewall rule dropped it.
#
# `egress_blocked` says nothing reaches the target and offers "probably by
# design", which is a guess about somebody else's intent made from the outside.
# The kernel counts every rule, so the box can be asked instead.
#
# Not by reading the ruleset and working out what it would do to a packet. That
# is a simulation of a vendor-generated ruleset and it would be wrong quietly.
# The counters are read once before the probes and once after, and a drop rule
# whose packet count moved across that window dropped something during it. The
# probes are what this box sent during it. That is not a proof, and on a busy
# relay several rules will have moved, so what comes out is a shortlist in the
# order they counted rather than a verdict.
#
# Both readers need privilege. A run without it gets nothing here and the
# finding reads as it did before.
# ---------------------------------------------------------------------------

FIREWALL_READ_BYTES = 4_000_000
# The verdicts that stop a packet. Both spellings, because nft is lowercase and
# iptables is not, and a rule that jumps to a user chain is not a verdict at all.
STOPS_A_PACKET = ("DROP", "REJECT", "drop", "reject")

_IPT_RULE = re.compile(r"^\[(\d+):(\d+)\]\s+(-A\s+(\S+)\s+.*)$")
_IPT_JUMP = re.compile(r"-j\s+(\S+)")
_NFT_TABLE = re.compile(r"^table\s+(\S+)\s+(\S+)\s*\{")
_NFT_CHAIN = re.compile(r"^\s*chain\s+(\S+)\s*\{")
_NFT_POLICY = re.compile(r"policy\s+(\w+)")
_NFT_COUNTER = re.compile(r"counter packets (\d+) bytes (\d+)")
# nft renders a rule's comment inline, in double quotes. Cut out before the
# verdict is read, so what somebody wrote about a rule cannot become the rule.
_NFT_COMMENT = re.compile(r'\bcomment\s+"[^"]*"')
_NFT_HOOK = re.compile(r"type filter hook (\w+)")
# Which way traffic was going when a chain saw it. Both spellings, because nft
# hooks are lowercase and iptables built-ins are not, and only the built-ins
# are on here: a chain named by hand is reachable from either direction.
_FACES = {"input": "in", "INPUT": "in", "output": "out", "OUTPUT": "out",
          "forward": "through", "FORWARD": "through"}
# A rule that names a port. Both spellings again, and both the single and the
# multiport forms.
_RULE_DPORT = re.compile(r"\bdports?\s+([\d,\s:-]+)")


def parse_iptables_save(text):
    """`iptables-save -c`: a counter in brackets before every rule.

    Preferred over `iptables -L -v -n` because the format is meant to be read
    by a program rather than by a person, so it does not reflow, and because
    the chain policy comes with it.
    """
    rules, policies, table = [], {}, None
    for line in (text or "").splitlines():
        if line.startswith("*"):
            table = line[1:].strip()
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2:
                policies["%s/%s" % (table, parts[0])] = parts[1]
            continue
        m = _IPT_RULE.match(line)
        if not m:
            continue
        jump = _IPT_JUMP.search(m.group(3))
        rules.append({"table": table, "chain": m.group(4),
                      "packets": int(m.group(1)), "bytes": int(m.group(2)),
                      "verdict": jump.group(1) if jump else None,
                      "rule": m.group(3).strip(),
                      # Only the built-in chains say which way traffic was
                      # going. A rule in a chain somebody named themselves can
                      # be reached from either, so it gets no direction rather
                      # than a guessed one.
                      "faces": _FACES.get(m.group(4).lower())})
    return {"rules": rules, "policies": policies}


def parse_nft_ruleset(text):
    """`nft -a list ruleset`.

    nft only counts a rule that was written with a `counter` statement, so a
    ruleset can be complete and tell us nothing. That is a real limit of the
    reader rather than an answer about the box, and it is why iptables-save is
    tried as well rather than instead.
    """
    rules, policies, hooks = [], {}, {}
    table, chain = None, None
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        t = _NFT_TABLE.match(line)
        if t:
            table, chain = "%s %s" % (t.group(1), t.group(2)), None
            continue
        c = _NFT_CHAIN.match(raw_line)
        if c:
            chain = c.group(1)
            continue
        if "type filter hook" in line:
            p = _NFT_POLICY.search(line)
            if p and table and chain:
                policies["%s/%s" % (table, chain)] = p.group(1)
            # An nft chain is named by whoever wrote it, so the name says
            # nothing about direction. The hook does, and it is only on this
            # line, so it is captured here and carried to the rules below.
            hooked = _NFT_HOOK.search(line)
            if hooked and chain:
                hooks[chain] = hooked.group(1)
            continue
        counter = _NFT_COUNTER.search(line)
        if not counter or not chain:
            continue
        # Read off the rule, and a comment is not the rule. nft prints comments
        # inline, so a rule that accepts under `comment "do not reject this"`
        # was recorded as a rule that rejects - and rules_that_counted then
        # offers it, worst first, as the rule that stopped somebody's traffic.
        # An accept rule on a busy box has the fastest-moving counter there is,
        # so it goes to the top of that list.
        deciding = _NFT_COMMENT.sub("", line)
        verdict = next((v for v in ("drop", "reject") if re.search(r"\b%s\b" % v, deciding)),
                       None)
        rules.append({"table": table, "chain": chain,
                      "packets": int(counter.group(1)), "bytes": int(counter.group(2)),
                      "verdict": verdict, "rule": line,
                      "faces": _FACES.get(hooks.get(chain))})
    return {"rules": rules, "policies": policies}


def cmd_firewall_counters():
    """Every rule's packet count, from whichever tool this box uses.

    nft first: on a modern box it sees the inet tables the iptables compat
    layer does not. iptables-save behind it rather than instead, because a
    ruleset with no counter statements parses perfectly and says nothing, and
    the older tool counts every rule whether it was asked to or not.
    """
    if OS_NAME != "Linux":
        return {"ok": False, "cmd": "nft list ruleset", "applicable": False,
                "error": "firewall rule counters are Linux-only"}
    attempts = [(["nft", "-a", "list", "ruleset"], parse_nft_ruleset),
                (["iptables-save", "-c"], parse_iptables_save)]
    # A box with neither tool has no rules to read, which is not the same as a
    # box that has them and would not answer. Counting it as a check that
    # failed marks down the confidence of every verdict on a machine for not
    # having a firewall, which is the mistake collection_coverage exists to
    # avoid making about fibre optics.
    if not any(which(cmd[0]) for cmd, _p in attempts):
        return {"ok": False, "cmd": "nft list ruleset", "applicable": False,
                "error": "no firewall tool here to read counters from"}
    fallback = None
    for cmd, parser in attempts:
        if not which(cmd[0]) or parser is None:
            continue
        res = run(cmd, timeout=15, limit=FIREWALL_READ_BYTES)
        if not res.get("ok") or res.get("code"):
            continue
        parsed = parser(res.get("stdout") or "")
        res.update(parsed)
        res["stdout"] = _cap(res.get("stdout"))
        # A reader that found rules and no counters on any of them has read the
        # box correctly and learned nothing, so the next one still gets a turn.
        # Its policies are worth keeping in the meantime.
        if any(r["packets"] for r in parsed["rules"]) or not parsed["rules"]:
            return res
        fallback = fallback or res
    return fallback or {"ok": False, "cmd": "nft list ruleset",
                        "error": "no firewall rule counters here (tried nft, "
                                 "iptables-save); this usually needs root"}


def firewall_window(before, after):
    """The two reads as one result, with the difference already taken.

    One capability read twice is one collection, not two. Carrying them as two
    raw keys counted a box that cannot read rules as two checks that could not
    run, and marked the confidence of every verdict down twice for one gap.
    """
    ok = bool(before.get("ok") and after.get("ok"))
    out = {"ok": ok, "cmd": after.get("cmd") or before.get("cmd"),
           "before": before, "after": after,
           "moved": rules_that_counted(before, after) if ok else [],
           "policies": (after.get("policies") if ok else None) or {}}
    if not ok:
        # Both reads have to work for the difference to mean anything, so the
        # reason the pair failed is whichever of them failed.
        failed = before if not before.get("ok") else after
        out["error"] = failed.get("error") or "the rule counters could not be read"
        if failed.get("applicable") is False:
            out["applicable"] = False
    return out


def _rule_key(rule):
    return (rule.get("table"), rule.get("chain"), rule.get("rule"))


def rules_that_counted(before, after):
    """Drop and reject rules whose packet count moved between two reads.

    Worst first, so a shortlist reads as one. A rule that appeared between the
    two reads is skipped rather than counted from zero: somebody reloading the
    firewall mid-run is not evidence about the probe.
    """
    was = {_rule_key(r): r["packets"] for r in (before or {}).get("rules") or []}
    moved = []
    for rule in (after or {}).get("rules") or []:
        if rule.get("verdict") not in STOPS_A_PACKET:
            continue
        key = _rule_key(rule)
        if key not in was:
            continue
        gained = rule["packets"] - was[key]
        if gained > 0:
            moved.append(dict(rule, gained=gained))
    return sorted(moved, key=lambda r: -r["gained"])


def _ports_named_by(rule):
    """The destination ports a rule names, if it names any."""
    found = _RULE_DPORT.search(rule.get("rule") or "")
    if not found:
        return set()
    out = set()
    for part in found.group(1).replace(" ", "").split(","):
        for piece in part.replace("-", ":").split(":"):
            if piece.isdigit():
                out.add(piece)
    return out


def inbound_drops_on_served_ports(raw):
    """Rules that dropped traffic arriving for something this box serves.

    Not every inbound drop. An internet-facing box drops scan noise all day and
    a rule counting is what a firewall looks like working, so reporting any of
    them would put a warning on every healthy box and teach a reader to skip
    the section.

    What is not ordinary is dropping traffic addressed to a port this box is
    listening on. That is the box turning away the thing it exists to answer,
    and it is the same reader that already names what stopped the probes going
    out, pointed at the direction that matters more here.
    """
    window = (raw or {}).get("firewall") or {}
    if not window.get("ok"):
        return []
    serving = {str(p) for p in
               ((raw.get("sockets") or {}).get("listen_ports") or [])}
    serving |= {str(l["port"]) for l in
                ((raw.get("udp_sockets") or {}).get("listeners") or [])}
    if not serving:
        return []
    out = []
    for rule in window.get("moved") or []:
        if rule.get("faces") != "in":
            continue
        hit = _ports_named_by(rule) & serving
        if hit:
            out.append(dict(rule, ports=sorted(hit)))
    return out


def _dropped_by(raw):
    """The sentence naming what stopped the probes, or nothing.

    Three answers, in descending order of how much they say: the rules that
    counted while the probes were in flight, the chain policy where no rule
    counted but the default is to drop, and nothing at all.
    """
    window = (raw or {}).get("firewall") or {}
    if not window.get("ok"):
        return ""
    moved = window.get("moved") or []
    if moved:
        shown = "; ".join("%s/%s %s (%d packet(s))"
                          % (r["chain"], r["verdict"], r["rule"], r["gained"])
                          for r in moved[:2])
        return (" While those probes were in flight this box's firewall counted "
                "%d packet(s) on %d %s rule(s): %s. That is what stopped them, or "
                "what was busy at the same moment: the counters say a rule fired, "
                "not that it fired on this traffic."
                % (sum(r["gained"] for r in moved), len(moved),
                   "drop or reject", shown))
    dropping = [name for name, policy in (window.get("policies") or {}).items()
                if policy in STOPS_A_PACKET and "OUTPUT" in name.upper()]
    if dropping:
        return (" No rule counted while the probes were in flight, and the "
                "default on %s is to drop, so they were stopped by the policy "
                "rather than by a rule written for them."
                % ", ".join(sorted(dropping)))
    return ""


# ---------------------------------------------------------------------------
# The queues on this box's own interfaces.
#
# Three findings say connections are waiting in a queue rather than travelling,
# and then offer three candidates for where: a full link, an overrun interface
# queue, or a device buffering to hide one. The middle one is on this box and
# the kernel counts it, so the three-way guess was only ever a guess about two.
#
# `tc -s qdisc` is a read-only netlink dump and needs no privilege, which is
# what makes this the cheapest of the lot: nothing was in the way of collecting
# it except nobody having asked.
# ---------------------------------------------------------------------------

_QDISC_HEAD = re.compile(r"^qdisc (\S+) (\S+) dev (\S+)")
_QDISC_SENT = re.compile(r"Sent \d+ bytes (\d+) pkt \(dropped (\d+), "
                         r"overlimits (\d+) requeues (\d+)\)")
_QDISC_BACKLOG = re.compile(r"backlog (\d+)b (\d+)p")


def parse_qdisc(text):
    """`tc -s qdisc` into one row per queue.

    Three lines per queue: the header naming the kind and the interface, the
    totals, and the backlog. Anything that does not parse is skipped, because a
    queueing discipline this does not know still prints a header this does.
    """
    out, current = [], None
    for line in (text or "").splitlines():
        head = _QDISC_HEAD.match(line.strip())
        if head:
            current = {"kind": head.group(1), "handle": head.group(2),
                       "iface": head.group(3), "root": " root " in line + " ",
                       "sent_pkts": 0, "dropped": 0, "overlimits": 0,
                       "requeues": 0, "backlog_bytes": 0, "backlog_pkts": 0}
            out.append(current)
            continue
        if current is None:
            continue
        sent = _QDISC_SENT.search(line)
        if sent:
            current["sent_pkts"] = int(sent.group(1))
            current["dropped"] = int(sent.group(2))
            current["overlimits"] = int(sent.group(3))
            current["requeues"] = int(sent.group(4))
        backlog = _QDISC_BACKLOG.search(line)
        if backlog:
            current["backlog_bytes"] = int(backlog.group(1))
            current["backlog_pkts"] = int(backlog.group(2))
    return out


def cmd_qdisc():
    """What this box's own egress queues are doing.

    Opportunistic like the rest: a box without `tc` says so and every message
    built on this reads as it did before.
    """
    if OS_NAME != "Linux":
        return {"ok": False, "cmd": "tc -s qdisc", "applicable": False,
                "error": "queue statistics are Linux-only"}
    res = run_first_usable([["tc", "-s", "qdisc", "show"], ["tc", "-s", "qdisc"]],
                           timeout=10)
    if not res.get("ok"):
        return res
    res["queues"] = parse_qdisc(res.get("stdout") or "")
    return res


def worst_local_queue(raw):
    """The interface queue holding or dropping the most, if any is.

    Loopback is excluded. It is a queue by the kernel's reckoning and never the
    answer to "where is traffic being held up on the way out".
    """
    queues = ((raw or {}).get("qdisc") or {}).get("queues") or []
    real = [q for q in queues if q.get("iface") != "lo"]
    if not real:
        return None
    worst = max(real, key=lambda q: (q["backlog_pkts"], q["dropped"]))
    if not worst["backlog_pkts"] and not worst["dropped"]:
        return None
    return worst


def _queues_here_say(raw):
    """Whether this box's own egress queues are part of the delay, or are not.

    Both answers are worth a sentence, and the second more than the first. The
    message this joins offers three candidates and the reader has to eliminate
    them by hand; an empty queue here eliminates one of them from the box the
    report is being written on.
    """
    queues = ((raw or {}).get("qdisc") or {}).get("queues") or []
    if not queues:
        return ""
    worst = worst_local_queue(raw)
    if not worst:
        return (" This box's own egress queues are empty and have dropped nothing, "
                "so the buffering is not happening here.")
    parts = []
    if worst["backlog_pkts"]:
        parts.append("%d packet(s) waiting" % worst["backlog_pkts"])
    if worst["dropped"]:
        parts.append("%d dropped" % worst["dropped"])
    return (" This box's own %s queue on %s has %s, so at least some of the holding "
            "up is here rather than further out."
            % (worst["kind"], worst["iface"], " and ".join(parts)))


def owners_in_state(owners, state):
    """[(process, sockets)] worst first, for one TCP state."""
    want, counts = _norm_state(state), {}
    for o in owners or []:
        if o.get("state") == want and o.get("process"):
            counts[o["process"]] = counts.get(o["process"], 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def owner_of_port(owners, port):
    """The process listening on a port, when exactly one is.

    Two names on one port means this cannot answer, and naming either would be
    picking at random on the report that most needs the right one. Falls back to
    any socket on that port, for the readers that do not mark a listener.
    """
    def named(rows):
        return {o["process"] for o in rows if o.get("process")}

    # Compared as text on both sides. A port arrives here as an int from one
    # caller and as a string from another, because one reads it off a socket
    # address and the other off a listener table, and a silent type mismatch
    # here reads as "the process could not be named" - which is a sentence this
    # prints on purpose, so nothing looks wrong when it happens.
    port = str(port)
    on_port = [o for o in (owners or []) if str(o.get("local_port")) == port]
    listening = named([o for o in on_port if o.get("state") == "LISTEN"])
    if listening:
        return next(iter(listening)) if len(listening) == 1 else None
    any_of = named(on_port)
    return next(iter(any_of)) if len(any_of) == 1 else None


def process_holding(pairs):
    """Who holds them, as a phrase, or "" when nothing could be read.

    The empty string is the important half. A run that could not read the
    process table has to leave the sentence exactly as it was, because "an
    application" is still true and "an application called None" is not.
    """
    if not pairs:
        return ""
    if len(pairs) == 1:
        return pairs[0][0]
    return ", ".join("%s (%d)" % (name, count) for name, count in pairs[:3])


def socket_owners(raw):
    """The owner rows, or nothing at all when no command could read them."""
    res = (raw or {}).get("socket_owners") or {}
    return (res.get("owners") or []) if res.get("ok") else []


def _held_by(pairs):
    """The sentence naming who holds them, or nothing.

    Nothing is the whole point of the helper. Every message this is appended to
    reads correctly without it, because "an application" was always true - so a
    box where the process table could not be read says exactly what it said
    before, rather than saying it with a hole in it.
    """
    who = process_holding(pairs)
    return (" The sockets are held by %s." % who) if who else ""


def _biggest_holder(owners):
    """Who holds the most sockets on this box, when one process stands out.

    A descriptor ceiling is a system-wide number and this cannot say which
    process spent them, so it says the one thing it can see and says it as a
    lead: nothing here counts descriptors, only sockets. It stays quiet unless
    one process holds a clear majority, because "nginx 34%, envoy 33%" points
    at nobody and reads as though it points at somebody.
    """
    counts = {}
    for o in owners or []:
        if o.get("process"):
            counts[o["process"]] = counts.get(o["process"], 0) + 1
    if not counts:
        return ""
    total = sum(counts.values())
    name, held = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
    if held * 2 <= total:
        return ""
    return (" Most of the open sockets here belong to %s (%d of %d), which is "
            "where to look first." % (name, held, total))


def _the_listeners_are(owners):
    """Which services are listening here, for the counters that cannot say
    which of them overflowed.

    ListenOverflows is one number for the whole box. Naming a single service
    from it would be an accusation this cannot support, so this names the
    candidates and says that is what they are. One listener is not a shortlist,
    so on that box the sentence is a straight answer.
    """
    names = sorted({o["process"] for o in owners or []
                    if o.get("state") == "LISTEN" and o.get("process")})
    if not names:
        return ""
    if len(names) == 1:
        return " The only service listening here is %s." % names[0]
    return (" The services listening here are %s, and the counter is for the box "
            "rather than for any one of them." % ", ".join(names[:5]))


def _that_service_is(owners, port):
    """Name the process on a port, for the findings that already know which one.

    These are the two that earn the most from it. "The service on port 8443
    answered nothing" is a sentence somebody has to go and resolve into a
    process before they can restart anything, and on a box running several
    instances behind several ports that step is the work.
    """
    who = owner_of_port(owners, port)
    return (" That service is %s." % who) if who else ""


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
# "Minimum = 13ms, Maximum = 15ms, Average = 14ms". Named rather than ordered,
# and in an order of its own - the middle figure is the maximum here and the
# average in the form above.
PING_STATS_WIN_RE = re.compile(
    r"Minimum\s*=\s*([\d.]+)ms.*?Maximum\s*=\s*([\d.]+)ms.*?Average\s*=\s*([\d.]+)ms",
    re.I | re.S)


# The hop count on the way *in*, off the TTL of a ping reply.
#
# A traceroute only goes outward. Nothing on this box can watch the route a
# client's packets took to arrive - which is why the inbound side has always
# been measured on the connections themselves rather than drawn as a path.
#
# But every ping reply carries the TTL it arrived with, and TTL is decremented
# by each router on the way here. The sender starts it at a well-known value, so
# the difference is the number of hops that reply crossed getting to us. The
# tool has been running pings and keeping min/avg/max off them since the
# beginning, and throwing this away.
#
# What it measures is the path *from that host to this one*, which is the
# direction a traceroute cannot see and the one worth having.
PING_TTL_RE = re.compile(r"\bttl[=\s](\d{1,3})\b", re.I)

# What senders start it at. Almost every stack uses one of these three, and a
# reply cannot have arrived with more than it started with - so the smallest of
# them that is not below what arrived is the one it started at.
TTL_INITIALS = (64, 128, 255)


def parse_ping_ttl(ping_result):
    """The TTL a ping reply arrived with, if the output carried one.

    Linux prints `ttl=57`, BSD and macOS the same, Windows `TTL=57`. Every reply
    line has one; the first is enough, and taking the first rather than the
    lowest avoids reading a rewritten TTL from one odd reply as the truth.
    """
    if not (ping_result or {}).get("ok"):
        return None
    m = PING_TTL_RE.search(ping_result.get("stdout") or "")
    return int(m.group(1)) if m else None


def hops_from_ttl(arrived):
    """(hops, the initial value assumed) from a TTL that arrived here.

    Returns None where the reading cannot mean anything: a TTL above every
    initial value is a rewritten one, and zero hops is a reply from this box.

    The assumption is returned with the answer rather than buried, because it is
    a guess - a host starting at 255 read as starting at 64 would give a
    nonsense count, and a reader who can see "assuming 64" can tell.
    """
    if not arrived or arrived <= 0:
        return None
    for initial in TTL_INITIALS:
        if arrived <= initial:
            hops = initial - arrived
            # Same host, or one rewriting TTL to a round number on the way out.
            return (hops, initial) if hops else None
    return None                      # above 255: nothing standard starts there


def parse_ping_stats(ping_result):
    """min/avg/max/stddev from a ping summary.

    Two layouts. Linux and BSD print them as a slash-separated run after an
    `=`, differing only in whether a fourth figure is there. Windows names each
    one and puts them in a different order, and used to match neither - so it
    returned nothing at all, while the branch below claimed in a comment to be
    handling it.
    """
    if not ping_result.get("ok"):
        return {}
    text = ping_result.get("stdout") or ""
    m = PING_STATS_RE.search(text)
    if not m:
        win = PING_STATS_WIN_RE.search(text)
        if not win:
            return {}
        # Minimum, Maximum, Average - not the min/avg/max the slash form uses.
        # Read in the order they are printed, the average and the maximum swap,
        # which is a wrong number rather than a missing one.
        low, high, avg = (float(win.group(i)) for i in (1, 2, 3))
        # No deviation is offered, and the spread is a usable stand-in: this is
        # what that comment was always for.
        return {"min_ms": low, "avg_ms": avg, "max_ms": high,
                "stdev_ms": round(high - low, 2)}
    out = {"min_ms": float(m.group(1)), "avg_ms": float(m.group(2)),
           "max_ms": float(m.group(3))}
    if m.group(4):
        out["stdev_ms"] = float(m.group(4))
    else:
        # A summary of three: the spread stands in for a deviation nobody gave.
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
        with open("/proc/net/snmp", encoding="utf-8", errors="replace") as fh:
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
        with open("/proc/net/softnet_stat", encoding="utf-8", errors="replace") as fh:
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
        with open("/proc/net/netstat", encoding="utf-8", errors="replace") as fh:
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


def _proc_stat_rows(path):
    """A /proc/net/stat table as one dict of {column: value} per CPU row.

    These files are a header of column names and one hex row per CPU, and both
    readers of them had written out the same header-and-row walk: split the
    names, skip a row whose width disagrees with the header, decode hex, ignore
    a column that will not parse.

    What is deliberately *not* folded in is what to do with a column once it is
    read, because that is where the two differ and where the subtlety lives.
    Most columns are a per-CPU share and want summing. "entries" repeats the
    whole table on every row, so summing it reports a table over its own ceiling
    on any box with more than one core. Returning rows leaves that decision with
    the caller that knows which column it is asking about.

    Column names come from the header rather than a fixed list, because they
    vary by kernel version.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    if len(lines) < 2:
        return []
    names = lines[0].split()
    rows = []
    for row in lines[1:]:
        cols = row.split()
        if len(cols) != len(names):
            continue
        parsed = {}
        for name, col in zip(names, cols):
            try:
                parsed[name] = int(col, 16)
            except ValueError:
                continue
        rows.append(parsed)
    return rows


def _sysfs_names(base):
    """Interface names under a sysfs directory, or nothing if it is not there.

    Four readers walk /sys/class/net and each opened with the same four lines.
    Nothing rather than an error, because a box without sysfs - a Mac, a
    container built without it - is one these readers have no answer for rather
    than one that failed, and each of them already returns an empty result on
    that path.
    """
    try:
        return sorted(os.listdir(base))
    except OSError:
        return []


def _read_text(path):
    """A small file's contents, or None if it isn't there.

    Every /proc and /sys reader here wants exactly this and three of them had
    written it out as their own closure. The int-reading variants beside it are
    deliberately *not* folded in: they differ in what a failure means - unknown,
    skip the field, or leave the default - and that distinction is load-bearing.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
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
                with open(path, encoding="utf-8", errors="replace") as fh:
                    out[key] = int(fh.read().strip())
                break
            except (OSError, ValueError):
                continue
    # insert_failed and drop are genuinely per-CPU and are the two worth having,
    # so both are summed across rows.
    rows = _proc_stat_rows("/proc/net/stat/nf_conntrack")
    for name in ("insert_failed", "drop"):
        if any(name in row for row in rows):
            out["ct_" + name] = sum(row.get(name, 0) for row in rows)
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
        path = os.path.join(base, "sys/net/ipv4/neigh/default/gc_thresh3")
        with open(path, encoding="utf-8", errors="replace") as fh:
            out["gc_thresh3"] = int(fh.read().strip())
    except (OSError, ValueError):
        pass
    rows = _proc_stat_rows(os.path.join(base, "net/stat/arp_cache"))
    fulls = 0
    for row in rows:
        # Assigned, never accumulated: this column repeats the whole table on
        # every row rather than holding a per-CPU share, so adding it up would
        # report a table over its own ceiling on any box with more than one core.
        if "entries" in row:
            out["entries"] = row["entries"]
        # table_fulls is a real per-CPU count and is summed.
        fulls += row.get("table_fulls", 0)
    # Only reported when the column was actually there. A kernel that does not
    # publish it must read as unknown rather than as zero overflows, which is a
    # claim this cannot make.
    if any("table_fulls" in row for row in rows):
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
    names = _sysfs_names(base)
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
                with open(os.path.join(base, name, "thermal_throttle", field),
                          encoding="utf-8", errors="replace") as fh:
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
        if _answered(res):
            offset, synced = parse_chrony_tracking(res.get("stdout", ""))
            res.update({"offset_ms": offset, "synced": synced, "source": "chronyc"})
            return res
    if which("timedatectl"):
        res = run(["timedatectl", "show"], timeout=5)
        if _answered(res):
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
        if _answered(res):
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


def _is_loopback(addr):
    """The box talking to itself.

    Split out from _flow_is_local because scope needs the two apart: loopback
    is host scope and link-local is link scope, and a check that lumps them
    together cannot tell "this address never leaves the box" from "this address
    never leaves the segment". Everything that only needs "not the network
    under test" still asks _flow_is_local and gets both.
    """
    lower = (addr or "").lower().strip("[]")
    return lower.startswith("127.") or lower in ("::1", "localhost")


def _is_link_local(addr):
    """Self-assigned, or scoped to one segment. An IPv4 box on 169.254 never
    heard from DHCP; an IPv6 fe80 address is on every interface regardless."""
    lower = (addr or "").lower().strip("[]")
    return lower.startswith("169.254.") or lower.startswith("fe80:")


def _flow_is_local(peer):
    """Loopback and link-local peers are not the network under test. Loss on
    loopback is memory pressure, and must never read as a path fault."""
    if not peer:
        return True
    return _is_loopback(peer) or _is_link_local(peer)


def _own_ssh_peer():
    """The client end of the SSH session this tool is probably running over.

    That flow is real, but blaming the network for the session we arrived on is
    a distraction - and on a quiet box it can be the only sample there is.
    """
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return (parts[0], parts[1]) if len(parts) >= 2 else (None, None)


def _own_access_service():
    """(where we came from, which port of ours we came in on), or (None, None).

    Not the same question as _own_ssh_peer, which identifies one flow so that
    flow's loss can be set aside. This identifies the *service* the operator
    arrived on, so every session like it can be set aside: usually several,
    because a box being worked on has more than one window open on it.

    Both halves are needed and neither is enough. Matching the peer alone would
    discard real traffic from a host that is both a way in and a client.
    Matching the port alone would discard every session on a box whose actual
    job is SSH. Together they mean "administrative sessions from the place the
    administrator came from", which is what this is for.

    A jump host is why this reads the peer from the connection rather than
    assuming anything: arriving through one, the box sees the jump host as the
    client, and every operator working through it lands on the same address.
    """
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return (parts[0], parts[3]) if len(parts) >= 4 else (None, None)


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
        # What came back the other way. Only the sent side was kept, which is
        # enough for a box that talks outward and not for one that relays: the
        # question there is whether what arrives on one side leaves on the
        # other, and half the pair cannot answer it. None rather than 0.0 when
        # the kernel does not offer it, so "nothing arrived" stays separable
        # from "nobody asked" - the same distinction direction_readable makes.
        flow["bytes_received"] = _flow_num(kv.get("bytes_received"))
        # A bare word rather than a key and a value, so the pair matcher
        # above cannot see it: the kernel prints "app_limited" or prints
        # nothing. It means the sending was paced by whatever is feeding the
        # socket rather than by the network - which is the normal state of
        # any connection not filling its window, so it is recorded and
        # deliberately not graded. There is no share of active time behind
        # it the way there is for the receive window and the send buffer,
        # and those two use exactly that share to avoid firing on a healthy
        # box. A finding here would have nothing to hold it back.
        flow["app_limited"] = bool(re.search(r"\bapp_limited\b", blob))
        # The fields that know which way a connection stopped working. Every one
        # of these was already in the line this parser reads and was dropped on
        # the floor, so the tool said the return path could not be measured
        # while the kernel was handing it over on every socket.
        #
        # lastsnd and lastrcv are milliseconds since this box last sent and last
        # received. Sending now while nothing has come back for seconds is the
        # return direction stalled, and it is not an inference - it is two
        # counters disagreeing.
        #
        # dsack_dups is the far end saying "I already had that": proof the data
        # arrived, so whatever those retransmits were, they were not the forward
        # path losing packets.
        flow["bytes_acked"] = _flow_num(kv.get("bytes_acked")) or 0.0
        flow["last_send_ms"] = _flow_num(kv.get("lastsnd"))
        flow["last_recv_ms"] = _flow_num(kv.get("lastrcv"))
        flow["last_ack_ms"] = _flow_num(kv.get("lastack"))
        flow["dsack_dups"] = _flow_num(kv.get("dsack_dups")) or 0.0
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


def _queue_message(info, where, raw=None):
    """One sentence for a queue, wherever it was found."""
    return (f"{info['queued']} connection(s) {where} are waiting in a queue rather "
            f"than travelling: the worst is {info['queue_peer']} at "
            f"{info['queue_rtt_ms']}ms against its own best of {info['queue_min_ms']}ms, "
            f"so {info['queue_ms']}ms of every round trip is spent buffered. That is "
            f"not distance - the same connection has been faster. Something on this "
            f"path is holding traffic instead of dropping it: a full link, an overrun "
            f"interface queue, or a device buffering to hide one."
            + _queues_here_say(raw))


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


# Deciding a connection has stopped hearing back. Both halves matter and the
# second is the one that keeps this honest.
#
# A quiet connection has a large lastrcv for the plainest reason there is:
# nothing is happening on it. Reading that as a stalled return path would fire
# on every idle socket on a healthy box, which is the false positive this tool
# has spent its life removing. So the box has to be *sending* - recently, and
# enough to expect an answer - before its silence means anything.
DIR_SENDING_MS = 1000        # last send this recent, or the socket is idle
DIR_SILENT_MS = 5000         # nothing back for this long
DIR_SILENCE_RATIO = 10       # and that much longer than since it last sent
DIR_MIN_BYTES = 100_000      # enough traffic that an answer was owed
DIR_SILENT_SHARE = 50        # or this much of the side's traffic, however few


def flow_direction(flow):
    """Which way this connection stopped working, or None when it cannot say.

    None is the common answer and has to stay comfortable to return. Most
    connections are fine, most of the rest are ambiguous, and a direction is
    only claimed on two counters that disagree with each other rather than on
    anything inferred.
    """
    sent, recv = flow.get("last_send_ms"), flow.get("last_recv_ms")
    ack = flow.get("last_ack_ms")
    if sent is None or recv is None or ack is None:
        return None                      # an older ss, or a kernel not reporting
    # Written as what has to be true rather than as a run of rejections, so each
    # threshold is compared at or beyond the value the reference documents.
    owed_a_reply = (flow.get("bytes_sent") or 0) >= DIR_MIN_BYTES
    still_sending = sent <= DIR_SENDING_MS
    gone_quiet = recv >= DIR_SILENT_MS and recv >= sent * DIR_SILENCE_RATIO
    if not (owed_a_reply and still_sending and gone_quiet):
        return None
    # lastrcv counts data, and a far end that is merely slow sends none while
    # still acknowledging everything it receives. Read on data alone, a database
    # taking nine seconds over a query looked exactly like a return path that had
    # stopped carrying anything - opposite situations, one of them a network
    # fault and one of them not, and the first reading sends somebody to chase a
    # carrier over a slow query.
    #
    # The acknowledgement is what separates them, because unlike a reply it is
    # not the far end's choice to send. Still arriving means the path back is
    # carrying and the far end is holding our request; stopped means nothing is
    # coming back at all.
    if ack >= DIR_SILENT_MS and ack >= sent * DIR_SILENCE_RATIO:
        return "return"
    return "unanswered"


def side_return_stalled(group):
    """Has the way back from this side stopped, and how sure is that.

    Two ways to be sure, because counting alone has a hole in it. Most of the
    connections going quiet is one. The other is a minority of them carrying
    most of the traffic: a box that holds one long-lived session beside forty
    short ones is a normal shape, and on it the session that matters is a
    minority of one. Counted alone, a dead one stayed invisible behind its
    healthy neighbours, which is the reading that sends someone to look at the
    short connections that were never the problem.

    Returns (stalled, quiet, total, share_pct) so whoever draws it can say
    which of the two made it true - "1 of 40, carrying 92%" and "38 of 40" are
    the same verdict reached for different reasons and want different words.
    """
    total = len(group)
    quiet_flows = [f for f in group if flow_direction(f) == "return"]
    quiet = len(quiet_flows)
    sent = sum((f.get("bytes_sent") or 0) for f in group)
    share = round(100.0 * sum((f.get("bytes_sent") or 0)
                              for f in quiet_flows) / sent) if sent else 0
    stalled = bool(quiet) and (quiet * 2 >= total or share >= DIR_SILENT_SHARE)
    return stalled, quiet, total, share


def flow_delivered(flow):
    """Did the far end confirm data this box thought it had to resend?

    A DSACK is the receiver saying it already had that segment, so the original
    arrived. It does not prove the acknowledgement was lost rather than late,
    which is why this reports what it knows - the data got there - instead of
    naming the return path.
    """
    return bool(flow.get("dsack_dups")) and bool(flow.get("bytes_retrans"))


def _where_that_is(peers):
    """Whether "an internal segment" is a claim this is entitled to make.

    It used to say so outright - "an internal segment, not the internet, and not
    the carrier" - which is true of a reverse proxy in front of a database and
    false of a forward proxy, where the connections this box opens are the
    destinations its users asked for. Which side a connection is on is decided
    by whether its local port was one this box listens on, and that says nothing
    at all about where the far end sits. The addresses do, so they are asked.
    """
    hosts = [p.rsplit(":", 1)[0] if p.count(":") == 1 else p
             for p in (peers or "").split(", ") if p]
    if not hosts:
        return ""
    if all(is_private_ip(h) for h in hosts):
        return " - an internal segment, not the internet and not the carrier"
    if not any(is_private_ip(h) for h in hosts):
        return " - destinations out on the internet rather than an internal segment"
    return ""


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
                # Which way this side stopped working, where the counters can
                # say. Counted rather than reduced to a verdict: three of forty
                # connections gone quiet is a different sentence from forty of
                # forty, and the reader is owed the denominator.
                "silent_return": sum(1 for f in group
                                     if flow_direction(f) == "return"),
                # The other half of that question. These are connections the far
                # end is acknowledging and not answering: its network is
                # carrying and it is holding the request, which is a slow
                # service rather than a broken path. Kept apart from the count
                # above rather than summed into one silence, because the two
                # have different owners and only one of them is a network
                # fault.
                "unanswered": sum(1 for f in group
                                  if flow_direction(f) == "unanswered"),
                # The decision itself, made once here rather than twice in the
                # two renderers. A threshold written out in both Python and the
                # page's JavaScript is two copies of a rule and two chances for
                # them to disagree about the same report.
                "return_stalled": side_return_stalled(group)[0],
                # What share of the side's traffic the quiet ones carry, so the
                # drawing can say which way it became true.
                "silent_share_pct": side_return_stalled(group)[3],
                # What crossed this side, each way. A box that relays is meant
                # to hand what arrives on one side out on the other, and these
                # are the two numbers that say whether it did. Summed rather
                # than averaged: the question is about the side, not about any
                # connection on it.
                "bytes_in": sum((f.get("bytes_received") or 0) for f in group),
                # Connections the kernel says were waiting on this box to
                # supply data rather than on the network to carry it.
                # Reported, never judged: see the parser for why.
                "app_limited": sum(1 for f in group if f.get("app_limited")),
                "bytes_out": sum((f.get("bytes_sent") or 0) for f in group),
                # Whether the kernel offered the received counter at all, so a
                # side that carried nothing stays separable from one nobody
                # could measure.
                "volume_readable": sum(1 for f in group
                                       if f.get("bytes_received") is not None),
                # Connections where the far end confirmed it already had the
                # data this box resent. Whatever those retransmits were, they
                # were not the forward path dropping packets.
                "delivered_anyway": sum(1 for f in group if flow_delivered(f)),
                # Whether the kernel offered the counters at all, so a silence
                # of zero can be told from a question never asked.
                "direction_readable": sum(1 for f in group
                                          if f.get("last_recv_ms") is not None),
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
    if res.get("code"):
        # Only one utility reads per-connection TCP state, so there is nothing
        # to fall through to. What matters is that a trimmed ss which rejects
        # -i is reported as a failed read: parsed as an answer it becomes zero
        # flows, and zero flows is indistinguishable from a box with no
        # connections, which is a finding rather than a gap.
        return {"ok": False, "cmd": res.get("cmd", "ss -tin"),
                "error": "ss exited %s - per-connection TCP state could not be read"
                         % res.get("code")}
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
        with open("/proc/uptime", encoding="utf-8", errors="replace") as fh:
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
    names = _sysfs_names(base)
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
    names = _sysfs_names(base)
    for name in names:
        sdir = os.path.join(base, name, "statistics")
        if not os.path.isdir(sdir):
            continue
        vals = {}
        for field in LINK_COUNTERS:
            try:
                with open(os.path.join(sdir, field), encoding="utf-8", errors="replace") as fh:
                    vals[field] = int(fh.read().strip())
            except (OSError, ValueError):
                # Not every driver exports every counter. None means "unknown",
                # which must not be presented as "zero errors" - see below.
                vals[field] = None
        try:
            with open(os.path.join(base, name, "operstate"),
                      encoding="utf-8", errors="replace") as fh:
                vals["operstate"] = fh.read().strip()
        except OSError:
            vals["operstate"] = "unknown"
        # How many times the link has gone down and come back. operstate says
        # what the link is doing now; this says what it has been doing. A port
        # that has flapped hundreds of times still reads "up" between drops,
        # which is exactly why an intermittent fault survives a snapshot.
        try:
            with open(os.path.join(base, name, "carrier_changes"),
                      encoding="utf-8", errors="replace") as fh:
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
    names = _sysfs_names(base)
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


# What `status:` reads on a link that is actually carrying. Held as whole words
# because the interesting one is a substring of its own negation: "inactive"
# contains "active", and a link reported up while it is down is worse than one
# reported unknown. "associated" is the wireless spelling of the same state.
IFCONFIG_LINK_UP = frozenset(("active", "associated"))


def parse_ifconfig_modes(text):
    """mtu, media and link state per interface, out of `ifconfig -a` text.

    Split from the command so it can be handed a fixture and asked what it
    makes of it, the same way parse_server_limits is - the state read here is
    what the baseline diff compares between visits, and it was previously only
    reachable by stubbing the command runner.
    """
    modes, current = {}, None
    for line in (text or "").splitlines():
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
            # Taken as a whole word. Tested as a substring, "status: inactive"
            # answered yes - so a dead link read as a live one, and the
            # baseline diff, whose whole job is to notice a link going down
            # between two visits, compared up against up and saw no change.
            state = stripped.split(":", 1)[1].strip().lower()
            active = state in IFCONFIG_LINK_UP
            modes[current]["carrier"] = active
            modes[current]["operstate"] = "up" if active else "down"
    return modes


def _link_modes_bsd():
    """macOS/BSD: pull mtu and the negotiated media line out of `ifconfig -a`."""
    res = run(["ifconfig", "-a"])
    if not res.get("ok"):
        return {}
    return parse_ifconfig_modes(res.get("stdout", ""))


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


# "Frag needed and DF set (mtu = 1492)" on Linux, "frag needed and DF set
# (MTU 1492)" on macOS, "Packet needs to be fragmented but DF set" on Windows -
# which names no size, so the presence of the message is the signal there.
_FRAG_NEEDED = re.compile(
    r"frag(?:mentation)?\s+needed"          # Linux and the BSDs
    r"|needs?\s+to\s+be\s+fragmented",     # Windows says it the other way round
    re.I)
_FRAG_MTU = re.compile(r"\bmtu[ =]+(\d{3,5})", re.I)


def _pmtu_signalled(res):
    """The MTU a router reported back, True if it complained without a number,
    or None when the packet simply vanished.

    This is the whole difference between a path that is merely smaller and one
    that is broken.
    """
    text = (res.get("stdout") or "") + "\n" + (res.get("stderr") or "")
    if not _FRAG_NEEDED.search(text):
        return None
    found = _FRAG_MTU.search(text)
    return int(found.group(1)) if found else True


def _dont_fragment_ping(payload, target):
    """One do-not-fragment ping of a given size, in each platform's spelling.

    Three ways to say the same thing. Windows sets the bit with -f and sizes
    with -l, BSD and macOS use -D and -s, Linux wants -M do. The wait flag
    differs too, and the source flag differs again, which _source_flag already
    knows about.

    Built here rather than in the probe loop, where the same construction
    appeared three times. That is not a tidiness point: adding source binding
    meant editing all three lines, getting one wrong would have bound two
    platforms and silently not the third, and a fourth platform would be a
    fourth place to forget. One place to change is also one place to read when
    the question is what this actually sent.

    Path MTU is a property of a path, and a box holding two addresses can have
    two of them: a tunnel on one and not the other is the ordinary way that
    happens. Measured unbound, the primary address's path MTU was reported as
    the answer for whichever address was asked about.
    """
    src = _source_flag("ping")
    if OS_NAME == "Windows":
        return ["ping", "-f", "-l", str(payload), "-n", "1", "-w", "2000"] + src + [target]
    if OS_NAME == "Darwin":
        return ["ping", "-D", "-s", str(payload), "-c", "1", "-t", "3"] + src + [target]
    return ["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", "2"] + src + [target]


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
        cmd = _dont_fragment_ping(payload, target)
        res = run(cmd, timeout=6)
        got = bool(res.get("ok")) and res.get("code") == 0
        attempts.append({"mtu": mtu, "payload": payload, "ok": got,
                         "signalled": None if got else _pmtu_signalled(res),
                         "cmd": res.get("cmd", " ".join(cmd))})
        if got:
            break

    working = next((a["mtu"] for a in attempts if a["ok"]), None)
    # Did anything on the path say so? A smaller path MTU is ordinary - PPPoE
    # is 1492, a tunnel is less - and it costs nothing when the router replies
    # "fragmentation needed" with the size, because the sender then adapts and
    # transfers are fine. A blackhole is the same measurement with that reply
    # missing, and only that one hangs a transfer. Measuring the size alone
    # cannot tell them apart, so this reads the reply.
    signalled = next((a["signalled"] for a in attempts
                      if not a["ok"] and a.get("signalled")), None)
    lines = [f"probing path MTU to {target} (interface MTU {ceiling})", ""]
    for a in attempts:
        lines.append(f"  {a['mtu']:>5} bytes  {'passes' if a['ok'] else 'blocked'}")
    if working is None:
        lines.append("\n  no size got through - the target may not answer pings at all")
    return {"ok": True, "cmd": f"ping -c1 (do-not-fragment) x{len(attempts)} -> {target}",
            "stdout": "\n".join(lines), "stderr": "", "code": 0,
            "target": target, "iface_mtu": ceiling, "path_mtu": working,
            "signalled_mtu": signalled, "attempts": attempts}


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
            # Bound like every other probe. This one was missed, and it is the
            # one most worth binding: a port check is the question "can a client
            # of this address reach that service", and answered from the box's
            # primary address it is a confident answer to a question nobody
            # asked. The report said every check left from the chosen source
            # while this one did not.
            source = _source_for(family)
            if source:
                try:
                    s.bind(source)
                except OSError as exc:
                    return fail("source", "could not send from %s: %s"
                                % (SOURCE_ADDRESS, exc))
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
# How the three severities order. Written out inline in four places, which
# is four chances for one of them to disagree about what is worse than what.
SEVERITY_RANK = {"ok": 0, "warning": 1, "critical": 2}

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
    "route_to": {
        "label": "the route to the target", "layer": 3,
        "desc": "Which route this box would actually use for the target, asked of the "
                "kernel rather than worked out from the routing table. Compared against "
                "the first hop the trace found: when they disagree the probe and the "
                "traffic are taking different routes, and everything measured below is "
                "about the other one.",
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
                "table. Nothing is scanned or probed, so it says what this device has talked "
                "to rather than what exists on the segment. Names come from reverse DNS.",
    },
    "sockets": {
        "label": "socket states", "layer": 4,
        "desc": "This device's own TCP sockets by state. Connections stuck in SYN_SENT mean "
                "nothing is answering; a pile of CLOSE_WAIT means an application isn't closing "
                "its sockets, which is not a network fault.",
    },
    "udp_sockets": {
        "label": "datagram listeners", "layer": 4,
        "desc": "This box's UDP sockets. A datagram listener serves any number of peers "
                "without the kernel recording them, so this counts what is bound and what "
                "is queued behind it rather than who is connected - which is the one thing "
                "a socket table cannot say about this plane.",
    },
    "firewall": {
        "label": "firewall rule counters, either side of the probes", "layer": 3,
        "desc": "Every rule's packet count, read once before anything was sent and once "
                "after. Only the difference means anything: a ruleset says what could happen "
                "to a packet, and a pair of reads says which rules actually fired while the "
                "probes were in flight. Needs root, and says nothing without it.",
    },
    "proxy_reachable": {
        "label": "can this box reach the proxy it is told to use", "layer": 7,
        "desc": "One TCP connect to each configured proxy, nothing sent and nothing read. "
                "A proxy that refuses or does not answer breaks every application here "
                "while ping, traceroute and DNS all pass, because none of those read the "
                "setting - which is the shape of clean report this exists to stop.",
    },
    "proxy_stats": {
        "label": "the proxy's own view of its backends", "layer": 7,
        "desc": "Which backends the proxy on this box has taken out of rotation, which "
                "check failed, and how long they have been out. The one reading here that "
                "the kernel cannot produce: a socket table says what is connected, never "
                "which of those a service has decided to stop using. Read only where a "
                "stats socket exists, which is almost nowhere.",
    },
    "qdisc": {
        "label": "interface queues", "layer": 2,
        "desc": "What this box's own egress queues are holding and dropping. Three findings "
                "say traffic is waiting rather than travelling and offer three candidates "
                "for where; this is the one of them that is on this box, and the kernel "
                "counts it, so it can be named or ruled out rather than left to the reader.",
    },
    "udp_tunnels": {
        "label": "datagram tunnels, counted", "layer": 4,
        "desc": "How many tracked UDP flows are arriving at this box's own listeners. A "
                "datagram socket serves any number of peers and records none of them, so "
                "this is the only place the count exists. Counted and never listed: the "
                "flow table is who every client reached, and a number is the whole of what "
                "this needs.",
    },
    "socket_owners": {
        "label": "who holds the sockets", "layer": 4,
        "desc": "The process behind each TCP socket. Several findings blame a service on this "
                "box without being able to say which one, which is a shrug on a box running "
                "one service and the whole question on a box running several. Absent when no "
                "command here could answer, and then those findings read as they always did.",
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


# The same two numbers, written two ways. Windows spends a line on them and
# names them rather than ordering them, so the percentage parsed on both
# platforms and the sample size on only one - which left every judgement about
# loss on a Windows box without the denominator the docstring below demands.
# Both spellings are English, like the "% loss" this sits beside: a localised
# ping is not read here, and saying so is cheaper than half-solving it.
_PING_COUNTS = (
    re.compile(r"(\d+)\s+packets? transmitted,\s*(\d+)\s+(?:packets? )?received"),
    re.compile(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+)", re.I),
)


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
    for pattern in _PING_COUNTS:
        m = pattern.search(out)
        if m:
            sent, received = int(m.group(1)), int(m.group(2))
            return sent, max(0, sent - received)
    return None, None


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


# ---------------------------------------------------------------------------
# Which route the kernel would actually use for the target.
#
# The routing table is read here to find the default gateway and for nothing
# else, which leaves the most useful question about it unasked: is the path
# being measured the path the traffic takes.
#
# Comparing the first hop against the *default* gateway would be wrong, and
# wrong in the direction that produces false alarms. A more specific route, a
# second table, a VPN that grabs a prefix - all of those are ordinary and all
# of them make the first hop something other than the default next hop. The
# kernel already answers the exact question: `ip route get` says which route
# would be used for one destination, out which interface, from which address.
#
# So this asks, and then compares the answer against what the trace observed.
# It is the one-box version of computing a path from forwarding state instead
# of probing for it.
# ---------------------------------------------------------------------------

_ROUTE_GET_VIA = re.compile(r"\bvia (\S+)")
_ROUTE_GET_DEV = re.compile(r"\bdev (\S+)")
_ROUTE_GET_SRC = re.compile(r"\bsrc (\S+)")
_ROUTE_GET_BSD = re.compile(r"^\s*(gateway|interface):\s*(\S+)", re.M)


def parse_route_to(text):
    """`ip route get` or `route -n get` into the next hop it names.

    A destination on a directly connected network has no next hop at all - the
    kernel prints the interface and no `via`, because there is nothing between
    here and there. That is not a missing answer, it is the answer, and the
    caller has to know the difference.
    """
    if not text:
        return None
    line = text.strip().splitlines()[0] if "via " in text or " dev " in text else ""
    if line:
        via = _ROUTE_GET_VIA.search(text)
        dev = _ROUTE_GET_DEV.search(text)
        src = _ROUTE_GET_SRC.search(text)
        return {"via": via.group(1) if via else None,
                "dev": dev.group(1) if dev else None,
                "src": src.group(1) if src else None, "onlink": not via}
    found = dict(_ROUTE_GET_BSD.findall(text))
    if not found:
        return None
    via = found.get("gateway")
    # BSD names a link-layer route's gateway after the interface, which is the
    # same thing as no next hop.
    if via and not _looks_like_ipv4(via) and ":" not in via:
        via = None
    return {"via": via, "dev": found.get("interface"), "src": None,
            "onlink": not via}


# A route whose action is to throw the packet away. Three spellings, and the
# difference between them is only what the sender is told: nothing at all, an
# ICMP unreachable, or an ICMP prohibited.
_DISCARD_ROUTE = re.compile(r"^\s*(blackhole|unreachable|prohibit)\s+(\S+)", re.M)


def parse_discard_routes(text):
    """Routes this box holds that discard traffic instead of forwarding it."""
    return [{"kind": kind, "prefix": prefix}
            for kind, prefix in _DISCARD_ROUTE.findall(text or "")]


def discards_the_target(routes, target_ip):
    """The discard route the target falls inside, if one does.

    Only worth saying when it catches the thing being diagnosed. A box holding
    discard routes is ordinary - they are how a site drops known-bad prefixes
    and how anti-spoofing is written - and listing them all would be inventory
    rather than a finding. Catching the target is not ordinary: it means this
    box throws that traffic away and every symptom past it is a consequence.
    """
    if not routes or not target_ip:
        return None
    try:
        address = ipaddress.ip_address(target_ip)
    except ValueError:
        return None                 # a name that never resolved; nothing to place
    # The narrowest match, not the first, because that is the one the kernel
    # will actually apply - routing is longest-prefix and this has to name the
    # route that decides, not merely a route that contains. It did not matter
    # while `default` was unreadable and every other prefix was disjoint; it
    # matters the moment a box holds an all-addresses discard and a specific
    # one, which is the ordinary shape of a deny-by-default table.
    best, best_len = None, -1
    for route in routes:
        prefix = route["prefix"]
        # `ip route` prints the all-addresses prefix by name, and ip_network
        # cannot read the name - so the one discard route that catches every
        # destination was the one route that could never match a target, while
        # every narrower prefix beside it matched fine. Both tables spell it
        # this way, so it takes the family of whatever is being placed.
        if prefix == "default":
            prefix = "::/0" if address.version == 6 else "0.0.0.0/0"
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if (address.version == network.version and address in network
                and network.prefixlen > best_len):
            best, best_len = route, network.prefixlen
    return best


def cmd_route_to(target):
    """Ask the kernel which route it would use to reach the target."""
    if not valid_target(target):
        return bad_target()
    if OS_NAME == "Windows":
        return {"ok": False, "cmd": "ip route get", "applicable": False,
                "error": "asking for one destination's route is not supported here"}
    attempts = [["ip", "route", "get", target], ["route", "-n", "get", target]]
    # A box with neither command cannot answer route questions at all, and
    # `routes_unreadable` already says so. Counting this as a second failed
    # check marks the confidence of every verdict down twice for one missing
    # capability, which is the mistake the firewall reader made first.
    if not any(which(cmd[0]) for cmd in attempts):
        return {"ok": False, "cmd": "ip route get", "applicable": False,
                "error": "nothing here can be asked which route it would use"}
    res = run_first_usable(attempts, timeout=10)
    if not res.get("ok"):
        return res
    chosen = parse_route_to(res.get("stdout") or "")
    if chosen:
        res.update(chosen)
    return res


def route_disagrees_with_trace(raw, hops, target):
    """Does the first hop the trace found match the route the kernel would use.

    Only the first hop can be checked this way: it is the only one this box
    decides. Everything past it belongs to somebody else's forwarding table and
    is not knowable from here, which is the whole reason a trace is sent at all.

    Returns nothing where the comparison cannot be made rather than guessing at
    it - no route answer, no hops, or a first hop that did not reply.
    """
    chosen = (raw or {}).get("route_to") or {}
    if not chosen.get("ok") or not hops:
        return None
    first = hops[0]
    if first.get("timed_out") or not first.get("host"):
        return None
    # On-link, the first hop is the destination itself. Anything else means the
    # trace crossed a router the kernel says is not in the way.
    expected = chosen.get("via") or (target if chosen.get("onlink") else None)
    if not expected or first["host"] == expected:
        return None
    return {"expected": expected, "observed": first["host"],
            "dev": chosen.get("dev"), "onlink": bool(chosen.get("onlink"))}


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


def translations_seen(hops, sent_from):
    """Where a router quoted our packet back with a different source on it.

    An ICMP error carries the header of the packet that provoked it. That is
    the router repeating our packet back as it saw the packet, and a NAT is
    exactly a device that changes what the next router sees. So the first hop
    whose quote carries an address that is not the one we sent from has a
    translation in front of it, and this is the one thing here that observes a
    NAT rather than inferring one from an address range.

    Which is what separates it from double_nat. That reads private addresses
    and says two networks, then concedes in its own message that a trace cannot
    tell a translating router from one that only routes. This can: routed
    subnets do not rewrite a source address and translating ones do.

    Needs the constant-flow walk, because the quote is only kept there. A text
    traceroute prints the router's address and throws the quote away.
    """
    if not sent_from:
        return []
    was, seen, out = sent_from[0], None, []
    for hop in hops or []:
        now = (hop.get("quoted") or {}).get("src")
        if not now:
            continue
        if seen is None:
            # The first hop that answered. Comparing it against what we sent
            # from, rather than against the hop before it, because there is no
            # hop before it: a difference here means the translation is in
            # front of everything this walk can see.
            seen = now
            if now != was:
                out.append({"hop": None, "from": was, "to": now,
                            "host": "before the first hop that answered"})
            continue
        if now != seen:
            out.append({"hop": hop["hop"], "from": seen, "to": now,
                        "host": hop.get("display") or hop.get("host")})
            seen = now
    return out


def balanced_hops(hops):
    """Hop numbers where more than one router answered.

    The parser has kept these since it learned to read continuation lines, and
    nothing has ever read them back: the terminal prints the extra names and no
    conclusion has been allowed to depend on them. That is the collected and
    discarded case, and this is what it is worth.
    """
    return [h["hop"] for h in hops or [] if h.get("also")]


def balanced_between(balanced, first, last):
    """Did the path fan out anywhere between two hop numbers, inclusive.

    Whether an observation about two hops survives depends on what happened
    between them, not on whether the trace load balanced somewhere else
    entirely: a fan-out past the target says nothing about a jump at hop 2.
    """
    lo, hi = min(first, last), max(first, last)
    return [h for h in balanced or [] if lo <= h <= hi]


def mark_fanout(hops, fanned):
    """Note on each hop in a fanned span that a conclusion rests on it.

    Marked here rather than wherever it is drawn, because the question the mark
    answers is "why did the reading below hedge" - and the only place that is
    known is where the hedge was made. A hop that fanned out under a claim
    nobody softened is a true fact about the trace and not an explanation of
    anything, so it stays unmarked: on a backbone that load-balances at half
    its hops, marking them all is a mark nobody reads.
    """
    wanted = set(fanned or [])
    for hop in hops or []:
        if hop.get("hop") in wanted and hop.get("also"):
            hop["fanout_hedged"] = True


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


def annotate_hops(hops, gateway=None, target=None, sent_from=None):
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

    # Two private networks in series before the edge means the traffic
    # crossed at least two routers on the way out.
    #
    # Only before the edge. Scanning the whole trace counted the provider's
    # own core, which is on RFC1918 at plenty of carriers - a path of
    # 192.168.1.1, carrier NAT, 10.250.0.1 was reported as two private
    # networks *inside this site*, naming an address several hops past the
    # point where the site ends.
    edge_at = next((i for i, h in enumerate(hops)
                    if h.get("private") is False or h.get("cgnat")), len(hops))
    private_subnets = []
    for h in hops[:edge_at]:
        if h.get("private") and not h.get("cgnat"):
            sn = subnet24(h.get("host"))
            if sn and sn not in private_subnets:
                private_subnets.append(sn)
    double_nat = private_subnets if len(private_subnets) > 1 else []

    # Where the trace stopped following one path.
    #
    # Classic traceroute varies the destination port on every probe, which is
    # part of the flow identifier a per-flow load balancer hashes on. So under
    # ECMP - ordinary in carrier cores and universal in cloud fabrics - each
    # probe can take a different branch, and the numbered list stops being a
    # path and becomes a sample of several. Paris traceroute exists to fix
    # exactly this and needs raw sockets to do it.
    #
    # It is visible without them. Several routers answering for one hop is that
    # happening, and the parser has always kept them. Three conclusions here
    # read consecutive hops as adjacent, and where the list is a sample of
    # several paths they are not.
    balanced = balanced_hops(hops)

    # Where a router quoted our packet back with a different source on it. Only
    # the constant-flow walk keeps the quote, so this is empty on every other
    # trace and the inference below carries on alone.
    translations = translations_seen(hops, sent_from)

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

    # Where traffic stops being the site's network. The first public hop, or
    # the carrier-NAT segment if there is one: 100.64.0.0/10 is RFC1918-like
    # in that it is not routable on the internet, but it is the provider's
    # range and not the site's. Taking the first public hop alone put the
    # site edge past the carrier's NAT layer, so the picture showed that
    # layer as inside the site while the cgnat finding called it the
    # provider's and the latency wall placed a jump there on their side. The
    # three now agree.
    demarc = next((h["hop"] for h in hops
                   if h.get("private") is False or h.get("cgnat")), None)
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
        "balanced_hops": balanced,
        "translations": translations,
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


# ---------------------------------------------------------------------------
# The addresses this box holds.
#
# has_ipv4 answers "is this box on the network", which is the right question
# for a laptop and far too coarse for a proxy. A box terminating a service
# address alongside its own management address has several, they behave
# differently, and until now a report could not name one of them.
# ---------------------------------------------------------------------------

# An interface header, in the three shapes the three commands write it:
#   ip addr:            "2: eth0: <BROADCAST,MULTICAST,UP>"
#   ifconfig (both):    "eth0: flags=4163<UP,BROADCAST>"
#   ipconfig /all:      "Ethernet adapter Ethernet:"
_IFACE_HEADER = re.compile(
    r"^(?:\d+:\s*(?P<numbered>[^:@\s]+)[:@]"
    r"|(?P<bsd>[A-Za-z][\w.-]*):\s*flags="
    r"|(?:\w[\w ]*adapter\s+(?P<win>[^:]+):))")

_ADDR_LINE = re.compile(
    r"\b(?P<family>inet6?)\s+(?P<addr>[0-9a-fA-F:.]+)"
    r"(?:%[\w.-]+)?(?:/(?P<prefix>\d{1,3}))?", re.I)
_NETMASK = re.compile(r"\bnetmask\s+(0x[0-9a-fA-F]{8}|\d{1,3}(?:\.\d{1,3}){3})")
_PREFIXLEN = re.compile(r"\bprefixlen\s+(\d{1,3})")
_SCOPE = re.compile(r"\bscope\s+(global|link|host|site)\b")

# Windows names the parts on their own lines instead of one address line.
_WIN_ADDR = re.compile(r"IP(?:v4|v6)? Address[.\s]*:\s*([0-9a-fA-F:.]+)", re.I)
_WIN_MASK = re.compile(r"Subnet Mask[.\s]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", re.I)


def _mask_to_prefix(text):
    """A netmask in any of the three notations, as a prefix length.

    BSD writes it hex (0xffffff00), Linux ifconfig and Windows write it dotted
    (255.255.255.0), and `ip` writes the prefix directly. Counting set bits
    rather than looking the value up in a table means a non-contiguous mask -
    legal to write, meaningless in practice - is counted rather than rejected,
    which is the reading that cannot throw on a box someone has misconfigured.
    """
    if not text:
        return None
    try:
        if text.startswith("0x"):
            value = int(text, 16)
        else:
            parts = [int(p) for p in text.split(".")]
            if len(parts) != 4 or any(p > 255 for p in parts):
                return None
            value = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except (TypeError, ValueError):
        return None
    return bin(value).count("1")


def _scope_of(addr, stated):
    """Where an address is usable, taken from the text or read off the address.

    Only `ip` states it. For everything else it comes from the address itself,
    which is not a guess: the ranges are what define the scope.
    """
    if stated:
        return stated
    if _is_loopback(addr) or (addr or "").strip() == "::":
        return "host"
    if _is_link_local(addr):
        return "link"
    return "global"


def parse_own_addresses(iface_result):
    """Every address on this box as {address, prefix, family, interface, scope}.

    One parser over all four command dialects rather than one each, because
    they differ in punctuation and not in content: an interface header, then
    indented address lines beneath it. Windows is the exception that spends a
    line per field, so its mask is carried down to the address above it.

    Addresses are kept in the order the commands print them, which is the order
    they were configured. On an interface holding a primary and a service
    address, that ordering is itself information: the first is the one the
    kernel will choose when nobody says otherwise.
    """
    if not iface_result.get("ok"):
        return []
    out = iface_result.get("stdout") or ""
    found, iface, pending = [], None, None

    for line in out.splitlines():
        header = _IFACE_HEADER.match(line.strip()) or _IFACE_HEADER.match(line)
        if header:
            iface = (header.group("numbered") or header.group("bsd")
                     or (header.group("win") or "").strip())
            pending = None
            continue

        win = _WIN_ADDR.search(line)
        if win:
            pending = {"address": win.group(1), "prefix": None,
                       "family": "inet6" if ":" in win.group(1) else "inet",
                       "interface": iface,
                       "scope": _scope_of(win.group(1), None)}
            found.append(pending)
            continue
        mask = _WIN_MASK.search(line)
        if mask and pending is not None:
            pending["prefix"] = _mask_to_prefix(mask.group(1))
            pending = None
            continue

        m = _ADDR_LINE.search(line)
        if not m:
            continue
        addr = m.group("addr")
        # "inet" is also a word inside flag lists and encapsulation names; an
        # address has to look like one.
        if "." not in addr and ":" not in addr:
            continue
        prefix = m.group("prefix")
        if prefix is not None:
            prefix = int(prefix)
        else:
            plen = _PREFIXLEN.search(line)
            netmask = _NETMASK.search(line)
            prefix = (int(plen.group(1)) if plen
                      else _mask_to_prefix(netmask.group(1)) if netmask else None)
        scope = _SCOPE.search(line)
        found.append({"address": addr, "prefix": prefix,
                      "family": m.group("family").lower(), "interface": iface,
                      "scope": _scope_of(addr, scope.group(1) if scope else None)})
    return found


def service_addresses(addresses):
    """The addresses that look configured onto this box to be served, not to be
    the box - keepalived, VRRP, a load balancer's front end.

    The signature is a host route sitting on an interface that also carries a
    real subnet: /32 for IPv4 or /128 for IPv6 beside a /24. A box's own
    address comes with the prefix of the network it is on, because that is what
    tells it who is local. A service address does not need that and is
    conventionally given none, so the pair on one interface is the shape worth
    reporting.

    Deliberately a shape and not a certainty. A point-to-point link and some
    cloud instances present a /32 for the box's own address, which is why this
    is context in a report rather than a fault, and why it requires the second
    address to be there: alone, a /32 is just how that network is built.
    """
    host_route = {"inet": 32, "inet6": 128}
    by_iface = {}
    for entry in addresses:
        if entry.get("scope") != "global":
            continue
        by_iface.setdefault(entry.get("interface"), []).append(entry)

    out = []
    for entries in by_iface.values():
        for entry in entries:
            if entry.get("prefix") != host_route.get(entry.get("family")):
                continue
            if any(o is not entry and o["family"] == entry["family"]
                   and o.get("prefix") not in (None, host_route[o["family"]])
                   for o in entries):
                out.append(entry)
    return out


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
    ("source_address_not_held", "this device, or whatever should have failed over to it",
     "The address this run was told to measure from is not on this box",
     "Either the address moved to its partner and this is now the standby, or it "
     "was never configured here. Check the failover state before reading anything "
     "else in this report: none of it was measured from the address you asked for."),
    ("service_address_unserved", "whatever should be accepting on this address",
     "A service address is configured here and nothing is accepting on it",
     "Check the service is running and bound as you think. If this box forwards in "
     "the kernel (IPVS, DNAT, direct return) there is no listener to find and this "
     "is expected."),
    ("source_cannot_reach", "whatever routes or filters by source address",
     "One of this box's addresses cannot reach the target while others can",
     "The box is not the problem - the same routing table serves all of them. Look "
     "at what treats that source differently: a policy route, a firewall matching "
     "on source, or an address something upstream still sends elsewhere."),
    ("service_endpoint_idle", "whatever steers clients to that port, or the instance behind it",
     "One listener on this address is serving nobody while another on it is busy",
     "The address works - traffic is arriving on it and going to a different port. "
     "Check the instance behind the idle port, and what is meant to be sending "
     "clients to it."),
    ("service_address_idle", "the failover pair, or whatever steers traffic to it",
     "A service address is up and served here, and no traffic is arriving on it",
     "Traffic for it is going elsewhere. Check the failover state on both nodes and "
     "whether a load balancer has taken this one out of rotation."),
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
    ("path_jitter_backends", "the path between this box and what it connects out to",
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
    ("tcp_flow_loss_backends", "the segment between this box and what it connects out to",
     "The loss is on what this box talks to, not on what talks to it",
     "Client connections are clean, so the service and the path to your users "
     "are fine. Look at the internal segment between here and the backend named "
     "in the finding - this is inside your own network, not the carrier's."),
    ("tcp_flow_loss_clients", "the path between this box and the people using it",
     "The loss is on what talks to this box, not on what it talks to",
     "Everything this box depends on is clean, so the service itself is healthy. "
     "The loss is between here and your users - the edge, the load balancer in "
     "front, or the internet path to them."),
    # Below the loss findings above, deliberately. A side losing traffic is the
    # nearer cause of a side gone quiet, and where both fire the percentage is
    # the more useful sentence - it says how much is getting through, where this
    # only says that something is not. Above the service findings below, because
    # a return path carrying nothing is a network fault and they are not.
    #
    # These are the only findings drawn from lastsnd, lastrcv and lastack, and
    # they are what the split arrowhead has always been drawn from. It was drawn
    # without a finding underneath it for long enough that a report could show a
    # broken return leg over a verdict reading "no fault found".
    ("tcp_return_stalled_backends", "what this box connects out to, or the path back from it",
     "This box is sending to its backends and nothing is coming back",
     "The connections are open and this box is still sending on them. Nothing "
     "has arrived back - no reply and no acknowledgement either, which is what "
     "separates this from a backend that is merely slow to answer. Traffic is "
     "leaving here and not returning: look at the segment out to the backend "
     "named below, and at whether that host is up at all."),
    ("tcp_return_stalled_clients", "the path back to the people using it",
     "This box is answering clients and nothing is coming back",
     "This box is sending responses and the clients are not acknowledging them. "
     "The requests arrived, so the way in works and the service is answering - "
     "it is the way back out to your users that has stopped carrying. Look at "
     "the edge, the load balancer in front, or the path to them."),
    # Above the certificate findings: a service that answers nothing is more
    # broken than one whose certificate is wrong, and a client meets it first.
    # Above the findings that need a completed connection, because it is the
    # reason they could not run: nothing below here got as far as a handshake.
    ("answered_closer_than_the_path", "something between here and the target",
     "Something nearer than the target is answering for it",
     "A handshake that finished sooner than the path allows, and a reply from fewer "
     "hops than the trace walked. That is what a transparent proxy looks like from "
     "here, and it is usually policy rather than a fault - but everything below about "
     "reaching that address describes the connection to whatever answered."),
    ("proxy_unreachable", "the proxy this box is told to use, not the path to it",
     "The proxy every application here is told to use does not answer",
     "Nothing else on this report will show it: every probe here goes direct and does "
     "not read the proxy setting, so they pass while nothing on the box can load "
     "anything. Check the proxy is up and that this box is allowed to reach it."),
    ("proxy_backend_down", "the backend the proxy stopped using, not this box",
     "The proxy here has taken backends out of rotation",
     "The proxy's own health checks decided these are not answering. It knows which "
     "check failed and how long they have been out, which nothing else here can see. "
     "Start with the check it names rather than with the network."),
    ("own_service_not_accepting", "the service on this box, or a rule in front of it",
     "This box cannot finish a connection to its own listener",
     "Nothing was refused, so something is listening and is not completing the "
     "handshake. Check the accept queue and whether a rule on this box is dropping "
     "traffic to that port - a packet that cannot cross from this box to itself will "
     "not cross from a client."),
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
    # Above "nothing is reaching it", because it is the reason nothing is:
    # a client refused at the firewall never becomes a connection, so the
    # absence below is this rule's consequence and not a separate fact.
    ("inbound_filtered_here", "this box's own firewall, possibly by design",
     "This box is dropping traffic addressed to a port it serves",
     "Clients refused at the firewall never reach the service, so every check below "
     "passes while nobody gets served. Read the rule named below and decide whether it "
     "is meant to be catching this traffic."),
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
    ("tunnel_payload_short", "the path's packet size, not this box",
     "A datagram tunnel here has less room than what it carries expects",
     "Small packets fit and large ones do not, so ping, DNS and handshakes all pass "
     "while transfers stall inside the tunnel. Raise the path MTU, or lower the MTU of "
     "whatever is handed to the tunnel so it stops sending packets that will not fit."),
    ("target_is_discarded", "this box's own routing table, not the network",
     "This box throws away traffic to the target instead of sending it",
     "A blackhole, unreachable or prohibit route on this box catches the address being "
     "diagnosed. Nothing past here is involved and no reachability result below means "
     "anything. Remove the route, or aim at something outside it."),
    ("transport_fell_back", "the path between the clients and here, not this box",
     "Clients are reaching this box over TCP because datagrams are not getting through",
     "The fallback works, which is why nothing is failing and nobody will report it. "
     "What it costs is the reason the datagram transport exists: one lost packet stalls "
     "the whole tunnel instead of one packet inside it. Look for what is stopping UDP on "
     "that port between the clients and here."),
    ("udp_queue_standing", "an application on this device",
     "Datagrams are arriving faster than the service is reading them",
     "The kernel has taken delivery and the process has not. Nothing on the wire is "
     "wrong and the sender is never told - a datagram plane has no window to push back "
     "with, so the queue fills and then the kernel drops. Look at what the listener is "
     "doing rather than at the network."),
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
    # Ranked above double_nat because it is about the same thing and knows it
    # rather than suspecting it. Where both fire, the observation should be the
    # headline and the inference should read as backing it up.
    ("nat_observed", "the site network",
     "A device on the way out is rewriting this box's address",
     "This is measured rather than guessed: a router past that point quoted our own "
     "packet back with a different source on it, which is what translation is. Inbound "
     "connections and port forwarding do not survive it without configuration, and it "
     "puts a device in the path that holds state per connection - worth knowing about "
     "before chasing an intermittent fault through it."),
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
                  # Which address the run left from, and which addresses this box
                  # serves rather than owns. Both reframe how every measurement
                  # below should be read, and neither is a fault.
                  "service_address_present", "bound_to_source_address",
                  # Serving clients while connected to nothing. Two ordinary
                  # boxes look identical here, so it names both and judges
                  # neither.
                  "no_upstream_sessions",
                  # Says a question cannot be answered from a socket table,
                  # which is the opposite of a fault to rank.
                  "clients_may_be_on_the_datagram_plane",
                  "tunnel_payload_room",
                  "forwards_inside_tunnels",
                  "trace_took_another_route",
                  # What arrived on one side against what left on the other.
                  # A policy refusing requests and a box that stopped
                  # forwarding look the same here, so it names both.
                  "relay_volume_lopsided",
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
                  # How this box is told to reach the internet. It says nothing
                  # about whether anything is broken - only that the checks and
                  # the traffic may not take the same route.
                  "proxy_configured",
    "pmtu_reduced",
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
    "tcp_return_stalled_backends", "tcp_return_stalled_clients",
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
    # An address that should be here and is not. Local even when the reason is
    # a failover that happened elsewhere: the box being asked is the box that
    # does not have it.
    "source_address_not_held",
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
    "tcp_return_stalled_clients": "downstream",
    "service_address_unserved": "downstream",
    "service_address_idle": "downstream",
    "service_endpoint_idle": "downstream",
    "source_cannot_reach": "upstream",
    "clients_may_be_on_the_datagram_plane": "downstream",
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
    "udp_queue_standing": "downstream",
    "transport_fell_back": "downstream",
    "inbound_filtered_here": "downstream",
    "target_is_discarded": "upstream",
    "tunnel_payload_short": "upstream",
    # Context about the path out, same as the fault it is the other half of.
    "tunnel_payload_room": "upstream",
    # About the way out, and specifically about what it does not cover.
    "forwards_inside_tunnels": "upstream",
    "trace_took_another_route": "upstream",
    # The certificate this box serves is only ever seen by whoever connects.
    "own_tls_expired": "downstream",
    "own_service_not_accepting": "downstream",
    "proxy_backend_down": "upstream",
    "proxy_unreachable": "upstream",
    "answered_closer_than_the_path": "upstream",
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
    "tcp_return_stalled_backends": "upstream",
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
    "nat_observed": "upstream",
    "pmtu_blackhole": "upstream",
    "pmtu_reduced": "upstream",
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
    # The way in. Everything after this walks outward from the box, so a fault
    # on the traffic arriving at it has no stage of that chain to land on - and
    # it used to land on "internet", which reads as the way out. A report could
    # then say the loss was on what talks to this box, over a strip announcing
    # that the internet had failed, and both halves were the tool's own words.
    # This stage is the inbound leg the strip was missing; it reads "-" on a box
    # nothing is connected to, where there is no such leg to judge.
    # "no clients connected" is deliberately absent: it fires exactly when
    # there is no inbound leg, and the answer to that is "-", not a warning
    # about a direction this box does not have.
    ("clients", set(),
     {"service_address_unserved", "service_address_idle", "service_endpoint_idle",
      "tcp_flow_loss_clients", "tcp_return_stalled_clients",
      "path_jitter_clients", "queuing_delay_clients",
      "syncookies_live", "syncookies_historical", "syn_recv_backlog",
      "reqq_full_drops", "fd_pressure",
      # The rest of the accept path. Overflowing the accept queue is the
      # plainest way a box turns clients away, and sockets left in CLOSE_WAIT
      # are how it runs out of room to accept into - both were headlining over
      # a strip with nothing on it.
      "accept_overflow_live", "accept_overflow_historical",
      "close_wait_backlog", "udp_queue_standing", "transport_fell_back",
      "inbound_filtered_here"}),
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
    ("address", {"no_ipv4", "no_gateway", "duplicate_ip", "virtual_router_conflict",
                 "target_is_discarded",
                 "source_address_not_held"},
     {"interfaces_unreadable", "routes_unreadable",
      "neigh_table_full", "neigh_table_near_limit"}),
    ("gateway", {"gw_unreachable"},
     {"gw_partial_loss", "gw_unknown", "gw_loss_unmeasured"}),
    # A routing loop means traffic never arrives, so it fails the stage rather
    # than merely warning it.
    ("internet", {"inet_unreachable", "destination_unresponsive", "loop",
                  # One address failing while its neighbours succeed is a
                  # failure of this stage for whoever uses that address, even
                  # though the run's own probe reached the target.
                  "source_cannot_reach",
                  "conntrack_drops_live"},
     {"inet_partial_loss", "inet_loss_unmeasured", "path_loss", "trace_stalls",
      "latency_wall", "latency_high", "tcp_retransmits", "path_admin_prohibited",
      # The uplink is this site's internet stage, whoever owns the congestion.
      "uplink_saturated", "saturation_bursts", "uplink_busy", "egress_blocked",
      "tcp_flow_loss_some_peers", "tcp_flow_loss_one_peer", "tcp_flow_loss_unclear",
      "tcp_flow_loss_backends", "tcp_return_stalled_backends",
      "queuing_delay", "queuing_delay_backends",
      "path_jitter_backends",
      "syn_retrans_high", "tcp_checksum_errors", "connect_failures_high",
      "resets_sent_high", "connections_reset_by_peer",
      "udp_recv_buffer_full", "udp_datagrams_corrupt", "fragments_lost",
      "tcp_orphans_high",
      "retrans_spurious",
      # Listed as warnings, but build_stages promotes a critical to fail, so
      # "degraded" warns the stage and "unusable" fails it without a second rule.
      "call_quality_degraded", "call_quality_bad",
      "conntrack_near_limit", "conntrack_drops_historical",
      # Ceilings that stop this box opening connections of its own. The ones
      # that stop it *accepting* face the other way and belong to "clients".
      "no_traffic_at_all", "ephemeral_ports_low",
      "aborts_on_memory", "aborts_on_timeout",
      # Attempts outward that nothing answers, which is the same stage as the
      # retransmitted SYNs and failed connects already here.
      "syn_sent_backlog",
      # The rest of the per-flow readings. The loss ones are above; these two
      # say the flow was held up by a buffer at one end rather than by the
      # path, which is an answer about the way out and belongs beside them.
      "tcp_flow_sendbuf_limited", "tcp_flow_receiver_limited",
      # What sits between this site and the internet. Neither is a fault on
      # its own, and both change what the way out can do.
      "cgnat", "double_nat", "nat_observed", "proxy_backend_down",
      "proxy_unreachable", "answered_closer_than_the_path"}),
    ("dns", {"dns_fail", "dns_all_resolvers_down", "dns_no_resolvers"},
     {"dns_resolver_down", "dns_resolver_slow", "dns_hijack", "dns_disagree",
      "resolvers_unreadable"}),
    ("mtu", {"pmtu_blackhole"}, {"pmtu_unmeasurable", "mtu_nonstandard",
                                 "tunnel_payload_short"}),
    ("ports", {"no_route_to_target", "port_host_unreachable",
               "tls_handshake_failed", "tls_expired", "tls_not_yet_valid",
               "own_tls_expired", "own_tls_handshake_failed",
               "own_service_silent", "own_service_erroring",
               "own_service_not_accepting",
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
    # Only present when no command could list the interfaces, and it belongs
    # to the address stage rather than the link one: it says the box has an
    # address, not which interface carries it.
    "kernel_source_address": "address",
    # Which addresses this box holds, which of them it serves rather than
    # owns, and which one this run left from.
    "own_addresses": "address", "service_addresses": "address",
    # One row per thing this box serves. The ports stage, because that is
    # where what this box offers is judged.
    "service_instances": "ports",
    "source_address": "address", "source_address_held": "address",
    "neigh_table": "address",
    "ping_gateway": "gateway",
    "ping_internet": "internet", "path_trace": "internet",
    # One capture, two stages: the same `ss` output carries loss to backends
    # and loss to clients, and they now sit on opposite ends of the strip. It
    # is evidence for both, so it survives while either is unwell - keyed to
    # one of them, a client-side fault would drop the very output it was read
    # from out of a compact export.
    "tcp_flows": ("internet", "clients"), "tcp_health": "internet",
    # The fallback when ping is filtered: reaching the target the way an
    # application would, before calling a site's uplink down.
    "reachability_tcp": "internet",
    "proxy": "internet",
    # Kept when the TCP path is used instead, so both attempts are on record.
    "path_trace_icmp": "internet",
    "path_mtu": "mtu",
    # Which route this box would use for the target: the way out.
    "route_to": "internet",
    # The address the target resolved to, kept beside the kind it is.
    "target_ip": "internet",
    "dns_lookup": "dns", "dns_health": "dns",
    # Same again: socket states answer the ports stage, while the accept queue,
    # SYN cookies and the descriptor ceiling read from them answer "clients".
    "sockets": ("ports", "clients"), "ports": "ports",
    "source_matrix": "internet",
    # Which target the matrix asked about, so a row means something on its
    # own. Same stage as the matrix it labels.
    "probe_target": "internet",
    # The other plane. Kept for the clients stage, because what it answers
    # is whether an empty TCP table means an empty box.
    "udp_sockets": "clients",
    "udp_tunnels": "clients",
    # Read from the same table and answering the same two stages: who is
    # listening belongs to ports, who is holding them open to clients.
    "socket_owners": ("ports", "clients"),
    # An egress queue is the link stage: it is this box's own interface
    # holding traffic, which is what that stage is about.
    "qdisc": "link",
    # What the proxy thinks of what it connects out to.
    "proxy_stats": "internet",
    # Whether the proxy this box is told to use answers at all.
    "proxy_reachable": "internet",
    # Egress rules are the way out, which is the internet stage.
    "firewall": "internet",
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
    """Which stages a captured command belongs to, as a tuple, or None if it
    belongs to none and must therefore always be kept.

    A tuple because one capture can answer for two stages: `ss` output is read
    for loss to backends and loss to clients alike, and those are now opposite
    ends of the strip.
    """
    stage = None
    if key in RAW_STAGE:
        stage = RAW_STAGE[key]
    else:
        for prefix, mapped in RAW_STAGE_PREFIXES:
            if key.startswith(prefix):
                stage = mapped
                break
    if stage is None:
        return None
    return stage if isinstance(stage, tuple) else (stage,)


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

    Evidence is kept when any stage it answers for is not passing, and when a
    check could not run at all: a gap in coverage is a thing the reader has to
    be able to see, and a missing panel would look like a check that passed.
    """
    slim = {k: v for k, v in report.items() if k not in ("raw", "panel_help")}
    state = {s["stage"]: s["state"] for s in report.get("stages") or []}
    keep = {}
    for key, value in (report.get("raw") or {}).items():
        stages = raw_stage(key)
        ran = not isinstance(value, dict) or value.get("ok", True)
        unwell = stages and any(state.get(s) in ("fail", "warn") for s in stages)
        if stages is None or unwell or not ran:
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
        # A box nothing connects to has no inbound leg, and "-" is the answer
        # for a stage nobody measured. Reading PASS there would claim the way
        # in is healthy on a box where it was never looked at.
        #
        # A finding overrides that, because it is itself proof there was
        # something to measure: a box whose accept queue is overflowing is
        # being connected to, whatever the open-socket count came to while the
        # kernel was busy refusing them.
        elif (name == "clients" and not _serves_traffic(raw)
                and not codes & (fail_codes | warn_codes)):
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


# What a hop's own loss percentage has to reach to be drawn as a fault. Only mtr
# reports one; a traceroute is judged on how many of its probes came back.
HOP_LOSS_CRIT_PCT = 20
HOP_LOSS_WARN_PCT = 5


def count_the_hops_in(legs, quick=False):
    """How many hops away each side is, off the TTL of a reply from it.

    The way in has never had a path. A traceroute goes outward, so the route a
    client's packets took to arrive cannot be watched from here, and the inbound
    side has only ever been described by what its connections are doing.

    A reply's TTL is the one thing that carries it: each router on the way here
    decrements it, so the difference from where the sender started is the hops
    that reply crossed. One ping per side, to a host this box already holds
    connections to.

    Absent whenever the peer does not answer ICMP, which for internet clients
    behind a firewall is most of the time. Blank is the ordinary case here, not
    a failure, and it must not read as zero.
    """
    if quick:
        return
    for side in (legs or []):
        peer = str(side.get("peer") or "")
        if not _looks_like_ipv4(peer):
            continue
        inbound = hops_from_ttl(parse_ping_ttl(cmd_ping(peer, 1, 1)))
        if inbound:
            side["hops_in"], side["ttl_assumed"] = inbound


def name_the_addresses(shown, raw, quick=False):
    """Reverse-resolve the handful of addresses a report actually displays.

    The neighbour inventory has resolved names since it was written, and nothing
    else has: every column heading, finding message and hop row has carried a
    bare address. `10.0.2.40` is a fact a reader has to go and look up;
    `db-primary` is one they can act on.

    Only what is on the page. A forward proxy holds connections to hundreds of
    destinations and resolving all of them would be hundreds of lookups for
    names nobody will read - so this takes the peers the columns name, the
    destination that was traced, and the hosts on its hops.

    Bounded by the same deadline the inventory uses, against the resolver this
    box is already configured with. Whatever has not answered when it expires
    stays an address, which is the honest fallback and the common one.
    """
    if quick:
        return {}
    resolvers = [r.get("server") for r in
                 ((raw.get("dns_health") or {}).get("resolvers") or [])
                 if r.get("server")]
    wanted = sorted({a for a in shown if a and _looks_like_ipv4(a)})
    if not resolvers or not wanted:
        return {}
    resolver = resolvers[0]
    deadline = time.monotonic() + PTR_DEADLINE_SECONDS

    def lookup(ip):
        if time.monotonic() > deadline:
            return None
        return dns_ptr(resolver, ip, timeout=1.0)

    names = {}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(PTR_WORKERS, len(wanted))) as pool:
        for ip, name in zip(wanted, pool.map(lookup, wanted)):
            # A PTR record is written by whoever owns the reverse zone, which is
            # not necessarily whoever owns the host. It is a label to read, and
            # nothing here may decide anything from it - the address stays the
            # thing that gets acted on, which is why the page shows both.
            if name and name.rstrip(".") != ip:
                names[ip] = name.rstrip(".")
    return names


def _looks_like_ipv4(value):
    parts = str(value).split(".")
    return (len(parts) == 4
            and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))


def addresses_on_the_page(report):
    """Every address the report will actually show, and no others."""
    shown = set()
    for side in (report.get("path_legs") or []):
        shown.add(side.get("peer"))
        shown.update((side.get("left"), side.get("right")))
    columns = [s.get("traced") for s in (report.get("path_legs") or [])]
    for column in columns + [report.get("probe_path")]:
        if not column:
            continue
        shown.add(column.get("target"))
        shown.update(h.get("host") for h in (column.get("hops") or []))
    return {a for a in shown if a and _looks_like_ipv4(a)}


def build_probe_column(hops, target, baseline_path=None):
    """The traced path as a column beside the two measured ones.

    It used to be a titled section with a full-width ribbon and a row of hop
    boxes. On the 150 reports in 164 where every hop is clean that was the
    largest thing on the page and the last one - a picture of a path nobody
    asked about, drawn at the size of an answer.

    One column, always present, because the trace always runs: the hops stay
    visible on every report rather than only on the fourteen that mark one. What
    a fault changes is the colour and which row is called out.

    One leg, not two. A traceroute is one way, so there is no return measurement
    to draw, and drawing one anyway is the mistake the boundary arrow carried
    for two releases.

    Each hop's state is settled here rather than in the page. It used to live in
    the viewer as hopSeverity, which is a second copy of a threshold the moment
    anything else needs to ask - and it meant the only test of it had to run
    JavaScript.
    """
    if not hops:
        return None
    rows, run = [], 0.0
    for hop in hops:
        # Averaged here when nobody has done it already. The target's hops come
        # through the path pipeline, which adds avg_ms on the way; the ones
        # traced to a backend come straight from the parser and carry only the
        # individual timings. Reading avg_ms alone gave every one of those a
        # null, and the page rendered it as "nullms".
        avg = hop.get("avg_ms")
        if avg is None:
            times = [t for t in (hop.get("times_ms") or []) if t is not None]
            avg = sum(times) / len(times) if times else None
        delta = max(0.0, (avg or 0) - run)
        if avg is not None:
            run = avg
        blame = hop.get("blame") or {}
        rows.append({
            "hop": hop.get("hop"),
            "host": hop.get("display") or hop.get("host") or "*",
            "ms": round(avg, 1) if avg is not None else None,
            "delta_ms": round(delta, 1) if delta >= 1 else None,
            "timed_out": bool(hop.get("timed_out")),
            "loss_pct": hop.get("loss_pct"),
            "probes": len(hop.get("times_ms") or []),
            # A hop the report called cosmetic is loss at an intermediate router
            # that clears by the destination - context, not a fault, and the
            # chain must not colour it as one.
            "cosmetic": bool(hop.get("cosmetic")),
            "blame": (blame.get("code") or "").replace("_", " ") or None,
            "_severity": blame.get("severity"),
            "edge": hop.get("enters_network") or None,
            # How many routers answered here, and only where a conclusion below
            # was softened because of it. Zero everywhere else, so the page can
            # draw the explanation without drawing every fan-out on the path.
            "fanout": (len(hop.get("also") or []) + 1
                       if hop.get("fanout_hedged") else 0),
            "fanout_also": (list(hop.get("also") or [])
                            if hop.get("fanout_hedged") else []),
        })

    most = max((r["probes"] for r in rows), default=0)
    total = run or 0.0
    for row in rows:
        if row["cosmetic"]:
            row["state"] = "ok"
        elif row["blame"]:
            row["state"] = "crit" if row["_severity"] == "critical" else "warn"
        elif row["timed_out"]:
            row["state"] = "crit"
        elif row["loss_pct"] is not None:
            row["state"] = ("crit" if row["loss_pct"] >= HOP_LOSS_CRIT_PCT
                            else "warn" if row["loss_pct"] >= HOP_LOSS_WARN_PCT
                            else "ok")
        # Fewer timings than the rest of the path returned means probes went
        # missing here. Only where the path gives a real sample: a source that
        # reports one timing per hop would otherwise mark every hop on it.
        elif most >= 3 and row["probes"] and row["probes"] < most:
            row["state"] = "warn"
        else:
            row["state"] = "ok"
        row.pop("_severity", None)
        # Every marked hop says why, in words. Red and green are the commonest
        # pair a reader cannot tell apart, and this was the one place a severity
        # arrived as a tint and nothing else - the stage chips say FAIL, the
        # zones say FAULT, a finding carries its severity in its tag.
        row["why"] = (row["blame"]
                      or ("no reply" if row["timed_out"] else None)
                      or ("%g%% loss" % row["loss_pct"]
                          if row["loss_pct"] and row["state"] != "ok" else None)
                      or ("fewer replies than the rest of the path"
                          if row["state"] == "warn" else None))
        row["share_pct"] = (round(row["delta_ms"] / total * 100)
                            if row["delta_ms"] and total else None)

    # Where this site's network stops and somebody else's begins: the first hop
    # that is public, or the carrier's own NAT range if there is one. The same
    # rule the path pipeline applies to the target's trace, asked again here so
    # that a path traced to a peer gets it too - those hops come straight from
    # the parser and carry none of that enrichment.
    #
    # It is the most useful single boundary on a path, because it is the one
    # that answers who to escalate to, and the page lost it with the hop chain.
    for row in rows:
        host = row["host"] or ""
        private = is_private_ip(host) if host and host != "*" else None
        row["site_edge"] = bool(private is False
                                or (host.startswith("100.") and private))
    first = next((r for r in rows if r["site_edge"]), None)
    for row in rows:
        row["site_edge"] = row is first

    # The same path on the last visit, where there was one. A line rather than a
    # second ribbon: it is a comparison, not a measurement, and it only exists
    # on runs given --baseline.
    was = None
    if baseline_path:
        old = [h for h in baseline_path if h.get("avg_ms")]
        if old:
            was = "last run: %d hops, %.1fms" % (len(baseline_path), old[-1]["avg_ms"])
            moved = (old[-1]["avg_ms"] - total) if total else 0
            was += (" (%+.1fms now)" % -moved) if abs(moved) >= 1 else " - unchanged"
    return {
        "target": target,
        "state": ("fail" if any(r["state"] == "crit" for r in rows)
                  else "warn" if any(r["state"] == "warn" for r in rows) else "pass"),
        "hops": rows,
        "total_ms": round(total, 1) if total else None,
        "baseline": was,
    }


def _quiet_side(name, state, sock, raw):
    """A boundary with nothing measured across it, drawn rather than dropped.

    Two different silences, and telling them apart is the whole value of
    showing it: nothing is connected on this side, which is a fact about the
    box, or something is and the per-connection statistics could not be read,
    which is a fact about what could be looked at. A blank column that does not
    say which is worse than no column at all.
    """
    far = ("what this box connects out to" if name == "backend" else "clients")
    connected = (sock.get("inbound") if name == "client"
                 else sock.get("outbound")) or 0
    flows = (raw or {}).get("tcp_flows") or {}
    if connected:
        why = ("%d connection(s) cross here and none of them could be measured: %s"
               % (connected, flows.get("error")
                  or "the per-connection statistics were not readable"))
    elif name == "client":
        why = "nothing is connected inbound, so no traffic is arriving to measure"
    else:
        why = ("this box holds no outbound connection of its own, so nothing is "
               "leaving it to measure")
    return {"side": name, "state": state or "skip",
            "title": ("this box and what it connects out to" if name == "backend"
                      else "clients and this box"),
            "peer": None, "connections": connected, "via": None,
            "rtt_ms": None, "loss_pct": None,
            # Same convention the measured column uses: this box on the
            # inside of the boundary, the far side on the outside. Both ends
            # named, or the reader cannot tell which gap the column is.
            "left": "this box" if name == "backend" else far,
            "right": far if name == "backend" else "this box",
            "legs": [], "quiet_because": why}


def build_path_legs(raw=None, sides=None):
    """The path as four legs: out and back, on each side of this box.

    A box that relays has two sides and two directions on each, and until now
    the page drew a chain per side and left the directions to an arrowhead. The
    four legs are what a reader is actually asking about - the request arrived,
    the request went out, the answer came back, the answer went out - and each
    one has its own evidence.

    Grouped by side rather than run end to end, because the two sides are
    different equipment with different owners. That split is already in the
    data: `by_side` exists for exactly this reason.

    Nothing here is new measurement. It is the same fields the arrow and the two
    chains were reading, arranged the way the question is asked.
    """
    flows = ((raw or {}).get("tcp_flows") or {})
    by_side = flows.get("by_side") or {}
    # The state the three boxes already give this side. Taken rather than worked
    # out again: a column heading that disagrees with the box above it is the
    # contradiction this whole panel replaced.
    zone = {"client": "downstream", "backend": "upstream"}
    zoned = {z.get("side"): z.get("state") for z in (sides or [])}
    out = []
    # Both sides, always. Three boxes are three places and the two columns are
    # the two boundaries between them, so dropping the side with nothing on it
    # left one column under three boxes - which reads as a single path straight
    # through with the middle box bypassed. The boundary exists whether or not
    # anything crossed it today.
    sock = (raw or {}).get("sockets") or {}
    for name, near, out_first in (("client", by_side.get("client"), False),
                                  ("backend", by_side.get("backend"), True)):
        if not near:
            out.append(_quiet_side(name, zoned.get(zone[name]), sock, raw))
            continue
        total = near.get("connections") or 0
        stalled = bool(near.get("return_stalled"))
        confirmed = (near.get("delivered_anyway") or 0)
        waiting = near.get("unanswered") or 0
        readable = near.get("volume_readable")

        def volume(key):
            # "Carried nothing" and "could not be measured" are different
            # answers, and a byte count printed for both would merge them.
            if not readable:
                return None
            return _fmt_bytes(near.get(key) or 0)

        # The leg away from this box. An acknowledgement is proof the data
        # arrived, so a side that is hearing anything back is a side whose
        # outbound direction is carrying. When nothing comes back at all, that
        # proof is exactly what is missing - "my data is arriving and their
        # replies are not" and "my data is not arriving" look identical from
        # here - so the leg is unknown rather than either colour.
        out_ev = []
        vol = volume("bytes_out")
        if vol:
            out_ev.append("%s sent" % vol)
        if confirmed:
            out_state = "pass"
            out_ev.append("%d of %d connections confirmed data resent had "
                          "already arrived" % (confirmed, total))
        elif stalled:
            out_state = "unknown"
            out_ev.append("arrival cannot be confirmed while nothing is coming "
                          "back")
        else:
            out_state = "pass"
            out_ev.append("acknowledged, so it is arriving")

        # The leg towards this box.
        back_ev = []
        vol = volume("bytes_in")
        if vol:
            back_ev.append("%s received" % vol)
        if stalled:
            back_state = "fail"
            back_ev.append("%d of %d connections silent"
                           % (near.get("silent_return") or 0, total))
            back_ev.append("no data and no acknowledgement")
            share = near.get("silent_share_pct")
            if (near.get("silent_return") or 0) * 2 < total and share:
                back_ev.append("carrying %d%% of this side's traffic" % share)
        elif waiting:
            # Acknowledged and not answered. The path back is carrying, so this
            # is not a network fault and must not be drawn as one - but it is
            # the answer to "why is nothing coming back" and the reader needs it.
            back_state = "warn"
            back_ev.append("%d of %d acknowledged and not answered" % (waiting, total))
            back_ev.append("the path back is carrying; the far end is slow")
        else:
            back_state = "pass"
            back_ev.append("answering" if name == "backend" else "arriving")

        peer = str(near.get("worst_peer") or "")
        far = (peer.rsplit(":", 1)[0] if peer.count(":") == 1 else peer) or (
            "what this box connects out to" if name == "backend" else "clients")
        this = "this box"
        legs = [
            {"direction": "out", "state": out_state,
             "what": "request out" if name == "backend" else "response out",
             "src": this, "dst": far, "evidence": out_ev},
            {"direction": "back", "state": back_state,
             "what": "response back" if name == "backend" else "request in",
             "src": far, "dst": this, "evidence": back_ev},
        ]
        if not out_first:
            legs.reverse()          # a client's request arrives before we answer
        out.append({
            "side": name,
            "state": zoned.get(zone[name]) or "pass",
            "title": ("this box and what it connects out to" if name == "backend"
                      else "clients and this box"),
            "peer": far,
            # The side's own facts, kept off the legs. A retransmit ratio counts
            # packets this box had to send again and cannot say which direction
            # lost them, so putting it on a leg would attribute a direction the
            # number does not have.
            "connections": total,
            # The address most of this side's connections go through, where one
            # dominates - a balancer in front, or a single backend. Carried so
            # whatever traces this side can pick the path nearly everything
            # takes rather than an outlier.
            "via": (near.get("via") or "").rsplit(":", 1)[0] or None,
            "rtt_ms": near.get("rtt_ms"),
            "loss_pct": near.get("worst_loss_pct"),
            "left": this if name == "backend" else far,
            "right": far if name == "backend" else this,
            "legs": legs,
        })
    # Only when neither boundary has anything to say. One column has never been
    # a shape this panel should draw.
    return out if any(side["legs"] for side in out) else None


# The headline per finding, for the zone that has to say which finding it owns
# rather than repeat the measurement taken on the other side of the box.
HEADLINE = {code: head for code, _o, head, _n in VERDICT_RULES}


# Which box the verdict blames, where that is not the box its direction lights.
#
# Membership is not a judgement call: it is every finding whose owner names this
# box, or something running on it, as the thing at fault. The suite derives that
# list from the owner text and fails if this set is not exactly it.
#
# The first version of this was built by hand from the findings that said "not
# the network", which read like the right filter and was not: egress_blocked
# owns this box's own policy without using the phrase, so the blocked-egress
# report went on saying "no outbound internet from here" over a box drawn OK.
# Twelve of the nineteen were missed that way.
#
# FINDING_SIDE answers which direction stopped working. The owner answers whose
# fault it is. For most findings those are the same box; for these they are not,
# and the panel drew only the first - so the port-exhaustion report coloured the
# way out while its own owner said "not the network", and left the box it blamed
# green. It was the first thing a reader looked at and disbelieved.
#
# Running out of ephemeral ports really does break the way out, and running out
# of descriptors really does break the way in: the direction is right and is
# kept. What is added is who owns it.
CAUSE_OWNED_BY_BOX = frozenset({
    # The way in: something on this box turns clients away, or answers them
    # wrongly, or runs out of room to accept them.
    "accept_overflow_historical",
    "accept_overflow_live",
    "close_wait_backlog",
    "fd_pressure",
    "own_service_erroring",
    "own_service_not_accepting",
    "own_service_silent",
    "own_tls_expired",
    "own_tls_expiring",
    "own_tls_handshake_failed",
    "own_tls_untrusted",
    "reqq_full_drops",
    "syn_recv_backlog",
    "inbound_filtered_here",
    "target_is_discarded",
    "udp_queue_standing",
    "syncookies_historical",
    "syncookies_live",
    # The way out: something on this box stops it reaching what it needs.
    "dns_no_resolvers",
    "egress_blocked",
    "ephemeral_ports_low",
    "no_gateway",
    "tls_not_yet_valid",
})

def cause_owner_side(code):
    """The zone that owns a finding, which is not always the one it faces.

    Everything not listed above owns the direction it faces. Which of the two a
    finding belongs in cannot be read off its owner text - "the destination, not
    the path to it" and "this box's file descriptor limit, not the network" are
    the same sentence shape with opposite answers - so the suite keeps the
    review and fails on a new finding of that shape until somebody says which.
    """
    if code in CAUSE_OWNED_BY_BOX:
        return "local"
    return finding_side(code)


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
        ("upstream", "what this box connects out to",
         "backends, DNS, and the path out"),
    ]
    # On a box that brokers through tunnels the outbound column is what it
    # opens for itself, and calling that "what this box connects out to" reads
    # as where the users' traffic goes. It is not: that goes inside the
    # tunnels and is not a connection this box holds. Renamed rather than
    # removed, because the column is still true and still worth having - the
    # control plane failing is a real outage - it just is not what a reader
    # assumes it is.
    brokering = forwards_out_of_band(raw)
    if brokering:
        order = [(side,
                  "what this box connects out to for itself" if side == "upstream"
                  else label,
                  "its control plane, DNS, and the path out - not where the "
                  "traffic it carries goes" if side == "upstream" else detail)
                 for side, label, detail in order]
    rank = {"pass": 0, "warn": 1, "fail": 2}
    out = []
    for side, label, detail in order:
        # Findings facing this zone, and findings this zone owns.
        #
        # Direction alone left the box green on the seven whose owner is this
        # box: the port-exhaustion report said "this box is running out of
        # ports" over a box reading OK, because nothing about its link, NIC or
        # clock was failing. True about the direction, false about the box, and
        # the reader believes the box.
        #
        # Lighting both is what is actually the case: the way out stopped, and
        # this box is why. Two lit zones would read as two faults, which is what
        # the "the cause" tag is there to prevent.
        #
        # This is the drawing only. build_verdict reasons on finding_side, so
        # what explains what, and which findings can corroborate each other, are
        # untouched - a port ceiling still cannot explain an inbound fault.
        # Kept apart, because a zone that has a finding because it *faces* it
        # and a zone that has one because it *owns* it are answering different
        # questions, and the summary below has to answer the right one.
        loud = [f for f in findings
                if f.get("severity") in ("warning", "critical")
                and f.get("code") not in VERDICT_EXEMPT]
        facing = [f for f in loud if finding_side(f.get("code")) == side]
        owning = [f for f in loud
                  if cause_owner_side(f.get("code")) == side
                  and finding_side(f.get("code")) != side]
        mine = facing + owning
        state = ("fail" if any(f["severity"] == "critical" for f in mine)
                 else "warn" if mine else "pass")
        # Nothing connects to this box, so there is no inbound path to report
        # on. Showing it green would claim something was checked.
        #
        # Unless something inbound-facing did fire. Skip means "nothing to say
        # here", and a finding is something to say: a service address nothing
        # accepts on, a backlog overflowing, descriptors running out. Those are
        # about the way in whether or not enough clients are connected right now
        # to call the box busy, and the threshold for "serving" is three. The
        # strip below never applied that gate, so the same stage read warn in
        # one view and not-applicable in the other, on eight scenarios.
        if side == "downstream" and not serving and not mine:
            state = "skip"
        entry = {"side": side, "label": label, "detail": detail, "state": state,
                 "because": sorted(f.get("code") for f in mine),
                 "worst": None,
                 # Whether this is the box the verdict blames. Two boxes lit is
                 # ordinary and the colours cannot say which of them is the
                 # cause, so it is said here.
                 "owns_cause": False}
        if mine:
            top = sorted(mine, key=lambda f: -rank.get(
                "fail" if f["severity"] == "critical" else "warn", 0))[0]
            # Two zones lighting for one finding used to print its whole
            # message under both, which said the same thing twice and wasted
            # the second box. They are not the same answer: the zone the fault
            # faces is where it shows, and the zone that owns it is why. So the
            # facing one keeps the measurement and the owning one gets the
            # reason, which is a sentence the finding already carries.
            if top in owning:
                # The headline, not the owner phrase, and not the word "cause".
                # Two zones can own two different findings while only one of
                # them is the verdict's cause, and "The cause is ..." under a
                # zone the cause tag is not on says two things at once. The
                # headline names which finding this zone is answering for,
                # which is the disambiguation that is actually needed.
                entry["worst"] = HEADLINE.get(top.get("code")) or top["message"]
            else:
                entry["worst"] = top["message"]
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
        rank = SEVERITY_RANK
        direction = ("worse" if rank.get(cv.get("severity"), 0) > rank.get(bv.get("severity"), 0)
                     else "better" if rank.get(cv.get("severity"), 0) < rank.get(bv.get("severity"), 0)
                     else "neutral")
        changes.append({"what": "verdict", "before": bv.get("headline"),
                        "after": cv.get("headline"), "direction": direction})
    changes.extend(compare_findings(current, baseline, same_target))
    return changes


# Only faults are diffed. A context finding arriving or leaving is usually the
# box being read slightly differently - a listener that happened to be idle, a
# trace that took one hop fewer - and a list of those buries the two lines that
# matter. What is worth saying is which faults are new and which have gone.
_COMPARED_SEVERITIES = ("warning", "critical")
# And the two findings that are themselves about the comparison. A baseline
# report carries its own, so diffing them would report last visit's summary of
# its own baseline as a fault that has since cleared.
_ABOUT_THE_COMPARISON = ("regression_since_baseline", "baseline_changes")


def compare_findings(current, baseline, same_target=True):
    """Which faults appeared, cleared, or changed severity since last time.

    The comparison used to diff about ten hand-picked scalars and the verdict
    sentence, which meant a box going from clean to a critical loss finding
    reported one line: the headline text is different. True, and useless - it
    said something changed without saying what, on the one feature whose entire
    job is saying what.

    Findings are the right unit for it because they are already the unit
    everything else here is expressed in: each one has a code that is stable
    across releases, a severity that can move in a known direction, and a
    headline written to be read. Nothing new has to be measured.
    """
    def faults(report):
        return {f.get("code"): f for f in (report or {}).get("findings") or []
                if f.get("severity") in _COMPARED_SEVERITIES
                and f.get("code") and f["code"] not in _ABOUT_THE_COMPARISON}

    was, now = faults(baseline), faults(current)
    if not same_target:
        # The same rule the target-dependent scalars already follow: two visits
        # that measured different destinations did not measure the same thing,
        # and half the findings differ because the question changed rather than
        # because the network did. What survives a change of target is what was
        # never about the target - this box's own link, hardware and limits.
        #
        # `--target auto` moves on its own when a box gains its first client,
        # so this is not a rare case, and reporting a dozen new faults on a box
        # where nothing happened is how a diff stops being read.
        was = {c: f for c, f in was.items() if finding_side(c) == "local"}
        now = {c: f for c, f in now.items() if finding_side(c) == "local"}
    if not was and not now:
        return []
    out = []
    for code in sorted(set(now) - set(was)):
        out.append({"what": HEADLINE.get(code) or code, "before": "not present",
                    "after": now[code]["severity"], "direction": "worse"})
    for code in sorted(set(was) - set(now)):
        out.append({"what": HEADLINE.get(code) or code, "before": was[code]["severity"],
                    "after": "gone", "direction": "better"})
    for code in sorted(set(was) & set(now)):
        before, after = was[code]["severity"], now[code]["severity"]
        if before == after:
            continue
        out.append({"what": HEADLINE.get(code) or code, "before": before, "after": after,
                    "direction": "worse" if after == "critical" else "better"})
    return out


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
    "own_service_not_accepting": "own_service",
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
    # How much of the pressure is already-closed connections waiting out
    # their timer. Same number of ports held either way, different thing to
    # go and change.
    waiting = sock.get("outbound_worst_waiting") or 0
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
                           f"end refusing it. "
                           + (f"{waiting:,} of those have already closed and are only "
                              f"waiting out their timer. They come back on their own, "
                              f"so what to change is how quickly this box opens and "
                              f"closes connections to that one destination - reusing "
                              f"them, or pooling them - rather than the size of the "
                              f"range."
                              if waiting * 2 >= worst else
                              f"Widen ip_local_port_range, or find what is holding the "
                              f"sockets (TIME_WAIT is {states.get('TIME_WAIT', 0):,})."),
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
                           f"wire is wrong."
                           # System-wide is the number; who is holding the most
                           # sockets is the nearest thing to who is spending
                           # them, and it is a lead rather than an accusation.
                           + _biggest_holder(socket_owners(raw)),
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


def _check_accept_queues(stats, findings, counter_window, owners=()):
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
                       f"its listen backlog is too small."
                       + _the_listeners_are(owners) + _load_context(),
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
                               f"gets reported as the network being unreliable."
                               + _the_listeners_are(owners),
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
    _check_accept_queues(stats, findings, counter_window,
                         socket_owners(raw))
    _check_connection_setup(stats, findings, counter_window)
    _check_server_limits(stats, findings, counter_window, raw)
    _check_thermal(stats, findings, counter_window)
    _check_udp(stats, findings, counter_window)
    _check_fragments(stats, findings, counter_window)
    _check_orphans(stats, findings, counter_window)


# ---------------------------------------------------------------------------
# How many datagram tunnels are up.
#
# A UDP socket serves any number of peers and the socket table records none of
# them, which is why the finding about this plane refuses to count clients. The
# socket table is not the only place the kernel keeps that, though: a box that
# tracks connections has a row per UDP flow, and counting the rows answers the
# question the socket table cannot.
#
# `_read_conntrack` reads the table's counters and says why it does not read the
# table: it "lists who this box has been talking to and is both large and
# nobody's business". That is right, and on a box that brokers traffic it is
# more right, because those rows are every client and every destination they
# reached, in a report that gets attached to tickets.
#
# So this counts and never enumerates. No address, port pair or peer is kept,
# returned or exported - the rows are consumed while reading and what comes out
# is integers. That distinction is the whole design and there is a test that
# fails if an address ever reaches the report.
# ---------------------------------------------------------------------------

CONNTRACK_PATHS = ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack")
_CT_DPORT = re.compile(r"\bdport=(\d+)")
_CT_UNREPLIED = "[UNREPLIED]"


def count_udp_flows(ports, paths=CONNTRACK_PATHS):
    """How many tracked UDP flows are arriving at these ports.

    Returns counts only. The line is examined and dropped; nothing that could
    identify a peer survives the loop, which is what makes this safe to run on
    a box whose flow table is a list of who its users are talking to.

    "Replied" is the kernel having seen traffic in both directions, which for a
    tunnel is the difference between one that is carrying and one where
    something arrived and nothing came back.
    """
    want = {str(p) for p in ports or ()}
    if not want:
        return None
    for path in paths:
        try:
            handle = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        replied = unreplied = 0
        with handle:
            for line in handle:
                if " udp " not in line:
                    continue
                found = _CT_DPORT.search(line)
                if not found or found.group(1) not in want:
                    continue
                if _CT_UNREPLIED in line:
                    unreplied += 1
                else:
                    replied += 1
        return {"tunnels": replied, "unanswered": unreplied,
                "total": replied + unreplied, "source": path}
    return None


def cmd_udp_tunnels(raw=None):
    """The count of datagram tunnels arriving at this box's own listeners.

    Opportunistic like the rest. A box with no connection tracking, or one that
    will not let this user read it, gets nothing and every message reads as it
    did before.
    """
    # Defaulted so this answers like every other collector when called with
    # nothing, which is how the bare-box check exercises all of them at once.
    ports = ((raw or {}).get("udp_sockets") or {}).get("listen_ports") or []
    if not ports:
        return {"ok": False, "cmd": "/proc/net/nf_conntrack", "applicable": False,
                "error": "no datagram listener here to count tunnels for"}
    counted = count_udp_flows(ports)
    if counted is None:
        return {"ok": False, "cmd": "/proc/net/nf_conntrack",
                "error": "the connection tracking table is not readable here, "
                         "so datagram peers cannot be counted"}
    return dict(counted, ok=True, cmd="/proc/net/nf_conntrack (counted, not read)",
                ports=[str(p) for p in ports],
                # Deliberately no stdout. Every other collector keeps its output
                # so a conclusion can be audited later; this one cannot, because
                # the output is the thing being kept out of the report.
                stdout="%d tracked udp flow(s) to %s"
                       % (counted["total"], ", ".join(str(p) for p in ports)))


# A transport that offers datagrams and falls back to TCP on the same port
# expects to be on datagrams. Below this share of its clients actually being
# there, something is stopping them and they have quietly taken the slower way.
FALLBACK_WARN_PCT = 50


# What a datagram tunnel spends before any payload gets in.
#
# Outer IPv4 header 20, outer UDP header 8, DTLS record header 13, and the
# cipher's own overhead: an explicit nonce and an authentication tag, which for
# the AEAD suites in use is 8 + 16. That is 65, and it is an estimate rather
# than a measurement - a different cipher or a sequence-number optimisation
# moves it by a few bytes, and any inner headers the payload carries are on top.
#
# Written out rather than folded into one number so the arithmetic on the page
# can be argued with. Someone who knows their own tunnel's overhead should be
# able to see which part this got wrong.
TUNNEL_OVERHEAD = {"outer IP": 20, "outer UDP": 8, "DTLS record": 13,
                   "cipher nonce and tag": 24}


def encapsulation_headroom(raw):
    """What the tunnel hands out, against what the path can carry it in.

    The arithmetic on its own is not a fault. A path that carries 1500 and a
    tunnel that spends 65 on headers leaves 1435, and a tunnel configured for
    1435 works perfectly - that is a tunnel doing its job, and warning about it
    would put a warning on every correctly built box.

    The fault is the mismatch. When the interface hands the tunnel packets
    bigger than what is left after encapsulation, those packets cannot cross
    the path whole. Small ones still fit, so ping, DNS and handshakes all pass
    while large transfers stall inside the tunnel where nobody can see them.

    Where there is no tunnel interface to read - encapsulation done in the
    service rather than by the kernel, which is the ordinary shape for a broker
    - the mismatch cannot be established, and this reports the arithmetic
    without grading it.
    """
    listeners = ((raw or {}).get("udp_sockets") or {}).get("listeners") or []
    mtu = (raw or {}).get("path_mtu") or {}
    if not listeners or not mtu.get("ok") or not mtu.get("path_mtu"):
        return None
    spent = sum(TUNNEL_OVERHEAD.values())
    room = mtu["path_mtu"] - spent
    # The tunnel interfaces this box holds, if the kernel is doing the
    # encapsulation. The widest one is the one that decides.
    handing_out = [i for i in ((raw.get("link_modes") or {}).get("interfaces") or [])
                   if is_tunnel(i.get("name")) and i.get("mtu")]
    inner = max((i["mtu"] for i in handing_out), default=None)
    return {"path_mtu": mtu["path_mtu"], "overhead": spent, "payload": room,
            "parts": dict(TUNNEL_OVERHEAD), "inner_mtu": inner,
            "iface": next((i["name"] for i in handing_out
                           if i["mtu"] == inner), None),
            "over_by": (inner - room) if inner and inner > room else 0,
            "ports": sorted({str(l["port"]) for l in listeners})}


def transport_split(raw):
    """Clients on the datagram transport against clients on the TCP fallback.

    Only meaningful where the same port answers both, which is what a transport
    designed to fall back looks like: try datagrams, and if they do not get
    through, do the same work over TCP on the port that was already open.

    That fallback is the problem. It works, so nothing fails and no check here
    notices, and the box goes on serving every client over the transport it was
    built to avoid. The clients are the only ones who see it, as latency they
    have no way to report.
    """
    listeners = ((raw or {}).get("udp_sockets") or {}).get("listeners") or []
    counted = (raw or {}).get("udp_tunnels") or {}
    served = ((raw or {}).get("sockets") or {}).get("served_endpoints") or {}
    if not listeners or not counted.get("ok"):
        return None
    both = sorted({str(l["port"]) for l in listeners}
                  & {key.rsplit(":", 1)[-1] for key in served})
    if not both:
        return None                 # nothing answers on both transports here
    on_tcp = sum(n for key, n in served.items() if key.rsplit(":", 1)[-1] in both)
    on_udp = counted.get("total") or 0
    total = on_tcp + on_udp
    if not total:
        return None
    return {"ports": both, "on_datagrams": on_udp, "on_tcp": on_tcp,
            "datagram_pct": round(100.0 * on_udp / total, 1)}


def _tunnels_counted(raw):
    """What the tracking table can add about a plane the socket table cannot.

    Two sentences, and which one depends on whether the count was readable. It
    matters that the refusal survives: on a box with no connection tracking the
    question genuinely cannot be answered here, and the finding has to keep
    saying so rather than falling silent and reading as an answer of zero.
    """
    counted = (raw or {}).get("udp_tunnels") or {}
    if not counted.get("ok"):
        return (" Nothing here can count them either: this box is not tracking "
                "connections, or the table is not readable. Whether nothing is "
                "reaching it or everything is reaching it over UDP is not a "
                "question this run can answer.")
    total, live, quiet = counted["total"], counted["tunnels"], counted["unanswered"]
    if not total:
        return (" The connection tracking table has no datagram flows arriving at "
                "those ports either, so nothing is reaching this box on the plane "
                "it is listening on.")
    return (" The connection tracking table does: %d datagram flow(s) are arriving "
            "at those ports, %d of them carrying in both directions%s. That is the "
            "count the socket table cannot give, and it is a count only - which "
            "peers they are is not read."
            % (total, live,
               " and %d with nothing coming back" % quiet if quiet else ""))


def forwards_out_of_band(raw):
    """Does this box carry traffic it never opens a connection for.

    The socket table splits connections into ones that arrived and ones this
    box opened, which is a true statement about TCP and the right split for a
    proxy: clients on one side, backends on the other, two networks with two
    owners. A box that brokers through tunnels breaks that in a way the split
    cannot see.

    On one, the traffic it exists to carry goes *inside* the tunnels, so it
    never appears as a connection at all. What is left in the outbound column
    is whatever the box opens for itself, which is its control plane - and the
    report labels that column "what this box connects out to", which reads as
    where the users' traffic goes. It is the one place the picture is not
    merely incomplete but pointed the wrong way.

    Recognised rather than inferred: datagram tunnels are arriving, and the
    outbound connections are a handful of long-lived ones rather than a
    population. That is what a broker looks like and what a proxy does not.
    """
    counted = (raw or {}).get("udp_tunnels") or {}
    sock = (raw or {}).get("sockets") or {}
    if not counted.get("ok") or not counted.get("total"):
        return None
    outbound = sock.get("outbound") or 0
    # Written as the condition for being a broker rather than for not being
    # one, so the bar reads the way it is documented: a box at the number is
    # still holding a control plane, and one past it has a population out and
    # is a proxy, which the existing split already describes correctly.
    if outbound <= CONTROL_PLANE_MAX_SESSIONS:
        return {"tunnels": counted["total"], "outbound": outbound,
                "ports": counted.get("ports") or []}
    return None


# A control plane is a few sessions to the service this box enrols with. More
# outbound connections than this and the box is opening them for the work,
# which is a proxy and is exactly what the existing split describes correctly.
CONTROL_PLANE_MAX_SESSIONS = 8


def other_plane(raw):
    """The datagram listeners, when this box has any, so the rest can say so.

    Every per-connection reading here is TCP: the client table is `ss -tan` and
    the statistics are `ss -tin`. On a box whose control plane is TCP and whose
    user traffic is datagrams, that means direction, stalled returns, relay
    volume, queuing delay, TIME_WAIT pressure and ephemeral ports all describe
    the control plane, under headings that read as how users are being served.

    None of it is wrong, and a control plane failing is a real outage worth
    every one of those findings. What a reader cannot do is tell which plane
    they are looking at, and on this shape of box the two have different owners
    and different symptoms.

    Returned rather than stamped on everything, because the label is only worth
    printing where there is another plane to confuse it with. On a box with no
    datagram listeners "TCP" on every heading is a word repeated on every
    report to rule out a possibility nobody had - the same reason the fan-out
    is drawn only where a conclusion rested on it, and the privilege line
    appears only on the run that saw less.
    """
    listeners = ((raw or {}).get("udp_sockets") or {}).get("listeners") or []
    if not listeners:
        return None
    # Coerced to text: the parser reads ports out of an address and gets
    # strings, and a fixture that hands back integers would otherwise
    # render differently from a real run.
    return {"ports": sorted({str(l["port"]) for l in listeners})}


def _check_encapsulation_headroom(raw, findings):
    """The tunnel's own arithmetic, graded only where it can be.

    A warning needs two numbers that disagree. With only one of them this
    states what it knows and stops, which is the difference between a report
    that is useful on a broker and one that cries wolf on every box with a
    tunnel on it.
    """
    room = encapsulation_headroom(raw)
    if not room:
        return
    where = ", ".join(room["ports"])
    parts = ", ".join("%s %d" % (name, size)
                      for name, size in sorted(room["parts"].items(),
                                               key=lambda kv: -kv[1]))
    arithmetic = (
        f"The path to the target carries {room['path_mtu']}-byte packets, and a "
        f"datagram tunnel on port {where} spends {room['overhead']} of that on its own "
        f"headers ({parts}), leaving about {room['payload']} bytes for what it carries. "
        f"That overhead is estimated from the header sizes rather than measured, so "
        f"treat the last few bytes of it as approximate.")
    if room["over_by"]:
        findings.append({
            "severity": "warning",
            "layer": 3,
            "code": "tunnel_payload_short",
            "message": (
                f"{arithmetic} {room['iface']} is handing it packets of "
                f"{room['inner_mtu']}, which is {room['over_by']} more than fits. Those "
                f"do not bounce: they are carried by fragmenting the outer packet, or "
                f"dropped by something that will not fragment, and either way it shows "
                f"up as large transfers stalling inside the tunnel while ping, DNS and "
                f"handshakes all pass. Lower {room['iface']} to {room['payload']}, or "
                f"find why the path carries less than it used to."),
        })
        return
    findings.append({
        "severity": "ok",
        "layer": 3,
        "code": "tunnel_payload_room",
        "message": (
            arithmetic
            + (f" {room['iface']} is set to {room['inner_mtu']}, which fits."
               if room["inner_mtu"] else
               " Nothing on this box holds a tunnel interface, so the encapsulation is "
               "being done by the service rather than the kernel and what it hands out "
               "cannot be read from here. The number above is the ceiling it has to "
               "stay under.")),
    })


def _check_route_agrees(raw, findings, hops, target):
    """The trace and the kernel disagreeing about the first hop.

    Not a fault on its own. A box with policy routing, a second table, or a
    tunnel that grabs a prefix will legitimately send the probe one way and the
    traffic another, and that is a configuration rather than a break.

    It is the most important piece of context on the page when it happens,
    though, because everything below it is about a path the traffic does not
    take. A loss figure, a latency wall, a site edge, a NAT: all measured on
    the wrong route, and all of them will read as facts about the service.
    """
    off = route_disagrees_with_trace(raw, hops, target)
    if not off:
        return
    findings.append({
        "severity": "ok",
        "layer": 3,
        "code": "trace_took_another_route",
        "message": (
            f"The path below was traced through {off['observed']}, and this box's own "
            f"routing table sends traffic for {target} "
            + (f"straight onto {off['dev']} with no router in the way"
               if off["onlink"] else
               f"via {off['expected']}%s" % (" on %s" % off["dev"] if off["dev"] else ""))
            + ". The probe and the traffic are taking different routes, so every hop "
              "below describes a path this box does not actually send that traffic "
              "down - the loss, the latency and the site edge are all measured on the "
              "other one. That is ordinary on a box with policy routing or a tunnel "
              "holding a prefix, and it is worth knowing before acting on anything "
              "further down."),
    })


TELLS_THE_SENDER = {
    "blackhole": "nothing at all, so the sender waits for a timeout",
    "unreachable": "an ICMP unreachable, so the sender fails quickly",
    "prohibit": "an ICMP administratively-prohibited, so the sender fails quickly",
}


def _check_discard_route(raw, findings, target):
    """The target sitting inside a route this box throws traffic away on.

    Decisive when it happens, and it presents as a dead upstream: nothing
    arrives, nothing answers, and every check past this one measures a path the
    packets never got onto. The route is on this box and nobody has to go
    looking further than it.
    """
    routes = (raw or {}).get("routes") or {}
    if not routes.get("ok"):
        return
    caught = discards_the_target(parse_discard_routes(routes.get("stdout") or ""),
                                 (raw or {}).get("target_ip"))
    if not caught:
        return
    findings.append({
        "severity": "critical",
        "layer": 3,
        "code": "target_is_discarded",
        "message": (
            f"This box holds a {caught['kind']} route for {caught['prefix']}, and "
            f"{target} is inside it. Traffic to that address is thrown away here rather "
            f"than sent anywhere, and the sender is told "
            f"{TELLS_THE_SENDER.get(caught['kind'], 'nothing useful')}. Nothing past "
            f"this box is involved: every reachability result below describes a packet "
            f"that never left. The route is on this box, so this is the whole of the "
            f"fault and the place to fix it."),
    })


# What each check status means, in the words a reader needs rather than the
# code. Taken from the proxy's own vocabulary because it is a good one: it
# separates faults that look identical from outside the box.
CHECK_MEANS = {
    "L4CON": "the connection was refused, so nothing is listening there",
    "L4TOUT": "the connection timed out, so something is there and did not answer",
    "L4OK": "it connects, and nothing above that was checked",
    "L6TOUT": "the TLS handshake timed out",
    "L6RSP": "the TLS handshake was answered with something invalid",
    "L7TOUT": "it connected and the application never replied",
    "L7RSP": "the application answered with something unreadable",
    "L7STS": "the application answered, with a status the check rejects",
    "L7OK": "the application answered correctly",
}


# A handshake that completes in less than this share of the round trip did not
# make the round trip. Generous on purpose: a legitimate cache or edge node is
# genuinely nearer than the name it serves, and the claim being made is only
# that something closer answered - not that anybody is doing anything wrong.
CLOSER_THAN_PATH_PCT = 40
# And a floor under it, because on a path of a couple of milliseconds every
# measurement is noise and a share of nothing means nothing.
CLOSER_THAN_PATH_FLOOR_MS = 20
# How many hops short of the traced path a reply can arrive from before it is
# somebody else answering. One or two is ordinary: the trace and the reply can
# take different routes, and the initial TTL is assumed rather than known.
TTL_SHORTFALL_HOPS = 3


def answered_closer_than_the_path(raw, hops, port_results=()):
    """Signs that something nearer than the target completed the connection.

    Two instruments, deliberately, because they fail in different ways and
    agreeing is what turns either into a finding.

    Timing: a TCP handshake to a host 80ms away that completes in 2ms did not
    reach that host. Round trips are noisy and a nearby cache is a real thing,
    so this alone is a suggestion.

    Distance: a reply whose TTL says it crossed two routers, on a path the
    trace walked twelve of, came from something two hops away. Discrete rather
    than noisy, and wrong in different circumstances - an assumed initial TTL,
    an asymmetric return path.

    Neither is an accusation. Transparent interception is usually somebody's
    policy rather than a fault, and the report's job is to say the connection
    is not ending where the reader thinks it is.
    """
    out = {}
    reached = hops and hops[-1].get("host") and not hops[-1].get("timed_out")
    # The round trip the ping measured, falling back to the last hop the trace
    # reached: a box with ICMP filtered has no ping figure and still has a
    # traced path, and the comparison is worth making on either.
    rtt = (parse_ping_stats(raw.get("ping_internet") or {}) or {}).get("avg_ms")
    if rtt is None and reached:
        rtt = (hops[-1] or {}).get("avg_ms")
    quickest = [p for p in (port_results or [])
                if p.get("open") and p.get("connect_ms") is not None]
    if rtt and rtt >= CLOSER_THAN_PATH_FLOOR_MS and quickest:
        soonest = min(quickest, key=lambda p: p["connect_ms"])
        share = round(100.0 * soonest["connect_ms"] / rtt, 1)
        if share <= CLOSER_THAN_PATH_PCT:
            out["timing"] = {"connect_ms": soonest["connect_ms"], "rtt_ms": rtt,
                             "share_pct": share, "port": soonest.get("port")}
    implied = hops_from_ttl(parse_ping_ttl(raw.get("ping_internet") or {}))
    if implied and reached:
        came_from, assumed = implied
        walked = len(hops)
        if walked - came_from >= TTL_SHORTFALL_HOPS:
            out["distance"] = {"replied_from": came_from, "traced": walked,
                               "ttl_assumed": assumed}
    return out or None


def _check_answered_closer(raw, findings, target, hops, port_results):
    """Something between here and the target answering as the target.

    The one interception check that needs neither TLS nor a certificate.
    `tls_intercepted` reads the issuer of what came back, which works and only
    works where there is a handshake to read and a name to recognise. This is
    the same fault seen from the outside of the envelope, on any port.
    """
    seen = answered_closer_than_the_path(raw, hops, port_results) or {}
    timing, distance = seen.get("timing"), seen.get("distance")
    # Both, or nothing. Either alone is a lead and neither is worth a finding:
    # a round trip is noisy and a nearby cache really is nearer than the name
    # it serves, and an initial TTL is assumed rather than known. They are
    # wrong under different conditions, so the two agreeing is the whole of
    # what makes this sayable - and the alternative is a warning on every box
    # with an edge node in front of it.
    if not (timing and distance):
        return
    parts = []
    if timing:
        parts.append(
            "the TCP handshake on port %s finished in %sms on a path with a %sms round "
            "trip, which is %s%% of it" % (timing["port"], timing["connect_ms"],
                                           round(timing["rtt_ms"]), timing["share_pct"]))
    if distance:
        parts.append(
            "the reply arrived having crossed %d router(s) on a path the trace walked "
            "%d of, counted from a starting TTL of %d"
            % (distance["replied_from"], distance["traced"], distance["ttl_assumed"]))
    findings.append({
        "severity": "warning",
        "layer": 4,
        "code": "answered_closer_than_the_path",
        "message": (
            f"Something nearer than {target} appears to be answering for it: "
            + ", and ".join(parts) + ". "
            + "Two independent readings agree, which is what makes this worth "
              "saying rather than a guess: one is a timing and the other is a hop "
              "count, and they are wrong under different conditions. "
            + "This is what a transparent proxy looks like from here, and it is usually "
              "somebody's policy rather than a fault. It matters because everything "
              "below about reaching that address describes the connection to whatever "
              "answered, not to the host you named."),
    })


def _check_proxy_backends(raw, findings):
    """Backends the proxy on this box has taken out of rotation.

    The one thing on this report that the kernel cannot know. A socket table
    says what is connected; it cannot say which of those the proxy has decided
    not to send traffic to, which check failed, or how many times it has
    flapped today.

    Servers taken out deliberately are counted and not graded. Somebody put
    them in maintenance, and reporting that as a fault teaches a reader that
    this section is wrong.
    """
    servers = ((raw or {}).get("proxy_stats") or {}).get("servers") or []
    if not servers:
        return
    down = [s for s in servers if s["status"] in PROXY_IS_DOWN]
    parked = [s for s in servers if s["status"] in PROXY_ON_PURPOSE]
    if not down:
        return
    worst = max(down, key=lambda s: s.get("times_down") or 0)
    means = CHECK_MEANS.get(worst.get("check_status") or "")
    findings.append({
        "severity": "critical" if len(down) == len(
            [s for s in servers if s["status"] not in PROXY_ON_PURPOSE]) else "warning",
        "layer": 7,
        "code": "proxy_backend_down",
        "message": (
            f"The proxy on this box has taken {len(down)} of its "
            f"{len(servers) - len(parked)} live backend(s) out of rotation"
            + (", and %d more %s parked deliberately"
               % (len(parked), "is" if len(parked) == 1 else "are") if parked else "")
            + f". The worst is {worst['proxy']}/{worst['server']}"
            + (f", where {means}" if means else "")
            + (f", down for {_fmt_span(worst['downtime_s'])}"
               if worst.get("downtime_s") else "")
            + (f" and taken out {worst['times_down']} time(s) since the proxy started"
               if worst.get("times_down") else "")
            + ". This is the proxy's own judgement rather than anything measured "
              "here: nothing in a socket table says which backends a service has "
              "decided to stop using, or which check it was that failed."),
    })


def _check_inbound_filtering(raw, findings):
    """This box turning away traffic addressed to its own service.

    The counterpart to what already gets said about the way out, and the more
    important direction on a box whose job is accepting connections: a client
    that is refused here never reaches the service, and every check below the
    firewall passes because the service really is up.
    """
    dropped = inbound_drops_on_served_ports(raw)
    if not dropped:
        return
    worst = dropped[0]
    ports = ", ".join(worst["ports"])
    findings.append({
        "severity": "warning",
        "layer": 4,
        "code": "inbound_filtered_here",
        "message": (
            f"This box's own firewall dropped {worst['gained']} packet(s) addressed to "
            f"port {ports} while this ran, on a port it is listening on: "
            f"{worst['chain']}/{worst['verdict']} {worst['rule']}. Traffic refused here "
            f"never reaches the service, and every check below this one passes because "
            f"the service itself is fine - it is simply not being given anything to "
            f"answer. Ordinary inbound noise being dropped is not this: the rule that "
            f"counted names a port this box serves."
            + (f" {len(dropped)} rules are doing it." if len(dropped) > 1 else "")),
    })


def _check_forwarding_shape(raw, findings):
    """Say that the far side of the traffic this box carries is not on here.

    Context, never a fault. Nothing is wrong with a box that forwards inside
    tunnels - that is the job - and the report has to stop implying it can see
    where that traffic went. Every other finding on the way out is about the
    control plane, and a reader who takes them for the user path will chase
    the wrong thing.
    """
    shape = forwards_out_of_band(raw)
    if not shape:
        return
    where = ", ".join(shape["ports"]) if shape["ports"] else "its listeners"
    findings.append({
        "severity": "ok",
        "layer": 4,
        "code": "forwards_inside_tunnels",
        "message": (
            f"{shape['tunnels']} datagram tunnel(s) are arriving on {where}, and this "
            f"box holds {shape['outbound']} outbound connection(s) of its own. The "
            f"traffic those tunnels carry is forwarded inside them, so it never appears "
            f"as a connection here and nothing on this report describes where it went. "
            f"What the outbound side does describe is what this box opens for itself - "
            f"its control plane, its resolvers, its own path out. That is worth having "
            f"and is a real outage when it breaks, but it is not the user path: a loss "
            f"figure or a stalled return on that side is about this box reaching the "
            f"service it enrols with, not about anyone's traffic getting through."),
    })


def _check_transport_fallback(raw, findings):
    """Clients that could not use the datagram transport and took the slow way.

    The fault this exists for is invisible by construction. A fallback that
    works produces no error, no retransmit and no failed check: the box serves
    everybody, every probe passes, and the only symptom is that a transport
    built to avoid TCP is running on TCP. Nothing else in this tool would ever
    mention it.
    """
    split = transport_split(raw)
    if not split or split["datagram_pct"] >= FALLBACK_WARN_PCT:
        return
    where = ", ".join(split["ports"])
    findings.append({
        "severity": "warning",
        "layer": 4,
        "code": "transport_fell_back",
        "message": (
            f"{split['on_tcp']} of the {split['on_tcp'] + split['on_datagrams']} "
            f"client session(s) on port {where} are on TCP, and only "
            f"{split['on_datagrams']} are on datagrams "
            f"({split['datagram_pct']}%). This box offers both on the same port, so "
            f"a client that cannot get datagrams through falls back to TCP and "
            f"connects anyway. That is why nothing here is failing: the fallback "
            f"works. What it costs is the reason the datagram transport exists - "
            f"head-of-line blocking returns, and every loss stalls the whole tunnel "
            f"instead of one packet inside it. Something between those clients and "
            f"this box is stopping UDP {where}: a firewall, a policy on their "
            f"network, or a middlebox that only forwards TCP. Nothing on this box "
            f"is broken and nobody will report it, because from a client's side it "
            f"works and is merely slower."),
    })


def _check_udp_queues(raw, findings):
    """Datagrams the kernel is holding that the process has not taken.

    The counterpart to an accept queue, for a plane that has no accept. On a
    box whose user traffic is datagrams this is the one thing that plane says
    plainly: not how many peers it serves, not whether anything was lost in
    flight, but whether what arrived is being picked up.

    Everything careful about it is in `udp_window`, which decides what two
    readings support. This says it.
    """
    standing = (raw.get("udp_sockets") or {}).get("standing_queues") or []
    if not standing:
        return
    worst = standing[0]
    where = "%s:%s" % (worst["address"] or "*", worst["port"])
    process = owner_of_port(socket_owners(raw), worst["port"])
    findings.append({
        "severity": "warning",
        "layer": 4,
        "code": "udp_queue_standing",
        "message": (
            f"{worst['recv_q']:,} bytes are waiting unread on the datagram listener at "
            f"{where} - {worst['share_pct']}% of that socket's own receive buffer - and "
            f"were still waiting {worst['window_seconds']}s later "
            f"({worst['first_recv_q']:,} bytes at the start of that window). The kernel "
            f"has taken delivery and the process has not, which is this box failing to "
            f"keep up with what is arriving rather than anything on the wire."
            + (f" That listener is {process}." if process else "")
            + (f" {len(standing)} listeners are in that state." if len(standing) > 1 else "")
            + " Two readings cannot separate one standing backlog from two bursts, so "
              "confirm with a longer --soak before acting on it. A datagram plane cannot "
              "say how many peers it serves or whether anything was lost in flight - "
              "those need the listener's own counters."),
    })


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
    # Keyed on the address as well as the port. Keyed on the port alone, a box
    # running several instances behind several addresses on 443 - which is the
    # ordinary shape of a front end, not an exotic one - had exactly one of them
    # checked and the rest silently skipped, so the certificate expiry this
    # exists to catch was being read off one instance and assumed of the others.
    seen, listening = set(), []
    for addr, port in (sockets.get("bound") or []):
        if not port.isdigit() or int(port) not in TLS_PORTS:
            continue
        key = (_listener_address(addr), int(port))
        if key not in seen:
            seen.add(key)
            listening.append(key)
    if not listening:
        return
    results = []
    for addr, port in listening[:OWN_TLS_MAX_LISTENERS]:
        res = cmd_own_tls(port, address=addr)
        results.append(res)
        _own_tls_findings(res, port, findings)
    skipped = len(listening) - len(results)
    if results:
        lines = [
            f"{r['host']}:{r['port']:<6} " + (
                f"{r.get('tls_version', '?')}  {r.get('verified_as', '?')}  "
                f"expires {r.get('expires', '?')}"
                + (f"  ({r['days_left']}d)" if r.get("days_left") is not None else "")
                if r.get("ok") else
                f"not listening on {r['host']}" if r.get("unreachable_locally")
                else f"handshake failed: {r.get('error', '?')}")
            for r in results]
        if skipped:
            # Said out loud. A cap that trims quietly reads as full coverage,
            # and "every certificate here is good for 200 days" is exactly the
            # sentence that must not be built on a partial reading.
            lines.append(f"({skipped} more listener(s) not checked, "
                         f"limit {OWN_TLS_MAX_LISTENERS} per run)")
        raw["own_tls"] = {
            "ok": any(r.get("ok") for r in results), "cmd": "tls handshake (own listeners)",
            "stderr": "", "code": 0, "listeners": results, "not_checked": skipped,
            "stdout": "\n".join(lines),
        }


def _check_upstream_sessions(raw, findings):
    """A box serving clients while connected to nothing itself.

    The shape this is for: something that only exists to relay, brokering
    between the clients in front of it and whatever it forwards to, holding a
    session to its control plane the whole time it is enrolled. Lose that and
    the box keeps its address, keeps its listener, keeps accepting, and every
    connection it accepts fails on the far side. Nothing else here notices,
    because everything else here is measuring a box that is up.

    Context and not a fault, deliberately, because one reading cannot separate
    two ordinary states: a service that answers from itself is supposed to hold
    no outbound sessions, and there is nothing in a socket table that says
    which kind of box this is. The message names both and lets the person who
    knows decide, which is the same bargain the service-address findings make.

    Silent when connections are stuck in SYN_SENT. That is a box trying and
    failing rather than a box not trying, syn_sent_backlog already says so, and
    two findings for one condition is how a report stops being a verdict.
    """
    sockets = raw.get("sockets") or {}
    if not sockets.get("ok"):
        return
    inbound = sockets.get("inbound") or 0
    outbound = sockets.get("outbound") or 0
    if outbound or inbound < SERVING_INBOUND_MIN:
        return
    if (sockets.get("states") or {}).get("SYN_SENT", 0) >= SYN_SENT_WARN:
        return
    findings.append({
        "severity": "ok",
        "code": "no_upstream_sessions",
        "layer": 4,
        "message": f"This box has {inbound} connection(s) from clients and holds no "
                   f"outbound connection to anything. A service that answers from "
                   f"itself is supposed to look like this. Anything that relays, "
                   f"brokers or proxies is not: its upstream is gone, and every "
                   f"connection those clients are making is failing on the far side "
                   f"of this box while everything measured here stays healthy.",
    })


# Enough traffic on a side before its volume says anything, and the ratio at
# which one side is carrying so much less than the other that it is worth
# naming. Gross on purpose: a box that inspects rewrites what it forwards, and
# a box that terminates TLS re-frames it, so the two sides never match closely
# and a tight ratio would fire on every healthy one.
RELAY_MIN_BYTES = 10_000_000
RELAY_RATIO = 20


def _check_source_reachability(raw, findings):
    """One address on this box cannot reach what its neighbours can.

    The whole reason for asking every address rather than one. A box holding a
    service address beside its own has a path per address, and they are not the
    same path - a policy route, a filter matched on source, or an address held
    by a partner that never gave it up. The ordinary run leaves from whichever
    address the kernel picks, so it can pass while the address the clients
    actually use cannot reach anything.

    Silent unless at least one address succeeded. All of them failing is the
    target being unreachable, which every other check on this run already says
    better, and repeating it here per address would be one fault reported four
    times.
    """
    rows = raw.get("source_matrix") or []
    if len(rows) < 2:
        return
    reached = [r for r in rows if r.get("reached")]
    failed = [r for r in rows if not r.get("reached")]
    if not reached or not failed:
        return
    where = ", ".join(r["address"] for r in failed[:4])
    ok = ", ".join(r["address"] for r in reached[:2])
    findings.append({
        "severity": "critical",
        "layer": 3,
        "code": "source_cannot_reach",
        "message": f"{where} cannot reach {raw.get('probe_target') or 'the target'} "
                   f"while {ok} can, from this same box. Every address here is on "
                   f"the same interface list and the same routing table, so what "
                   f"differs is what happens to the traffic after it leaves: a "
                   f"policy route, a filter matched on source address, or an "
                   f"address this box holds and something upstream still sends "
                   f"elsewhere. A client using that address sees an outage that a "
                   f"run from this box's own address does not.",
    })


def _check_relay_volume(raw, findings):
    """What arrived on one side against what left on the other.

    Context and not a fault, for the same reason no_upstream_sessions is. A box
    that inspects traffic is supposed to stop some of it: policy denying a
    request looks in a socket table exactly like a box that has stopped
    relaying, and nothing here can separate them. So this reports the shape and
    names both readings rather than calling one of them broken.

    The comparison is deliberately crude. Payloads change size on the way
    through anything that inspects or re-originates, so only an order of
    magnitude means anything - a side carrying a twentieth of the other is a
    different claim from a side carrying nine tenths of it.
    """
    by_side = ((raw.get("tcp_flows") or {}).get("by_side")) or {}
    client, backend = by_side.get("client") or {}, by_side.get("backend") or {}
    if not client or not backend:
        return                              # not a box with two sides to compare
    # A kernel that does not report bytes_received leaves this unanswerable,
    # and an unanswered question must not read as a side carrying nothing.
    if not client.get("volume_readable") or not backend.get("volume_readable"):
        return
    arrived = client.get("bytes_in") or 0
    forwarded = backend.get("bytes_out") or 0
    # Written as what has to be true, the way the direction rules are, so each
    # threshold is compared at or beyond the value the reference documents
    # rather than one step inside it.
    enough_to_judge = arrived >= RELAY_MIN_BYTES
    broadly_relaying = forwarded * RELAY_RATIO >= arrived
    if not enough_to_judge or broadly_relaying:
        return
    findings.append({
        "severity": "ok",
        "code": "relay_volume_lopsided",
        "layer": 4,
        "message": f"{_fmt_bytes(arrived)} arrived from the clients this box "
                   f"serves and {_fmt_bytes(forwarded)} left it towards what it "
                   f"depends on. A box that inspects traffic is meant to stop "
                   f"some of it, so this is what a policy refusing requests "
                   f"looks like - and it is also what a box that has stopped "
                   f"forwarding looks like. Nothing in a socket table separates "
                   f"the two. If this box is supposed to be relaying most of "
                   f"what it receives, the far side is where to look.",
    })


def _fmt_bytes(n):
    """Bytes as something a person reads, at one decimal from megabytes up."""
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n:.0f} B"


def _build_service_instances(raw):
    """One row per thing this box is serving, from readings already taken.

    A box running several instances behind several addresses has no single
    "is the service up" answer, and every check here produced one anyway: a
    certificate read off one listener, a connection count for the whole box. A
    row per endpoint is what makes them separable.

    Up and serving are kept apart on purpose, in two columns rather than one
    light. An instance that has just started, or one behind a load balancer
    that has not sent it anything yet, is up and not serving, and collapsing
    those into a single red would make the table lie about the commonest
    harmless state there is.

    The name comes off the certificate the instance serves, which is the name
    its clients actually use. There is deliberately no reverse-DNS fallback:
    a PTR lookup is a network call, and this runs on boxes whose DNS is the
    thing being diagnosed, where it would hang the run to add a name that is
    stale as often as not. Without a certificate the address is the name.
    """
    sockets = raw.get("sockets") or {}
    bound = sockets.get("bound") or []
    if not bound:
        return
    endpoints = sockets.get("served_endpoints") or {}
    served_on = sockets.get("served_on") or {}
    # Kept apart rather than merged into one dict per endpoint. Both probes can
    # run against the same listener and they answer different questions, so
    # merging let the HTTP attempt's failure overwrite a successful handshake
    # and report a healthy instance as unreachable.
    def by_endpoint(key):
        return {(r.get("host"), r.get("port")): r
                for r in ((raw.get(key) or {}).get("listeners") or [])}
    tls_probe, http_probe = by_endpoint("own_tls"), by_endpoint("own_service")

    rows, seen = [], set()
    for addr, port in bound:
        if not str(port).isdigit():
            continue
        port = int(port)
        clean = (addr or "").strip("[]")
        wildcard = clean in _WILDCARD_BINDS
        if (clean, port) in seen:
            continue
        seen.add((clean, port))

        # A wildcard listener answers on every address the box holds, so its
        # traffic is whatever arrived on that port anywhere, not on one address.
        if wildcard:
            traffic = sum(count for key, count in endpoints.items()
                          if key.rsplit(":", 1)[-1] == str(port))
            where = "*:%d" % port
        else:
            traffic = endpoints.get("%s:%d" % (clean, port),
                                    served_on.get(clean, 0) if not endpoints else 0)
            where = "%s:%d" % (clean, port)

        key = (_listener_address(addr), port)
        # Whichever actually reached the service wins, TLS first: a handshake
        # says more than a request, and a plain HTTP instance simply has no
        # handshake to give. Both failing keeps the TLS answer, which names the
        # more specific reason.
        res = tls_probe.get(key) or {}
        alt = http_probe.get(key) or {}
        if not res.get("ok") and (alt.get("ok") or not res):
            res = alt or res
        name = res.get("verified_as") or (res.get("names") or [None])[0]
        rows.append({
            "endpoint": where, "address": clean, "port": port,
            "wildcard": wildcard,
            "name": name or where,
            "named_from": "certificate" if name else "the address",
            "up": _instance_up(res),
            "traffic": traffic,
            "expires": res.get("expires"), "days_left": res.get("days_left"),
            # Whether this is worth a line in the report. Every row stays in
            # the data - what is listening is a fact and the export keeps it -
            # but an ordinary workstation holds a dozen wildcard listeners it
            # got from its own operating system, and a table of those saying
            # "listening, nothing arriving" buries the two rows that matter.
            #
            # Something is notable when anything was actually learned about it:
            # a probe reached it, traffic is arriving on it, or somebody bound
            # it to one specific address, which is a decision rather than a
            # default and is how a deliberate instance is configured.
            "notable": bool(res) or bool(traffic) or not wildcard,
        })
    if rows:
        raw["service_instances"] = sorted(rows, key=lambda r: (r["port"], r["address"]))


def _instance_up(res):
    """Up, as far as anything actually looked.

    "listening" is not a weaker "ok", it is a different claim: the socket is
    open and nothing opened a connection to it this run, because the port is
    not one conventionally used for TLS or HTTP. Reporting that as ok would be
    a pass nobody earned, and as a fault it would be a fault nobody has.
    """
    if not res:
        return "listening"
    if res.get("unreachable_locally"):
        return "not on this address"
    if not res.get("ok"):
        return "failed"
    days = res.get("days_left")
    if days is not None and days < 0:
        return "certificate expired"
    if days is not None and days <= CERT_EXPIRY_WARN_DAYS:
        return "expires in %dd" % days
    if res.get("verified") is False:
        return "certificate not verified"
    return "ok"


def _check_own_service(raw, findings, quick=False):
    """Does the service answer, or only accept?

    Runs against the ports this box already listens on that are conventionally
    HTTP, so this never probes anything - it asks a service already taking
    requests for one response.
    """
    if quick:
        return
    sockets = raw.get("sockets") or {}
    # Address and port, for the reason the TLS check above carries the same
    # comment: several instances behind several addresses on one port is the
    # ordinary shape here, and keying on the port checked one of them.
    seen, targets = set(), []
    for addr, port in (sockets.get("bound") or []):
        if port not in SERVING_PORTS:
            continue
        key = (_listener_address(addr), int(port))
        if key not in seen:
            seen.add(key)
            targets.append(key)
    if not targets:
        return
    results = []
    for addr, port in targets[:OWN_TLS_MAX_LISTENERS]:
        res = cmd_own_http(port, address=addr, tls=int(port) in TLS_PORTS)
        results.append(res)
        _own_service_findings(res, port, findings, socket_owners(raw))
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


def _own_service_findings(res, port, findings, owners=()):
    """One listener's answer, or its refusal to give one."""
    if res.get("unreachable_locally"):
        # Refused and timed out are two different faults, and collapsing them
        # meant a box that would not complete a connection to its own listener
        # produced no finding at all, under a verdict reading "the service is
        # up and nothing is reaching it".
        #
        # Refused stays silent here on purpose: it means nothing is listening
        # on that address, which `service_address_unserved` says better and
        # with the address check's own evidence behind it.
        if res.get("refusal") == "timeout":
            findings.append({
                "severity": "critical",
                "layer": 4,
                "code": "own_service_not_accepting",
                "message": (
                    f"This box is listening on port {port} and did not finish a "
                    f"connection to its own listener: the handshake was started from "
                    f"here and timed out."
                    + _that_service_is(owners, port)
                    + " Nothing was refused, so something is listening and is not "
                      "completing. A packet that cannot cross from this box to itself "
                      "will not cross from a client either, and every check that needs "
                      "a connection to this service is below this line and did not "
                      "run. Look at the accept queue, and at whether a rule on this "
                      "box is dropping traffic to that port."),
            })
        return
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
                         "while the box it runs on looks entirely healthy."
                       + _that_service_is(owners, port),
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
                       f"the network."
                       + _that_service_is(owners, port),
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
    if "udp_sockets" not in raw:
        raw["udp_sockets"] = cmd_udp_sockets()
    if "udp_tunnels" not in raw:
        raw["udp_tunnels"] = cmd_udp_tunnels(raw)
    if "socket_owners" not in raw:
        raw["socket_owners"] = cmd_socket_owners()
    if "qdisc" not in raw:
        raw["qdisc"] = cmd_qdisc()
    if "proxy_stats" not in raw:
        raw["proxy_stats"] = cmd_haproxy_stats()
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
                       f"out of file descriptors."
                       + _held_by(owners_in_state(socket_owners(raw), "CLOSE_WAIT")),
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

    # A side gone quiet, before the loss shapes below and separate from them.
    # Emitted ahead of the returns further down rather than after, because those
    # exit the moment a side is found to be losing traffic - and a side can be
    # both losing traffic and hearing nothing back, which are two findings with
    # two owners. Which of them headlines is the rule order's decision, not this
    # function's.
    #
    # Written out per side rather than looped, so each code appears as a literal
    # where the guard that every rule names a real finding can see it. A loop
    # over (side, code) pairs reads better and is invisible to that check.
    def _stalled_message(near, where):
        quiet = near.get("silent_return") or 0
        seen = near.get("connections") or 0
        share = near.get("silent_share_pct") or 0
        # Say which way it became true. A minority of connections carrying most
        # of the side's traffic is the held-tunnel shape, and "1 of 40" without
        # that sentence reads as the tool over-reacting to one bad connection.
        weight = (f", and they carry {share}% of that side's traffic"
                  if quiet * 2 < seen and share else "")
        return (f"{quiet} of {seen} connection(s) to {where} have gone quiet in "
                f"one direction{weight}: this box sent on them within the last "
                f"second and nothing has come back for seconds - no data and no "
                f"acknowledgement either. An acknowledgement is not the far end's "
                f"to withhold, so this is the path back rather than a far end "
                f"taking its time over a reply.")

    by_side = stats.get("by_side") or {}
    if (by_side.get("backend") or {}).get("return_stalled"):
        findings.append({
            "severity": "critical",
            "layer": 4,
            "code": "tcp_return_stalled_backends",
            "message": _stalled_message(by_side["backend"],
                                        "what this box connects out to"),
        })
    if (by_side.get("client") or {}).get("return_stalled"):
        findings.append({
            "severity": "critical",
            "layer": 4,
            "code": "tcp_return_stalled_clients",
            "message": _stalled_message(by_side["client"],
                                        "the clients using it"),
        })

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
                            f"between this box and what it connects out to"
                            f"{_where_that_is(peers)}."),
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
                                      "between this box and what it connects out to",
                                      raw),
        })
    elif sides.get("client", {}).get("queued"):
        findings.append({
            "severity": "warning", "layer": 3, "code": "queuing_delay_clients",
            "message": _queue_message(sides["client"],
                                      "between this box and the people using it", raw),
        })
    elif not sides and (stats.get("queue") or {}).get("queued"):
        findings.append({
            "severity": "warning", "layer": 3, "code": "queuing_delay",
            "message": _queue_message(stats["queue"], "on the path out of this box", raw),
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
                                       "between this box and what it connects out to"),
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
    # The other plane's queues, read again now the window has run. Recv-Q is a
    # level rather than a counter, so the second reading is the measurement and
    # not a refinement of the first.
    if raw.get("udp_sockets", {}).get("ok") and counter_window:
        raw["udp_sockets"] = udp_window(raw["udp_sockets"], cmd_udp_sockets(),
                                        counter_window)
    _check_udp_queues(raw, late)
    _check_proxy_backends(raw, late)
    _check_inbound_filtering(raw, late)
    _check_forwarding_shape(raw, late)
    _check_transport_fallback(raw, late)
    _check_encapsulation_headroom(raw, late)
    # After the flows, because it reads them. Wired in beside the sessions
    # check first, which runs before the socket table is even collected, so
    # it read an empty side and quietly concluded nothing every time.
    _check_relay_volume(raw, late)
    _check_source_reachability(raw, late)
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
    # The constant-flow walk first, where this box will give us a socket to
    # hear the replies on. It answers the same question as the binary below it
    # and answers it about one path rather than about several, which is the
    # difference every conclusion drawn from hop adjacency rests on.
    #
    # Below rather than instead. It is serial, so it is slower; it needs a raw
    # socket, so most boxes will not run it; and mtr's per-hop loss over many
    # cycles is worth more than either when mtr is installed.
    walked = trace_constant_flow(target)
    if walked and any(h["host"] for h in walked["hops"]):
        return {"raw": {"ok": True, "cmd": "constant-flow walk to %s:%d"
                                           % (walked["target"], walked["dest_port"]),
                        "stdout": render_walk(walked), "walk": walked},
                "hops": walked["hops"], "source": "constant-flow", "mtr": None}
    res = cmd_traceroute(target)
    hops = parse_traceroute_hops(res.get("stdout", "")) if res.get("ok") else []
    return {"raw": res, "hops": hops, "source": "traceroute", "mtr": None}


def render_walk(walked):
    """The walk as the text a traceroute would have printed.

    Every export keeps the output of the command behind a conclusion so it can
    be audited later. This one has no command, so it writes what one would have
    said, in the layout a reader already knows how to read.
    """
    lines = []
    for hop in walked["hops"]:
        times = "  ".join("%.1f ms" % t for t in hop["times_ms"]) or "*"
        lines.append("%2d  %s  %s%s" % (hop["hop"], hop["display"], times,
                                        "  " + " ".join(hop["flags"])
                                        if hop.get("flags") else ""))
    if not walked["arrived"]:
        lines.append("    (%s did not answer within %d hops)"
                     % (walked["target"], TRACE_MAX_HOPS))
    return "\n".join(lines)


# The findings that name a peer worth tracing, per side. A finding on the way
# out points at a backend; one on the way in points at whatever the clients come
# through, which is usually a balancer rather than any one of them.
SIDE_TRACE_CODES = {
    "backend": ("tcp_flow_loss_backends", "tcp_return_stalled_backends"),
    "client": ("tcp_flow_loss_clients", "tcp_return_stalled_clients"),
}


def fold_the_probe_into_the_way_out(report):
    """Put the reference probe inside the way-out column instead of beside it.

    The probe to `--target` exists for a box that opens no connections of its
    own: there is nothing it depends on to trace, so the way out is whatever a
    fixed address can show. It used to get a column of its own, because with no
    outbound connections there was no way-out column for it to sit in.

    There always is one now, and a third column under three boxes is worse than
    the problem it solved - the panel's whole claim is that three places have
    two boundaries between them. So the probe becomes that column's traced
    path, which is what it always was.
    """
    probe = report.get("probe_path")
    if not probe:
        return
    # A probe is itself something to show on the way-out boundary, so it is a
    # reason to draw the panel rather than an exception to it. Without this the
    # panel stayed absent and the probe rendered on its own - one column under
    # three boxes, which is the shape all of this exists to stop.
    if not report.get("path_legs"):
        zoned = {z.get("side"): z.get("state") for z in (report.get("sides") or [])}
        raw = report.get("raw") or {}
        sock = raw.get("sockets") or {}
        report["path_legs"] = [
            _quiet_side("client", zoned.get("downstream"), sock, raw),
            _quiet_side("backend", zoned.get("upstream"), sock, raw)]
    for side in report.get("path_legs") or []:
        if side["side"] != "backend" or side["legs"] or side.get("traced"):
            continue
        side["traced"] = probe
        # The reasons do not end in a full stop, because most of them are read
        # as a clause. Joined to a second sentence, one has to be added.
        side["quiet_because"] = (
            "%s. The hops below are a reference probe to %s rather than to "
            "anything this box depends on, because it depends on nothing: they "
            "say the way out works, not that the work is getting through."
            % (side.get("quiet_because") or "", probe.get("target")))
        report["probe_path"] = None
        return


def trace_each_side(legs, findings, quick=False):
    """Trace a destination on both sides, and hang each path off its own column.

    Only the way out had one. The clients' side carried what its connections
    were doing and nothing about the route between here and them, which left
    half the picture describing a journey and half describing a state.

    Tracing a client goes *to* them, so it is not the route their packets took
    to arrive - that cannot be watched from here, and the TTL count beside it is
    the closest thing there is. It is still the segment between this box and the
    people using it, hop by hop, which is what the column is about.

    Within the same rule everything else here follows: nothing is probed that
    was not already talking to this box.
    """
    for side in (legs or []):
        column = trace_one_peer(side, findings, quick)
        if column:
            side["traced"] = column


def trace_one_peer(side, findings, quick=False):
    """Trace a destination this box is actually talking to.

    The path chain traced the target, which defaults to a public address chosen
    for being reliably reachable. On a box that relays, that is a reachability
    check rather than the route the work takes, and it left the page carrying
    two things that both pointed at the internet: the connections this box
    opened, with no hop detail, and hops to somewhere it never sends anything.

    So it traces a peer from the connections themselves. Which one is a
    judgement on a box with hundreds of them, so it is made in this order and
    recorded, because "hop 2 is slow" means nothing without knowing hop 2 of
    what:

      - the peer a finding named, if one did. That is the connection the report
        is already about.
      - the peer carrying most of the side, if one dominates. That is the
        load-balancer shape, and its path is the path nearly everything takes.
      - otherwise the worst-performing peer, which is the one worth looking at.

    Returns None where there is nothing outbound to trace, and on --quick, which
    skips the first trace too.
    """
    if quick or not side:
        return None
    near = side
    named = [f for f in (findings or [])
             if f["code"] in SIDE_TRACE_CODES.get(side.get("side"), ())]
    # Phrased as destinations, because that is what is being chosen. Calling it
    # "the connection this report is about" and printing the side's connection
    # count beside it read as though the hops below were the connections - they
    # are the path to one destination, and the count is of connections on the
    # side, which are two different numbers that happened to sit together.
    if named:
        host, why = near.get("peer"), "the destination this report is about"
    elif near.get("via"):
        host, why = near.get("via"), "where most of this side's connections go"
    else:
        host, why = near.get("peer"), "the worst-performing destination here"
    host = str(host or "")
    if not host or not valid_target(host):
        return None
    res = cmd_traceroute(host)
    hops = parse_traceroute_hops(res.get("stdout", "")) if res.get("ok") else []
    column = build_probe_column(hops, host)
    if column:
        # The way back, off the TTL of a reply from the same host. The trace
        # counts hops out; this counts hops in, and the two differing is
        # asymmetric routing - which nothing else here can see, because a
        # traceroute only goes one way.
        #
        # One extra probe, to a host this box already has connections to and has
        # just traced. Absent whenever the host does not answer ICMP, which on a
        # forward proxy's clients is most of the time.
        seen = parse_ping_ttl(cmd_ping(host, 1, 1))
        inbound = hops_from_ttl(seen)
        if inbound:
            column["hops_in"], column["ttl_assumed"] = inbound
            column["ttl_seen"] = seen
        # Said on the page, because one destination is standing in for a side
        # that may have many, and a reader has to know which.
        column["picked"] = why
        column["of"] = near.get("connections") or 0
    return column


def probe_each_source(target, addresses, count, wait):
    """Ask every address this box holds whether it can reach the target.

    A box holding a service address beside its own has one path off it per
    address, and they are not the same path: a service address may be routed by
    a policy the box's own address is not, or be held by a partner that has not
    given it up. One probe from whichever address the kernel picks says nothing
    about the others.

    Only the probe repeats. Everything read *about* the box - counters, socket
    tables, certificates - is a property of the box rather than of an address,
    so re-reading it once per address would multiply the run for no answer.
    The trace is deliberately not here either: it is the expensive half, and
    tracing twelve identical paths to learn what one trace already said is how
    a two-second run becomes a thirteen-minute one.

    In parallel, which is only safe because the source is passed rather than
    set: a global would have to be assigned per probe and they would overwrite
    each other.

    Global scope only. A link-local address cannot reach off the segment and a
    loopback one cannot leave the box, so both would report a failure that is
    simply what they are.
    """
    wanted = [a for a in (addresses or [])
              if a.get("scope") == "global" and a.get("address")]
    if len(wanted) < 2:
        return []                      # one address is the ordinary run
    def probe(entry):
        res = cmd_ping(target, count, wait, source=entry["address"])
        sent, lost = parse_ping_counts(res)
        return {"address": entry["address"], "interface": entry.get("interface"),
                "family": entry.get("family"),
                # None rather than 0 where the counts could not be read: a ping
                # that never ran has not measured no loss.
                "sent": sent, "lost": lost,
                "loss_pct": (round(100.0 * lost / sent) if sent else None),
                "avg_ms": parse_ping_stats(res).get("avg_ms"),
                "reached": bool(sent) and lost < sent}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(wanted))) as pool:
        return list(pool.map(probe, wanted))


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
        # Reachable by anything already established, not by ping alone.
        # _check_internet sets inet_loss to None in exactly one case - TCP
        # reached a target that would not answer a ping - so keying the retry
        # on ping switched the TCP trace off in the one situation that had
        # already proved TCP gets through, and left it on only where ping was
        # working anyway. A target that answered nothing at all is still left
        # alone: there is no evidence to act on, and the extra trace would be
        # spent establishing that there is none.
        reach = raw.get("reachability_tcp") or {}
        answered = (inet_loss is not None and inet_loss < 100) or bool(reach.get("ok"))
        # `not quick` was tested here and is always true - this is the else of
        # `if quick` a few lines above.
        if not trace_reached(hops, target) and answered:
            # The port something already reached, rather than an assumption.
            # Under --target auto the target is the backend this box leans on
            # most, and 443 is usually shut on a database - the trace would
            # fail for a reason that has nothing to do with the path. A port
            # that refused the connection serves as well as one that accepted:
            # an RST is a completed round trip, which is all a hop needs to
            # answer.
            tcp_res = cmd_traceroute_tcp(target, port=int(reach.get("port") or 443))
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

        # The walk records what it sent from, which is what a translation
        # is a difference against. Absent on every other trace.
        # Before anything is concluded from the hops: whether they are the
        # route this box would actually use. Everything below reads differently
        # if they are not.
        raw["route_to"] = cmd_route_to(target)
        _check_discard_route(raw, findings, target)
        _check_route_agrees(raw, findings, hops, target)
        path_insight = annotate_hops(
            hops, gw, target,
            sent_from=((trace or {}).get("raw") or {}).get("walk", {}).get("sent_from")
            if isinstance(((trace or {}).get("raw") or {}).get("walk"), dict) else None)

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
            # Marked on the hops themselves, not only said in the message. The
            # chain colours a hop from its own loss figure, so 40% at a router
            # that is rate-limiting replies was drawn as a critical hop directly
            # beneath a verdict reading "no fault found". The report had already
            # decided this loss means nothing; the picture had not been told.
            for lossy_hop in lossy:
                lossy_hop["cosmetic"] = True
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
        elif (pm.get("path_mtu") < pm.get("iface_mtu", STANDARD_MTU)
                and pm.get("signalled_mtu")):
            # Smaller, and the path said so. PPPoE is 1492 and a tunnel is
            # less; when the router replies "fragmentation needed" the sender
            # adapts and nothing stalls. Reporting that as a fault told a
            # working machine it was broken.
            told = pm["signalled_mtu"]
            named = f" and reported it as {told}" if told is not True else ""
            findings.append({
                "severity": "ok",
                "code": "pmtu_reduced",
                "layer": 3,
                "message": f"Path MTU to {target} is {pm['path_mtu']} bytes against an "
                           f"interface set to {pm['iface_mtu']}, and the path signalled "
                           f"that{named}. That is what a tunnel or a PPPoE line looks "
                           f"like, and it is not a fault: the sender is told the limit "
                           f"and adapts, so transfers complete. It is here because it "
                           f"explains a smaller effective packet size, and because the "
                           f"same measurement without the signal is a blackhole.",
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
                           f"copies, TLS handshakes or VPN traffic stall. Nothing on the path "
                           f"reported the smaller limit, which is what separates this from an "
                           f"ordinary tunnel: something drops oversized packets without "
                           f"sending the ICMP message that would let the sender adapt. This "
                           f"measures the path to {target} in the outbound direction only - "
                           f"routing is often asymmetric, so a service elsewhere may see a "
                           f"different limit, and the return path is not tested at all.",
            })

    if path_insight.get("loop_at"):
        lp = path_insight["loop_at"]
        # A router answering twice is a loop, or it is one router that two
        # branches of an unequal-length path both reach. The two are identical
        # in a trace that changes flow on every probe, which is what this one
        # does, and telling them apart is the whole reason Paris traceroute
        # exists. So the fan-out between the repeats decides how hard the claim
        # can be made: with one path there is nothing else this can be, and
        # with several the alternative is at least as likely as the loop.
        fanned = balanced_between(path_insight.get("balanced_hops"),
                                  lp["hops"][0], lp["hops"][1])
        mark_fanout(hops, fanned)
        severity = "warning" if fanned else "critical"
        for hop in hops:
            if hop.get("hop") in lp["hops"]:
                hop["blame"] = {"code": "loop", "severity": severity}
        findings.append({
            "severity": severity,
            "code": "loop",
            "layer": 3,
            "message": (
                f"Routing loop: {lp['host']} answers at both hop {lp['hops'][0]} and hop "
                f"{lp['hops'][1]}. Traffic is circling between routers instead of moving "
                f"toward {target}, and will die when the TTL runs out. This is a routing "
                f"misconfiguration upstream, not a fault on this device."
                if not fanned else
                f"{lp['host']} answers at both hop {lp['hops'][0]} and hop {lp['hops'][1]}, "
                f"which is either a routing loop or one router that two branches of the "
                f"path both reach. More than one router answered at hop"
                f"{'s' if len(fanned) > 1 else ''} "
                f"{', '.join(str(h) for h in fanned)}, so the path fans out between those "
                f"two points and this trace changes flow on every probe - which means the "
                f"hops either side of the repeat are not necessarily on one path. A real "
                f"loop stops traffic dead; if {target} is answering at all, this is the "
                f"second reading. Confirm with a trace that holds the flow constant "
                f"before escalating it as a loop."),
        })

    if path_insight.get("translations"):
        seen = path_insight["translations"]
        first = seen[0]
        where = ("before the first hop that answered"
                 if first["hop"] is None else
                 "at hop %s (%s)" % (first["hop"], first["host"]))
        findings.append({
            "severity": "warning",
            "code": "nat_observed",
            "layer": 3,
            "message": f"Something {where} is rewriting this box's address: it sent from "
                       f"{first['from']} and a router past that point quoted the packet "
                       f"back as coming from {first['to']}. That is a NAT, measured rather "
                       f"than guessed - a router that only routes hands the packet on "
                       f"unchanged."
                       + (f" It happens {len(seen)} times along this path, so there is more "
                          f"than one translating device between here and the target."
                          if len(seen) > 1 else "")
                       + " Inbound connections and port forwarding do not survive it "
                         "without configuration, and it puts a device in the path holding "
                         "state per connection.",
        })

    if path_insight.get("double_nat"):
        subnets = path_insight["double_nat"]
        # "In series" is the claim, and a fan-out before the edge is what takes
        # it away: two branches of a load-balanced path each holding their own
        # subnet look exactly like two subnets one behind the other once the
        # answers are written down as a numbered list.
        fanned = balanced_between(path_insight.get("balanced_hops"), 1,
                                  path_insight.get("demarc_hop") or len(hops) or 1)
        mark_fanout(hops, fanned)
        findings.append({
            "severity": "warning",
            "code": "double_nat",
            "layer": 3,
            # What a trace establishes is two private networks in series, and
            # therefore two routers. Whether either of them translates is not
            # visible from here - routed subnets and NAT look identical in a
            # traceroute, and a site with several routed VLANs is ordinary.
            # This said "double NAT" outright and then listed the consequences
            # of NAT as though they followed, which for a routed path they do
            # not. The observation is stated, the likely cause is named as a
            # likelihood, and the consequences are attached to the cause
            # rather than to the observation.
            "message": f"Two private networks before traffic leaves this site "
                       f"({', '.join(s + '.x' for s in subnets)}) - so traffic crosses at "
                       f"least two routers on the way out. Commonly that is double NAT, "
                       f"though a trace cannot tell a translating router from one that "
                       f"only routes, and several internal subnets are ordinary in "
                       f"themselves. If it is NAT, it breaks inbound connections and port "
                       f"forwarding, and either way it makes an intermittent fault harder "
                       f"to place - there is a second device in the path to rule out."
                       + (f" Read that carefully here: more than one router answered at "
                          f"hop{'s' if len(fanned) > 1 else ''} "
                          f"{', '.join(str(h) for h in fanned)}, so these two networks may "
                          f"be side by side on a load-balanced path rather than one behind "
                          f"the other."
                          if fanned else ""),
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
        # The jump is the difference between this hop's time and the one above
        # it, which is a cost of the link between them only if there is a link
        # between them. Where the path fans out across the pair, the two times
        # can be from different branches and the difference is the gap between
        # two routes rather than a wall on one.
        fanned = balanced_between(path_insight.get("balanced_hops"),
                                  max(1, wj["hop"] - 1), wj["hop"])
        mark_fanout(hops, fanned)
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
                  "looking slow is expected rather than separate."
                + (" More than one router answered across that pair of hops, so the two "
                   "times may be from different branches of a load-balanced path: the "
                   "jump is then the difference between two routes rather than the cost "
                   "of one link, and the size of it is real either way."
                   if fanned else "")),
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

def source_address_is_held(address):
    """Is this address on this box? Ask the kernel to bind to it.

    Definitive where reading a command's output is not: it is the same question
    the kernel answers when a probe actually leaves, so it cannot disagree with
    the measurement it is vouching for. It also works when nothing could list
    the interfaces, which on an appliance is the case that matters.

    Costs nothing and sends nothing. A bind reserves a local address; no packet
    leaves, no name is resolved, and the socket is closed immediately.

    A stream socket rather than a datagram one, deliberately. This never calls
    listen(), and a TCP socket that has not listened cannot accept a connection
    even in principle, so the check cannot be read as this program opening a
    port. A bound UDP socket would answer the same question and would be able
    to receive while it was open, which is a thing this program does not do.
    """
    family = socket.AF_INET6 if ":" in (address or "") else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((address, 0))
        return True
    except (OSError, socket.error):
        return False


def _check_source_address(raw, findings):
    """What this box holds, and whether it holds what the run was told to use.

    Two findings out of one reading. Without --source, a service address is
    named as context: it changes how every measurement below should be read,
    because the kernel will not choose it and so none of them are about it.

    With --source, this is the finding that outranks the rest of the run. If
    the address is not here, nothing measured afterwards is about the path
    anyone asked about, and the danger is that it all looks fine: on a
    redundant pair the backup node holds its own address, reaches everything
    from it, and reports a healthy box that is serving nothing.
    """
    addresses = raw.get("own_addresses") or []
    service = service_addresses(addresses)
    raw["service_addresses"] = service

    if service and not SOURCE_ADDRESS:
        named = ", ".join("%s on %s" % (s["address"], s["interface"] or "?")
                          for s in service[:4])
        findings.append({
            "severity": "ok",
            "code": "service_address_present",
            "layer": 3,
            "message": f"This box holds {len(service)} address(es) configured as a service "
                       f"address rather than as the box's own ({named}). Nothing in this "
                       f"report was measured from them: the kernel sends from the "
                       f"interface's primary address unless told otherwise. Re-run with "
                       f"--source to measure the path a client of that address actually "
                       f"gets.",
        })

    if not SOURCE_ADDRESS:
        return

    raw["source_address"] = SOURCE_ADDRESS
    held = source_address_is_held(SOURCE_ADDRESS)
    raw["source_address_held"] = held
    if held:
        match = [a for a in addresses if a["address"] == SOURCE_ADDRESS]
        where = (" (%s on %s)" % ("/%s" % match[0]["prefix"] if match[0]["prefix"]
                                  else "no prefix", match[0]["interface"] or "?")
                 ) if match else ""
        findings.append({
            "severity": "ok",
            "code": "bound_to_source_address",
            "layer": 3,
            "message": f"Every probe that can name a source left from {SOURCE_ADDRESS}"
                       f"{where}, so the path measured is the one a client of that "
                       f"address gets, including its return path. A few utilities have "
                       f"no such option - Windows ping and tracert, tracepath, nslookup "
                       f"- and where one of those was the only one available, that "
                       f"check left from whichever address the kernel chose.",
        })
    else:
        findings.append({
            "severity": "critical",
            "code": "source_address_not_held",
            "layer": 3,
            "message": f"{SOURCE_ADDRESS} is not an address on this box, so nothing here "
                       f"was measured from it. The kernel refused to bind to it, which is "
                       f"as certain as this gets. On a redundant pair this is what a "
                       f"standby node looks like: the address lives on its partner, and a "
                       f"run that let the kernel choose would have measured this node's "
                       f"own address and called the box healthy.",
        })


_WILDCARD_BINDS = ("", "*", "0.0.0.0", "::", "[::]", "*.*")


def _serves(bound, address):
    """Is anything on this box accepting on `address`?

    A wildcard bind answers for every address the box holds, including one
    added after the process started, so it counts as serving all of them. That
    is why this cannot be a set membership test on the address alone: the
    common case is nginx on 0.0.0.0 and a service address added underneath it
    by keepalived, and calling that unserved would be wrong about nearly every
    box this is written for.
    """
    wants_v6 = ":" in (address or "")
    for host, _port in bound or []:
        clean = (host or "").strip("[]")
        if clean == address:
            return True
        if clean not in _WILDCARD_BINDS:
            continue
        # Which wildcard, and for which family. 0.0.0.0 is the IPv4 wildcard
        # and never accepts an IPv6 connection, so counting it as cover for a
        # v6 service address suppressed the finding on an address that really
        # did have nothing accepting on it. "::" is allowed to cover both,
        # because a dual-stack listener on it takes v4 as mapped addresses,
        # which is how most of them are built.
        if clean == "0.0.0.0" and wants_v6:
            continue
        return True
    return False


def _check_service_addresses(raw, findings):
    """A service address that is up, and whether anything is actually using it.

    Holding the address is the easy half and the tool now does it. The half
    that goes wrong quietly is what happens next: the address is configured,
    it answers ARP, and traffic is going somewhere else. A failover that moved
    the address without moving the traffic, a partner that never gave it up, a
    service that died and left the address behind - all of them leave a box
    that looks configured and serves nobody, and every check in this tool would
    have passed on it.

    Both findings are warnings rather than faults, and the reason is the same
    for both: this reads userland sockets, and a box forwarding at the kernel
    (IPVS, nftables or iptables DNAT, and every direct-return load balancer)
    serves a service address with nothing bound to it at all. That is the
    normal shape of the deployment this exists for, so an absent listener has
    to be reported as something to look at rather than as a broken box.
    """
    service = raw.get("service_addresses") or []
    sockets = raw.get("sockets") or {}
    if not service or not sockets.get("ok"):
        return                              # nothing to say, or no way to tell

    bound = sockets.get("bound") or []
    served_on = sockets.get("served_on") or {}

    for entry in service:
        address = entry["address"]
        here = served_on.get(address, 0)
        if here:
            continue                        # in use, which is the whole question
        # Everything arriving anywhere on this box, which past the line above
        # means everywhere but here. Other service addresses count: a box
        # holding two and serving one is the clearest case there is of traffic
        # reaching this machine and choosing somewhere other than this address.
        arriving_elsewhere = sum(served_on.values())
        if not _serves(bound, address):
            findings.append({
                "severity": "warning",
                "code": "service_address_unserved",
                "layer": 4,
                "message": f"{address} is configured on "
                           f"{entry.get('interface') or 'this box'} and nothing on this "
                           f"box is listening on it, or on a wildcard that would cover "
                           f"it. Clients reaching it get a refused connection while ARP "
                           f"answers normally, which is why it looks reachable. If this "
                           f"box forwards in the kernel rather than accepting - IPVS, a "
                           f"DNAT rule, direct return - then there is nothing here to "
                           f"see and this is expected.",
            })
        elif arriving_elsewhere:
            findings.append({
                "severity": "warning",
                "code": "service_address_idle",
                "layer": 4,
                "message": f"{address} is up and something is listening for it, but no "
                           f"connection is arriving on it, while {arriving_elsewhere} "
                           f"connection(s) are arriving on this box's other addresses. "
                           f"Traffic for this address is going somewhere else: a "
                           f"failover that moved the address without moving the "
                           f"traffic, a partner still answering for it, or a load "
                           f"balancer that has taken this box out of rotation.",
            })


def _check_idle_endpoint(raw, findings):
    """One listener on an address serving nobody while its siblings serve.

    The address-level check above cannot see this. It asks whether traffic is
    arriving on an address at all, so an address holding three listeners answers
    yes on the strength of any one of them, and a wedged instance beside two
    working ones is invisible - which on a box that runs several is the failure
    worth finding.

    Deliberately silent unless a sibling on the *same address* is serving. An
    instance that has just started, or one a load balancer has not sent anything
    to yet, is up and not serving, and that is the commonest harmless state
    there is. What makes this different is that something is arriving at this
    address and choosing another port on it, so routing, ARP and the interface
    are all ruled out by the traffic itself.

    Wildcard listeners are left out. `*:443` answers on every address the box
    holds, so it has no address of its own to compare siblings against.
    """
    rows = [r for r in (raw.get("service_instances") or [])
            if not r.get("wildcard") and r.get("address")]
    by_address = {}
    for row in rows:
        by_address.setdefault(row["address"], []).append(row)
    for address, group in sorted(by_address.items()):
        # No count check here on purpose: a group of one cannot hold both a
        # serving and an idle member, so the pair below already excludes it,
        # and a second guard saying the same thing is one no test can tell the
        # difference about.
        serving = [r for r in group if (r.get("traffic") or 0) > 0]
        idle = [r for r in group if not (r.get("traffic") or 0)]
        if not serving or not idle:
            continue
        for row in idle:
            busiest = max(serving, key=lambda r: r.get("traffic") or 0)
            findings.append({
                "severity": "warning",
                "layer": 4,
                "code": "service_endpoint_idle",
                "scope": row.get("endpoint"),
                "message": f"Something is listening on {row['endpoint']} and no "
                           f"connection is arriving on it, while "
                           f"{busiest['endpoint']} on the same address is "
                           f"carrying {busiest.get('traffic'):,}. Traffic reaches "
                           f"this address and goes to another port on it, so the "
                           f"route, the address and the interface are all working "
                           f"- what is not is whatever should be steering clients "
                           f"to this port, or the instance behind it.",
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
    raw["own_addresses"] = parse_own_addresses(raw["interfaces"])
    _check_source_address(raw, findings)
    _check_service_addresses(raw, findings)
    if not raw["interfaces"].get("ok"):
        # No command could describe the interfaces, so ask the kernel for the
        # one fact this finding turns on. It answers on a box shipping none of
        # the programs above, and when it does the run stops having to assume.
        source = kernel_source_address()
        raw["kernel_source_address"] = source
        if source:
            message = (f"Couldn't read the interface list "
                       f"({raw['interfaces'].get('error', 'command failed')}), so which "
                       f"interface holds what is unknown. The device does have an address "
                       f"and a route off itself: the kernel says it would leave from "
                       f"{source}. Everything below rests on that rather than on an "
                       f"assumption.")
        else:
            message = (f"Couldn't read the interface list "
                       f"({raw['interfaces'].get('error', 'command failed')}), so this run "
                       f"can't say whether the device has an address. Everything below assumes "
                       f"it does.")
        findings.append({
            "severity": "warning",
            "code": "interfaces_unreadable",
            "layer": 1,
            "message": message,
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
    # A datagram listener serves peers the kernel never records, so an empty TCP
    # table is not an empty box. On one that forwards user traffic over UDP this
    # fired while every tunnel it was built to carry was up, and said the service
    # was reaching nobody - at high confidence, with every other check passing,
    # which is the most expensive way to be wrong.
    datagram = (raw.get("udp_sockets") or {}).get("listeners") or []
    if datagram:
        where = ", ".join(str(p) for p in ports_in_order({l["port"] for l in datagram})[:4])
        findings.append({
            "severity": "ok",
            "layer": 4,
            "code": "clients_may_be_on_the_datagram_plane",
            "message": (
                f"No TCP connection is open inbound, and this box is also listening "
                f"for datagrams on {where}. A datagram socket serves any number of "
                f"peers without the kernel recording one of them, so the socket table "
                f"cannot say how many are being served."
                + _tunnels_counted(raw)),
        })
        return
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


_PROXY_URL = re.compile(r"^(?:[a-z]+://)?(?:[^@/]*@)?\[?([^\]/:]+)\]?(?::(\d+))?",
                        re.I)


def proxy_endpoints(cfg):
    """Every host and port this box is told to reach the internet through.

    Deduplicated, because the same proxy is usually named three times - once
    for http, once for https, once in the system settings - and probing it
    three times would report one dead proxy as three faults.

    A PAC file names no endpoint here on purpose. Working out which proxy it
    would choose means running its JavaScript, and this does not have a
    JavaScript engine or any business acquiring one.
    """
    found = {}
    values = list((cfg.get("env") or {}).values())
    sysc = cfg.get("system") or {}
    for key in ("HTTPSProxy", "HTTPProxy"):
        if sysc.get(key):
            port = sysc.get(key.replace("Proxy", "Port"))
            values.append("%s:%s" % (sysc[key], port) if port else sysc[key])
    for value in values:
        m = _PROXY_URL.match((value or "").strip())
        if not m or not m.group(1):
            continue
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else 8080
        found[(host, port)] = {"host": host, "port": port}
    return list(found.values())


def cmd_proxy_reachable(cfg, timeout=3):
    """Can this box open a connection to the proxy it is told to use.

    One TCP connect, no request sent and nothing read. The point is not to
    exercise the proxy - it is that a proxy which refuses or does not answer
    breaks every application on the box while ping, traceroute and DNS all
    pass, which is the shape of report this check exists to stop producing.
    """
    endpoints = proxy_endpoints(cfg or {})
    if not endpoints:
        return {"ok": False, "cmd": "tcp connect (proxy)", "applicable": False,
                "error": "no proxy endpoint to probe"}
    tried = []
    for where in endpoints:
        started = time.monotonic()
        try:
            connect_from(where["host"], where["port"], timeout).close()
            tried.append(dict(where, reachable=True,
                              connect_ms=round((time.monotonic() - started) * 1000, 1)))
        except (OSError, ValueError) as exc:
            tried.append(dict(where, reachable=False,
                              refusal=why_it_would_not_connect(exc) or "unreachable"))
    return {"ok": True, "cmd": "tcp connect (proxy)", "proxies": tried,
            "stdout": "\n".join(
                "%s:%s  %s" % (t["host"], t["port"],
                               "reachable" if t["reachable"] else t.get("refusal"))
                for t in tried)}


WHAT_A_REFUSAL_MEANS = {
    "refused": "refused the connection, so nothing is listening on that port",
    "timeout": "did not answer, so it is either gone or being filtered on the way",
    "no such address": "is not an address this box can reach at all",
}


def _check_proxy(raw, findings, target):
    """Say when the checks and the traffic take different routes.

    Every probe here goes direct: ping, traceroute and a TCP connect do not
    read a proxy setting, and nothing in the standard library makes them. An
    application on the same box, told to use a proxy, does not go direct. So
    on a proxied box the checks measure a path that nothing here uses, and a
    completely clean report can sit beside a user who cannot load anything.

    Reported as context and never as a fault. A proxy is a normal thing to
    have and this says nothing about whether it is working - only that
    thirty-odd findings below are about a route that may not be the one in
    use, which is the reader's to weigh and not the tool's to guess at.
    """
    cfg = cmd_proxy_config()
    raw["proxy"] = cfg
    # A collector that could not run returns the shape every other one does,
    # without these keys. Nothing is known about the routing then, which is
    # not the same as knowing there is no proxy - so it says nothing.
    env = {k: v for k, v in (cfg.get("env") or {}).items()
           if not k.lower().startswith("no_")}
    sysc = cfg.get("system") or {}
    on = (sysc.get("HTTPEnable") == "1" or sysc.get("HTTPSEnable") == "1")
    pac = sysc.get("ProxyAutoConfigEnable") == "1"
    wpad = sysc.get("ProxyAutoDiscoveryEnable") == "1"
    if not (env or on or pac or wpad):
        return

    where = []
    if env:
        where.append("set in this shell's environment ("
                     + ", ".join(sorted(env)) + ")")
    if on:
        server = sysc.get("HTTPSProxy") or sysc.get("HTTPProxy") or "a proxy"
        where.append(f"configured on this system ({server})")
    if pac:
        where.append("configured by a PAC file"
                     + (f" at {sysc['ProxyAutoConfigURLString']}"
                        if sysc.get("ProxyAutoConfigURLString") else ""))
    if wpad:
        where.append("discovered automatically (WPAD)")

    # And whether it answers. Reading the setting was always the easy half:
    # the report says every check below describes the direct route, and then
    # said nothing about the route that is actually in use.
    raw["proxy_reachable"] = cmd_proxy_reachable(cfg)
    dead = [p for p in (raw["proxy_reachable"].get("proxies") or [])
            if not p["reachable"]]
    if dead:
        worst = dead[0]
        findings.append({
            "severity": "critical",
            "layer": 7,
            "code": "proxy_unreachable",
            "message": (
                f"This box is told to reach the internet through {worst['host']}:"
                f"{worst['port']}, and that address "
                + WHAT_A_REFUSAL_MEANS.get(worst.get("refusal"),
                                           "could not be connected to")
                + ". Every application here that honours the setting is failing right "
                  "now, and nothing else on this report will show it: a ping, a "
                  "traceroute and a TCP connect to the target all go direct and do not "
                  "read that setting, so they can pass while nothing on the box can "
                  "load anything."
                + (f" {len(dead)} configured proxies are unreachable."
                   if len(dead) > 1 else "")),
        })

    findings.append({
        "severity": "ok",
        "layer": 7,
        "code": "proxy_configured",
        "message": f"This box is told to reach the internet through a proxy - "
                   f"{'; '.join(where)}. Every check here went direct: a ping, a "
                   f"traceroute and a TCP connect do not read that setting. So what "
                   f"is said below about reaching {target}, and about resolving names "
                   f"for it, describes the direct route rather than the one an "
                   f"application here would take - and the two can disagree "
                   f"completely."
                   + (" Read from this shell's environment, which is not necessarily "
                      "what a service running here sees." if env and not (on or pac or wpad)
                      else ""),
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
                               f"internet - check the egress rules before the carrier."
                               + _dropped_by(raw),
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


# The one word to go and touch.
#
# `owner` already says who owns a finding, but it is prose - 106 distinct
# phrases across the ranked findings, nearly one each. That is a sentence to
# read. This is a label to scan, from a closed set small enough to learn.
#
# It is deliberately incomplete. A hint that is wrong is worse than none at all,
# because one word carries more authority than the paragraph under it, so a
# finding nobody has classified gets no chip rather than a guess. The guard
# below allows that; what it does not allow is a word outside the vocabulary.
#
# The trap is naming the obvious answer rather than the conclusion. Climbing CRC
# errors look like a cable, and on a full-duplex link they are a duplex
# mismatch that no cable will fix - which is one of the cases this tool exists
# to get right. So duplex_mismatch points at the switch port, and anything whose
# whole purpose is to contradict the obvious reading has to be checked by hand
# before it is given a word.
HINT_WORDS = (
    "cable", "switch port", "optics", "this box", "cooling", "clock",
    "DNS", "ISP", "LAN", "capacity", "certificate", "the service",
    "the app", "firewall", "MTU", "the backend", "the client path",
)

FINDING_HINT = {
    # --- the physical link ---------------------------------------------
    "link_errors_live": "cable",
    "link_flapping_live": "cable",
    "link_flapping_logged": "cable",
    "link_flapping": "cable",
    "slow_link": "cable",
    "link_errors_historical": "cable",
    # Not "cable". A full-duplex link reporting collisions is the switch port
    # disagreeing about duplex, and replacing the cable is the wrong answer the
    # ranking exists to prevent.
    "duplex_mismatch": "switch port",
    "collisions": "switch port",
    "negotiated_below_capacity": "switch port",
    "bond_degraded": "switch port",
    "optics_alarm": "optics",
    "optics_rx_low": "optics",
    "optics_rx_marginal": "optics",
    "optics_warning": "optics",

    # --- the box itself ------------------------------------------------
    "no_ipv4": "this box",
    "no_gateway": "this box",
    "no_route_to_target": "this box",
    "drops_live": "this box",
    "nic_drops_live": "this box",
    "nic_ring_overruns": "this box",
    "nic_reset_logged": "this box",
    "rcv_buffer_pruned": "this box",
    "tcp_orphans_high": "this box",
    "conntrack_drops_live": "this box",
    "conntrack_near_limit": "this box",
    "neigh_table_full": "this box",
    "neigh_table_near_limit": "this box",
    "fd_pressure": "this box",
    "ephemeral_ports_low": "this box",
    "resets_sent_high": "this box",
    "udp_recv_buffer_full": "this box",
    "source_address_not_held": "this box",
    "cpu_throttled_live": "cooling",
    "cpu_throttled_historical": "cooling",
    "clock_skewed": "clock",
    "clock_unsynced": "clock",
    # The certificate is not the fault: it is not valid *yet*, which is almost
    # always this device's clock.
    "tls_not_yet_valid": "clock",

    # --- names ----------------------------------------------------------
    "dns_fail": "DNS",
    "dns_all_resolvers_down": "DNS",
    "dns_resolver_down": "DNS",
    "dns_resolver_slow": "DNS",
    "dns_disagree": "DNS",
    "dns_no_resolvers": "DNS",
    "dns_hijack": "DNS",

    # --- off the site ----------------------------------------------------
    "inet_partial_loss": "ISP",
    "inet_unreachable": "ISP",
    "cgnat": "ISP",
    "trace_stalls": "ISP",
    "loop": "ISP",
    "tcp_flow_loss_some_peers": "ISP",

    # --- the segment this box sits on ------------------------------------
    "gw_unreachable": "LAN",
    "gw_partial_loss": "LAN",
    "duplicate_ip": "LAN",
    "double_nat": "LAN", "nat_observed": "LAN",
    "virtual_router_conflict": "LAN",

    # --- not a fault, a limit --------------------------------------------
    "link_saturated": "capacity",
    "link_busy": "capacity",
    "uplink_saturated": "capacity",
    "uplink_busy": "capacity",
    "saturation_bursts": "capacity",

    # --- certificates -----------------------------------------------------
    "own_tls_expired": "certificate",
    "own_tls_expiring": "certificate",
    "own_tls_untrusted": "certificate",
    "tls_expired": "certificate",
    "tls_expiring": "certificate",
    "tls_untrusted": "certificate",
    "tls_intercepted": "certificate",

    # --- something is listening, and it is the problem ---------------------
    "own_service_not_accepting": "this box",
    "proxy_backend_down": "the backend",
    "proxy_unreachable": "the app",
    "own_service_silent": "the service",
    "own_service_erroring": "the service",
    "own_service_not_http": "the service",
    "own_tls_handshake_failed": "the service",
    "port_refused": "the service",
    "tls_handshake_failed": "the service",
    "tls_handshake_slow": "the service",
    "accept_overflow_live": "the app",
    "accept_overflow_historical": "the app",
    "close_wait_backlog": "the app",
    "udp_queue_standing": "the app",
    "transport_fell_back": "firewall",
    "inbound_filtered_here": "firewall",
    "target_is_discarded": "this box",
    "tunnel_payload_short": "MTU",
    "syn_recv_backlog": "the app",
    "syncookies_live": "the app",
    "syncookies_historical": "the app",
    "reqq_full_drops": "the app",

    # --- something is refusing on purpose ----------------------------------
    "egress_blocked": "firewall",
    "path_admin_prohibited": "firewall",
    "port_timeout": "firewall",

    # --- how big a packet may be -------------------------------------------
    "pmtu_blackhole": "MTU",
    "fragments_lost": "MTU",
    "tunnel_mtu": "MTU",
    "frame_length_errors": "MTU",
    "mtu_nonstandard": "MTU",

    # --- the two sides of a box that relays --------------------------------
    "tcp_flow_loss_backends": "the backend",
    "tcp_return_stalled_backends": "the backend",
    "queuing_delay_backends": "the backend",
    "path_jitter_backends": "the backend",
    "tcp_flow_loss_clients": "the client path",
    "tcp_return_stalled_clients": "the client path",
    "queuing_delay_clients": "the client path",
    "path_jitter_clients": "the client path",
    "service_address_unserved": "the client path",
    "service_address_idle": "the client path",
    "service_endpoint_idle": "the client path",
}


# Findings whose subject is the destination itself, rather than the path to it.
# They mark the target hop by role rather than by number, since which hop is the
# target varies with the path.
#
# Two shapes end up here for opposite reasons. The first two say traffic to the
# target is not arriving even though the trace got a reply from it - an egress
# policy that blocks echo and 443 while leaving traceroute's probes alone. The
# third says the opposite: the path is genuinely fine and the thing at the end
# of it is what went quiet. Both need the same endpoint marked, because in both
# the report names the destination and the chain would otherwise draw it clean.
#
# destination_unresponsive was left out of this for a long time, which is how
# "the path reaches the target and the target answers nothing" came to be drawn
# as a green target at the end of a green path.
TARGET_UNREACHED = ("egress_blocked", "inet_partial_loss",
                    "destination_unresponsive")


def _mark_target_hop(hops, findings):
    """Stop the path drawing a clean destination the report says is not.

    The chain colours each hop from the trace's own replies, and a trace gets
    through where the traffic being diagnosed does not: an egress policy that
    blocks ICMP echo and TCP 443 while leaving traceroute's probes alone
    answers at every hop. So the report said nothing reaches the target and the
    picture drew the target green, one panel apart.

    These two codes are named rather than taken from whatever marked the
    outbound direction, because most of what marks it is not about reaching the
    target at all - a resolver that is down, carrier NAT, a local port limit -
    and the path to the target really is fine in those. One of them says so
    outright: inet_loss_unmeasured exists to report that a single unanswered
    probe out of four is not established loss, and marking the destination on
    the strength of it would be the picture claiming what the sentence
    declines to. Findings that already agree with a clean path are left alone
    for the same reason: destination_unresponsive says the trace reached the
    target and the target is what went quiet, which is a clean path and a
    marked endpoint, and that is what it should look like.

    A hop already carrying a more serious mark keeps it - the path check runs
    first and knows things about a specific hop that this does not.
    """
    reached = [f for f in findings if f["code"] in TARGET_UNREACHED]
    if not reached:
        return
    worst = max(reached, key=lambda f: SEVERITY_RANK.get(f["severity"], 0))
    for hop in hops:
        if "target" not in (hop.get("roles") or []):
            continue
        held = hop.get("blame")
        if held and SEVERITY_RANK.get(held["severity"], 0) >= \
                SEVERITY_RANK.get(worst["severity"], 0):
            return
        hop["blame"] = {"code": worst["code"], "severity": worst["severity"]}
        return


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
    # The other plane. A box can carry its user traffic over datagrams while its
    # control plane is TCP, and every other socket reading here is TCP - without
    # this the busiest half of such a box is simply absent from the report.
    raw["udp_sockets"] = cmd_udp_sockets()
    # And how many tunnels are arriving at them, which the socket table cannot
    # say and the connection tracking table can. Counted, never listed.
    raw["udp_tunnels"] = cmd_udp_tunnels(raw)
    # Who holds them, read beside the table itself so every finding built from
    # that table can name a process instead of saying "an application".
    raw["socket_owners"] = cmd_socket_owners()
    # What this box's own egress queues are doing, for the three findings that
    # otherwise offer three candidates and can eliminate none of them.
    raw["qdisc"] = cmd_qdisc()
    # PROTOTYPE: what the proxy on this box believes about its own backends,
    # if there is one and it is willing to say. Absent on almost every box.
    raw["proxy_stats"] = cmd_haproxy_stats()
    target, target_kind = _choose_target(target, raw["sockets"], findings)
    raw["target_kind"] = target_kind
    # The resolved address, kept so a route prefix can be matched against it.
    # A name that never resolved leaves this absent, and the check stays quiet.
    try:
        raw["target_ip"] = socket.gethostbyname(target)
    except (OSError, UnicodeError):
        raw["target_ip"] = None
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
    # Only the probe repeats, and only when asked. Everything read before this
    # is a property of the box rather than of one of its addresses, so it is
    # read once however many addresses there turn out to be.
    if PROBE_EVERY_SOURCE:
        raw["probe_target"] = target
        raw["source_matrix"] = probe_each_source(target, raw.get("own_addresses"),
                                                 ping_count, ping_wait)

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
    # The firewall counters, read either side of the probes so a rule that
    # counted can be attributed to the window they were in flight. Bracketing
    # them is the whole design: the ruleset on its own says what could happen,
    # and the pair says what did.
    _rules_before = cmd_firewall_counters()
    probes = collect_probes(target, gw, ping_count, ping_wait, quick, mtr_cycles,
                            parallel=not soak)
    raw["firewall"] = firewall_window(_rules_before, cmd_firewall_counters())
    _check_gateway(raw, findings, gw, probes, arp_entries)

    _check_proxy(raw, findings, target)
    inet_loss = _check_internet(raw, findings, target, probes)

    say("reading the path and measuring MTU")
    hops, path_insight, path_source = _check_path(
        raw, findings, target, gw, inet_loss, quick, mtr_cycles, primary_mtu,
        trace=probes.get("trace"))

    # Runs here because it is the first point where both exist: the internet
    # checks reach their conclusion before there is a path to mark.
    _mark_target_hop(hops, findings)

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
    # After both, so the rows carry whatever those two learned. It reads what
    # is already there and probes nothing itself, which is why it runs even
    # under --quick, where the up column simply says less.
    _build_service_instances(raw)
    # After the table, because it compares its rows.
    _check_idle_endpoint(raw, findings)
    _check_upstream_sessions(raw, findings)

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
    # After the port checks, because it compares how long a handshake took
    # against how long the path is, and those timings are what they produce.
    # Called earlier it read an empty list and concluded nothing, silently.
    _check_answered_closer(raw, findings, target, hops, port_results)

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
                                  # Every check has run by here, so the fault
                                  # list is complete. The verdict has not been
                                  # built yet and is compared further down,
                                  # where it exists.
                                  "findings": findings,
                                  "verdict": None}, baseline) if baseline else []
    # The previous visit's path, kept only as far as it can be drawn: the hop
    # number and how long the round trip to it took. Enough to lay the last
    # visit under this one on the same scale, and nothing that was not needed
    # for that - the addresses, names and counters stay in the report they
    # came from. Absent unless --baseline was given, so a run without one
    # carries nothing extra.
    baseline_path = [{"hop": h.get("hop"), "avg_ms": h.get("avg_ms")}
                     for h in ((baseline or {}).get("hops") or [])
                     if h.get("avg_ms") is not None] or None
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

    # The verdict line, unless the fault behind it is already in the list. The
    # verdict headline *is* a finding's headline, so on the ordinary change -
    # one fault appears and becomes the verdict - both lines carry the same
    # sentence and the second one is read as a second change.
    #
    # And not at all when the verdict is itself about the comparison. "The
    # verdict changed to: something changed since the last visit" is the
    # section describing itself, printed above the list it is describing.
    _named = {c["what"] for c in comparison}
    _top = (verdict.get("based_on") or [None])[0]
    _behind_it = HEADLINE.get(_top)
    if baseline and (baseline.get("verdict") or {}).get("headline") \
            and verdict.get("headline") != baseline["verdict"]["headline"] \
            and _behind_it not in _named \
            and _top not in _ABOUT_THE_COMPARISON:
        rank = SEVERITY_RANK
        comparison.append({
            "what": "verdict",
            "before": baseline["verdict"]["headline"],
            "after": verdict["headline"],
            "direction": ("worse" if rank.get(verdict.get("severity"), 0)
                          > rank.get(baseline["verdict"].get("severity"), 0)
                          else "better" if rank.get(verdict.get("severity"), 0)
                          < rank.get(baseline["verdict"].get("severity"), 0) else "neutral"),
        })

    # Built once and used twice: the three boxes read it, and the four legs take
    # each side's state from it so a column heading cannot disagree with the box
    # sitting directly above it.
    # The one word to go and touch, where the finding has been classified.
    # Attached here rather than worked out in a renderer, so the page and the
    # terminal cannot end up pointing at different things.
    for _f in findings:
        # Checked against the vocabulary on the way out, so a word nobody chose
        # cannot reach a report even if the table grows one. The set is the
        # point: a label is only scannable while it is small enough to learn.
        _hint = FINDING_HINT.get(_f.get("code"))
        if _hint in HINT_WORDS:
            _f["hint"] = _hint

    # Worst first, and the cause ahead of its equals.
    #
    # The list was in collection order, which is the order the checks happen to
    # run in and means nothing to a reader: a report could open with two notes
    # about things that are fine and put the one fault under them. Sorted here
    # rather than in either renderer, because two orderings of the same list is
    # two reports.
    #
    # Stable, so findings of equal weight keep the order they were found in -
    # which is roughly outward from this box, and is a better tiebreak than
    # anything alphabetical.
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.get("severity"), 0),
                                 0 if f.get("relation") == "cause" else 1))

    _sides = build_sides(findings, raw)
    # Which box the verdict blames. The colours say which direction stopped
    # working, and for nineteen findings that is a different box - so on those
    # the panel pointed at a side the verdict had just exonerated.
    #
    # Only when there is something to blame. A verdict is always based on the
    # top finding, including on a clean run where that finding is a note about
    # something being fine, so marking the cause off `based_on` alone tagged a
    # green box "the cause" on every all-clear report.
    _cause = (verdict.get("based_on") or [None])[0]
    if _cause and verdict.get("severity") in ("warning", "critical"):
        _owner = cause_owner_side(_cause)
        for _z in _sides:
            _z["owns_cause"] = _z["side"] == _owner
    report = {
        "verdict": verdict,
        "stages": build_stages(findings, raw, checked_ports=bool(check_ports), quick=quick),
        "sides": _sides,
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
        "baseline_path": baseline_path,
        "networks_crossed": path_insight.get("networks_crossed") or [],
        "double_nat": path_insight.get("double_nat") or [],
        "loop_at": path_insight.get("loop_at"),
        "cgnat_hop": path_insight.get("cgnat_hop"),
        "port_results": port_results,
        "quick": quick,
        "soak_seconds": soak or None,
        "path_source": path_source,
        # The path as four legs, decided here so the page and the terminal
        # cannot end up with two versions of which direction stopped.
        "path_legs": build_path_legs(raw, _sides),
        # Present only on a box that has one, because that is the only box
        # where saying "TCP" tells a reader anything.
        "other_plane": other_plane(raw),
        # Names for the addresses this report shows, and only those. Carried as
        # a lookup rather than folded into the fields, so every address stays
        # exactly what it was and the page decides how to show both.
        "peer_names": None,
        # The traced path, as the third column. Present whenever a trace ran.
        # The reference probe, kept only where this box opens no connections of
        # its own. On a box that relays it duplicated the column beside it -
        # both pointing at the internet, one of them at an address the box
        # never sends anything to.
        "probe_path": (build_probe_column(hops, target, baseline_path)
                       if not (((raw.get("tcp_flows") or {}).get("by_side")
                                or {}).get("backend")) else None),
        # The hops out to the backend a finding named, where one was named.
        # The chain to the target is a reachability check on a box that relays;
        # this is the segment the work actually crosses.
        # The hops out to a destination this box actually uses. Where there
        # are none, the reference probe below stands in for the way out.
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
    # How far away each side is, on the way in. Done here rather than in
    # build_path_legs, which reads what has already been collected and does not
    # probe: this is one ping per side and belongs where the other probes are.
    trace_each_side(report.get("path_legs"), findings, quick)
    fold_the_probe_into_the_way_out(report)
    count_the_hops_in(report.get("path_legs"), quick)
    report["peer_names"] = name_the_addresses(
        addresses_on_the_page(report), raw, quick)
    return report


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
  /* One row per address this box holds. Under the zones because it is a
     statement about the way out: which of this box's addresses can take it. */
  .srcs{width:100%; border-collapse:collapse; margin:10px 0 2px;
    font-family:var(--mono); font-size:11px;}
  .srcs th{text-align:left; font-weight:400; color:var(--text-dim);
    padding:2px 10px 4px 0; border-bottom:1px solid var(--border);}
  .srcs td{padding:3px 10px 3px 0; color:var(--text-dim);}
  .srcs td:first-child{color:var(--text);}
  .srcs tr.no td, .srcs tr.no td:first-child{color:var(--crit);}
  .srcs .num{text-align:right;}
  .srcnote{font-family:var(--mono); font-size:10.5px; color:var(--text-dim);
    opacity:.85; margin:0 0 6px;}
  /* Two heads stacked. line-height:1 still leaves the glyphs' own leading
     between them, which reads as a gap rather than as one arrow split in two,
     so the stack is tightened until they sit as a pair. */
  .zarrow.split{flex-direction:column; justify-content:center;
    line-height:.72; font-size:15px;}
  .zarrow.split .pass{color:var(--ok);}
  .zarrow.split .fail{color:var(--crit);}
  /* A direction with no evidence either way. Muted rather than coloured,
     because the two states it sits between - carrying, and broken - are both
     claims, and this head is drawn precisely when neither can be made. */
  .zarrow.split .unknown{color:var(--text-dim); opacity:.5;}
  /* The one word to go and touch, beside the tags that already label a finding.
     A chip rather than a sentence at the end of the message: the point is to be
     read without reading, and the owner beside it is already the prose. */
  .hint{display:inline-flex; align-items:center; gap:4px;
    font-family:var(--mono); font-size:10.5px; letter-spacing:.02em;
    padding:1px 7px; border-radius:999px; white-space:nowrap;
    color:var(--text); border:1px solid var(--border);
    border-color:color-mix(in srgb, var(--accent) 45%, var(--border));
    background:color-mix(in srgb, var(--accent) 12%, transparent);}
  /* The four legs. One column per side, two lanes in each. */
  .pcols{display:grid; grid-template-columns:1fr; gap:14px; margin:6px 0 22px;}
  /* The traced path's hops, inside its own column. A bar per hop for the share
     of the total it added - the one thing the full-width ribbon did that a
     number cannot, which is show proportion without being read. */
  /* The rule at the top is where the column stops being about connections and
     starts being about the path to one of them. It has moved twice: it sat on
     the heading that named the destination, which put it between that heading
     and its own rows, and that heading has since gone for over-explaining. */
  .hops{padding:9px 14px 10px; margin-top:2px;
    border-top:1px dashed var(--border);}
  .hrow{display:flex; align-items:center; gap:8px; padding:3px 0;
    font-family:var(--mono); font-size:11px; color:var(--text-dim);}
  .hrow.crit{color:var(--crit);} .hrow.warn{color:var(--warn);}
  .hrow .hn{opacity:.6; min-width:38px;}
  .hrow .hh{color:var(--text); min-width:74px;}
  .hrow.crit .hh{color:var(--crit);} .hrow.warn .hh{color:var(--warn);}
  .hrow .ht{margin-left:auto; white-space:nowrap; opacity:.85;}
  .hbar{flex:1; min-width:26px; height:4px; border-radius:2px;
    background:var(--border); overflow:hidden;}
  .hbar > span{display:block; height:100%; background:var(--text-dim); opacity:.55;}
  .hrow.crit .hbar > span{background:var(--crit); opacity:.9;}
  .hrow.warn .hbar > span{background:var(--warn); opacity:.9;}
  /* Under the row, not on it. A resolved name is the longest thing a hop
     carries, and the row's own content is a bar showing where the time went -
     on that line the name squeezes the one element that is a measurement. */
  .hname{font-family:var(--mono); font-size:10px; color:var(--text-dim);
    opacity:.75; padding:0 0 2px 46px;}
  .hwhy{font-family:var(--mono); font-size:10.5px; color:var(--crit);
    padding:0 0 3px 46px;}
  .hwhy.warn{color:var(--warn);}
  .hwhy.edge{color:var(--text-dim); opacity:.7;}
  /* Not a severity. The other .hwhy lines say what is wrong with a hop; this
     one says what the trace could not tell about it, which is why it takes the
     dim colour rather than warn or crit. */
  .hwhy.fan{color:var(--text-dim); opacity:.85;}
  .base{padding:8px 14px; border-top:1px dashed var(--border);
    font-family:var(--mono); font-size:10.5px; color:var(--text-dim); opacity:.8;}
  /* However many columns there are, they share the width equally.
     Fixed track counts were wrong twice over: at two tracks a third column
     wrapped underneath the first, and at three tracks - once the traced path
     moved into the column it belongs to and most reports were back to two - the
     third track stayed empty and the two columns sat squeezed against the left
     under three boxes that filled the row.
     A box that relays has two boundaries; one that opens nothing has one and a
     probe. Neither number is worth a breakpoint. */
  @media (min-width: 780px){
    .pcols{grid-auto-flow:column; grid-auto-columns:1fr;
      grid-template-columns:none;}
  }
  .pcol{border:1px solid var(--border); border-radius:9px; background:var(--panel-2);
    overflow:hidden; min-width:0;}
  .pcol.fail{border-color:var(--crit);
    border-color:color-mix(in srgb, var(--crit) 40%, var(--border));}
  .pcol.warn{border-color:var(--warn);
    border-color:color-mix(in srgb, var(--warn) 40%, var(--border));}
  .pcol-hd{display:flex; justify-content:space-between; align-items:baseline;
    gap:10px; padding:10px 14px; border-bottom:1px solid var(--border);
    font-family:var(--mono); font-size:12px;}
  .pcol-hd .pwho{color:var(--text);}
  .pcol-hd .pfacts{color:var(--text-dim); font-size:11px; text-align:right;}
  /* Which plane the numbers beside it describe. Only rendered on a box that
     has another one, so on most reports this styles nothing. */
  .planetag{font-family:var(--mono); font-size:9px; letter-spacing:.08em;
    color:var(--text-dim); border:1px solid var(--border); border-radius:3px;
    padding:0 4px; vertical-align:1px; cursor:help;}
  .planenote{color:var(--text-dim); font-size:12px; line-height:1.5;
    margin:-4px 0 12px; max-width:74ch;}
  .planenote b{color:var(--text); font-weight:600;}
  /* Where this site's network stops and somebody else's begins, drawn as a
     place in the path because that is what it is. The single most useful
     annotation on a path: it is the one that says who to escalate to. */
  .edge{display:flex; align-items:center; gap:8px; margin:5px 0 4px 46px;
    font-family:var(--mono); font-size:9.5px; letter-spacing:.06em;
    text-transform:uppercase; color:var(--text-dim); opacity:.8;}
  .edge:before, .edge:after{content:""; flex:1; height:1px;
    background:var(--border);}
  .edge span{white-space:nowrap;}
  .plane{padding:13px 14px;}
  .plane + .plane{border-top:1px solid var(--border);}
  .plane .ptop{display:flex; justify-content:space-between; align-items:baseline;
    gap:10px; font-family:var(--mono); font-size:11px;}
  .plane .pwhat{color:var(--text);}
  /* A boundary nothing crossed. Drawn, and drawn as obviously empty: a dashed
     line and a word, so it cannot be mistaken for a measurement that passed. */
  .plane.quiet .pwhat, .plane.quiet .pverd{color:var(--text-dim);}
  .plane.quiet .pline{border-top-style:dashed; opacity:.55;}
  .plane.quiet .pend{opacity:.6;}
  .plane .pverd{color:var(--text-dim); letter-spacing:.06em; white-space:nowrap;}
  .plane.pass .pverd{color:var(--ok);}
  .plane.warn .pverd{color:var(--warn);}
  .plane.fail .pverd{color:var(--crit);}
  .ptrack{display:flex; align-items:center; gap:8px; margin:9px 0 7px;
    font-family:var(--mono); font-size:11px; color:var(--text-dim);}
  .ptrack .pend{white-space:nowrap;}
  .ptrack .pline{flex:1; height:2px; border-radius:2px; background:var(--border);
    min-width:24px;}
  .plane.pass .ptrack .pline{background:var(--ok);}
  .plane.warn .ptrack .pline{background:var(--warn);}
  .plane.fail .ptrack .pline{background:var(--crit);}
  /* Not measured is not a colour. Dashed, so it cannot be mistaken for either
     of the two claims it sits between. */
  .plane.unknown .ptrack .pline{opacity:.55;
    background:repeating-linear-gradient(90deg, var(--text-dim) 0 5px,
      transparent 5px 10px);}
  .ptrack .ptip{font-size:14px; line-height:1;}
  .plane.pass .ptrack .ptip{color:var(--ok);}
  .plane.warn .ptrack .ptip{color:var(--warn);}
  .plane.fail .ptrack .ptip{color:var(--crit);}
  .plane.unknown .ptrack .ptip{color:var(--text-dim); opacity:.55;}
  .plane .pev{font-family:var(--mono); font-size:10.5px; color:var(--text-dim);
    opacity:.85; line-height:1.55;}

  /* The hop timings are round trips. Under a heading reading "request out" they
     would be read as one way, which is a claim no traceroute can make: the
     reply that stops the clock is the router's own, so out and back are in
     every figure and nothing here can split them. */
  /* Under the timings it describes, not above them. */
  .pboth{display:block; margin-top:7px; padding-top:6px;
    border-top:1px dotted var(--border); font-family:var(--mono);
    font-size:10px; color:var(--text-dim); opacity:.8;}
  /* Observations about this side that are not a leg. */
  .zarrow.pass{color:var(--ok);}
  .zarrow.warn{color:var(--warn);}
  .zarrow.fail{color:var(--crit);}
  .zarrow.skip{color:var(--text-dim); opacity:.55;}
  .zarrow{display:flex; align-items:center; padding:0 10px; color:var(--text-dim);
          font-size:18px;}
  .zone{flex:1 1 180px; min-width:150px; padding:10px 12px; border-radius:8px;
        border:1px solid var(--border); background:var(--panel-2);}
  /* The colour of a zone says which direction stopped working. On a report with
     two zones lit it cannot say which of them is the cause, and on the seven
     findings whose owner is this box it points at the wrong one entirely - so
     the box the verdict blames says so, in the words the findings already use. */
  .zone .zname{font-size:12px; color:var(--text-dim-lift); line-height:1.35;}
  .zone .zname .rel{vertical-align:1px; margin-left:6px;}
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
  /* A stage that failed has to look failed from across the room. Colouring only
     the word inside left every chip the same shape, the same border and the same
     background, so a strip with one FAIL in it read as uniformly quiet - which is
     the opposite of what the strip is for, it being the line someone acts on.
     Same treatment as the verdict panel: tinted edge, tinted ground, and the
     state's colour carried on the chip rather than on six characters of it.
     The flat declaration comes first so a browser without color-mix still gets
     the edge, rather than falling back to no marking at all. */
  .stage.fail{
    color:var(--text); border-color:var(--crit);
    border-color:color-mix(in srgb, var(--crit) 45%, var(--border));
    border-left:3px solid var(--crit);
    background:color-mix(in srgb, var(--crit) 10%, var(--panel));
  }
  .stage.warn{
    color:var(--text); border-color:var(--warn);
    border-color:color-mix(in srgb, var(--warn) 45%, var(--border));
    border-left:3px solid var(--warn);
    background:color-mix(in srgb, var(--warn) 10%, var(--panel));
  }
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
  .paste-box{
    width:100%; box-sizing:border-box; margin-bottom:8px;
    background:var(--bg); color:var(--text); border:1px solid var(--border);
    border-radius:6px; padding:8px; font-family:var(--mono); font-size:11px;
    resize:vertical;
  }
  .paste-box:focus-visible, .paste-go:focus-visible{
    outline:2px solid var(--accent); outline-offset:2px;
  }
  .paste-go{
    width:100%; padding:6px 10px; border-radius:6px; cursor:pointer;
    background:var(--panel-2); color:var(--text); border:1px solid var(--border);
    font-family:var(--mono); font-size:12px;
  }
  .paste-go:hover{border-color:var(--accent);}
  .paste-err{color:var(--crit); font-size:11px; margin-top:6px; line-height:1.4;}
  .report-meta{
    font-family:var(--mono); font-size:11px; color:var(--text-dim);
    margin-top:8px; line-height:1.5;
  }

  /* Five groups, each with a rail down its side. Headings alone mark where a
     group begins and say nothing about where it ends, which left the path
     heading reading as though it floated between the direction zones above it
     and the findings below. The rail shows extent, and does it without a
     fourth frame - the zones and the findings are already cards, and a
     container around cards is a box inside a box inside a box.

     The answer has no rail: it is the one group that is a single object, and
     the verdict is already the loudest thing on the page.

     Hidden until a report arrives, or an unloaded viewer shows five empty
     rails and a stack of headings with nothing under them. */
  .grp{display:none; border-left:2px solid var(--border); padding-left:18px;
       margin-bottom:26px;}
  body.report-loaded .grp{display:block;}
  #grpAnswer{border-left-color:transparent; padding-left:0;}
  /* The one group with something nested inside it, so it says so. */
  #grpWhere{border-left-color:var(--accent-dim);}
  .section-title.sub{margin-top:20px;}
  /* A heading belongs to what follows it, and this one was not getting the
     chance: the zones above end 4px up and the columns below start 18px down,
     so "the path, out and back on each side" read as a caption on the three
     boxes. Proximity is the lever, not indentation - an indent would only break
     its alignment with the full-width columns it introduces. */
  .section-title.over{margin:26px 0 7px;}
  .section-title{
    font-family:var(--mono); font-size:11px; color:var(--text-dim);
    text-transform:uppercase; letter-spacing:0.08em; margin:0 0 12px;
  }

  /* Proportional digits change width as they change value, so a column of
     latencies shifts sideways every time one of them ticks over - the numbers
     are the reading, and they were the least steady thing on the page. Tabular
     figures fix the advance width; slashed zero keeps a zero from reading as a
     capital O in an interface name or a hex address. Applied only where digits
     are load-bearing, since tabular figures in prose are worse than neither. */
  .verdict .vmeta, .stage, .led-row, .report-meta, .hrow, .srcs,
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
    /* A browser drops background colours when it prints unless it is told
       not to, and the ribbon is nothing but background colour - without
       this it comes out as an empty outline. */
    .topbar, .sidebar, #reportControls, .file-input{display:none !important;}
    .layout{display:block; min-height:0;}
    .main{padding:0;}
    .panel.collapsed .panel-body, .panel.collapsed .panel-desc{display:block !important;}
    .panel-head .chev{display:none;}
    pre{max-height:none; overflow:visible;}
    /* A hop or a finding split across a page break is the one thing on the
       page that has to be read whole. */
    .verdict, .finding, .zone, .panel{box-shadow:none; break-inside:avoid;}
    /* On paper there is no glow to carry a lamp, so the dot needs its edge. */
    .led, .finding .sev{box-shadow:none; border:1px solid var(--border);}
    /* The recede-and-emphasise pass reads as ink density on screen; on paper a
       55% grey hop just looks badly printed. */
    .zone.skip{opacity:1;}
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
      <!-- The path off a box you cannot copy a file from: the report is
           printed, selected in your own terminal, and pasted here. SSH
           sends characters and the local terminal draws them, so the
           selection never involves the box at all - which is why it works
           in exactly the places scp does not. -->
      <label class="field-label" for="pasteBox" id="pasteLabel">Or paste one</label>
      <textarea id="pasteBox" class="paste-box" rows="3" spellcheck="false"
                placeholder="paste the output of --export-compact - here"></textarea>
      <button type="button" id="pasteGo" class="paste-go">Read pasted report</button>
      <div class="paste-err" id="pasteErr"></div>
      <div class="viewer-hint" id="viewerHint">
        Choose a <code>report.json</code> above, drop one anywhere on this page,
        or paste one in.
        <br><br>
        Cannot copy a file off the box? Print it and paste it:<br>
        <code>python3 faultone.py --export-compact -</code><br>
        select the output in your terminal and paste it above. Wrapped lines
        and a stray prompt either side are fine.
        <br><br>
        Produce one with:<br><code>python3 faultone.py --export report.json</code>
        <br><br>
        Or skip this viewer entirely:<br><code>python3 faultone.py --export report.html</code><br>
        gives you a single file that opens on its own.
      </div>
    </div>
  </div>

  <div class="main">
    <div class="empty-state" id="emptyState">Load a report exported with <code>--export</code> — choose the file on the left, or drop it anywhere on this page.</div>
    <section class="grp" id="grpAnswer"><div id="answerWrap"></div></section>
    <section class="grp" id="grpWhere">
      <div id="whereWrap"></div>
      <!-- Inside the direction group on purpose: the path is the detail of
           one of those three zones, not a sixth thing on the page. -->
      <!-- Traffic in sits above the path-out heading, not under it. It was
           inside, so a box losing packets from its clients drew a red inbound
           node beneath a title reading "the path out" and above a path that
           was entirely green. They are opposite directions and the heading
           was claiming one of them. -->
      <!-- The path, as four legs in two columns: one column per side of this
           box, each carrying the leg out and the leg back.

           This replaced a chain per side with the directions left to an
           arrowhead. The two sides are different equipment with different
           owners - the split is the data's own, `by_side` exists for it - and
           out-and-back is the pair a reader compares when the question is which
           direction stopped. -->
      <div id="pathWrap"></div>
    </section>
    <section class="grp" id="grpFound">
      <div id="foundWrap"></div>
      <div id="findingsWrap"></div>
    </section>
    <section class="grp" id="grpRan"><div id="ranWrap"></div></section>
    <section class="grp" id="grpEvidence">
      <div class="section-title">Evidence &middot; the output every check produced</div>
      <div id="output"></div>
    </section>
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

// A value that lands in a class attribute, reduced to something that cannot
// leave it. Severities and states come from a closed vocabulary - pass, warn,
// fail, skip, ok, crit - but they arrive inside a report this box did not
// write, and `class="zone ${z.state}"` with a quote in it ends the attribute
// and opens a tag. escapeHtml is the wrong tool here: it is for text, and it
// says nothing about what belongs in a class. Anything outside the shape of
// the vocabulary becomes nothing, which renders unstyled rather than hostile.
function cls(value){
  const s = String(value == null ? '' : value);
  return /^[a-z][a-z0-9 _-]{0,40}$/.test(s) ? s : '';
}

function escapeHtml(s){
  return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function clearEmptyState(){
  const empty = document.querySelector('.empty-state');
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

// A leg of the picture, coloured by what the report concluded about that
// direction rather than by re-reading a counter underneath it. Both ends were
// deciding for themselves and both were wrong in the same way: the way in
// scored itself on client loss, so a direction marked degraded for jitter or
// queuing delay - neither of which is loss - drew green beside a zone reading
// DEGRADED; and this device was given ok outright, so a box with a failing
// transceiver in it was drawn clean under a panel saying the fault was the box.
//
// The zone is the conclusion about a direction and these are the picture of
// it. Thresholds in the picture are a second copy of the ones in the analysis,
// and two copies of a threshold are two chances to disagree. The measured loss
// and rtt stay on the node's own line, where they are readings rather than a
// judgement.
const ZONE_SEV = {pass: 'ok', warn: 'warn', fail: 'crit', skip: 'ok'};
// The words the report uses for a state. Module scope because the path
// chain says them too, and a second set for the hops would be a second
// vocabulary for one idea.
const ZONE_WORD = {pass: 'OK', warn: 'DEGRADED', fail: 'FAULT',
                   // The socket table was read and nothing was coming in.
                   // That is an answer, not a gap.
                   skip: 'none connected'};
// Red and green are the commonest pair a reader cannot tell apart, and the
// hop chain was the one place a severity arrived as hue and nothing else -
// the stage chips say PASS and FAIL, the zones say OK and FAULT, a finding
// carries its severity in its tag. Only a marked hop gets a word: putting
// one on the clean hops would be noise across most of the page, and the
// clean ones are already the ones being told to look past.
const HOP_WORD = {warn: ZONE_WORD.warn, crit: ZONE_WORD.fail};

// Where each finding stands to the verdict. The words come from the report so
// the page and the terminal say the same thing.
const RELATION_LABEL = {cause: 'the cause', corroborates: 'backs it up',
                        explained: 'caused by it', unrelated: 'separate problem'};

const ZONE_NAME = {downstream: 'clients reaching this box', local: 'this box',
                   upstream: 'what this box connects out to'};

// One boundary between two zones. A proxy relays, so traffic crosses this in
// both directions and a single head drew a box that relays as a one-way chain.
//
// Named and returning a string rather than built inline, so a test can call it
// with a side and read what comes back. The version of this that lived in a
// template literal could only be checked by searching the page source for the
// field it was supposed to read, which pins how the code is written rather
// than what it draws - and that is the shape of test that held a drawing bug
// in place here once already.
//
// Both heads take one colour by default, from the measured state of the leg
// the arrow spans. Splitting them is allowed on exactly one signal: lastsnd
// against lastrcv, this box sending and nothing coming back. A retransmit
// ratio is a single number for a connection and cannot say which direction
// lost the packet, so colouring a return head from it would be an invented
// measurement drawn with more authority than anything else on the page.
// Why a conclusion under this hop hedged. Only set where a finding actually
// softened itself on the fan-out - the row carries 0 everywhere else - so this
// draws an explanation rather than an inventory of every place the path
// balanced.
//
// Named and returning a string for the same reason boundaryArrow is: a line
// built inline in a template literal can only be checked by searching the page
// source, which pins how it is written instead of what it draws.
function fanoutLine(h){
  if(!h.fanout) return '';
  const also = h.fanout_also || [];
  const title = also.length ? 'also answered: ' + also.join(', ') : '';
  return `<div class="hwhy fan"${title ? ` title="${escapeHtml(title)}"` : ''}>`
    + `${escapeHtml(String(h.fanout))} routers answered here \u2014 the path fans out</div>`;
}

function boundaryArrow(sides, i, flows){
  const leg = sides[i].side === 'local' ? sides[i - 1] : sides[i];
  const near = (flows || {})[leg.side === 'downstream' ? 'client' : 'backend'] || {};
  const total = near.connections || 0;
  // Two counters, each carrying one direction and nothing about the other.
  //
  // lastsnd against lastrcv: this box sending and nothing coming back says the
  // return leg has stalled. It says nothing about the way out - the sending is
  // what makes the silence mean anything in the first place.
  //
  // A DSACK is the far end saying it already had a segment this box resent,
  // which is proof the original arrived. That is evidence about the way out,
  // and the only kind there is: it makes the affirmative claim that whatever
  // those retransmits were, they were not the forward path dropping packets.
  //
  // A head with no counter behind it keeps the leg's own colour rather than
  // inventing one. The earlier version of this hardcoded the outbound head to
  // pass whenever the return stalled, which read as "the way out is fine" on
  // no evidence at all.
  // The stall decision is made once, where the counters are read, and carried
  // in the report. A report written before that field existed still has the
  // counts, so the older rule stays here as the fallback rather than drawing
  // a saved report as though nothing had ever gone quiet on it.
  const stalled = near.return_stalled !== undefined
    ? !!near.return_stalled
    : ((near.silent_return || 0) > 0 && (near.silent_return || 0) * 2 >= total);
  const arrived = (near.delivered_anyway || 0) * 2 >= total && (near.delivered_anyway || 0) > 0;
  if(total && (stalled || arrived)){
    const why = [];
    if(arrived) why.push(near.delivered_anyway + ' of ' + total
      + ' connections: the far end confirmed data this box resent had arrived');
    // A minority carrying most of the traffic is the same verdict reached a
    // different way, and reads as a mistake without the share beside it.
    if(stalled) why.push(near.silent_return + ' of ' + total
      + ' connections: this box is sending, nothing is coming back'
      + (near.silent_return * 2 < total && near.silent_share_pct
         ? ', carrying ' + near.silent_share_pct + '% of this side\'s traffic' : ''));
    // The way out, when the way back has stopped and no DSACK confirmed
    // anything. It is tempting to draw this green - the box is plainly sending,
    // so surely that direction works - and it cannot be earned. The only proof
    // a segment this box sent arrived is something coming back about it, and in
    // a stall that is exactly what is missing: "my data is arriving and their
    // replies are not" and "my data is not arriving at all" produce the same
    // silence here, because the acknowledgement that would separate them
    // travels the broken direction.
    //
    // Painting it with the leg's colour was the other half of that mistake, and
    // the half that shipped: it asserted the way out had failed on the same
    // absent evidence. Drawn muted instead, which is the honest third state and
    // the reason this arrow splits at all.
    if(stalled && !arrived) why.push('the way out cannot be judged from here: '
      + 'the only proof it is carrying is something coming back, which is what '
      + 'has stopped');
    const outState = arrived ? 'pass' : (stalled ? 'unknown' : leg.state);
    return `<div class="zarrow split" title="${escapeHtml(why.join(' · '))}">`
      + `<span class="${cls(outState)}">→</span>`
      + `<span class="${stalled ? 'fail' : cls(leg.state)}">←</span></div>`;
  }
  return `<div class="zarrow ${cls(leg.state)}" title="${
    escapeHtml(ZONE_NAME[leg.side] || leg.side)} · both directions, judged together">`
    + '<span>⇄</span></div>';
}

function quietLane(side){
  // A boundary with nothing measured across it is still a boundary, and is
  // drawn so the panel keeps two columns under three boxes. One column read as
  // a single path straight through, with the middle box bypassed.
  //
  // Empty string rather than a lane when there is something to draw, so the
  // caller can fall through to the real legs.
  if((side.legs || []).length) return '';
  return '<div class="plane quiet"><div class="ptop">'
    + '<span class="pwhat">nothing measured across here</span>'
    + '<span class="pverd">QUIET</span></div>'
    + '<div class="ptrack"><span class="pend">' + escapeHtml(side.left) + '</span>'
    + '<span class="pline"></span>'
    + '<span class="pend">' + escapeHtml(side.right) + '</span></div>'
    + '<div class="pev">' + escapeHtml(side.quiet_because || '') + '</div></div>';
}

function planeTag(otherPlane){
  // The label on the column's own numbers. Empty on a box with one plane,
  // which is why it is a function rather than a string in the template.
  if(!otherPlane) return '';
  return ' <span class="planetag" title="Every per-connection reading here is TCP: '
    + 'the connection count, the round trip, the loss, and which direction stalled. '
    + 'This box also carries datagrams, and none of these numbers describe that '
    + 'traffic.">TCP</span>';
}

function planeNote(otherPlane){
  // Said once, under the section, rather than repeated in every heading.
  if(!otherPlane || !(otherPlane.ports || []).length) return '';
  return '<div class="planenote">These are this box\'s <b>TCP</b> connections. It is '
    + 'also listening for datagrams on ' + otherPlane.ports.map(escapeHtml).join(', ')
    + ', and nothing measured here describes that traffic: a datagram socket serves '
    + 'any number of peers without the kernel recording one of them.</div>';
}

// The hop list, and the footnote that says what its numbers assume. Named and
// declared at the top level rather than built inside the render, because a test
// that asserts a string appears in this template passes against a branch that is
// never taken - the dead branch still contains the string. That has happened
// three times here. Everything conditional below is now reachable by a test that
// runs it.
//
// `names` is passed rather than closed over: it is the reverse-DNS map, which
// belongs to the report and not to this fragment.
function hopWhy(col){
  return [
    `Traced to ${col.target}` + (col.picked ? `, ${col.picked}` : ''),
    col.of > 1 ? `out of ${col.of} connections on this side` : '',
    'each time is a round trip to that hop, out and back together, which a traceroute cannot separate',
    col.hops_in ? `the ${col.hops_in} back is from a reply that arrived with ttl ${col.ttl_seen}, assuming it left at ${col.ttl_assumed}` : '',
  ].filter(Boolean).join(' \u00b7 ') + '.';
}

function hopList(col, names){
  names = names || {};
  return `<div class="hops" title="${escapeHtml(hopWhy(col))}">${col.hops.map(h => `
      ${h.site_edge ? `<div class="edge"><span>site edge \u00b7 past here is the provider's network</span></div>` : ''}
      <div class="hrow ${cls(h.state === 'ok' ? '' : h.state)}">
        <span class="hn">hop ${escapeHtml(String(h.hop))}</span>
        <span class="hh">${escapeHtml(h.host)}</span>
        <span class="hbar"><span style="width:${Math.max(2, h.share_pct || 0)}%"></span></span>
        <span class="ht">${h.timed_out ? 'no reply'
          : h.ms == null ? 'no timing'
          : escapeHtml(String(h.ms)) + 'ms'}${h.delta_ms ? ' +' + h.delta_ms + 'ms' : ''}</span>
      </div>${fanoutLine(h)}${names[h.host] ? `<div class="hname">${escapeHtml(names[h.host])}</div>` : ''}${
          h.why ? `<div class="hwhy ${cls(h.state)}">${escapeHtml(h.why)}</div>` : ''}${
        h.edge ? `<div class="hwhy edge">enters ${escapeHtml(h.edge)}</div>` : ''}`).join('')}
      ${col.hops_in ? `<div class="pboth">${
        col.hops.length} out, ${col.hops_in} back${
        col.hops_in !== col.hops.length ? ' \u00b7 asymmetric' : ''}</div>` : ''}
    </div>${col.baseline ? `<div class="base">${escapeHtml(col.baseline)}</div>` : ''}`;
}

// A finding's tags, and the zone box beside them. Both were built inline in
// the render, so the only tests that could reach them searched this template
// for a string - which passes against a branch that is never taken, because the
// dead branch still holds the string. See HANDOVER; it had been wrong three
// times before the hop list was pulled out the same way.
//
// `layers` and `lowest` are passed rather than closed over: which layer is the
// lowest broken one is a property of the report, not of a badge.
function layerBadge(f, layers, lowest){
  if(!f.layer) return '';
  const meta = (layers || {})[String(f.layer)] || {};
  const isLowest = f.layer === lowest && f.severity !== 'ok';
  return `<span class="layer${isLowest ? ' low' : ''}" title="${escapeHtml(meta.hint || '')}">L${escapeHtml(String(f.layer))}${meta.name ? ' \u00b7 ' + escapeHtml(meta.name) : ''}</span>`;
}

function findingTags(f, layers, lowest){
  return `<span class="tag">${escapeHtml(f.severity)}</span>${layerBadge(f, layers, lowest)}${
    f.relation ? `<span class="rel rel-${escapeHtml(f.relation)}">${escapeHtml(RELATION_LABEL[f.relation] || f.relation)}</span>` : ''}${
    f.kind === 'hardware' ? `<span class="rel rel-hardware">needs hands on it</span>` : ''}${
    f.hint ? `<span class="hint">&rarr; ${escapeHtml(f.hint)}</span>` : ''}`;
}

function zoneCard(z){
  return `<div class="zone ${cls(z.state)}">
          <div class="zname">${escapeHtml(ZONE_NAME[z.side] || z.side)}${
            z.owns_cause ? `<span class="rel rel-cause">the cause</span>` : ''}</div>
          ${z.via ? `<div class="zvia">via ${escapeHtml(z.via)}</div>` : ''}
          <div class="zstate">${escapeHtml(ZONE_WORD[z.state] || z.state)}</div>
          ${z.worst ? `<div class="zwhy">${escapeHtml(z.worst)}</div>` : ''}
        </div>`;
}

// A heading and the thing it introduces, kept together. Separately they drift:
// a heading is a promise that something follows it, and the failure worth
// guarding is a title standing over an empty section. Named so a test can ask
// for the empty case, which is the one a substring search cannot see - the
// string is in the template either way.
function pathSection(pathHtml, otherPlane){
  if(!pathHtml) return '';
  return '<div class="section-title over">The path, out and back on each side</div>'
    + planeNote(otherPlane)
    + pathHtml;
}

// Every address this box holds, asked the same question. Drawn whenever the
// run was asked to ask - the flag is the gate, and three agreeing rows are the
// answer somebody typed a flag to get. Silence here is the one reply that
// cannot be told apart from the flag having done nothing, which is why this
// does not follow the draw-it-only-where-it-differs rule the plane tag and the
// fan-out mark do.
function sourceTable(rows, target){
  rows = rows || [];
  if(rows.length < 2) return '';
  const cell = (r, key, suffix) => r[key] == null ? '-' : escapeHtml(String(r[key])) + (suffix || '');
  const body = rows.map(r => `<tr class="${r.reached ? '' : 'no'}">`
    + `<td>${escapeHtml(r.address)}</td>`
    + `<td>${escapeHtml(r.interface || '-')}</td>`
    + `<td>${r.reached ? 'yes' : 'no'}</td>`
    + `<td class="num">${cell(r, 'loss_pct', '%')}</td>`
    + `<td class="num">${cell(r, 'avg_ms', ' ms')}</td></tr>`).join('');
  const failed = rows.filter(r => !r.reached).map(r => r.address);
  const note = !failed.length
    ? 'every address this box holds can reach the target'
    : failed.length < rows.length
      ? failed.join(', ') + ' reaches nothing while its neighbours do'
      : 'no address on this box can reach the target, so this is the target rather than the addressing';
  return `<table class="srcs"><tr><th>address</th><th>interface</th>`
    + `<th>reaches ${escapeHtml(target || 'the target')}</th>`
    + `<th class="num">loss</th><th class="num">latency</th></tr>${body}</table>`
    + `<div class="srcnote">${escapeHtml(note)}</div>`;
}

function whereSection(sidesHtml, howMany){
  if(!howMany) return '';
  return '<div class="section-title">Which direction the fault is on</div>' + sidesHtml;
}

function renderDiagnosis(data, opts){
  opts = opts || {};
  output.innerHTML = '';
  panelSeq = 0;

  osBadge.textContent = [(data.os_label || data.os) && `${data.os_label || data.os} report`,
                         data.version && `v${data.version}`].filter(Boolean).join(' · ')
                        || 'report viewer';


  const findings = data.findings || [];
  const layers = data.layers || {};
  if(data.panel_help) panelHelp = data.panel_help;
  const lowest = data.lowest_broken_layer || null;
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
  const sideFlows = ((data.raw || {}).tcp_flows || {}).by_side || {};
  const sidesHtml = sides.length ? `
    <div class="zones">
      ${sides.map((z, i) => `
        ${i ? boundaryArrow(sides, i, sideFlows) : ''}
        ${zoneCard(z)}`).join('')}
    </div>` : '';

  const stages = data.stages || [];
  const stageHtml = stages.length ? '<div class="stages">' + stages.map(st => {
    // The layer is only present when a finding put the stage in that state, so
    // a passing stage carries no layer rather than a guessed one.
    const layer = st.layer ? `<span class="layer">L${escapeHtml(String(st.layer))}</span>` : '';
    const why = (st.because && st.because.length)
      ? ` title="${escapeHtml(st.because.join(', '))}"` : '';
    return `<span class="stage ${cls(st.state)}"${why}>${escapeHtml(st.stage)} <b>${
      {pass:'PASS', warn:'WARN', fail:'FAIL', skip:'—'}[st.state] || ''}</b>${layer}</span>`;
  }).join('') + '</div>' : '';

  const changes = data.comparison || [];
  const changesHtml = changes.length ? `<div class="changes">
      <h4>changes since baseline</h4>
      ${changes.map(c => `<div class="row ${escapeHtml(c.direction || 'neutral')}">
        <span>${escapeHtml(String(c.what))}:</span>
        <span>${escapeHtml(String(c.before))} → ${escapeHtml(String(c.after))}</span>
      </div>`).join('')}
    </div>` : '';

  // Five groups in the order the questions arrive: what is wrong, which way,
  // what else was found, what was checked, and what the checks said. The path
  // picture used to sit above the verdict, so the reader met a hop-by-hop
  // diagram before being told what the answer was.
  document.getElementById('answerWrap').innerHTML = verdictHtml;
  // The path, as four legs in two columns. Everything the two chains drew is
  // here, plus the direction that used to live only in an arrowhead.
  //
  // The states are not decided here. They come from the report, where the same
  // fields the arrow reads are turned into legs once - a threshold written in
  // Python and again in this file is two copies of a rule and two chances for
  // them to disagree about the same report.
  const LEGWORD = {pass:'OK', warn:'SLOW', fail:'FAULT', unknown:'NOT MEASURABLE'};
  // An address with the name it answers to, where it answered to one. Both,
  // never the name alone: a PTR record is written by whoever owns the reverse
  // zone rather than by whoever owns the host, so it is a label to read and the
  // address stays the thing anyone acts on.
  const NAMES = data.peer_names || {};
  const named = a => NAMES[a] ? `${escapeHtml(NAMES[a])} (${escapeHtml(a)})`
                              : escapeHtml(String(a == null ? '' : a));
  const legSides = data.path_legs || [];
  // Only on a box that has one. See other_plane() for why this is
  // conditional rather than always printed.
  const otherPlane = data.other_plane || null;

  // The traced path, as the third column. Present whenever a trace ran, so the
  // hops stay visible on every report rather than only on the ones that mark
  // a hop - what a fault changes is the colour and which row is called out.
  //
  // One leg. A traceroute is one way, so there is no return measurement, and
  // drawing one anyway is the mistake the boundary arrow carried for two
  // releases. Every state here was decided in build_probe_column; nothing on
  // this side of the wire judges a hop.
  // One hop list, drawn the same way wherever it lands. The way out and the
  // reference probe are the same measurement of two different destinations, and
  // two copies of this markup would be two chances for them to diverge.
  // The whole honest footnote for a traced path, on the list rather than in it.
  // Which destination, why that one out of however many the side holds, that a
  // hop time is a round trip, and what the count back assumed. None of it is
  // worth a line on a report meant to be read in a hurry, and all of it is
  // worth being able to recover - a reading whose assumption cannot be
  // recovered is folklore.
  //
  // On the list, not on the counts underneath it: those only appear when the
  // peer answered ICMP, so hanging this there hid the choice on every report
  // where it did not.

  const pp = data.probe_path;
  const probeHtml = pp ? `<div class="pcol ${pp.state}">
      <div class="pcol-hd"><span class="pwho">reachability probe</span>
        <span class="pfacts">${escapeHtml(pp.target)}<br>${pp.hops.length} hop${
          pp.hops.length === 1 ? '' : 's'}${
          pp.total_ms ? ' \u00b7 ' + pp.total_ms + 'ms' : ''}</span></div>
      <div class="plane ${pp.state}">
        <div class="ptop"><span class="pwhat">path out</span>
          <span class="pverd">${{pass:'OK', warn:'SLOW', fail:'FAULT'}[pp.state]}</span></div>
        <div class="ptrack"><span class="pend">this box</span>
          <span class="pline"></span><span class="ptip">&rarr;</span>
          <span class="pend">${escapeHtml(pp.target)}</span></div>
        <div class="pev">a probe to one address, not the traffic this box carries \u2014 and the only thing that can see a fault at a single hop</div>
      </div>
      ${hopList(pp, NAMES)}
    </div>` : '';
  // Drawn when there is either a measured side or a traced path. It used to
  // hang off the measured sides alone, which meant a box with no readable
  // connections and a perfectly good trace lost the trace as well - the panel
  // vanished because the other half of it was empty.
  const pathHtml = (legSides.length || pp) ? '<div class="pcols">' + legSides.map(side => {
    const facts = [side.connections + ' connection' + (side.connections === 1 ? '' : 's'),
                   side.rtt_ms != null ? side.rtt_ms + 'ms rtt' : '',
                   // How far away this side is on the way in, off the TTL of a
                   // reply from it. The only hop count the inbound direction can
                   // have: a traceroute goes outward and cannot watch a client's
                   // packets arrive.
                   side.hops_in ? side.hops_in + ' hops away' : '',
                   // A retransmit ratio counts packets this box had to send
                   // again and cannot say which direction lost them, so it sits
                   // on the side and never on a leg.
                   side.loss_pct != null ? side.loss_pct + '% loss' : ''
                  ].filter(Boolean).join(' \u00b7 ');
    // A boundary with nothing measured across it is still a boundary, and is
    // drawn so the panel keeps two columns under three boxes. One column read
    // as a single path straight through with the middle box bypassed.
    const lanes = quietLane(side) || (side.legs || []).map(leg => {
      // The ends stay put and the arrow turns. Moving both says the same thing
      // twice, and they disagreed: a response going out read "this box <- clients".
      const away = leg.src === side.left;
      const tip = `<span class="ptip">${away ? '&rarr;' : '&larr;'}</span>`;
      const line = '<span class="pline"></span>';
      // The head sits at the end of the leg leaving this box and at the start
      // of the one coming back, so the two lanes in a column read as a circuit
      // rather than as two lines pointing at each other. With both heads in the
      // same place the pair looked like one measurement drawn twice.
      const track = leg.direction === 'back' ? tip + line : line + tip;
      return `<div class="plane ${leg.state}">
          <div class="ptop"><span class="pwhat">${escapeHtml(leg.what)}</span>
            <span class="pverd">${LEGWORD[leg.state] || leg.state}</span></div>
          <div class="ptrack"><span class="pend">${escapeHtml(side.left)}</span>
            ${track}
            <span class="pend">${escapeHtml(side.right)}</span></div>
          <div class="pev">${escapeHtml((leg.evidence || []).join(' \u00b7 '))}</div>
        </div>`;
    }).join('');
    // The hops out to a destination this side actually uses, inside the column
    // that names it. It used to be a probe to a fixed address in a column of its
    // own, which on a box that relays pointed at the internet twice - once at
    // the connections it opens, once at somewhere it never sends anything.
    const op = side.traced;
    const traced = op ? hopList(op, NAMES) : '';
    return `<div class="pcol ${side.state}">
        <div class="pcol-hd"><span class="pwho">${escapeHtml(side.title)}${planeTag(otherPlane)}</span>
          <span class="pfacts"${side.hops_in
            ? ` title="The distance is counted from a reply that arrived here, assuming it left at ttl ${side.ttl_assumed}. Each router on the way decrements it, so the difference is the hops it crossed."`
            : ''}>${named(side.peer)}<br>${escapeHtml(facts)}</span></div>
        ${lanes}${traced}</div>`;
  }).join('') + probeHtml + '</div>' : '';
  const pathWrap = document.getElementById('pathWrap');
  if(pathWrap) pathWrap.innerHTML = pathSection(pathHtml, otherPlane);

  const srcTable = sourceTable(((data.raw || {}).source_matrix) || [],
                               (data.raw || {}).probe_target || data.target);
  document.getElementById('whereWrap').innerHTML =
    whereSection(sidesHtml + srcTable, sides.length || (srcTable ? 1 : 0));
  document.getElementById('ranWrap').innerHTML = stageHtml
    ? '<div class="section-title">What was checked</div>' + stageHtml : '';
  document.getElementById('foundWrap').innerHTML = findings.length
    ? '<div class="section-title">What was found</div>' : '';
  document.body.classList.add('report-loaded');
  findingsWrap.innerHTML = changesHtml + '<div class="findings">' + findings.map(f => `
    <div class="finding ${f.severity}">
      <div class="sev"></div>
      <div>
        <div class="tagline">${findingTags(f, layers, lowest)}</div>
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
  // The strip lives in the main column now. Drawn in both, it was the same
  // seven boxes twice on one screen, and only the main copy survives print.
  ledsEl.innerHTML = verdictRow(data.verdict);

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
      inventory: 'neighbours (not a scan)',
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
    ['reportFileLabel', 'reportFile', 'viewerHint',
     'pasteLabel', 'pasteBox', 'pasteGo', 'pasteErr'].forEach(id => {
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

// A report copied off a console arrives mangled in two ways, and both are
// repairable. Select-all takes the shell prompt above and below it, so the
// blob is cut from the first brace to the last. And a terminal that hard-wraps
// on copy - tmux copy mode, most browser consoles - inserts real newlines at
// the wrap column: in a compact report most of those land inside a quoted
// string, where a literal newline is a parse error, and some split a bare
// token like null down the middle.
//
// Every one of them can go. Valid JSON escapes the newlines inside its
// strings, so a literal one can only be the terminal's; and outside a string a
// newline is whitespace between tokens that are already delimited. Removing
// all of them repairs both faults and cannot damage a blob that arrived clean.
function readPastedReport(text){
  const body = (text || '');
  const open = body.indexOf('{'), close = body.lastIndexOf('}');
  if(open === -1 || close <= open) throw new Error('no report found in that text');
  return JSON.parse(body.slice(open, close + 1).replace(/[\r\n]/g, ''));
}

document.getElementById('pasteGo').addEventListener('click', () => {
  const err = document.getElementById('pasteErr');
  err.textContent = '';
  try{
    renderDiagnosis(readPastedReport(document.getElementById('pasteBox').value),
                    {imported: true});
  }catch(e){
    // Shown in the panel rather than an alert: the text is still in the box,
    // and a dialog you have to dismiss before you can look at it is the wrong
    // shape for something you are about to correct and retry.
    err.textContent = 'Could not read that as a report - ' + e.message;
  }
});

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
    with open(path, encoding="utf-8", errors="replace") as fh:
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


# The conventional names, lower and upper. Both are honoured by curl, pip, apt
# and most runtimes, and a box very often sets only one of the pair.
PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")


def parse_scutil_proxy(text):
    """The scalar settings out of `scutil --proxy`.

    The output is a plist rendered as nested blocks. Only the top-level
    scalars matter here, and the nested ones - the exceptions list - are
    skipped rather than parsed: a list of hosts that bypass the proxy does not
    change the answer to "is one configured".
    """
    out, depth = {}, 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.endswith("{"):
            depth += 1
            continue
        if stripped == "}":
            depth = max(0, depth - 1)
            continue
        if depth != 1 or " : " not in stripped:
            continue
        key, _, value = stripped.partition(" : ")
        out[key.strip()] = value.strip()
    return out


def cmd_proxy_config():
    """How this box is told to reach the internet, if it is told anything.

    Nothing is probed and nothing is contacted - this reads configuration that
    is already there. The point is not the proxy itself but what it means for
    every other check: ping, traceroute and a TCP connect do not read any of
    this, so they measure the direct path whether or not the direct path is
    the one anything here uses.
    """
    env = {}
    for name in PROXY_ENV_VARS:
        for key in (name, name.upper()):
            value = os.environ.get(key)
            if value:
                env[key] = value
    system = {}
    if OS_NAME == "Darwin" and which("scutil"):
        res = run(["scutil", "--proxy"], timeout=5)
        if res.get("ok") and res.get("code") == 0:
            system = parse_scutil_proxy(res.get("stdout", ""))
    return {"ok": True, "cmd": "proxy configuration (read, not probed)",
            "code": 0, "stderr": "", "env": env, "system": system,
            "stdout": "\n".join([f"{k}={v}" for k, v in sorted(env.items())]
                                 + [f"{k}: {v}" for k, v in sorted(system.items())])
                      or "no proxy configuration found"}


def use_color(stream, disabled=False):
    """Color only for a real terminal, and only where it can be read.

    Output gets pasted into tickets and piped into files, where escape codes
    are just noise - so a stream that is not a terminal never gets them, and
    NO_COLOR turns them off wherever it is set.

    TERM=dumb is the case that matters most here and was missing. A dumb
    terminal cannot interpret an escape sequence by definition, so it prints
    it: a report read on a serial console or an out-of-band card comes out
    with ESC[31m scattered through it. That is the same class of terminal that
    could not encode a middle dot, and the same audience - somebody reading a
    diagnosis on a console because there is no other way in.

    `disabled` is the override for when all of that guesses wrong.
    """
    if disabled:
        return False
    # FORCE_COLOR overrides the guesses below, not the flag above.
    if forced_color():
        return True
    return bool(
        getattr(stream, "isatty", lambda: False)()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
        and OS_NAME != "Windows"
    )


def forced_color():
    """FORCE_COLOR set to anything but empty means colour even when piped.

    The companion to NO_COLOR, for the case the isatty check gets wrong: a
    report piped into `less -R`, or a CI log that renders escapes and is not
    a terminal. NO_COLOR still wins when both are set, and --no-color wins
    over either, because the explicit request beats the environment.
    """
    return (os.environ.get("FORCE_COLOR") not in (None, "")
            and os.environ.get("NO_COLOR") is None)


def worst_by_scope(findings):
    """The worst severity anything said about each interface.

    Read off the findings rather than worked out again from the counters. The
    tables below would otherwise need their own copy of every threshold - what
    counts as an error rate, a drop rate, a slow link - and a second copy of a
    rule is a second chance to disagree with the first. Anything with a scope
    has already been judged; this only asks what the answer was.
    """
    rank = SEVERITY_RANK
    worst = {}
    for f in findings or []:
        scope = f.get("scope")
        if not scope:
            continue
        sev = f.get("severity", "ok")
        if rank.get(sev, 0) > rank.get(worst.get(scope, "ok"), 0):
            worst[scope] = sev
    return worst


# Drawn in ASCII on purpose. Block and box-drawing characters make a better
# looking bar and arrive as mojibake on exactly the boxes this runs on - a
# serial console, a LANG=C jump host, a stripped appliance - and a bar that
# cannot be read is worse than a number that can.
BAR_FULL = "#"
BAR_EMPTY = "."


def render_bar(value, maximum, cells):
    """A `cells`-wide bar for `value` against `maximum`. "" if undrawable.

    Anything above zero keeps at least one filled cell. The HTML ribbon gives
    a hop that added almost nothing a four-pixel sliver for the same reason:
    rounding a real measurement down to an empty bar draws it as nothing
    having happened, which is a different claim than "not much".
    """
    if cells <= 0 or value is None or not maximum or maximum <= 0:
        return ""
    frac = value / maximum
    frac = 0.0 if frac < 0 else (1.0 if frac > 1 else frac)
    filled = int(frac * cells + 0.5)
    if filled == 0 and value > 0:
        filled = 1
    return BAR_FULL * filled + BAR_EMPTY * (cells - filled)


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
    # The path as a bar, one row per hop, sized by what that hop added. The
    # HTML report has drawn this since the ribbon landed; the text report was
    # still asking the reader to hold "12.4 ms" against "28.9 ms" in their
    # head. Both are built from the same two numbers so the two reports cannot
    # come to disagree about where the time went.
    #
    # The denominator is the last hop that answered, the same one the worst
    # jump takes its share of - a path ending in silence has no total, and
    # scaling to the slowest hop instead would draw every path as if one hop
    # ate all of it.
    answered = [h.get("avg_ms") for h in hops if h.get("avg_ms") is not None]
    total_ms = answered[-1] if answered else None
    timed = [h for h in hops if h.get("delta_ms") is not None]
    bar_cells = max(0, min(24, width - 40))
    # One segment is not a shape, and under eight cells the bar says less than
    # the numbers already beside it. The ribbon declines under two hops too.
    if total_ms and len(timed) >= 2 and bar_cells >= 8:
        steepest = max(timed, key=lambda x: x["delta_ms"] or 0)
        out.append(f"  where the {total_ms:.0f}ms went")
        for h in timed:
            d = h["delta_ms"] or 0
            share = round(100.0 * d / total_ms)
            # Only point at a hop when it really is the one to go and look at.
            # latency_wall declines to fire below this share and the summary
            # below says so in words; an arrow on the largest of ten even
            # steps would contradict both.
            mark = ("   <- biggest jump" if h is steepest
                    and share >= LATENCY_WALL_SHARE * 100 else "")
            out.append(f"  {str(h.get('hop', '?')):>3}  "
                       f"{render_bar(d, total_ms, bar_cells)} {d:6.1f}ms {share:>3}%{mark}")
        out.append("")
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
        # MOS drawn on its own scale, which runs 1 to 5 and not 0 to 5 - the
        # bottom of the scale is "unusable", not "nothing measured". The word
        # beside it says which band the score is in; the bar says how much
        # room is left before the band below, which the number alone does not
        # unless the reader already knows where the scale ends.
        gauge = render_bar(cq["mos"] - 1, 4, 12) if width >= 78 else ""
        out.append(f"  MOS {tint(str(cq['mos']), sev)}"
                   + (f" {gauge}" if gauge else "")
                   + f" ({rating})   "
                   f"latency {cq['avg_ms']:.0f}ms, jitter {(cq.get('jitter_ms') or 0):.0f}ms, "
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
        # err/M against the worst interface in the table, which answers the
        # question the table is read for: not "how many" but "which one".
        # A clean box is the common case and a column of empty bars would be
        # eight rows of noise, so the column appears only once one of them has
        # something to be worse than.
        ppms = [i.get("err_ppm") or 0 for i in ifaces]
        worst_ppm = max(ppms) if ppms else 0
        rank_col = worst_ppm > 0 and width >= 96
        out.append(f"  {'iface':<10}{'packets':>14}{'errors':>9}{'drops':>8}{'err/M':>8}"
                   + ("  " + " " * 10 if rank_col else "") + "   live")
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
                   f"{i['drops']:>8,}{i['err_ppm']:>8}"
                   + ("  " + render_bar(i.get("err_ppm") or 0, worst_ppm, 10)
                      if rank_col else "")
                   + f"   {live}{rate}")
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
        # The shape of the segment before the hosts in it. This sat at the
        # bottom, after twenty addresses and a note saying forty were not
        # shown, which is where a reader arrives already having read the list
        # they needed it to make sense of. One line, and it is the only part
        # that survives the cap - a stray on 169.254 among fifty on a /24 is
        # the thing worth seeing, and it can be the entry the cap cuts.
        if len(inv.get("subnets", {})) > 1:
            out.append("  subnets: " + ", ".join(f"{net}.0/24 x{n}"
                                                 for net, n in sorted(inv["subnets"].items())))
        show_names = any(h.get("name") for h in inv["hosts"])
        for host in inv["hosts"][:20]:
            name_col = f"{(host.get('name') or '-')[:30]:<32}" if show_names else ""
            out.append(f"  {host['ip']:<16}{name_col}{host.get('mac') or '-'}")
        if inv["count"] > 20:
            out.append(f"  ... and {inv['count'] - 20} more")

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

    # Every address asked the same question, where the run was asked to ask.
    # Drawn whenever it ran rather than only where the answers differ: the flag
    # is the gate. Somebody typed it, three agreeing rows are the answer to what
    # they typed, and silence would be the one reply that cannot be told apart
    # from the flag having done nothing.
    matrix = (report.get("raw") or {}).get("source_matrix") or []
    if len(matrix) > 1:
        out.append("")
        out.append(f"SOURCES TO {(report.get('raw') or {}).get('probe_target') or report.get('target', '?')}")
        addr_w = min(max(len(r["address"]) for r in matrix), max(width - 44, 15))
        out.append(f"  {'address':<{addr_w}}  {'iface':<10}{'reaches':<11}{'loss':>6}"
                   f"{'latency':>12}")
        for row in matrix:
            addr = row["address"]
            if len(addr) > addr_w:
                addr = addr[:addr_w - 1] + "…"
            loss = "-" if row.get("loss_pct") is None else f"{row['loss_pct']}%"
            avg = "-" if row.get("avg_ms") is None else f"{row['avg_ms']:.1f} ms"
            line = (f"  {addr:<{addr_w}}  {(row.get('interface') or '-'):<10}"
                    f"{('yes' if row.get('reached') else 'no'):<11}{loss:>6}{avg:>12}")
            out.append(tint(line, "ok" if row.get("reached") else "critical"))
        # One sentence under the rows, because a table of three yeses is a
        # measurement and not yet a reading.
        unreachable = [r["address"] for r in matrix if not r.get("reached")]
        if not unreachable:
            out.append("  -> every address this box holds can reach the target")
        elif len(unreachable) < len(matrix):
            out.append(f"  -> {', '.join(unreachable[:3])} reaches nothing while its "
                       f"neighbours do")
        else:
            out.append("  -> no address on this box can reach the target, so this is "
                       "the target rather than the addressing")

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
    # Say so when the target is the fallback rather than something this box
    # actually talks to. Everything below measures the path to it, and a
    # reader who does not notice which host that was will take a verdict
    # about the route to a public resolver as a verdict about their own
    # service. The finding that explains it is further down the report,
    # which is too late to change how the next line is read.
    out.append(f"target: {report.get('target', '?')}    gateway: {gw}" + mode
               + (f"    path via {src}" if src else ""))
    if (report.get("target") == DEFAULT_TARGET
            and (report.get("raw") or {}).get("target_kind") != "backend"):
        # Its own line: appended, this ran past a hundred columns.
        out.append("        nothing here depends on that host - pass --target for a "
                   "path you rely on")
    out.append("")

    v = report.get("verdict")
    # A headline is what the block is for, and a report can arrive from a file
    # now - pasted in, read as a baseline, exported by an older version. One
    # carrying a verdict without a headline used to raise here, which is the
    # traceback this renderer exists to avoid: a partial page beats a crash.
    if v and v.get("headline"):
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
    # restate an eight-stage strip that says the same thing more precisely.
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
        # Short forms of the zone labels, for a strip that has to fit a
        # terminal. Short, but the same words: when the side was renamed these
        # were missed, so one report called it "what this box connects out to"
        # on the page and "depends on" in the terminal.
        zname = {"downstream": "clients in", "local": "this box",
                 "upstream": "connects out to"}
        cells = []
        for zone in sides:
            via = f" ({zone['via']})" if zone.get("via") else ""
            cells.append(f"{zname[zone['side']]}{via} "
                         f"{tint(word[zone['state']], sev[zone['state']])}")
        # A box that relays is not a one-way chain. The page grew a second
        # head on these arrows when that was found; the terminal kept a single
        # "->", always green, so the same report drew a proxy one way here and
        # both ways there. The colour comes from the leg the arrow spans, the
        # way the page takes it, rather than from a fixed "ok".
        #
        # The split shape has to survive losing its colour. This line is what
        # gets pasted into a ticket, and two heads told apart only by an escape
        # sequence become one indistinguishable arrow the moment it is.
        flows = (((report.get("raw") or {}).get("tcp_flows") or {})
                 .get("by_side")) or {}
        line, notes = cells[0], []
        for i in range(1, len(sides)):
            leg = sides[i - 1] if sides[i]["side"] == "local" else sides[i]
            near = flows.get("client" if leg["side"] == "downstream"
                             else "backend") or {}
            total = near.get("connections") or 0
            quiet = near.get("silent_return") or 0
            arrived = near.get("delivered_anyway") or 0
            # The same two counters the page splits on, and nothing else. Each
            # carries one direction: silence about the way back, a DSACK about
            # the way out. A retransmit ratio carries neither and must never
            # reach this.
            share = near.get("silent_share_pct") or 0
            # The same decision the page reads, taken from the report rather
            # than worked out again here. Older reports carry only the counts.
            stalled = near.get("return_stalled")
            if stalled is None:
                stalled = bool(quiet) and quiet * 2 >= total
            confirmed = arrived and arrived * 2 >= total
            if total and stalled:
                line += tint("  -->x  ", "critical") + cells[i]
                # Say which way it became true. "1 of 40" on its own reads as
                # the tool over-reacting to one bad connection.
                weight = (f", and they carry {share}% of this side's traffic"
                          if quiet * 2 < total and share else "")
                notes.append(f"nothing coming back from {zname[leg['side']]}: "
                             f"{quiet} of {total} connections, while this box "
                             f"is still sending{weight}")
            elif total and confirmed:
                # The way out is confirmed and the way back is not in question,
                # so this is the one shape that says something good rather than
                # something wrong.
                line += tint("  <==>  ", "ok") + cells[i]
                notes.append(f"the way out to {zname[leg['side']]} is confirmed: "
                             f"{arrived} of {total} connections had resent data "
                             f"acknowledged as already arrived")
            else:
                line += tint("  <-->  ", sev[leg["state"]]) + cells[i]
            # The far end is acknowledging and not answering. Deliberately does
            # not touch the arrow: its network is carrying, which is what an
            # acknowledgement proves, so colouring the return leg would point at
            # a carrier for something sitting above it. Said in words instead,
            # because the reader still needs to know their request went nowhere.
            waiting = near.get("unanswered") or 0
            if total and waiting and not stalled:
                notes.append(f"{waiting} of {total} connections to "
                             f"{zname[leg['side']]} are being acknowledged and "
                             f"not answered - the path back is carrying, so this "
                             f"is that service taking its time, not the network")
            if total and stalled and confirmed:
                notes.append(f"the way out to {zname[leg['side']]} is confirmed "
                             f"delivered ({arrived} of {total}), so the fault is "
                             f"on the return leg alone")
        out.append("  " + line)
        # The page puts this in a tooltip. There is nothing to hover here, and
        # a shape nobody can look up is worse than a sentence.
        for note in notes:
            out.append(f"  -> {note}")
        out.append("")

    stages = report.get("stages") or []
    if stages:
        symbols = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "skip": "-"}
        sev = {"pass": "ok", "warn": "warning", "fail": "critical", "skip": "ok"}
        # Wrapped to the terminal rather than run out to whatever length the
        # chain happens to be. This is the line that gets pasted into a ticket,
        # and the inbound leg pushed it past eighty columns - where it broke
        # across two lines at whatever column the terminal chose, which on a
        # console narrow enough to care was mid-word.
        #
        # Measured on the plain text: an escape sequence occupies no space on
        # screen, so counting the tinted string would wrap a line that fits.
        rows, row, used = [], [], 0
        for st in stages:
            plain = f"{st['stage']} {symbols[st['state']]}"
            gap = 3 if row else 0
            if row and used + gap + len(plain) > max(width, 40) - 2:
                rows.append(row)
                row, used, gap = [], 0, 0
            row.append(f"{st['stage']} {tint(symbols[st['state']], sev[st['state']])}")
            used += gap + len(plain)
        if row:
            rows.append(row)
        for r in rows:
            out.append("  " + "   ".join(r))
        out.append("")

    # Only when there is more than one. A box serving a single thing is already
    # described by the findings above, and a one-row table is furniture.
    instances = [i for i in ((report.get("raw") or {}).get("service_instances") or [])
                 if i.get("notable")]
    if len(instances) > 1:
        out.append("SERVICE INSTANCES")
        name_w = min(max(len(i["name"]) for i in instances), max(width - 46, 16))
        out.append(f"  {'name':<{name_w}}  {'endpoint':<22}{'up':<20}serving")
        for inst in instances:
            name = inst["name"]
            if len(name) > name_w:
                name = name[:name_w - 1] + "…"
            served = inst["traffic"]
            # "serving" is a count and not a verdict. Nothing is arriving is a
            # fact about right now; whether that is wrong depends on what this
            # instance is for, which the findings above are where to say.
            state = "ok" if inst["up"] == "ok" else (
                "warning" if inst["up"] in ("listening", "not on this address")
                else "critical")
            out.append(f"  {name:<{name_w}}  {inst['endpoint']:<22}"
                       + tint(f"{inst['up']:<20}", state)
                       + (f"{served} connection(s)" if served else "nothing arriving"))
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
            out.append(" " * 26 + tint("^ " + ", ".join(marks),
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
    _render_closing_answer(report, out, tint, width)
    return "\n".join(out)


def _render_closing_answer(report, out, tint, width):
    """Say the answer again as the last thing on screen.

    A report is fifty-seven lines when nothing is wrong and seventy when
    something is. In an eighty by twenty-four terminal the verdict has scrolled
    off by the time it finishes, and what the reader is left looking at is a
    note about a flag they did not use. The conclusion is at the top, which is
    right for reading the report and wrong for finishing it.

    So it is said twice: once in full where the reader starts, and once in a
    line where the reader stops. Every tool people copy this from closes on its
    own conclusion - a plan summary, a pass and fail count, a vulnerability
    tally - and this one closed on housekeeping.

    Not a second verdict, and nothing worked out here. The headline and the
    owner are the ones the verdict already carries, so there is no second
    sentence that could disagree with the first.
    """
    v = report.get("verdict")
    if not v or not v.get("headline"):
        return
    owner = v.get("owner")
    line = f"=> {v['headline']}"
    if owner:
        line += f"  (owner: {owner})"
    out.append("")
    for wrapped in textwrap.wrap(line, width=min(width, 100),
                                 subsequent_indent="   "):
        out.append(tint(wrapped, v.get("severity", "warning")))


def build_parser():
    """Every flag the tool takes.

    Split out of main() so the flags can be read - and tested - without
    running a diagnosis; main() is then the dispatch it always meant to be.
    """
    # Exit codes belong in --help, not only in the reference: the person who
    # needs them is writing a wrapper at the time they need them.
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Wrapped by hand: RawDescriptionHelpFormatter stops argparse wrapping
        # the description as well as the epilog, and unwrapped this ran to 129
        # columns on an eighty column terminal.
        description=f"FaultOne {__version__} - field triage for a box you're logged\n"
                    f"into: is the fault this device, the network it's plugged into,\n"
                    f"or upstream?",
        epilog="exit codes: 0 nothing wrong, 1 a warning, 2 something critical,\n"
               "            3 no verdict reached (a crash, or a run that could not\n"
               "            reach a conclusion). 0, 1 and 2 all mean it ran.\n\n"
               "colour:     off when the output is not a terminal, when NO_COLOR is\n"
               "            set, and on a dumb terminal. FORCE_COLOR turns it back\n"
               "            on; --no-color beats both.")
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
                          "ARP/neighbour table. Nothing is scanned or probed - the only traffic "
                          "it adds is a reverse-DNS lookup per neighbour, to a resolver already "
                          "configured here")
    ap.add_argument("--no-color", action="store_true",
                     help="never colour the output. Colour is already off when the output "
                          "is redirected, when NO_COLOR is set, and on a dumb terminal - "
                          "this is the override for when that detection is wrong")
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
                          "--baseline reads. Use - for stdout, which is always JSON and "
                          "comes out on one line so a terminal can select it in one "
                          "click")
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
    ap.add_argument("--source", metavar="ADDR",
                     help="address to send from, for a box holding more than one. A "
                          "proxy's service address and its own address take different "
                          "paths off the box, and only this one measures the path a "
                          "client of that address gets. Reported as critical if this box "
                          "does not hold the address, which is what a standby node looks "
                          "like. Pass 'all' to ask every global-scope address instead, "
                          "which is one ping each and reports which of them can reach "
                          "the target. Default: whichever address the kernel picks")
    return ap


def _survive_a_narrow_encoding():
    """Print what can be printed rather than dying on one character.

    Everything this tool writes itself is ASCII, deliberately: box drawing and
    separators look better and arrive as mojibake on a serial console. But a
    hostname is not ours. A printer called Drucker-Buero, a switch named in
    Chinese, a PTR record with an accent - those are data read off the wire,
    and mangling them would be worse than showing them, so they are passed
    through as they came.

    On a terminal that cannot encode them - LANG=C, an out-of-band console,
    PYTHONIOENCODING=ascii - writing one used to raise, and the whole report
    was lost to a traceback because a neighbour had an umlaut in its name.
    That is the shape of failure this tool exists to avoid: a diagnosis that
    ran and then could not be delivered. The character is replaced and the
    rest of the report survives.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            # Not a text stream, or one that will not be reconfigured. The
            # report is worth attempting either way.
            pass


def main():
    """Parse the flags and run whichever single action was asked for."""
    _survive_a_narrow_encoding()
    ap = build_parser()
    args = ap.parse_args()

    if args.emit_viewer:
        with open(args.emit_viewer, "w", encoding="utf-8", errors="replace") as f:
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
        if args.source and args.source.strip().lower() == "all":
            # Every address rather than one. Kept on the same flag because it
            # is the same question - which address does this leave from - and a
            # second flag would let both be given and disagree.
            global PROBE_EVERY_SOURCE
            PROBE_EVERY_SOURCE = True
            args.source = None
        if args.source:
            # An address, not a hostname and not an interface name. Linux ping
            # would accept an interface for -I and nothing else here would,
            # which is a flag that means one thing on one platform and another
            # elsewhere. Rejected at the front rather than half-honoured.
            if not valid_ip(args.source):
                print(f"Invalid --source: {args.source!r} - give an address this box "
                      f"holds, not a hostname or an interface name", file=sys.stderr)
                raise SystemExit(EXIT_UNKNOWN)
            global SOURCE_ADDRESS
            SOURCE_ADDRESS = args.source
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
                # One line, because stdout is where a report goes to be piped
                # or pasted. Indented, a compact report is 192 logical lines
                # and about 198 rows on an 80-column terminal, so taking it off
                # a box you cannot copy a file from means dragging a selection
                # across all of it and scrolling part-way through. On one line
                # a terminal's triple-click takes the whole thing: a soft wrap
                # is not a line break to it. A named file keeps the
                # indentation - that is where a report goes to be read, diffed
                # and used as a baseline.
                #
                # JSON, always. The format comes from the filename extension
                # and "-" has none, so the branch that used to write a page
                # here could not be reached: to_stdout means the name is "-",
                # and wants_html means it ends in .html.
                json.dump(json_safe(written), sys.stdout, separators=(",", ":"))
                sys.stdout.write("\n")
            else:
                try:
                    # 0600: the report contains internal addressing, MAC
                    # addresses and listening ports - not for other users of a
                    # shared box.
                    fd = os.open(export_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
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
            print(render_text_report(report, color=use_color(msg, args.no_color)), file=msg)

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
