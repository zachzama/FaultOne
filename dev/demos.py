#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Five report pages for showing the tool to someone, written to your Desktop.

    python3 dev/demos.py                 # write them to ~/Desktop
    python3 dev/demos.py /tmp/demos      # or somewhere else

Why these five, in this order. The first two are the pair worth leading with:
the same box, the same kind of symptom, opposite directions, and the verdict
names a different owner for each. That is the whole product in two clicks. The
next two are faults that belong to the box rather than to either path, and the
last is a service address nothing is accepting on.

**Every page comes from the test corpus, never from a live run.** A report is a
map of the network it was taken on, so a demo taken from a real machine would
publish the addressing of whoever made it. The banner is pinned to Linux for
the same reason the README's hero image is: a proxy demo that says macOS is
reading its own author rather than the box it claims to describe.

Two of the five need a socket table built here rather than the corpus one:

  - port exhaustion ships with 450 outbound connections and no clients, which
    is a crawler rather than a proxy. A proxy exhausting a port range has
    clients in front of it, and the demo is about a proxy.
  - the service-address case needs the box to be genuinely serving, or the
    clients box reads "nothing connects here" and the story becomes a quiet
    machine instead of an address nobody can reach.

Checked, not assumed: each page's verdict has to name the fault its filename
claims, or this exits non-zero. A demo whose headline disagrees with its name is
worse than no demo, and the first version of this file shipped one - stubbing a
collector that the port-exhaustion finding reads its numbers from, which turned
that page into a box nobody was talking to.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# Taken before argv is replaced. The tool reads sys.argv at import time to work
# out how it was invoked, so this file has to blank it - which silently ate the
# output directory this script documents, and wrote to the Desktop regardless of
# what was asked for.
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/Desktop")
sys.argv = ["demos"]
os.environ.pop("SSH_CONNECTION", None)      # no operator session to exclude here

import test_faultone as T                                       # noqa: E402

VIP_INTERFACES = {"ok": True, "cmd": "ip addr", "stdout":
                  "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                  "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
                  "    inet 10.0.0.200/32 scope global eth0\n"}

# Read from the host and platform-dependent, so they are answered the same way
# on every machine that draws these. cmd_kernel_drops is deliberately *not* in
# here: it is where the port and table findings get their numbers.
PINNED = ("cmd_kernel_log", "cmd_clock_sync")


def sockets(*groups):
    return "\n".join(["State Recv-Q Send-Q Local Address:Port Peer Address:Port",
                      "LISTEN 0 128 10.0.0.5:443 0.0.0.0:*"]
                     + [row for group in groups for row in group]) + "\n"


def clients(n):
    return ["ESTAB 0 0 10.0.0.5:443 198.51.100.%d:51%02d" % (i, i)
            for i in range(1, n + 1)]


def backends(n):
    return ["ESTAB 0 0 10.0.0.5:5%03d 10.0.0.90:5432" % (100 + i) for i in range(n)]


def traffic_both_ways(mod):
    """Clients lossy, backends clean, and both carrying real connections.

    The corpus scenario has one client connection and nothing outbound, which
    reads as a box with nothing going out - and then a green outbound box looks
    like an absence of measurement rather than a measurement that came back
    clean. It is the distinction the page exists to draw, so the demo has to
    have both sides to draw it with.
    """
    T.sided_flows(
        mod,
        *[T.sided_sock("198.51.100.%d" % i, "443", sent=40_000_000, retrans=3_200_000)
          for i in range(1, 6)],
        *[T.sided_sock("10.0.0.90", "51%03d" % (100 + i), sent=60_000_000, retrans=0)
          for i in range(4)])
    T.serving(mod, sockets(clients(5), backends(4)))


def relaying_out_of_ports(mod):
    T.serving(mod, sockets(clients(7),
                           ["ESTAB 0 0 10.0.0.5:%d 10.0.0.90:5432" % (32768 + i)
                            for i in range(450)]))


def serving_but_not_on_the_vip(mod):
    mod.cmd_interfaces = lambda: VIP_INTERFACES
    T.serving(mod, sockets(clients(6)))


DEMOS = [
    ("1-inbound-loss",    "tcp_flow_loss_clients",    traffic_both_ways),
    ("2-outbound-loss",   "tcp_flow_loss_backends",   None),
    ("3-port-exhaustion", "ephemeral_ports_low",      relaying_out_of_ports),
    ("4-egress-blocked",  "egress_blocked",           None),
    ("5-service-address", "service_address_unserved", serving_but_not_on_the_vip),
]


def main():
    out_dir = OUT_DIR
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    wrong = []
    for slug, code, arrange in DEMOS:
        setup, kwargs = T.S[code]
        mod = T.fresh()
        mod.OS_NAME = "Linux"
        for name in PINNED:
            setattr(mod, name, (lambda n: lambda *a, **k: {
                "ok": False, "cmd": n, "error": "not read for this example"})(name))
        setup(mod)
        if arrange:
            arrange(mod)
        report = mod.diagnose(quick=False, **T.scenario_kwargs(kwargs))
        named = (report["verdict"].get("based_on") or ["-"])[0]
        path = os.path.join(out_dir, "faultone-demo-%s.html" % slug)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(mod.render_report_html(report))
        sides = {z["side"]: z["state"] for z in report["sides"]}
        print("  %s %-36s in %-5s box %-5s out %-5s  %s"
              % ("ok" if named == code else "!!", os.path.basename(path),
                 sides["downstream"], sides["local"], sides["upstream"],
                 report["verdict"]["headline"][:44]))
        if named != code:
            wrong.append("%s: verdict named %s" % (slug, named))
    if wrong:
        print("\n" + "\n".join(wrong))
        return 1
    print("\nwrote %d pages to %s" % (len(DEMOS), out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
