#!/usr/bin/env python3
"""PROTOTYPE: diff two reports as configuration, not as measurements.

    python3 dev/proto_config_diff.py before.json after.json
    python3 dev/proto_config_diff.py --demo        # a worked pair, no files needed

Nothing here is wired into the tool. It reads two exported reports and prints
what a configuration-aware `--baseline` would say.

## Why

The largest classified category in the public postmortem corpus is
configuration error - 51 of 227 entries, plus three of the eighteen official
AWS post-event summaries. `compare_reports` already diffs two visits, but it
diffs *what was measured*: loss, latency, link speed, which neighbours
answered. Those move on their own. Configuration does not: it changes because
somebody changed it, which is why it is worth a different sentence.

The distinction this draws is between

    "loss to the target went from 0% to 4%"        - a measurement moved

and

    "eth0 MTU: 1500 -> 1400"                       - somebody changed this

The second is not a fault and is not reported as one. It is the answer to
"what changed since it last worked", which is the question the corpus says
gets asked most and which no amount of probing can answer from a single visit.

## What it does not do

It cannot see a change that left no trace in a report - a firewall rule, a
route map on somebody else's box, an IAM policy. It sees what this tool
already collects. That is a smaller claim than "detects configuration errors"
and is the honest one.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# What counts as configuration: someone set it, and it stays set. Ordered so
# the output reads down the stack the way the report does.
SCENARIO = "all_clear"      # a healthy box, so nothing but the change shows

INTERFACE_FIELDS = [
    ("mtu", "MTU"),
    ("speed_mbps", "link speed (Mbps)"),
    ("duplex", "duplex"),
]


def _raw(report, key):
    return (report.get("raw") or {}).get(key) or {}


def _interfaces(report):
    return {i.get("name"): i
            for i in (_raw(report, "link_modes").get("interfaces") or [])
            if i.get("name")}


def _resolvers(report):
    return [r.get("server") for r in (_raw(report, "dns_health").get("resolvers") or [])
            if r.get("server")]


def changes(before, after):
    """(what, before, after, note) for everything somebody had to change."""
    out = []

    def note(what, was, now, why):
        if was is None or now is None:      # not measured on one side
            return
        if was != now:
            out.append((what, was, now, why))

    b_if, a_if = _interfaces(before), _interfaces(after)
    for name in sorted(set(b_if) & set(a_if)):
        for field, label in INTERFACE_FIELDS:
            note("%s %s" % (name, label), b_if[name].get(field), a_if[name].get(field),
                 "set on the interface, or negotiated with the port it lands in")

    # An interface appearing or going away is a bigger change than any field
    # on it, so it is stated as itself rather than as a row of Nones.
    for name in sorted(set(b_if) - set(a_if)):
        out.append(("interface %s" % name, "present", "gone",
                    "an interface this box had is no longer there"))
    for name in sorted(set(a_if) - set(b_if)):
        out.append(("interface %s" % name, "absent", "present",
                    "an interface appeared that was not here before"))

    note("default gateway", before.get("detected_gateway"), after.get("detected_gateway"),
         "the box is pointing somewhere else")
    note("gateway MAC", before.get("gateway_mac"), after.get("gateway_mac"),
         "same address, different device answering for it - a swap, "
         "a failover, or something impersonating it")

    b_dns, a_dns = _resolvers(before), _resolvers(after)
    if b_dns and a_dns and b_dns != a_dns:
        out.append(("resolvers", ", ".join(b_dns), ", ".join(a_dns),
                    "the list this box asks, in the order it asks them"))

    note("target", before.get("target"), after.get("target"),
         "the two visits aimed at different things, so measurements below "
         "are not comparable")
    note("os", before.get("os"), after.get("os"),
         "not the network - the box itself was rebuilt or replaced")
    return out


def render(before, after):
    rows = changes(before, after)
    if not rows:
        return ["configuration is identical across the two visits"]
    width = max(len(w) for w, *_ in rows)
    lines = ["%d configuration difference(s) - none of these changed by itself:"
             % len(rows), ""]
    for what, was, now, why in rows:
        lines.append("  %-*s  %s -> %s" % (width, what, was, now))
        lines.append("  %-*s  %s" % (width, "", why))
        lines.append("")
    return lines


def demo():
    """A worked pair, built by running one scenario twice with a change between.

    Uses the test corpus rather than a live run, for the same reason the hero
    image does: a report is a map of the network it was taken on.
    """
    sys.argv = [sys.argv[0]]
    import test_faultone as T

    def report(mutate=None):
        setup, kw = T.S[SCENARIO]
        mod = T.fresh()
        setup(mod)
        if mutate:
            mutate(mod)
        return mod.diagnose(quick=False, **T.scenario_kwargs(kw))

    before = report()

    def changed(mod):
        # Somebody set a jumbo-ish MTU, forced half duplex, and pointed the
        # box at a different resolver. None of these is a fault on its own.
        base = mod.cmd_link_modes
        mod.cmd_link_modes = lambda: _retune(base())
        gw = mod.cmd_routes
        mod.cmd_routes = lambda: {"ok": True, "cmd": "ip route",
                                  "stdout": "default via 10.0.0.254 dev eth0\n"}

    def _retune(res):
        out = json.loads(json.dumps(res))
        for iface in out.get("interfaces") or []:
            iface["mtu"] = 1400
            iface["duplex"] = "half"
        return out

    after = report(changed)
    return before, after


def main():
    if "--demo" in sys.argv:
        before, after = demo()
    elif len(sys.argv) == 3:
        with open(sys.argv[1], encoding="utf-8") as fh:
            before = json.load(fh)
        with open(sys.argv[2], encoding="utf-8") as fh:
            after = json.load(fh)
    else:
        print(__doc__.strip().splitlines()[2].strip())
        return 2
    print("\n".join(render(before, after)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
