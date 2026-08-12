#!/usr/bin/env python3
"""PROTOTYPE: which counter started moving first.

    python3 dev/proto_sequence.py            # three worked cases

Nothing here is wired into the tool. It takes counter series sampled on one
tick - which `--soak` already does for interface rates - and works out the
order in which things started, so "A explains B" can rest on A having happened
first rather than only on A sitting lower in the stack.

## Why

The layer rule answers "which of these is the cause" by position: the lowest
live fault wins. That is right and it is static. Every incident in the public
postmortem corpus has a shape the layer rule cannot express - a latent
condition that sat harmlessly for months, a trigger, and a cascade:

  - a race in DNS management that needed two processes to overlap
  - a network disruption that pushed metadata calls past their timeouts, so
    storage nodes removed themselves, which raised load, which timed out more
  - a fleet that crossed a thread ceiling it had never reached before

In each, several things are wrong at once and the order is what tells you
which one to fix. This tool currently reports them as simultaneous, because
from a snapshot they are.

## What it reports, and what it refuses to

Three states per counter, and the third is the one worth having:

  started at +Ns   it was quiet when sampling began and then moved
  already moving   it was elevated at the first sample - this is the latent
                   condition; sampling started too late to see it begin, and
                   saying "started at +0s" would be a guess dressed as a fact
  quiet            never moved

Two counters whose onsets fall within two samples of each other are reported
as simultaneous. The interval is the resolution: onsets one sample apart are
somewhere between nothing and two intervals apart, and ordering on that is the
invented precision that makes a sequence signal worse than none.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ...and stay there. One interval is a blip; the fault this exists to order
# is the one that starts and continues.
SUSTAIN = 2
# How far apart two onsets must be before the gap is called an order. One
# sample is not enough: at ten second resolution, onsets one sample apart are
# somewhere between nothing and twenty seconds apart, and a claim that rests
# on that is the invented precision this is supposed to avoid.
SEPARATION = 2
# The smallest per-interval change that counts as movement rather than noise.
# One unit suits integer counters - errors, retransmits, table entries. A
# series in milliseconds or percent would want its own floor, which is the
# first thing to fix if this becomes real.
FLOOR = 1.0


def onset(series):
    """(state, sample index) - where a series stops being still.

    Read as changes between samples, not as levels. A counter that is high and
    steady is not a fault in progress; a counter that is climbing is, whatever
    its absolute value. Comparing levels against an opening baseline cannot see
    the second case at all - a conntrack table already at 81% and rising two
    points a sample never reaches three times its own start, so the first
    version of this reported the textbook latent condition as "quiet".
    """
    if len(series) < SUSTAIN + 2:
        return "quiet", None
    deltas = [b - a for a, b in zip(series, series[1:])]
    moving = [d >= FLOOR for d in deltas]

    if not any(moving):
        return "quiet", None
    if all(moving):
        # Climbing in every interval, including the first. This window holds no
        # evidence of a beginning, and "+0s" would be a guess with a number on
        # it - the honest answer is that it was going before anyone looked.
        return "already", 0
    for j in range(len(moving) - SUSTAIN + 1):
        if all(moving[j:j + SUSTAIN]):
            return ("already", 0) if j == 0 else ("started", j + 1)
    return "quiet", None


def order(named_series, interval_s):
    """Readable lines: what started when, and what may not be ordered."""
    found = {}
    for name, series in named_series.items():
        found[name] = onset(series)

    started = sorted(((i, n) for n, (s, i) in found.items() if s == "started"))
    latent = sorted(n for n, (s, _i) in found.items() if s == "already")
    quiet = sorted(n for n, (s, _i) in found.items() if s == "quiet")

    lines = []
    for name in latent:
        lines.append("  %-22s already moving when sampling began" % name)
    for i, name in started:
        lines.append("  %-22s started at +%ds" % (name, int(i * interval_s)))
    for name in quiet:
        lines.append("  %-22s quiet throughout" % name)

    lines.append("")
    if latent:
        lines.append("  %s was already going before this window. Nothing here can"
                     % ", ".join(latent))
        lines.append("  say what started it, and this run is not evidence that it")
        lines.append("  began when the others did.")
    if len(started) >= 2:
        first_i, first = started[0]
        for i, name in started[1:]:
            gap = (i - first_i) * interval_s
            if i - first_i < SEPARATION:
                lines.append("  %s and %s are within %d samples of each other -"
                             % (first, name, SEPARATION))
                lines.append("  not orderable at %ds resolution." % int(interval_s))
            else:
                lines.append("  %s preceded %s by %ds (%d samples)."
                             % (first, name, int(gap), i - first_i))
    elif len(started) == 1 and not latent:
        lines.append("  only one counter moved, so there is no order to report.")
    return lines


def case(title, interval, **series):
    print(title)
    print("-" * len(title))
    for line in order(series, interval):
        print(line)
    print()


def main():
    # A cascade: the link starts corrupting frames, TCP reacts, the call
    # falls apart. Ten-second samples over two minutes.
    case("1. a cascade - the thing that started first is the thing to fix", 10,
         link_errors=[0, 0, 0, 4, 9, 14, 20, 27, 33, 39, 44, 50],
         tcp_retransmits=[1, 1, 1, 1, 1, 2, 9, 18, 26, 35, 44, 52],
         call_quality_mos=[0, 0, 0, 0, 0, 0, 0, 0, 3, 7, 12, 18])

    # Everything moves at once: a power event, a cable pulled, an upstream
    # device rebooting. There is no order to find and claiming one would be
    # worse than saying so.
    case("2. simultaneous onset - refuses to order what it cannot", 10,
         link_errors=[0, 0, 0, 11, 22, 33, 44, 55, 66, 77, 88, 99],
         tcp_retransmits=[0, 0, 0, 10, 21, 30, 41, 52, 63, 74, 85, 96],
         gateway_loss_pct=[0, 0, 0, 12, 25, 36, 48, 60, 71, 83, 94, 99])

    # The latent condition: conntrack has been filling for hours and the run
    # only sees the last two minutes of it. Reporting "+0s" would be a lie
    # with a number on it.
    case("3. a latent condition, plus something that really did start here", 10,
         conntrack_used=[81, 82, 84, 85, 87, 88, 90, 91, 93, 94, 96, 97],
         tcp_retransmits=[0, 0, 0, 0, 0, 0, 1, 7, 15, 24, 33, 41],
         link_errors=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
