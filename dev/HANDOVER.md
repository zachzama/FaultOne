# Open threads

Not a harness and not documentation. One thing that is unfinished and one that
is finished but easy to undo by accident, written down because the reasoning
behind them is not in the code and would otherwise have to be rediscovered.

Everything here is checkable from the repository. Where a number is quoted,
the command that produces it is next to it.

## Open: a flaky test, diagnosed by mechanism rather than caught

`DiagnoseHarness.test_healthy_device` failed roughly one run in six. It passed
300 times in isolation, which is the signature of something leaking between
tests rather than something wrong in the test.

The harness claimed in its own docstring that every collector was stubbed. It
named seventeen in a tuple; the tool had grown to thirty-eight. Twenty-two ran
for real, including `cmd_tls_check`, which opens a live TLS handshake — from a
suite that promises it sends no packets. Others read the host: socket states,
server limits, orphan counts. `test_healthy_device` asserts the only finding is
`all_clear`, so anything the machine happened to be doing could add one.

The list is derived from the module now and the failure has not recurred: nine
consecutive full runs, where about one and a half failures would have been
expected. That is good evidence and not proof — at a one-in-six rate there is
roughly a nineteen per cent chance of nine clean runs by luck.

**If it comes back, capture which finding joined `all_clear`.** That names the
collector immediately. The failing assertion was never captured the first time,
so the diagnosis above is inference from mechanism and rate, and a second round
of inference would not be worth much.

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
  how they are drawn — so it needs rules about what must never be folded away,
  and each of those is somewhere a bug can live. Its benefit could not be
  shown: every trace in the corpus is two to four hops, so it saved nine nodes
  across a hundred and fifty-two paths. The case for it rested on a synthetic
  path.
- **Moving the per-hop delay onto the connector.** Correct in principle — the
  delay belongs to the link, not the router at the far end — and it did not
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
  1000ms — the median is 20ms — so a fixed row never fills and never wraps, and
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

The second number is why the ribbon is nearly binary in practice — one long
segment and a row of slivers. That is what a traceroute looks like.

And a gap in the corpus that hid a real bug: every scenario names its hops
identically, so nothing exercised long or short PTR names. Real ones run from
one character to forty-two, and box width was being driven by the name rather
than by the time until a path with realistic naming was drawn. If a layout
change touches hop width, test it against names of both extremes.
