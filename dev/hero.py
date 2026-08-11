#!/usr/bin/env python3
"""Draw the top of a real report as an SVG, for the README.

    python3 dev/hero.py            # write docs/hero-dark.svg and docs/hero-light.svg

Why generated rather than a screenshot: a screenshot is a claim about the
output that stops being true the moment the output changes, and nothing would
notice. This renders the report through the tool itself, so the picture is the
program's own words or it is nothing.

Two things it is careful about.

**The report comes from a scenario, never from this machine.** A report is a
map of the network it was taken on - the README says so under Security - so a
hero image taken from a real run would publish the addressing of whoever built
it. The test corpus is synthetic and exists for exactly this.

**The output is deterministic.** The banner carries a timestamp and the host's
own OS and interpreter, which would make every regeneration a diff. They are
pinned here, so re-running this on another machine produces the same bytes and
the image only changes when the report does.

Pinning the banner was not enough, and CI is what said so. A scenario stubs
what the tool *runs*, not what it *reads*: a few checks open files under /proc
directly, which exist on Linux and do not on a Mac, so the same scenario
reported different coverage on each and the committed image matched only the
machine it was drawn on. The platform and those readers are both fixed below,
which also makes the banner honest - it says Linux because the report is now
genuinely a Linux-shaped one.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

SCENARIO = "tcp_flow_loss_clients"   # a fault on the way in, which is the one
                                     # the picture is meant to explain
LINES = 16                           # through the stage strip; the findings
                                     # below it are detail, not the pitch
WIDTH_COLS = 76

# Pinned so the image is reproducible. The date is the release this was drawn
# for; the OS and interpreter are the ones the README's other samples quote.
BANNER = "FaultOne {version} - Linux - python 3.11.2 - 2026-08-11T09:14:22Z"

ANSI = re.compile(r"\x1b\[([0-9;]*)m")

# The viewer's palette, so the image and the product agree on what a warning
# looks like. Light values are GitHub's own, so it sits on the page rather than
# glowing off it.
THEMES = {
    "dark":  {"bg": "#0d1117", "panel": "#0a0e13", "border": "#232b35",
              "text": "#dce4ec", "dim": "#8b97a5",
              "31": "#e5534b", "33": "#d9a02b", "32": "#3fb950"},
    "light": {"bg": "#ffffff", "panel": "#f6f8fa", "border": "#d0d7de",
              "text": "#1f2328", "dim": "#59636e",
              "31": "#cf222e", "33": "#9a6700", "32": "#1a7f37"},
}

FONT = ("ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
        "'DejaVu Sans Mono', monospace")
FONT_SIZE = 13.0
CHAR_W = 7.82          # advance width of the fonts above at this size
LINE_H = 19.0
PAD_X, PAD_Y = 18.0, 16.0


def report_lines():
    """The top of a report, as (text, colour-code) runs per line."""
    sys.argv = ["hero"]
    import test_faultone as T
    import faultone as nd

    setup, kw = T.S[SCENARIO]
    mod = T.fresh()
    # The report is a Linux one wherever it is drawn, which is what the banner
    # has always claimed.
    mod.OS_NAME = "Linux"
    setup(mod)
    # The three checks that read the host rather than running a command. Left
    # live they answer from whatever machine is drawing, so the picture came
    # out differently on Linux and on a Mac. "Could not read it" is a state the
    # report already knows how to show, and it is the same one on both.
    for name in ("cmd_kernel_drops", "cmd_kernel_log", "cmd_clock_sync"):
        setattr(mod, name, (lambda n: lambda *a, **k: {
            "ok": False, "cmd": n, "error": "not read for this example"})(name))
    report = mod.diagnose(quick=False, **T.scenario_kwargs(kw))
    text = mod.render_text_report(report, color=True, width=WIDTH_COLS)

    out = []
    for raw in text.splitlines()[:LINES]:
        runs, colour, pos = [], None, 0
        for m in ANSI.finditer(raw):
            if m.start() > pos:
                runs.append((raw[pos:m.start()], colour))
            codes = [c for c in m.group(1).split(";") if c]
            colour = None if not codes or "0" in codes else codes[-1]
            pos = m.end()
        if pos < len(raw):
            runs.append((raw[pos:], colour))
        out.append(runs)

    # The banner names the machine that drew it; pin it.
    if out:
        out[0] = [(BANNER.format(version=nd.__version__), None)]
    return out


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def svg(lines, theme):
    c = THEMES[theme]
    cols = max((sum(len(t) for t, _ in ln) for ln in lines), default=0)
    w = round(cols * CHAR_W + PAD_X * 2)
    h = round(len(lines) * LINE_H + PAD_Y * 2)

    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
        'viewBox="0 0 %d %d" font-family="%s" font-size="%s">'
        % (w, h, w, h, FONT, FONT_SIZE),
        '<rect width="%d" height="%d" rx="8" fill="%s" stroke="%s"/>'
        % (w, h, c["panel"], c["border"]),
    ]
    for i, runs in enumerate(lines):
        y = PAD_Y + FONT_SIZE + i * LINE_H
        spans, col = [], 0
        for text, code in runs:
            if not text:
                continue
            fill = c.get(code or "", c["text"])
            # Positioned per run rather than flowed, so a run that a renderer
            # measures differently cannot shift the rest of the line.
            # One x per character, rather than one per run plus a trust that
            # the reader's monospace advance matches CHAR_W. It does not have
            # to: this pins every glyph to the grid in any renderer, where
            # textLength is honoured by browsers and quietly ignored by some
            # preview tools - which draws a line wider than the panel it sits
            # in, on exactly the machines nobody tested.
            xs = " ".join("%.1f" % (PAD_X + (col + i) * CHAR_W)
                          for i in range(len(text)))
            spans.append('<tspan x="%s" y="%.1f" fill="%s" '
                         'xml:space="preserve">%s</tspan>'
                         % (xs, y, fill, esc(text)))
            col += len(text)
        if spans:
            parts.append("<text>" + "".join(spans) + "</text>")
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main():
    lines = report_lines()
    out = os.path.join(ROOT, "docs")
    if not os.path.isdir(out):
        os.makedirs(out)
    for theme in THEMES:
        path = os.path.join(out, "hero-%s.svg" % theme)
        with open(path, "w") as fh:
            fh.write(svg(lines, theme))
        print("wrote %s (%d lines, %d bytes)"
              % (os.path.relpath(path, ROOT), len(lines),
                 os.path.getsize(path)))


if __name__ == "__main__":
    main()
