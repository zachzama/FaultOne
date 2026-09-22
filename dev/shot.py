#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Capture the HTML export for the README, because a link is a line of text.

    python3 dev/shot.py              # write docs/export.png and docs/export.json
    python3 dev/shot.py --check      # say whether the committed one is stale

The hero image beside it is drawn rather than captured, and `dev/hero.py` says
why: a drawing is generated from the thing it depicts, so it cannot fall out of
step with it. A screenshot can, and nothing would notice - which is the whole
objection to committing one.

So this one records what it captured. `docs/export.json` carries the hash of
`VIEWER_TEMPLATE` and the version that was in the banner, and a test in the
suite fails when either moves without a recapture. That is the same bargain
hero.py makes, paid for with a sidecar file instead of a second renderer.

The page itself comes from `dev/demos.py`, which builds it from the test corpus
and refuses to write a page whose verdict does not name the fault its filename
claims. Running that rather than reimplementing it is deliberate: there is one
set of fixtures and it is already checked. **No live run is involved** - a
report is a map of the network it was taken on, and a screenshot of a real one
would publish the addressing of whoever took it.

Needs Chrome. That is why this is a dev script and not a harness: the tool has
no dependencies and the suite has none either, and this is not the place to
start. Nothing here ever runs on a box being diagnosed.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import faultone as nd  # noqa: E402  (after the path, on purpose)

PNG = os.path.join(ROOT, "docs", "export.png")
SIDECAR = os.path.join(ROOT, "docs", "export.json")

#: Demo 1 of the nine. It is the page whose whole argument is visible without
#: scrolling - clients in FAULT, this box and the way out both OK - which is
#: the one thing a reader should take from a single image.
DEMO = "faultone-demo-1-inbound-loss.html"

#: CSS pixels, doubled by the device scale factor below. The height stops just
#: under "WHAT WAS FOUND": the verdict, the three boxes and both path columns
#: fit above it, and a heading sliced in half is the kind of detail that makes
#: a careful project look careless.
WIDTH, HEIGHT = 1400, 940
SCALE = 2

#: Where Chrome lives on the two platforms this has been run on. Looked up
#: rather than configured, and it says what it could not find if it fails.
CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
]


def chrome():
    for path in CANDIDATES:
        if os.path.isabs(path):
            if os.path.exists(path):
                return path
        else:
            found = shutil.which(path)
            if found:
                return found
    sys.exit("no Chrome or Chromium found; looked for:\n  " + "\n  ".join(CANDIDATES))


def stamp():
    """What the committed image is a picture of.

    The template hash because the layout is the thing that can change under
    the image, and the version because the banner prints it.
    """
    return {
        "demo": DEMO,
        "version": nd.__version__,
        "viewer_sha256": hashlib.sha256(nd.VIEWER_TEMPLATE.encode()).hexdigest(),
        "width": WIDTH, "height": HEIGHT, "scale": SCALE,
    }


def committed():
    try:
        with open(SIDECAR, encoding="utf-8") as fh:
            return json.load(fh)
    except (IOError, OSError, ValueError):
        return None


def stale():
    """(is_it_stale, why). Kept here so the test and --check agree by
    construction rather than by both being written carefully."""
    was, now = committed(), stamp()
    if was is None:
        return True, "docs/export.json is missing or unreadable"
    if not os.path.exists(PNG):
        return True, "docs/export.png is missing"
    if was.get("viewer_sha256") != now["viewer_sha256"]:
        return True, ("VIEWER_TEMPLATE has changed since the screenshot was "
                      "taken, so the image may show a layout that no longer "
                      "exists")
    if was.get("version") != now["version"]:
        return True, ("the banner in the image says %s and the tool is now %s"
                      % (was.get("version"), now["version"]))
    return False, "the committed screenshot matches this tree"


def capture():
    exe = chrome()
    out = tempfile.mkdtemp(prefix="faultone-shot-")
    try:
        built = subprocess.run([sys.executable, os.path.join("dev", "demos.py"), out],
                               cwd=ROOT, capture_output=True, text=True)
        if built.returncode != 0:
            sys.exit("dev/demos.py would not build the pages, so there is "
                     "nothing to photograph:\n" + (built.stderr or built.stdout))
        page = os.path.join(out, DEMO)
        if not os.path.exists(page):
            sys.exit("dev/demos.py did not write %s - has the list changed?" % DEMO)
        shot = subprocess.run([
            exe, "--headless=new", "--disable-gpu", "--hide-scrollbars",
            "--force-device-scale-factor=%d" % SCALE,
            "--window-size=%d,%d" % (WIDTH, HEIGHT),
            "--screenshot=%s" % PNG, "file://" + page,
        ], capture_output=True, text=True)
        # Chrome writes the file and still says things on stderr about GPU and
        # process policy, so the file is the test rather than the exit code.
        if not os.path.exists(PNG) or os.path.getsize(PNG) < 10000:
            sys.exit("Chrome did not write a usable image:\n" +
                     (shot.stderr or shot.stdout))
        with open(SIDECAR, "w", encoding="utf-8") as fh:
            json.dump(stamp(), fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("wrote %s (%d KB) and %s"
              % (os.path.relpath(PNG, ROOT), round(os.path.getsize(PNG) / 1024),
                 os.path.relpath(SIDECAR, ROOT)))
    finally:
        shutil.rmtree(out, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the committed screenshot is stale")
    args = ap.parse_args()
    if args.check:
        bad, why = stale()
        print(why)
        if bad:
            print("recapture with: python3 dev/shot.py")
        return 1 if bad else 0
    capture()
    return 0


if __name__ == "__main__":
    sys.exit(main())
