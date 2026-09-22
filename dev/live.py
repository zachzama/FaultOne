#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Is the published example site actually still there?

    python3 dev/live.py                  # check the published site
    python3 dev/live.py --base URL       # or somewhere else, e.g. a preview

Everything else in `dev/` checks the site is *correct when built*. Nothing
checked that it is *still being served*, and those are different questions
with different failure modes: a repository setting changed, Pages switched
off, a rename that left the index pointing at files that no longer exist.

This is the same gap the resume card sat in for nine releases - a claim about
the world that nobody re-read. The build cannot notice it, because by then the
build has already succeeded.

**It follows the index rather than a list.** A hand-written list of the nine
pages would be a list of the pages that existed the day it was written, and
the failure worth catching is exactly the one where those two disagree. So it
reads the index the site is serving, takes the links out of it, and fetches
every one.

**Run by hand, after changing the demo pages.** There was a weekly workflow
doing this and it was the wrong shape: a recurring check guards against
change, and nothing here changes any more. What it bought was a red run
whenever somebody else's CDN hiccuped, on a repository whose whole job is the
impression it makes.
"""

import argparse
import re
import sys
import urllib.error
import urllib.request

BASE = "https://zachzama.github.io/FaultOne/"

#: Long enough for a CDN with a cold cache, short enough that a hung fetch
#: fails the run rather than occupying a runner for six minutes.
TIMEOUT = 20

#: One retry, and it says when it used one. A single transient blip against
#: somebody else's CDN is not worth waking anyone for, but a check that
#: silently retries is a check that hides a site which is up half the time.
ATTEMPTS = 2

#: What makes a page one of ours rather than a Pages 404, a parked page, or an
#: empty file that still answers 200. Substrings, because the markup around
#: them is the viewer's business and changes more often than the words do.
INDEX_MUST_HAVE = "example reports"

#: Two markers, because there are two different ways to serve a page that is
#: not a report, and one marker only catches the first.
#:
#: `IS_THE_VIEWER` says the response is our page rather than a Pages 404. It
#: is matched case-insensitively: the label reads LIKELY ROOT CAUSE on screen
#: and is lowercase in the file, because the capitals are `text-transform` in
#: the stylesheet. Matching what the screenshot showed found nothing on all
#: nine pages.
#:
#: `CARRIES_A_REPORT` tells a report apart from the **empty viewer** -
#: `static/index.html` is the same template with nothing in its island, and
#: serving that by accident is a real failure that answers 200 and looks
#: right. Checked rather than assumed: `headline` appears in both, twice in
#: the empty one, because the rendering code mentions it. `based_on` appears
#: once in a report and not at all in the empty viewer.
IS_THE_VIEWER = "likely root cause"
CARRIES_A_REPORT = "based_on"


def fetch(url):
    """(text, note). Raises on the last attempt rather than returning a lie."""
    last = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "faultone-live-check"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                if resp.status != 200:
                    raise IOError("HTTP %s" % resp.status)
                body = resp.read().decode("utf-8", "replace")
                note = "" if attempt == 1 else " (took %d attempts)" % attempt
                return body, note
        except (urllib.error.URLError, urllib.error.HTTPError, IOError) as e:
            last = e
    raise IOError("%s: %s" % (url, last))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=BASE, help="site to check (default: %s)" % BASE)
    args = ap.parse_args()
    base = args.base if args.base.endswith("/") else args.base + "/"

    problems = []
    print("checking %s" % base)

    try:
        index, note = fetch(base)
    except IOError as e:
        print("  the index is not being served: %s" % e)
        print("\nFAILED: the site the README links to is not answering")
        return 1
    print("  index%s" % (note or " ok"))

    if INDEX_MUST_HAVE not in index:
        problems.append("the index answered 200 but does not look like the index "
                        "- no %r in it" % INDEX_MUST_HAVE)

    # Taken from what is being served, not from dev/demos.py. If the two ever
    # disagree, the served copy is the one a reader gets, so it is the one
    # this has to read.
    pages = sorted(set(re.findall(r'href="(faultone-demo-[^"]+\.html)"', index)))
    if not pages:
        problems.append("the index links to no report pages at all")
    print("  index links to %d report page(s)" % len(pages))

    for page in pages:
        try:
            body, note = fetch(base + page)
        except IOError as e:
            problems.append("%s is linked from the index and not served (%s)" % (page, e))
            print("  %-42s MISSING" % page)
            continue
        if IS_THE_VIEWER not in body.lower():
            problems.append("%s answered 200 with something that is not the "
                            "viewer at all" % page)
            print("  %-42s NOT THE VIEWER" % page)
        elif CARRIES_A_REPORT not in body:
            problems.append("%s is the viewer with no report in it - an empty "
                            "viewer answers 200 and looks right" % page)
            print("  %-42s EMPTY" % page)
        else:
            print("  %-42s ok%s" % (page, note))

    if problems:
        print("\n" + "\n".join("  - " + p for p in problems))
        print("\nFAILED: %d problem(s) with the published site" % len(problems))
        return 1
    print("\nok: the index and all %d report pages are being served" % len(pages))
    return 0


if __name__ == "__main__":
    sys.exit(main())
