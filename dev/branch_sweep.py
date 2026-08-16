#!/usr/bin/env python3
"""Force every conditional in the viewer's JS, one at a time, and report which
ones no test notices.

A test that asserts a string appears in `VIEWER_TEMPLATE` passes against code
wired to a constant, because the dead branch still contains the string. Counting
those assertions was the first attempt at sizing that problem and it measured
the wrong thing: it counts how a test is written, not whether the behaviour is
covered. This measures the behaviour.

Each `cond ?` in the template is replaced with a literal, one site per run, and
the whole suite is run against the result. A site nothing complains about is a
branch no test exercises - which is the fact the count was a poor proxy for.

    python3 dev/branch_sweep.py false    # then-sides: is the markup ever drawn?
    python3 dev/branch_sweep.py true     # else-sides: is the fallback ever taken?

Both directions are needed and the second is not the lesser one. A fallback that
nothing reaches is how `setFavicon` ended up with two of them where deleting one
changed no test's answer.

Slow on purpose - one full suite run per site, so about half an hour. It is a
thing to run when the viewer's branching changes, not part of the suite.
"""
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(REPO, "dev", "_branch_sweep_work")
FORCE = sys.argv[1] if len(sys.argv) > 1 else "false"
if FORCE not in ("true", "false"):
    raise SystemExit("usage: branch_sweep.py [true|false]")

sys.path.insert(0, REPO)
sys.argv = ["x"]
import faultone as nd  # noqa: E402

src = open(os.path.join(REPO, "faultone.py"), encoding="utf-8").read()
tpl = nd.VIEWER_TEMPLATE
tpl_at = src.index(tpl[:200])

# Anchored on the offset inside the template so each site is mutated exactly
# once. Conditions that are already literals are skipped - forcing them proves
# nothing about a test.
sites = []
for m in re.finditer(r"([A-Za-z_][\w.\[\]$]*(?:\([^()]*\))?)\s*\?\s", tpl):
    if m.group(1) not in ("true", "false", "null", "undefined"):
        sites.append((m.start(1), m.end(1), m.group(1)))

print("sites: %d  forcing: %s" % (len(sites), FORCE), flush=True)

# The whole tree, not just the two Python files. Sixteen documentation tests
# error for want of a README, and an error counts the same as a failure when you
# are grepping for either - which once turned two catching tests into nineteen.
if os.path.isdir(WORK):
    shutil.rmtree(WORK)
os.makedirs(WORK)
for name in ("test_faultone.py", "README.md", "REFERENCE.md", "SECURITY.md"):
    shutil.copy(os.path.join(REPO, name), WORK)
for name in ("dev", "docs", "static", ".github"):
    if os.path.isdir(os.path.join(REPO, name)):
        shutil.copytree(os.path.join(REPO, name), os.path.join(WORK, name),
                        ignore=shutil.ignore_patterns("_branch_sweep_work"))

survivors = []
try:
    for start, end, cond in sites:
        lo, hi = tpl_at + start, tpl_at + end
        assert src[lo:hi] == cond, (src[lo:hi], cond)
        open(os.path.join(WORK, "faultone.py"), "w", encoding="utf-8").write(
            src[:lo] + FORCE + src[hi:])
        res = subprocess.run(
            [sys.executable, "-m", "unittest", "test_faultone", "-q"],
            cwd=WORK, capture_output=True, text=True, timeout=900)
        caught = len(re.findall(r"^(?:FAIL|ERROR):", res.stdout + res.stderr, re.M))
        line = tpl[:start].count("\n") + 1
        if caught:
            print("  caught    tpl-line %-5d %-28s (%d)" % (line, cond, caught),
                  flush=True)
        else:
            survivors.append((line, cond))
            print("  SURVIVED  tpl-line %-5d %s" % (line, cond), flush=True)
finally:
    shutil.rmtree(WORK, ignore_errors=True)

print("\n%d of %d branches survived forcing %s:" % (len(survivors), len(sites), FORCE),
      flush=True)
for line, cond in survivors:
    print("  tpl-line %-5d %s" % (line, cond), flush=True)
