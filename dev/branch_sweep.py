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

    python3 dev/branch_sweep.py false          # is the markup ever drawn?
    python3 dev/branch_sweep.py true           # is the fallback ever taken?
    python3 dev/branch_sweep.py true and       # only the && guards
    python3 dev/branch_sweep.py false ternary  # only the ?: conditions

Both `cond ? a : b` and `cond && markup` are swept, because both decide whether
a piece of the page exists. The second kind comes in two shapes and they mean
different things when forced, which is worth knowing when reading a survivor:

  a null-guard   `help && help.desc`     forcing true runs the right side
                                         against a value that may be absent, so
                                         a survivor means no test ever supplies
                                         the absent case
  a composition  `stalled && !arrived`   forcing either way is an ordinary
                                         branch, the same as a ternary

Two `&&` sites are not swept: their left operand is a parenthesised expression
rather than a name, and matching those needs a parser rather than a regex.

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
FORCE = sys.argv[1] if len(sys.argv) > 1 else "false"
# Optional, so the two operators can be swept separately. Sweeping all of them
# is the right default and forty minutes is a long time to re-spend on sites
# that have not changed.
ONLY = sys.argv[2] if len(sys.argv) > 2 else None
if ONLY not in (None, "ternary", "and"):
    raise SystemExit("usage: branch_sweep.py [true|false] [ternary|and]")
# Named for the direction, so the two can run at once without one deleting the
# other's tree half way through. They take half an hour each and waiting for
# the first before starting the second is half an hour nobody needs to spend.
WORK = os.path.join(REPO, "dev", "_branch_sweep_%s_%s" % (FORCE, ONLY or "all"))
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
NAME = r"[A-Za-z_][\w.\[\]$]*(?:\([^()]*\))?"
sites = []
for op, pattern in (("?", r"(%s)\s*\?\s" % NAME), ("&&", r"(%s)\s*&&\s" % NAME)):
    if ONLY and ONLY != {"?": "ternary", "&&": "and"}[op]:
        continue
    for m in re.finditer(pattern, tpl):
        if m.group(1) not in ("true", "false", "null", "undefined"):
            sites.append((m.start(1), m.end(1), m.group(1), op))
sites.sort()

print("sites: %d  forcing: %s%s"
      % (len(sites), FORCE, "  (%s only)" % ONLY if ONLY else ""), flush=True)

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
                        # Every work dir, not the one name this used to have. Naming the
                        # directory after the direction and leaving the pattern behind
                        # made copytree walk into the tree it was building, until the
                        # path was too long for the filesystem.
                        ignore=shutil.ignore_patterns("_branch_sweep_*"))

survivors = []
try:
    for start, end, cond, op in sites:
        lo, hi = tpl_at + start, tpl_at + end
        assert src[lo:hi] == cond, (src[lo:hi], cond)
        open(os.path.join(WORK, "faultone.py"), "w", encoding="utf-8").write(
            src[:lo] + FORCE + src[hi:])
        res = subprocess.run(
            [sys.executable, "-m", "unittest", "test_faultone", "-q"],
            cwd=WORK, capture_output=True, text=True, timeout=900)
        caught = len(re.findall(r"^(?:FAIL|ERROR):", res.stdout + res.stderr, re.M))
        line = tpl[:start].count("\n") + 1
        shown = "%s %s" % (cond, op)
        if caught:
            print("  caught    tpl-line %-5d %-30s (%d)" % (line, shown, caught),
                  flush=True)
        else:
            survivors.append((line, shown))
            print("  SURVIVED  tpl-line %-5d %s" % (line, shown), flush=True)
finally:
    shutil.rmtree(WORK, ignore_errors=True)

print("\n%d of %d branches survived forcing %s:" % (len(survivors), len(sites), FORCE),
      flush=True)
for line, cond in survivors:
    print("  tpl-line %-5d %s" % (line, cond), flush=True)
