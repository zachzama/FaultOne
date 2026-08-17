#!/usr/bin/env python3
"""Break a rule on purpose and see whether the suite objects.

    python3 dev/mutate.py mutations.json          # run a set
    python3 dev/mutate.py --self-test             # check this file works

A green test proves nothing until breaking the thing it tests makes it fail.
That is the standard here, and it was being applied by hand: a throwaway script
per change, written from memory each time, a dozen of them in a day. One of
those was wrong in a way that mattered - it copied four files instead of the
tree, so sixteen documentation tests failed for want of a README on every
mutant *and* on an unchanged control, which read as three separate rules being
well covered when nothing had been proved at all.

So the two things that went wrong are the two things this does not leave to
whoever is writing the mutation:

**The whole tree is copied.** Tests read the README, the reference, the viewer
and `dev/`. A partial copy fails for reasons that have nothing to do with the
mutation, and those failures look exactly like a catch.

**A control runs first, always.** A no-op edit that still fails the suite means
the harness is broken, and every result behind it is noise. It is not optional
and there is no flag to skip it, because the one time it would have been
skipped is the time it was needed.

Mutations are given as JSON so a set can be kept beside the work it belongs to:

    [
      {"label": "let the inputs corroborate again",
       "file": "faultone.py",
       "old": "and f.get(\\"code\\") not in derived_from\\n",
       "new": ""}
    ]

`file` defaults to faultone.py. An anchor that does not appear exactly once is
reported as a bad mutation rather than run, because a mutation that edits
nothing survives every time and reads as a coverage gap.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IGNORE = shutil.ignore_patterns("_branch_sweep_*", ".git", "__pycache__",
                                "*.pyc", "_mutate_*")
FAILED = re.compile(r"^(?:FAIL|ERROR): (\w+)", re.M)


def run_suite(tree):
    """The whole suite against a copy, returning the test names that failed."""
    res = subprocess.run([sys.executable, "-m", "unittest", "test_faultone", "-q"],
                         cwd=tree, capture_output=True, text=True,
                         # The suite refuses to run against an operator's own
                         # session; a mutation run is not one.
                         env=dict(os.environ, SSH_CONNECTION=""), timeout=1800)
    return sorted(set(FAILED.findall(res.stdout + res.stderr)))


def apply_one(tree, mutation, sources):
    """Write one mutation into the copy. Returns an error string, or None."""
    name = mutation.get("file", "faultone.py")
    src = sources.get(name)
    if src is None:
        return "no such file: %s" % name
    old, new = mutation["old"], mutation.get("new", "")
    seen = src.count(old)
    if seen != 1:
        # Reported rather than run. A mutation whose anchor matches nothing
        # edits nothing, survives, and reads as a hole in the tests.
        return "anchor matched %d times, not once" % seen
    with open(os.path.join(tree, name), "w", encoding="utf-8") as fh:
        fh.write(src.replace(old, new))
    return None


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[2].strip())
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        mutations = json.load(fh)
    sources = {}
    for m in mutations:
        name = m.get("file", "faultone.py")
        if name not in sources:
            with open(os.path.join(REPO, name), encoding="utf-8") as fh:
                sources[name] = fh.read()

    base = tempfile.mkdtemp()
    tree = os.path.join(base, "repo")
    shutil.copytree(REPO, tree, ignore=IGNORE)
    try:
        print("control: an unchanged tree, to prove a failure means something")
        noise = run_suite(tree)
        if noise:
            print("  the suite fails before anything is mutated, so every result "
                  "below would be noise:")
            for n in noise:
                print("    %s" % n)
            return 1
        print("  clean\n")

        survived, bad = [], []
        for m in mutations:
            label = m.get("label") or m["old"][:40]
            # Restored from the originals every time, so mutations cannot
            # accumulate into a tree that fails for a reason none of them names.
            for name, text in sources.items():
                with open(os.path.join(tree, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            problem = apply_one(tree, m, sources)
            if problem:
                bad.append((label, problem))
                print("  %-46s BAD MUTATION  %s" % (label[:46], problem))
                continue
            names = run_suite(tree)
            if names:
                print("  %-46s caught     %2d  %s"
                      % (label[:46], len(names), ", ".join(n[5:44] for n in names[:2])))
            else:
                survived.append(label)
                print("  %-46s SURVIVED" % label[:46])
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print("\n%d of %d mutation(s) survived%s"
          % (len(survived), len(mutations) - len(bad),
             ", %d could not be applied" % len(bad) if bad else ""))
    for label in survived:
        print("  %s" % label)
    if bad:
        print("\nthese edited nothing, so surviving says nothing about the tests:")
        for label, why in bad:
            print("  %-46s %s" % (label[:46], why))
    return 1 if survived or bad else 0


def self_test():
    """Prove the harness catches and reports, using rules that must hold.

    A harness for checking tests is the one place where "it ran and printed
    something reassuring" is worth least.
    """
    checks = [
        # A rule the suite certainly holds: the tool must not name a vendor.
        {"label": "self-test: a mutation the suite must catch",
         "old": "def build_verdict(findings, quick=False, raw=None):",
         "new": "def build_verdict(findings, quick=False, raw=None):\n    findings = []"},
        # And one that edits nothing, which must be reported rather than run.
        {"label": "self-test: an anchor that matches nothing",
         "old": "this string is not in faultone.py at all", "new": ""},
    ]
    path = os.path.join(tempfile.mkdtemp(), "self.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(checks, fh)
    print("running the harness against two mutations with known answers\n")
    code = main(["mutate.py", path])
    print("\nexpected: the first caught, the second reported as a bad mutation.")
    return 0 if code == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
