#!/usr/bin/env python3
"""Break a rule on purpose and see whether the suite objects.

    python3 dev/mutate.py dev/mutations           # every stored set
    python3 dev/mutate.py dev/mutations/both-sides.json   # one of them
    python3 dev/mutate.py --anchors               # do the stored sets still apply
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
nothing survives every time and reads as a coverage gap. Those are found up
front, without running anything, since a bad anchor is a string count.

Mutations run in parallel, one tree per worker. Each is a whole suite run of
its own and they have nothing to say to each other, so the only reason this was
serial is that it was written that way: thirteen mutations cost fourteen
sequential suite runs, about a quarter of an hour, and the same set on a
fourteen-core machine is closer to two minutes. The control still runs first
and alone - it is a gate on whether any of the rest means anything.
"""
import concurrent.futures
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import time

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


def does_not_import(tree):
    """Does the mutant still import. Returns the reason it does not, or None.

    The most dangerous way for this harness to be wrong. A mutation that breaks
    the syntax stops the suite from loading at all, so no line beginning FAIL:
    or ERROR: is ever printed - and zero failures reads as SURVIVED, which says
    "nothing tests this rule" about a rule that is perfectly well tested. It
    sends somebody to write tests that already exist.

    branch_sweep.py learned this and checks its edits with `node --check`. This
    did not, and reported two survivors that were both syntax errors.
    """
    res = subprocess.run([sys.executable, "-c", "import faultone"], cwd=tree,
                         capture_output=True, text=True,
                         env=dict(os.environ, SSH_CONNECTION=""), timeout=120)
    if res.returncode == 0:
        return None
    last = (res.stderr.strip().splitlines() or ["did not import"])[-1]
    return last[:70]


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


def workers_for(n):
    """How many suite runs to have in flight.

    Each one is a single-process, CPU-bound suite run in a tree of its own, and
    this process does nothing but wait on them - so the count is cores, less one
    so the machine stays usable while a long set runs.
    """
    cpus = os.cpu_count() or 2
    return max(1, min(n, cpus - 1))


def one_mutation(tree, mutation, sources):
    """Restore the tree, apply one mutation, and run. ('caught'|'survived'|'bad', detail).

    The restore is per run rather than per set because a worker's tree is
    reused: mutations must not accumulate into a tree that fails for a reason
    none of them names, which is the thing this harness exists to avoid.
    """
    for name, text in sources.items():
        with open(os.path.join(tree, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    problem = apply_one(tree, mutation, sources)
    if problem:
        return "bad", problem
    broken = does_not_import(tree)
    if broken:
        return "bad", broken
    names = run_suite(tree)
    return ("caught", names) if names else ("survived", None)


def in_parallel(trees, jobs, sources):
    """Run every (label, mutation) across the trees, yielding as each finishes.

    Yielded rather than collected so a long set still reports while it runs.
    A tree is checked out for the length of one mutation and handed back, so
    there are exactly as many trees as workers however many mutations there are.
    """
    free = queue.Queue()
    for tree in trees:
        free.put(tree)

    def work(item):
        label, mutation = item
        tree = free.get()
        try:
            return (label,) + one_mutation(tree, mutation, sources)
        finally:
            free.put(tree)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(trees)) as pool:
        futures = [pool.submit(work, item) for item in jobs]
        for future in concurrent.futures.as_completed(futures):
            yield future.result()


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if "--anchors" in argv:
        return check_anchors(argv)
    # Which tests caught each mutation, in full and untruncated. The printed
    # line names two of them and cuts them short, which is right for reading
    # and useless for the question this answers: given a test that only ever
    # asserts nothing fired, has any mutation ever made it fire? Cross-
    # referencing that against dev/vacuous.py is what separates a negative
    # this suite genuinely holds from one nothing has tested.
    catchers = None
    for arg in argv:
        if arg.startswith("--catchers="):
            catchers = arg.split("=", 1)[1]
    argv = [a for a in argv if not a.startswith("--catchers=")]
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[2].strip(), flush=True)
        return 2
    target = argv[1]
    if os.path.isdir(target):
        # A directory is every set in it, run as one. The sets live in
        # dev/mutations/ beside the rules they check, because writing them from
        # memory each time is how this harness came to be needed.
        mutations = []
        for name in sorted(os.listdir(target)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(target, name), encoding="utf-8") as fh:
                for m in json.load(fh):
                    m["label"] = "%s: %s" % (name[:-5], m.get("label", ""))
                    mutations.append(m)
    else:
        with open(target, encoding="utf-8") as fh:
            mutations = json.load(fh)
    sources = {}
    for m in mutations:
        name = m.get("file", "faultone.py")
        if name not in sources:
            with open(os.path.join(REPO, name), encoding="utf-8") as fh:
                sources[name] = fh.read()

    survived, bad, jobs, caught_by = [], [], [], {}
    # Anchors first, and without a tree. A bad anchor is a string count, and
    # finding it after a suite run costs a minute to learn the file moved.
    for m in mutations:
        label = m.get("label") or m["old"][:40]
        name = m.get("file", "faultone.py")
        seen = sources.get(name, "").count(m["old"])
        if name not in sources:
            bad.append((label, "no such file: %s" % name))
        elif seen != 1:
            bad.append((label, "anchor matched %d times, not once" % seen))
        else:
            jobs.append((label, m))
    for label, why in bad:
        print("  %-46s BAD MUTATION  %s" % (label[:46], why), flush=True)

    started = time.monotonic()
    base = tempfile.mkdtemp()
    workers = workers_for(len(jobs))
    try:
        control = os.path.join(base, "control")
        shutil.copytree(REPO, control, ignore=IGNORE)
        print("control: an unchanged tree, to prove a failure means something", flush=True)
        noise = run_suite(control)
        if noise:
            print("  the suite fails before anything is mutated, so every result "
                  "below would be noise:", flush=True)
            for n in noise:
                print("    %s" % n, flush=True)
            return 1
        print("  clean\n", flush=True)
        if not jobs:
            return 1

        # The control's tree is one of them - it is already a clean copy, and
        # every run restores the sources into whichever tree it is handed.
        trees = [control]
        for i in range(workers - 1):
            tree = os.path.join(base, "worker-%d" % i)
            shutil.copytree(REPO, tree, ignore=IGNORE)
            trees.append(tree)
        print("  %d mutation(s) across %d tree(s)\n" % (len(jobs), len(trees)), flush=True)

        for label, kind, detail in in_parallel(trees, jobs, sources):
            if kind == "bad":
                bad.append((label, detail))
                print("  %-46s BAD MUTATION  %s" % (label[:46], detail), flush=True)
            elif kind == "caught":
                caught_by[label] = sorted(detail)
                print("  %-46s caught     %2d  %s"
                      % (label[:46], len(detail),
                         ", ".join(n[5:44] for n in detail[:2])), flush=True)
            else:
                survived.append(label)
                print("  %-46s SURVIVED" % label[:46], flush=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if catchers:
        with open(catchers, "w", encoding="utf-8") as fh:
            json.dump(caught_by, fh, indent=1, sort_keys=True)
        print("\n  catching tests written to %s" % catchers, flush=True)
    print("\n  %.0fs" % (time.monotonic() - started), flush=True)

    print("\n%d of %d mutation(s) survived%s"
          % (len(survived), len(mutations) - len(bad),
             ", %d could not be applied" % len(bad) if bad else ""), flush=True)
    for label in survived:
        print("  %s" % label, flush=True)
    if bad:
        print("\nthese edited nothing, so surviving says nothing about the tests:", flush=True)
        for label, why in bad:
            print("  %-46s %s" % (label[:46], why), flush=True)
    return 1 if survived or bad else 0


def check_anchors(argv):
    """Do all the stored anchors still appear exactly once, without running.

    A set whose anchor has drifted reports every mutation in it as bad, which
    is correct and slow to find out - an hour of suite runs to be told the
    file moved. This asks in a second, and is the thing to run after touching
    anything the sets point at.
    """
    where = os.path.join(REPO, "dev", "mutations")
    sources, stale = {}, []
    for name in sorted(os.listdir(where)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(where, name), encoding="utf-8") as fh:
            for m in json.load(fh):
                f = m.get("file", "faultone.py")
                if f not in sources:
                    with open(os.path.join(REPO, f), encoding="utf-8") as src:
                        sources[f] = src.read()
                seen = sources[f].count(m["old"])
                if seen != 1:
                    stale.append((name[:-5], m.get("label", ""), seen))
    if stale:
        print("%d anchor(s) no longer match exactly once:" % len(stale), flush=True)
        for name, label, seen in stale:
            print("  %-18s %-46s matched %d" % (name, label[:46], seen), flush=True)
        return 1
    print("every anchor in dev/mutations still matches exactly once", flush=True)
    return 0


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
    print("running the harness against two mutations with known answers\n", flush=True)
    code = main(["mutate.py", path])
    print("\nexpected: the first caught, the second reported as a bad mutation.", flush=True)
    return 0 if code == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
