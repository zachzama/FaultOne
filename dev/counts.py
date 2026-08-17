#!/usr/bin/env python3
"""Bring the numbers in the docs back in line with the code.

    python3 dev/counts.py            # rewrite README.md and REFERENCE.md
    python3 dev/counts.py --check    # say what is stale, change nothing

Six numbers are quoted about this tool - findings, of which faults, ranked
causes, tests, and three file sizes - across two documents, and every one of
them moves when a finding is added. `TestDocsMatchReality` fails when they
drift, which is right and is only half the job: the other half was being done
by hand, on nearly every commit, and got it wrong often enough that a red suite
became the normal way to discover a release was one finding further along.

This is the mechanical half. The patterns are the ones those tests search for,
kept next to them on purpose: if a document phrases a number some other way,
this will not find it and the test will still fail, which is the correct
outcome - a number nothing can locate is one nobody can keep true.

What it will not do is invent a number. The sizes are measured from the file on
disk and the counts from the module, so running this on a broken tree writes
broken numbers into the docs. Run the suite first.
"""
import ast
import gzip
import io
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ("README.md", "REFERENCE.md")
# Read before argv is replaced. The tool reads sys.argv at import time to work
# out how it was invoked, so this file has to blank it - and blanking it first
# ate the --check flag, so two "say what is stale, change nothing" runs quietly
# rewrote both documents. dev/demos.py carries the same comment about the same
# mistake, which is twice now.
ARGS = list(sys.argv[1:])
sys.path.insert(0, REPO)
sys.argv = ["counts"]
os.environ.pop("SSH_CONNECTION", None)

import faultone as nd                                              # noqa: E402


def measured():
    """Every number the docs quote, taken from the thing it describes."""
    src = io.open(os.path.join(REPO, "faultone.py"), encoding="utf-8").read()
    raw = src.encode()
    codes = set(re.findall(r'"code": "(\w+)"', src))
    faults = {c for c in codes if c not in nd.VERDICT_EXEMPT}
    stripped = ast.unparse(ast.parse(src)).encode()
    # Counted by the loader rather than by finding "def test_" in the text.
    # The text version was off by one against what unittest reports, which is
    # the number the docs quote and the suite asserts - and a counter that
    # disagrees with the thing it counts is worse than no counter.
    import unittest
    tests = unittest.TestLoader().loadTestsFromName("test_faultone").countTestCases()
    return {
        "findings": len(codes),
        "faults": len(faults),
        "context": len(codes) - len(faults),
        "ranked": len(nd.VERDICT_RULES),
        "tests": tests,
        "disk_kb": round(len(raw) / 1024),
        "gz_kb": round(len(gzip.compress(raw, 9)) / 1024),
        "stripped_kb": round(len(gzip.compress(stripped, 9)) / 1024),
    }


#: (pattern, which measured number it is). The pattern captures the number and
#: nothing else, so a replacement can put the new one back without touching the
#: prose around it. `\s+` rather than a space in the wordy ones because the
#: documents are hard-wrapped, and a count once survived several versions purely
#: because the line broke between the number and the word after it.
PATTERNS = [
    (r"\*\*(\d+) distinct conclusions", "findings"),
    (r"(\d+)(?=\s+findings\b)", "findings"),
    (r"(\d+)(?=\s+are faults\b)", "faults"),
    (r"(?<=are faults[,;] )(\d+)(?=\s+are context\b)", "context"),
    (r"(?<=\| \*\*Findings\*\* \| \*\*)(\d+)", "findings"),
    (r"(?<=\| \*\*Ranked causes\*\* \| \*\*)(\d+)", "ranked"),
    (r"(\d+)(?=\s+tests\b)", "tests"),
    (r"(?<=is )(\d+)(?= KB of\b)", "disk_kb"),
    (r"(?<=wire at )(\d+)(?= KB\b)", "gz_kb"),
    (r"(\d+)(?= KB on the wire\b)", "stripped_kb"),
    (r"(?<=together it's )(\d+)(?= KB instead of )", "stripped_kb"),
    (r"(?<= KB instead of )(\d+)", "disk_kb"),
]

#: The same three sizes are pinned in the suite, which is what makes the README
#: numbers assertions rather than prose. Rewriting the documents alone leaves a
#: red suite, which is the thing this script exists to stop - so the pins move
#: with them. Nothing else in the test file is touched.
TEST_PINS = [
    (r'(?<="on disk": \(len\(raw\), )(\d+)', "disk_kb"),
    (r'(?<="compressed": \(len\(gzip\.compress\(raw, 9\)\), )(\d+)', "gz_kb"),
    (r'(?<="stripped and compressed": \(len\(gzip\.compress\(stripped, 9\)\), )(\d+)',
     "stripped_kb"),
]


def rewrite(text, want, patterns=None):
    """Put every number this knows how to find back to what it should be."""
    patterns = PATTERNS if patterns is None else patterns
    changed = []

    def swap(m, key):
        was = m.group(1)
        now = str(want[key])
        if was != now:
            changed.append((key, was, now))
        return m.group(0).replace(was, now, 1)

    for pattern, key in patterns:
        text = re.sub(pattern, (lambda k: lambda m: swap(m, k))(key), text)
    return text, changed


def main(argv=None):
    check = "--check" in (ARGS if argv is None else argv)
    want = measured()
    print("  ".join("%s=%s" % (k, v) for k, v in sorted(want.items())))
    stale = 0
    for name in DOCS + ("test_faultone.py",):
        path = os.path.join(REPO, name)
        before = io.open(path, encoding="utf-8").read()
        after, changed = rewrite(before, want,
                                 TEST_PINS if name.endswith(".py") else PATTERNS)
        if not changed:
            print("  %-14s already true" % name)
            continue
        stale += len(changed)
        for key, was, now in changed:
            print("  %-14s %-10s %s -> %s" % (name, key, was, now))
        if not check:
            io.open(path, "w", encoding="utf-8").write(after)
    if check and stale:
        print("\n%d number(s) are stale. Run without --check to fix them." % stale)
        return 1
    if not stale:
        print("\nnothing to do")
    elif check:
        print("\n%d number(s) are stale." % stale)
    else:
        print("\nrewrote %d number(s). Run the suite - some of these are also "
              "asserted in test_faultone.py and move together with it." % stale)
    return 0


def self_test():
    """Two properties this has already broken once each.

    Nothing in `dev/` is covered by the suite, which is usually fine - these
    are reporting harnesses. This one is not: it rewrites the pinned sizes
    inside test_faultone.py, so a bug here edits the thing that would otherwise
    catch it. A mutation confirmed there was no test standing behind it.

    The two checks are the two failures. `--check` wrote to both documents,
    because argv was blanked before the flag was read. And rewriting the
    documents without the pins left a red suite, which is the state this script
    exists to prevent.
    """
    import hashlib
    want = measured()

    def digest():
        return [hashlib.sha256(io.open(os.path.join(REPO, n), "rb").read()).hexdigest()
                for n in DOCS + ("test_faultone.py",)]

    # Something has to be stale before "did it write" means anything. The
    # first version compared digests against an already-correct tree, so a
    # --check that wrote identical content looked exactly like one that wrote
    # nothing - and it passed with the bug it was written for still in place.
    readme = os.path.join(REPO, "README.md")
    original = io.open(readme, encoding="utf-8").read()
    io.open(readme, "w", encoding="utf-8").write(
        original.replace("%d tests" % want["tests"], "%d tests" % (want["tests"] + 7), 1))
    try:
        before = digest()
        main(["--check"])
        if digest() != before:
            print("\nFAILED: --check wrote to a file")
            return 1
        if "%d tests" % (want["tests"] + 7) not in io.open(readme, encoding="utf-8").read():
            print("\nFAILED: --check repaired the number it was only meant to report")
            return 1
    finally:
        io.open(readme, "w", encoding="utf-8").write(original)
    main([])
    once = digest()
    main([])
    if digest() != once:
        print("\nFAILED: a second run changed something, so it does not settle")
        return 1
    print("\nok: --check writes nothing, and a rewrite settles in one pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test() if "--self-test" in ARGS else main())
