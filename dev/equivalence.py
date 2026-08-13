#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Prove a change is inert everywhere it was supposed to be inert.

    python3 dev/equivalence.py v1.5.0

Runs every registered scenario against the working tree and against the tool
as it was at some git ref, and diffs the answers - findings, headline, owner,
confidence, corroboration, unrelated, and every stage.

The point is the *silence*. Adding a direction to the ranking, or a panel, or a
new finding, should change nothing about the boxes those additions do not
describe. "All the tests still pass" does not show that: the tests assert what
each scenario should say, so a change that quietly alters a different scenario
in a way nobody wrote an assertion for slips through. This compares every
answer to itself.

Both runs use the *current* test file, so the scenarios are identical and only
the tool differs. That is what makes the comparison mean anything - and it also
means this only reaches back as far as the current fixtures still drive the old
tool, which in practice is a few versions.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Run inside each tree rather than imported, so the two tools never share an
# interpreter and one cannot leave state behind for the other.
SNAPSHOT = r'''
import sys, json
sys.path.insert(0, sys.argv[1]); sys.argv = ["x"]
import test_faultone as T
out = {}
for code in sorted(T.S):
    setup, kw = T.S[code]
    m = T.fresh(); setup(m)
    r = m.diagnose(quick=False, **T.scenario_kwargs(kw))
    v = r["verdict"]
    out[code] = {
        "findings": [f.get("code") for f in r["findings"]],
        "headline": v["headline"],
        "owner": v["owner"],
        "confidence": v["confidence"],
        "corroborated_by": sorted(v.get("corroborated_by") or []),
        "unrelated": sorted(u["code"] for u in (v.get("unrelated") or [])),
        "stages": {s["stage"]: s["state"] for s in r["stages"]},
        # The three boxes, which nothing here compared. They are a
        # user-facing answer to "where is it" and they can move without
        # a stage moving: the strip and the panel classify a finding by
        # different rules, so one can change while the other holds.
        "sides": {z["side"]: z["state"] for z in (r.get("sides") or [])},
    }
print(json.dumps(out, sort_keys=True))
'''


def snapshot(tool_dir, label):
    """Every scenario's answer, from the tool in `tool_dir`."""
    proc = subprocess.run([sys.executable, "-c", SNAPSHOT, tool_dir],
                          capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        sys.exit(f"{label} would not run:\n{proc.stderr.strip()[-2000:]}")
    return json.loads(proc.stdout)


def tool_at(ref):
    """The tool as it was at `ref`, paired with today's test file.

    Today's fixtures on purpose: if the scenarios moved too, the comparison
    would be between two different questions rather than two answers.
    """
    tmp = tempfile.mkdtemp(prefix="faultone-equiv-")
    old = subprocess.run(["git", "-C", ROOT, "show", f"{ref}:faultone.py"],
                         capture_output=True, text=True)
    if old.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"no faultone.py at {ref}: {old.stderr.strip()}")
    with open(os.path.join(tmp, "faultone.py"), "w") as fh:
        fh.write(old.stdout)
    shutil.copy(os.path.join(ROOT, "test_faultone.py"), tmp)
    return tmp


def main():
    ref = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
    print(f"comparing the working tree against {ref}\n")
    tmp = tool_at(ref)
    try:
        before = snapshot(tmp, ref)
        after = snapshot(ROOT, "the working tree")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    gone = sorted(set(before) - set(after))
    added = sorted(set(after) - set(before))
    shared = sorted(set(before) & set(after))
    differ = [k for k in shared if before[k] != after[k]]

    print(f"  {len(shared)} scenarios in both, {len(differ)} differ")
    if added:
        print(f"  {len(added)} new since {ref}: {', '.join(added)}")
    if gone:
        print(f"  {len(gone)} no longer present: {', '.join(gone)}")

    for code in differ:
        print(f"\n  {code}")
        for field in sorted(before[code]):
            if before[code][field] != after[code].get(field):
                print(f"    {field}:")
                print(f"      before  {before[code][field]}")
                print(f"      after   {after[code].get(field)}")

    print()
    if differ:
        print(f"{len(differ)} scenario(s) answer differently. Each one is either "
              f"the change you meant or one you did not.")
    else:
        print("every shared scenario answers identically.")
    return 1 if differ else 0


if __name__ == "__main__":
    raise SystemExit(main())
