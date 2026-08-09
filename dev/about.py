#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Check the GitHub About box against the copy of it kept in REFERENCE.md.

    python3 dev/about.py          # compare, exit 1 if they differ
    python3 dev/about.py --fix    # set the About box from REFERENCE.md

The About box lives on someone else's server, so the test suite cannot see it.
It sat quoting a finding count eighteen releases of findings out of date while
every number inside the repository stayed green - which is exactly the failure
mode the suite exists to prevent, happening in the one place it cannot look.

This is a dev harness rather than a test for that reason: it needs the network
and an authenticated `gh`, neither of which belongs in a suite that has to run
on a box with no internet. Run it when you tag.
"""
import json
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "zachzama/FaultOne"


def canonical():
    """The blockquote under "The repository description" in REFERENCE.md."""
    with open(os.path.join(ROOT, "REFERENCE.md")) as fh:
        text = fh.read()
    if "## The repository description" not in text:
        sys.exit("REFERENCE.md has no repository-description section")
    block = text.split("## The repository description", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.startswith("> "):
            lines.append(line[2:].strip())
        elif lines:
            break          # the blockquote has ended
    if not lines:
        sys.exit("the repository-description section has no blockquote in it")
    return " ".join(lines)


def live():
    proc = subprocess.run(["gh", "repo", "view", REPO, "--json", "description"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"could not read the About box: {proc.stderr.strip()}")
    return json.loads(proc.stdout).get("description") or ""


def main():
    want, have = canonical(), live()
    if want == have:
        print("the About box matches REFERENCE.md")
        return 0
    print("they differ.\n")
    print(f"  REFERENCE.md  {want}\n")
    print(f"  GitHub        {have}\n")
    if "--fix" not in sys.argv:
        print("run with --fix to set the About box from REFERENCE.md")
        return 1
    proc = subprocess.run(["gh", "repo", "edit", REPO, "--description", want],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"could not set the About box: {proc.stderr.strip()}")
    print("set the About box from REFERENCE.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
