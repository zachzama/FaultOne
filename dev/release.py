#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Cut a release: bump, test, commit, tag - and publish the GitHub Release.

    python3 dev/release.py 1.7.0 --notes-file notes.md            # local only
    python3 dev/release.py 1.7.0 --notes-file notes.md --push     # and ship it
    python3 dev/release.py 1.7.0 --notes-file notes.md --dry-run  # show the plan

Why this exists: `git push --follow-tags` creates a tag and nothing else. A
GitHub Release is a separate object built on top of one, and it is what drives
the "Latest" badge and notifies anyone watching. Nine tags shipped without one
before that was noticed, so the Releases page went on showing a version from
eight releases back while every tag was correct.

Nothing here pushes unless you pass --push, because pushing is the user's
decision and this file should not be able to make it by accident. When you do
pass it, the push and the Release happen together - which is the whole point,
since forgetting the second half is the failure this replaces.
"""
import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "zachzama/FaultOne"
TOOL = os.path.join(ROOT, "faultone.py")
REFERENCE = os.path.join(ROOT, "REFERENCE.md")


def run(cmd, dry=False, capture=False):
    printable = " ".join(cmd)
    if dry:
        print(f"  would run: {printable}")
        return ""
    proc = subprocess.run(cmd, cwd=ROOT, text=True,
                          capture_output=True if capture else False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-2000:]
        sys.exit(f"failed: {printable}\n{detail}")
    return proc.stdout if capture else ""


def current_version():
    m = re.search(r'^__version__ = "([^"]+)"', open(TOOL).read(), re.M)
    if not m:
        sys.exit("no __version__ in faultone.py")
    return m.group(1)


def bump(new, old, dry=False):
    """The version lives in two files. A guard fails if they disagree, so they
    move together or not at all."""
    tool = open(TOOL).read()
    if tool.count(f'__version__ = "{old}"') != 1:
        sys.exit(f"faultone.py does not carry exactly one __version__ of {old}")
    ref = open(REFERENCE).read()
    quoted = ref.count(f"FaultOne {old}")
    if dry:
        print(f"  would set __version__ to {new}, and {quoted} sample(s) in REFERENCE.md")
        return
    open(TOOL, "w").write(tool.replace(f'__version__ = "{old}"',
                                       f'__version__ = "{new}"'))
    open(REFERENCE, "w").write(ref.replace(f"FaultOne {old}", f"FaultOne {new}"))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="the new version, e.g. 1.7.0")
    ap.add_argument("--notes-file", help="markdown for the GitHub Release")
    ap.add_argument("--message", help="body of the release commit. Defaults to the "
                                      "first paragraph of --notes-file, because "
                                      "release notes are markdown written for a "
                                      "reader and a commit message is neither")
    ap.add_argument("--push", action="store_true",
                    help="push the branch and tag, then publish the Release")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and stop")
    args = ap.parse_args()

    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        sys.exit(f"'{args.version}' is not a three-part version")
    old = current_version()
    if args.version == old:
        sys.exit(f"already at {old}")

    dirty = run(["git", "status", "--porcelain"], capture=True).strip()
    if dirty and not args.dry_run:
        sys.exit(f"the working tree is not clean:\n{dirty}\n"
                 f"commit the work first - this cuts a release, it does not write one")

    print(f"{old} -> {args.version}")
    bump(args.version, old, dry=args.dry_run)

    # Before the commit, not after. A release that fails its own suite should
    # never reach a tag, and a tag is the one thing here that must not move.
    print("running the suite")
    if args.dry_run:
        print("  would run: python3 test_faultone.py")
    else:
        proc = subprocess.run([sys.executable, "test_faultone.py"], cwd=ROOT,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            run(["git", "checkout", "--", "faultone.py", "REFERENCE.md"])
            sys.exit("the suite failed - the bump has been reverted:\n"
                     + proc.stderr.strip()[-3000:])
        print(f"  {proc.stderr.strip().splitlines()[-1]}")

    notes = ""
    if args.notes_file:
        notes = open(args.notes_file).read()
    # The Release gets the markdown; the log gets prose. Rendering a page of
    # bullets and code fences into `git log` helps nobody, and the first
    # paragraph of any decent set of notes is already the summary.
    body = args.message
    if body is None:
        first = ""
        for para in notes.split("\n\n"):
            if para.strip() and not para.lstrip().startswith(("#", "```", "|")):
                first = " ".join(para.split())
                break
        body = re.sub(r"[*`]", "", first)
    message = f"FaultOne {args.version}\n\n{body}".rstrip() + "\n"
    if args.dry_run:
        print(f"  would commit and tag v{args.version} with:\n")
        for line in message.splitlines():
            print(f"      {line}")
    else:
        run(["git", "add", "-A"])
        run(["git", "commit", "-q", "-m", message])
        run(["git", "tag", "-a", f"v{args.version}", "-m", f"FaultOne {args.version}"])
        print(f"  committed and tagged v{args.version}")

    if not args.push:
        print(f"\nnot pushed. When you are ready:\n"
              f"  python3 dev/release.py {args.version} --push   # (re-run with --push)\n"
              f"or by hand:\n"
              f"  git push origin main --follow-tags\n"
              f"  gh release create v{args.version} --repo {REPO} "
              f"--title 'FaultOne {args.version}' --notes-file <file> --latest")
        return 0

    run(["git", "push", "origin", "main", "--follow-tags"], dry=args.dry_run)
    create = ["gh", "release", "create", f"v{args.version}", "--repo", REPO,
              "--title", f"FaultOne {args.version}", "--latest"]
    if args.notes_file:
        create += ["--notes-file", os.path.abspath(args.notes_file)]
    else:
        create += ["--notes", notes or f"FaultOne {args.version}"]
    run(create, dry=args.dry_run)
    about = [sys.executable, os.path.join(ROOT, "dev", "about.py"), "--fix"]
    if args.dry_run:
        print(f"  would run: {' '.join(about)}")
        return 0

    print(f"\npublished https://github.com/{REPO}/releases/tag/v{args.version}")
    # Set rather than compare. The finding count lives in REFERENCE.md, where
    # the suite pins it, and on GitHub, where nothing can - so it drifted on
    # three releases running and was caught each time by a check that only ever
    # reported it. There is no version of this where the two should disagree.
    #
    # Deliberately not fatal. The release is already published by this point;
    # a description that could not be set is worth saying loudly and is not
    # worth making a successful release look like a failed one.
    print("setting the About box from REFERENCE.md")
    if subprocess.run(about, cwd=ROOT).returncode != 0:
        print("\n  the About box could not be set - the release itself is fine.\n"
              "  Fix it with: python3 dev/about.py --fix", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
