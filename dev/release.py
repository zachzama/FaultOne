#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Cut a release: bump, test, commit, tag - and publish the GitHub Release.

    python3 dev/release.py 1.7.0 --notes-file notes.md            # local only
    python3 dev/release.py 1.7.0 --notes-file notes.md --push     # and ship it
    python3 dev/release.py 1.7.0 --notes-file notes.md --dry-run  # show the plan
    python3 dev/release.py --self-test                            # check the CI gate

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
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "zachzama/FaultOne"
TOOL = os.path.join(ROOT, "faultone.py")
REFERENCE = os.path.join(ROOT, "REFERENCE.md")
LOOK_BACK = 30      # runs of history to search for the commit being released


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


def what_ci_said(sha):
    """('ok'|'bad'|'unknown', sentence) for the run CI made on `sha`.

    The checks above this one all run here, on one machine, on one Python. CI
    runs four jobs the tool is meant to work on and this machine is none of
    them - so "it passed locally" is a statement about a Mac, and three
    releases were cut on it while every job was red. The suite passed here each
    time, which is what made it invisible.

    Unknown is its own answer and not a pass. A commit CI has never seen has
    never been checked on anything but this machine, which is the case a cut
    from unpushed work lands in.
    """
    try:
        out = subprocess.run(
            ["gh", "run", "list", "--limit", str(LOOK_BACK), "--json",
             "headSha,conclusion,status,workflowName"],
            cwd=ROOT, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return "unknown", f"could not ask GitHub ({e})"
    if out.returncode != 0:
        return "unknown", "could not ask GitHub: " + (out.stderr.strip() or "gh failed")
    runs = [r for r in json.loads(out.stdout or "[]") if r.get("headSha") == sha]
    if not runs:
        # LOOK_BACK is the window, so this means "not in recent history"
        # rather than "never ran". For a cut from the tip, which is the only
        # thing this is ever asked about, they are the same sentence.
        return "unknown", f"no CI run for {sha[:9]} in the last {LOOK_BACK} runs"
    pending = [r for r in runs if r.get("status") != "completed"]
    if pending:
        return "unknown", f"CI is still running on {sha[:9]}"
    bad = [r for r in runs if r.get("conclusion") != "success"]
    if bad:
        return "bad", "%s on %s: %s" % (
            ", ".join(sorted({r["workflowName"] for r in bad})), sha[:9],
            ", ".join(sorted({r["conclusion"] or "?" for r in bad})))
    return "ok", f"CI is green on {sha[:9]}"


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
    ap.add_argument("--no-ci-check", action="store_true",
                    help="cut without asking GitHub whether the commit being "
                         "released from is green. For working offline; say so "
                         "in the notes if you use it")
    args = ap.parse_args()

    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        sys.exit(f"'{args.version}' is not a three-part version")
    old = current_version()
    tag = f"v{args.version}"
    already_tagged = tag in run(["git", "tag", "--list", tag], capture=True).split()
    # Cut locally, then come back and ship it. That is what this script tells
    # you to do when it finishes without --push, and until now the advice could
    # not be followed: by then the bump has happened, so the version matches
    # and the guard below rejected the very command that was printed. The two
    # halves are separable on purpose - the point of the split is that pushing
    # is a decision taken later - so completing the second half has to work.
    finishing = args.version == old and already_tagged
    if args.version == old and not already_tagged:
        # Bumped by hand, or a half-finished cut that lost its tag. Cutting
        # again would commit nothing and tag whatever is at the tip.
        sys.exit(f"already at {old}, and {tag} does not exist - bump by hand or "
                 f"tag it yourself; this will not guess which you meant")
    if finishing and not args.push:
        sys.exit(f"{tag} is already cut. Re-run with --push to ship it, or "
                 f"pick a later version to cut a new one")

    dirty = run(["git", "status", "--porcelain"], capture=True).strip()
    if dirty and not args.dry_run:
        sys.exit(f"the working tree is not clean:\n{dirty}\n"
                 f"commit the work first - this cuts a release, it does not write one")

    # Asked before anything is bumped, so a red tree stops with the tree
    # untouched. The commit checked is the one being released *from*: a release
    # adds a version bump and a redrawn hero on top of it, and CI cannot have
    # seen a commit that does not exist yet.
    if args.no_ci_check:
        print("not asking GitHub about CI (--no-ci-check)")
    else:
        head = run(["git", "rev-parse", "HEAD"], capture=True).strip()
        state, said = what_ci_said(head)
        print(f"asking GitHub about CI\n  {said}")
        if state != "ok" and not args.dry_run:
            sys.exit(f"not cutting a release on this: {said}\n"
                     f"push and wait for it, fix it, or pass --no-ci-check if "
                     f"you are working offline and mean it")

    if finishing:
        print(f"{tag} is cut already - pushing and publishing it")
    else:
        print(f"{old} -> {args.version}")
        bump(args.version, old, dry=args.dry_run)
        # The hero image on the README carries the version in its banner, so a
        # bump makes the committed one stale and the suite says so - correctly,
        # and one step too late to be useful. Redrawing it here is the same
        # reason this file exists: the parts of a release that are easy to
        # forget belong in the thing that does the release.
        print("redrawing the README hero")
        if args.dry_run:
            print("  would run: python3 dev/hero.py")
        else:
            drawn = subprocess.run([sys.executable, os.path.join("dev", "hero.py")],
                                   cwd=ROOT, capture_output=True, text=True)
            if drawn.returncode != 0:
                bump(old, args.version)
                sys.exit("could not redraw the hero - the bump has been "
                         "reverted:\n" + (drawn.stderr or drawn.stdout))
            for line in drawn.stdout.splitlines():
                print("  " + line)

    # Before the commit, not after. A release that fails its own checks should
    # never reach a tag, and a tag is the one thing here that must not move.
    #
    # The suite is not all of them. `dev/audit.py` and `dev/deep_e2e.py` are a
    # CI job of their own and check rules no test does - the audit holds every
    # finding and five hundred combinations of them to the invariants that only
    # exist *between* findings - so they can go red without one test failing.
    # That is what happened: the audit was broken for three releases and each
    # of them was cut anyway, because this gate asked the suite and stopped.
    # They cost under two seconds together, which was never the reason.
    for what, cmd in (("the suite", [sys.executable, "test_faultone.py"]),
                      ("dev/deep_e2e.py", [sys.executable, "dev/deep_e2e.py"]),
                      ("dev/audit.py", [sys.executable, "dev/audit.py"]),
                      ("dev/vacuous.py", [sys.executable, "dev/vacuous.py"]),
                      ("dev/dialects.py", [sys.executable, "dev/dialects.py"]),
                      ("dev/dialects.py --self-test",
                       [sys.executable, "dev/dialects.py", "--self-test"]),
                      ("dev/counts.py --check",
                       [sys.executable, "dev/counts.py", "--check"])):
        print(f"running {what}")
        if args.dry_run:
            print(f"  would run: {' '.join(cmd[1:])}")
            continue
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            # Nothing to revert when the bump happened in an earlier run - the
            # commit and the tag are already made. Stopping short of the push
            # is the whole of what can still be withheld, and it is the part
            # that matters: a tag that never left this machine can be deleted.
            if not finishing:
                run(["git", "checkout", "--", "faultone.py", "REFERENCE.md"])
            said = (proc.stderr.strip() or proc.stdout.strip())[-3000:]
            sys.exit(f"{what} failed"
                     + ("" if finishing else " - the bump has been reverted")
                     + ":\n" + said)
        last = (proc.stderr.strip() or proc.stdout.strip()).splitlines()
        print(f"  {last[-1] if last else 'ok'}")

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
    if finishing:
        pass                      # committed and tagged by the run that cut it
    elif args.dry_run:
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


def self_test():
    """The CI gate, against runs that really happened.

    Nothing in `dev/` is covered by the suite, and this one decides whether a
    tag gets cut - so the check that would have stopped three bad releases has
    to be checked by something. It reads real history rather than a stub,
    because what it has to get right is GitHub's answer shape.

    b0a8b503 is the commit the whole gate exists for: pushed, red on all four
    jobs, released from anyway.
    """
    cases = [("HEAD", ("ok", "unknown")),         # green, or not yet pushed
             ("b0a8b5033", ("bad",)),
             ("0" * 40, ("unknown",))]            # a commit that does not exist
    bad = 0
    for ref, allowed in cases:
        sha = subprocess.run(["git", "rev-parse", ref], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip() or ref
        state, said = what_ci_said(sha)
        ok = state in allowed
        bad += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {ref:12} -> {state}: {said}")
    if bad:
        print("\nFAILED: the gate does not read CI the way it must")
        return 1
    print("\nok: green, red and never-run are three different answers")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test() if "--self-test" in sys.argv else main())
