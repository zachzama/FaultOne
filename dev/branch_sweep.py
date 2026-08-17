#!/usr/bin/env python3
"""Force every conditional in the viewer's JS, one at a time, and report which
ones no test notices.

A test that asserts a string appears in `VIEWER_TEMPLATE` passes against code
wired to a constant, because the dead branch still contains the string.
Counting those assertions was the first attempt at sizing that problem and it
measured the wrong thing: it counts how a test is written, not whether the
behaviour is covered. This measures the behaviour.

    python3 dev/branch_sweep.py false          # is the markup ever drawn?
    python3 dev/branch_sweep.py true           # is the fallback ever taken?
    python3 dev/branch_sweep.py true and       # only the && guards
    python3 dev/branch_sweep.py false ternary  # only the ?: conditions

Slow on purpose - one full suite run per site, so about an hour for all of
them. A thing to run when the viewer's branching changes, not part of the
suite.

How a condition gets forced
---------------------------
By inserting, not by replacing. Two earlier versions of this tried to find
where each condition *began* so it could be swapped for a literal: first with a
regex that required a bare name, which found 67 of the 88 conditions and missed
every comparison and every parenthesised one; then with a hand-written
tokeniser, which lost interpolations inside nested template literals. Both were
the same mistake - needing to know an expression's extent to force it.

Nothing needs to know that. `||` and `&&` both bind tighter than `?:`, so
appending to a condition forces it without touching where it starts:

    cond ? a : b        ->  cond || true ? a : b        always the then-side
    cond ? a : b        ->  cond && false ? a : b       always the else-side
    cond && markup      ->  cond && false && markup     never drawn

which needs only the operator's position, and that is one classification
question rather than a parsing one.

The one direction that is not free is forcing an `&&` guard *true*: making the
right side always evaluate means removing the left, and removing needs the
extent after all. Those sites are found by walking backwards and are only
accepted if the result still parses - see below.

Why every edit is checked
-------------------------
A syntax error fails every test, and a script that counts failures reads that
as the branch being covered. Without `node --check` a wrong edit reports a
clean sweep, which is the most expensive way for a tool like this to be wrong.
Anything that will not parse is reported as this script's bug, separately from
the results.
"""
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORCE = sys.argv[1] if len(sys.argv) > 1 else "false"
if FORCE not in ("true", "false"):
    raise SystemExit("usage: branch_sweep.py [true|false] [ternary|and]")
# Optional, so the two operators can be swept separately. Sweeping all of them
# is the right default and an hour is a long time to re-spend on sites that
# have not changed.
ONLY = sys.argv[2] if len(sys.argv) > 2 else None
if ONLY not in (None, "ternary", "and"):
    raise SystemExit("usage: branch_sweep.py [true|false] [ternary|and]")
# Named for the direction and the filter, so two sweeps can run at once instead
# of one deleting the other's tree half way through.
WORK = os.path.join(REPO, "dev", "_branch_sweep_%s_%s" % (FORCE, ONLY or "all"))
NODE = shutil.which("node")

sys.path.insert(0, REPO)
sys.argv = ["x"]
import faultone as nd  # noqa: E402

src = open(os.path.join(REPO, "faultone.py"), encoding="utf-8").read()
tpl = nd.VIEWER_TEMPLATE
tpl_at = src.index(tpl[:200])
BLOCK = re.compile(r"<script(?![^>]*application/json)[^>]*>(.*?)</script>", re.S)


def code_offsets(js):
    """The offsets that are code, and the floor of each one's expression.

    Three things share this file and only one of them is code. A quoted string
    is part of an expression and may contain anything. The text of a template
    literal is not code at all, and it is full of `?` and `&&` that belong to
    markup. And each `${...}` inside that text is code again, to any depth.

    """
    n = len(js)
    is_code = [False] * n
    # Each frame is ("tpl",) for template text or ("interp", brace_depth).
    stack = [("code", 0)]
    i, prev = 0, ""
    while i < n:
        top = stack[-1][0]
        c = js[i]
        if top == "tpl":
            if c == "\\":
                i += 2
                continue
            if c == "$" and js[i + 1:i + 2] == "{":
                stack.append(("interp", 0))
                i += 2
                continue
            if c == "`":
                stack.pop()
                i += 1
                continue
            i += 1
            continue
        # code, or an interpolation, which behaves the same way
        if c in "'\"":
            quote = c
            i += 1
            while i < n and js[i] != quote:
                i += 2 if js[i] == "\\" else 1
            i += 1
            prev = "'"
            continue
        if c == "`":
            stack.append(("tpl",))
            i += 1
            prev = "`"
            continue
        if c == "/" and js[i + 1:i + 2] == "/":
            while i < n and js[i] != "\n":
                i += 1
            continue
        if c == "/" and js[i + 1:i + 2] == "*":
            i = js.find("*/", i) + 2
            continue
        if c == "/" and prev in "(,=:[!&|?{};+-*%~^<>":
            i += 1
            while i < n and js[i] != "/":
                i += 2 if js[i] == "\\" else 1
            i += 1
            prev = "/"
            continue
        if c == "{" and stack[-1][0] == "interp":
            stack[-1] = ("interp", stack[-1][1] + 1)
        elif c == "}" and stack[-1][0] == "interp":
            if stack[-1][1] == 0:
                stack.pop()          # the interpolation closes here
                i += 1
                continue
            stack[-1] = ("interp", stack[-1][1] - 1)
        is_code[i] = True
        if not c.isspace():
            prev = c
        i += 1
    return is_code


def find_sites(js, is_code):
    """(offset, operator) for every conditional operator in code."""
    out = []
    for i in range(len(js) - 1):
        if not is_code[i]:
            continue
        if js[i] == "?" and js[i + 1] not in ".?" and js[i - 1:i] != "?":
            out.append((i, "?"))
        elif js[i:i + 2] == "&&" and js[i - 1:i] != "&":
            out.append((i, "&&"))
    return out


def edit_for(js, at, op, force):
    """The change that forces this operator, as (offset, remove, insert).

    Insertion wherever it works, which is everywhere except forcing an `&&`
    guard true. `||` and `&&` bind tighter than `?:`, so what is appended to a
    condition becomes part of it without needing to know where it began.
    """
    if op == "?":
        return (at, 0, " || true " if force == "true" else " && false ")
    if force == "false":
        return (at, 0, " && false ")
    return None                       # handled by the backwards walk


def left_operand_start(js, is_code, at):
    """Where the left side of an `&&` begins, for the one case that needs it.

    Only reached when forcing a guard true, where the left has to go rather
    than be added to. Wrong answers are caught by the parse check rather than
    trusted, which is why a walk this rough is acceptable here and was not
    acceptable as the only mechanism.
    """
    i = at
    while i > 0:
        c = js[i - 1]
        if c.isspace():
            i -= 1
            continue
        if not is_code[i - 1]:
            j = i - 1
            while j > 0 and not is_code[j - 1]:
                j -= 1
            if j and js[j - 1:j + 1] == "${":
                break
            i = j
            continue
        if c in ")]":
            depth, j = 0, i
            while j > 0:
                ch = js[j - 1]
                if is_code[j - 1] and ch in ")]":
                    depth += 1
                elif is_code[j - 1] and ch in "([":
                    depth -= 1
                    if not depth:
                        j -= 1
                        break
                j -= 1
            i = j
            continue
        if c.isalnum() or c in "_$.!~":
            i -= 1
            continue
        if c in "=<>+-*/%^":
            if c == ">" and js[i - 2:i] == "=>":
                break
            if c == "=" and js[i - 2:i - 1] not in ("=", "!", "<", ">") \
                    and js[i:i + 1] != "=":
                break
            i -= 1
            continue
        break
    while i < at and js[i].isspace():
        i += 1
    return i


js = BLOCK.search(tpl).group(1)
js_at = tpl.index(js)
is_code = code_offsets(js)

sites = []
for at, op in find_sites(js, is_code):
    if ONLY and ONLY != {"?": "ternary", "&&": "and"}[op]:
        continue
    edit = edit_for(js, at, op, FORCE)
    if edit is None:
        lo = left_operand_start(js, is_code, at)
        cond = js[lo:at].strip()
        if not cond:
            continue
        edit = (lo, at - lo, "true ")
    where = tpl[:at].count("\n") + 1
    shown = js[max(0, at - 34):at].split("\n")[-1].strip() or js[at:at + 20].strip()
    sites.append((at, op, edit, where, shown))

print("sites: %d  forcing: %s%s"
      % (len(sites), FORCE, "  (%s only)" % ONLY if ONLY else ""), flush=True)

# The whole tree, not just the two Python files. Sixteen documentation tests
# error for want of a README, and an error counts the same as a failure when
# you are grepping for either.
if os.path.isdir(WORK):
    shutil.rmtree(WORK)
os.makedirs(WORK)
for name in ("test_faultone.py", "README.md", "REFERENCE.md", "SECURITY.md"):
    if os.path.exists(os.path.join(REPO, name)):
        shutil.copy(os.path.join(REPO, name), WORK)
for name in ("dev", "docs", "static", ".github"):
    if os.path.isdir(os.path.join(REPO, name)):
        shutil.copytree(os.path.join(REPO, name), os.path.join(WORK, name),
                        # Every work dir, not the one name this used to have.
                        ignore=shutil.ignore_patterns("_branch_sweep_*"))


def still_parses(mutated):
    """Does the viewer's JavaScript still parse after the edit."""
    if not NODE:
        return True                    # cannot check; do not pretend to have
    block = BLOCK.search(mutated)
    if not block:
        return False
    path = os.path.join(WORK, "_check.js")
    open(path, "w", encoding="utf-8").write(block.group(1))
    return subprocess.run([NODE, "--check", path], capture_output=True).returncode == 0


survivors, broken = [], []
try:
    for at, op, (off, remove, insert), where, shown in sites:
        lo = tpl_at + js_at + off
        mutated = src[:lo] + insert + src[lo + remove:]
        if not still_parses(mutated):
            broken.append((where, shown))
            print("  BROKEN    tpl-line %-5d %-30s (this script's bug, not a result)"
                  % (where, shown[:30]), flush=True)
            continue
        open(os.path.join(WORK, "faultone.py"), "w", encoding="utf-8").write(mutated)
        res = subprocess.run(
            [sys.executable, "-m", "unittest", "test_faultone", "-q"],
            cwd=WORK, capture_output=True, text=True, timeout=900)
        caught = len(re.findall(r"^(?:FAIL|ERROR):", res.stdout + res.stderr, re.M))
        label = "%s %s" % (shown[-28:], op)
        if caught:
            print("  caught    tpl-line %-5d %-32s (%d)" % (where, label, caught),
                  flush=True)
        else:
            survivors.append((where, label))
            print("  SURVIVED  tpl-line %-5d %s" % (where, label), flush=True)
finally:
    shutil.rmtree(WORK, ignore_errors=True)

if broken:
    print("\n%d site(s) could not be forced without breaking the syntax. Those are "
          "bugs in this script, not findings about the tests:" % len(broken), flush=True)
    for where, shown in broken:
        print("  tpl-line %-5d %s" % (where, shown[:60]), flush=True)

print("\n%d of %d branches survived forcing %s%s:"
      % (len(survivors), len(sites) - len(broken), FORCE,
         " (%d not forced)" % len(broken) if broken else ""), flush=True)
for where, label in survivors:
    print("  tpl-line %-5d %s" % (where, label), flush=True)
