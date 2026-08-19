#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Find tests that pass without asserting anything.

    python3 dev/vacuous.py             # check every test in the suite
    python3 dev/vacuous.py --self-test # check this file works

`dev/mutate.py` asks the expensive question - would this test notice if the
rule it covers broke - one hand-written mutation at a time. There are 73 of
those against 1,780 tests, so most of the suite has never been asked anything.

This asks the cheap question of all of them at once: when this test ran, did it
execute an assertion, and did that assertion have anything in it. A test that
executes none has no opinion. A test whose every assertion compares one empty
thing to another passes whether the code works or not, because nothing it
looked at was ever populated - which is what "assert if it fired" looks like
from the inside, and four of those shipped together in one batch while every
one of them passed.

Neither answer is a verdict. Asserting that a list is empty is how this suite
says a rule stayed quiet, and that is a real assertion about real behaviour.
What it cannot tell apart on its own is a scenario that produced nothing
*because the rule declined to fire* from one that produced nothing because the
fixture never arranged the situation. So the empty-only list is a list to read,
not a list to fix - and the zero-assertion list is neither, because a test that
asserts nothing at all is broken however you look at it.

The instrument has its own control. Two tests with known answers are planted
and this has to find both, because an uncontrolled measurement reporting a
clean tree is exactly the failure this file exists to catch.
"""
import io
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Which operands have to be empty before an assertion is looking at nothing.
#:
#: Both sides for a comparison - `assertEqual(found, [])` is vacuous only when
#: `found` is also empty. The container alone for a membership test, because
#: the member is a literal the test author typed and is never empty:
#: `assertNotIn("queued", "")` passes for any string in the language.
#:
#: Assertions with no operand worth inspecting - assertTrue on a flag,
#: assertRaises - are not listed and count as substantial on sight.
CHECKED = {
    "assertEqual": (0, 1), "assertNotEqual": (0, 1),
    "assertIn": (1,), "assertNotIn": (1,),
    "assertCountEqual": (0, 1), "assertListEqual": (0, 1),
    "assertDictEqual": (0, 1), "assertSetEqual": (0, 1),
    "assertLess": (0, 1), "assertGreater": (0, 1),
    "assertLessEqual": (0, 1), "assertGreaterEqual": (0, 1),
}


def is_empty(value):
    """Nothing to compare. None, and anything with a length of zero.

    Numbers are not empty at zero: `assertEqual(losses, 0)` is a real claim,
    and treating it as vacuous would bury the check in false positives on the
    one shape this suite uses most.
    """
    if value is None:
        return True
    try:
        return len(value) == 0
    except TypeError:
        return False


class Watcher(object):
    """Counts what each test actually asserted, by wrapping the assertions.

    Wrapped rather than parsed. The source says which assertions a test
    contains; only running it says which ones a test *reached* - and an
    assertion inside a loop that never runs is the case worth finding, which no
    amount of reading the file will show.
    """

    def __init__(self):
        self.seen = {}          # test id -> [substantial, total]
        self.current = None
        self._original = {}

    def install(self):
        for name, where in CHECKED.items():
            original = getattr(unittest.TestCase, name)
            self._original[name] = original
            setattr(unittest.TestCase, name, self._wrap(original, where))
        for name in ("assertTrue", "assertFalse", "assertIsNone",
                     "assertIsNotNone", "assertIs", "assertIsNot",
                     "assertRaises", "assertAlmostEqual", "assertRegex"):
            original = getattr(unittest.TestCase, name, None)
            if original is None:
                continue
            self._original[name] = original
            setattr(unittest.TestCase, name, self._wrap(original, None))

    def remove(self):
        for name, original in self._original.items():
            setattr(unittest.TestCase, name, original)

    def _wrap(self, original, where):
        watcher = self

        def wrapped(case, *args, **kwargs):
            row = watcher.seen.setdefault(watcher.current, [0, 0])
            row[1] += 1
            if where is None or len(args) <= max(where):
                row[0] += 1                      # nothing to inspect: counts
            elif not all(is_empty(args[i]) for i in where):
                row[0] += 1
            return original(case, *args, **kwargs)
        return wrapped


class Result(unittest.TextTestResult):
    """Tells the watcher which test is running. Nothing else."""

    watcher = None

    def startTest(self, test):
        # Seeded here, not in the wrapper. A test that never calls an assertion
        # never reaches the wrapper, so it had no row and did not appear in the
        # results at all - the instrument was blind to the exact thing it is
        # for, and said so only because the control below plants one.
        Result.watcher.current = test.id()
        Result.watcher.seen.setdefault(test.id(), [0, 0])
        super(Result, self).startTest(test)


def survey(module_names=("test_faultone",)):
    """(silent, empty_only, ran) for every test in the suite."""
    sys.path.insert(0, REPO)
    sys.argv = ["vacuous"]
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([loader.loadTestsFromName(n) for n in module_names])
    watcher = Watcher()
    Result.watcher = watcher
    watcher.install()
    try:
        runner = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0,
                                         resultclass=Result)
        outcome = runner.run(suite)
    finally:
        watcher.remove()
    silent, empty_only = [], []
    for test_id, (substantial, total) in sorted(watcher.seen.items()):
        if total == 0:
            silent.append(test_id)
        elif substantial == 0:
            empty_only.append(test_id)
    # A test that errored asserted nothing for a reason that is already being
    # reported, so it is not this file's finding to make. Nor is one that was
    # skipped: it asserted nothing because it did not run, which the suite says
    # out loud. Both were reported as silent by the first version of this, and
    # the second of them is how the standard-library guard - which skips below
    # Python 3.10 - turned up beside a test that really was empty.
    broken = {t.id() for t, _ in
              list(outcome.failures) + list(outcome.errors) + list(outcome.skipped)}
    return ([t for t in silent if t not in broken],
            [t for t in empty_only if t not in broken],
            outcome.testsRun)


#: A test can assert by not raising, and several here do: hand a parser hostile
#: bytes and the claim is that it comes back at all. That is a real assertion
#: with no assert statement, so it cannot be counted - but it can be required
#: to say so, which is the point. A permanent list of eleven legitimate entries
#: is a list people learn to scroll past, and then the twelfth arrives.
#:
#: The words are the ones this suite already uses for it. A new silent test
#: that says none of them is either broken or badly named, and both are worth
#: a line of output.
DECLARES_NO_RAISE = ("survives", "raises", "raised", "not_fatal", "junk",
                     "malformed", "hostile", "parses", "still_renders")


def declares_not_raising(test_id, source):
    """Does the test say, in its own name, that not raising is the assertion."""
    name = test_id.rsplit(".", 1)[-1]
    return any(word in name for word in DECLARES_NO_RAISE)


def short(test_id):
    return test_id.split(".", 1)[-1] if "." in test_id else test_id


def main():
    silent, empty_only, ran = survey()
    print("%d tests ran\n" % ran, flush=True)
    source = open(os.path.join(REPO, "test_faultone.py"), encoding="utf-8").read()
    declared = [t for t in silent if declares_not_raising(t, source)]
    undeclared = [t for t in silent if t not in declared]
    print("=== executed no assertion, and does not say it asserts by not "
          "raising ===", flush=True)
    if undeclared:
        for test_id in undeclared:
            print("  %s" % short(test_id), flush=True)
    else:
        print("  none", flush=True)
    print("\n  (%d more assert by not raising and are named for it)" % len(declared),
          flush=True)
    print("\n=== every assertion compared one empty thing to another ===",
          flush=True)
    print("  A list to read, not a list to fix: asserting that nothing fired "
          "is how\n  this suite says a rule stayed quiet. What it cannot show "
          "from here is\n  whether the fixture arranged the situation at all.",
          flush=True)
    for test_id in empty_only:
        print("  %s" % short(test_id), flush=True)
    if not empty_only:
        print("  none", flush=True)
    print("\n%d undeclared silent, %d empty-only, of %d"
          % (len(undeclared), len(empty_only), ran), flush=True)
    return 1 if undeclared else 0


def self_test():
    """Plant both failure modes and require this to find them.

    An uncontrolled instrument reporting a clean tree is the exact failure this
    file exists to catch, so it is not allowed to report anything about the
    suite until it has proved it can see a test that says nothing.
    """
    class Planted(unittest.TestCase):
        def test_says_nothing_at_all(self):
            found = [1, 2, 3]
            len(found)

        def test_asserts_only_on_things_that_are_empty(self):
            found = []
            self.assertEqual(found, [])
            self.assertNotIn("anything", found)

        def test_only_asserts_if_it_fired(self):
            found = []
            for item in found:                      # never runs
                self.assertEqual(item, "x")

        def test_is_a_real_test(self):
            self.assertEqual([1, 2], [1, 2])
            self.assertIn(1, [1, 2])

        def test_was_skipped(self):
            # Asserts nothing because it did not run, which the suite already
            # says. Naming it here would be noise on top of a fact.
            self.skipTest("on purpose")
            self.assertEqual([1], [2])

    module = sys.modules[__name__]
    module.Planted = Planted
    silent, empty_only, ran = survey((__name__,))
    ok = True
    for name, where, expect in (
            ("test_says_nothing_at_all", silent, True),
            ("test_only_asserts_if_it_fired", silent, True),
            ("test_asserts_only_on_things_that_are_empty", empty_only, True),
            ("test_is_a_real_test", silent + empty_only, False),
            ("test_was_skipped", silent + empty_only, False)):
        found = any(name in t for t in where)
        if found != expect:
            print("  FAIL %s: %s" % (name, "not found" if expect else "wrongly named"),
                  flush=True)
            ok = False
        else:
            print("  ok   %s" % name, flush=True)
    # The filter that decides which silent tests are reported is an instrument
    # too, and an unchecked one would quietly excuse everything.
    for name, expect in (("test_no_parser_raises_on_junk", True),
                         ("test_the_comparison_survives_a_foreign_shape", True),
                         ("test_says_nothing_at_all", False),
                         ("test_only_asserts_if_it_fired", False)):
        if declares_not_raising("X.%s" % name, "") != expect:
            print("  FAIL the not-raising filter is wrong about %s" % name, flush=True)
            ok = False
    if not ok or ran != 5:
        print("\nFAILED: the instrument cannot see what it is for", flush=True)
        return 1
    print("\nok: a silent test, a guarded one and an empty-only one are all "
          "found, and a real one is not", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test() if "--self-test" in sys.argv else main())
