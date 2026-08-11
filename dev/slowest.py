#!/usr/bin/env python3
"""Run the suite and say where the time went.

    python3 dev/slowest.py           # the whole suite, then the slowest 20
    python3 dev/slowest.py 40        # ...the slowest 40

Exits with the suite's own status, so it is a gate and not just a report -
CI runs this instead of the plain command and gets the timings for free.

It exists because a slow suite is only ever fixed with a list. One test was
eighty-four per cent of the runtime here and nobody knew, because a suite that
takes a minute and a suite that takes twelve seconds both just look like
"waiting". Windows takes eight times longer than Linux for reasons no local
run can show, so the machine that is slow has to be the one that reports.
"""
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class Timed(unittest.TextTestResult):
    """Records every test's wall time, however it ended."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.durations = []

    def startTest(self, test):
        self._started = time.time()
        super().startTest(test)

    def stopTest(self, test):
        self.durations.append((time.time() - self._started, str(test)))
        super().stopTest(test)


def main():
    top = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    sys.argv = [sys.argv[0]]          # the suite reads argv on import
    import test_faultone

    loader = unittest.defaultTestLoader
    suite = loader.loadTestsFromModule(test_faultone)
    runner = unittest.TextTestRunner(resultclass=Timed, verbosity=1)
    started = time.time()
    result = runner.run(suite)
    total = time.time() - started

    rows = sorted(result.durations, reverse=True)[:top]
    width = max((len(name) for _d, name in rows), default=0)
    print("\n%-*s  %8s  %6s" % (width, "slowest %d" % len(rows), "seconds", "share"))
    for dur, name in rows:
        print("%-*s  %8.2f  %5.1f%%" % (width, name, dur, 100 * dur / total))
    print("\n%d tests in %.1fs; the %d above are %.0f%% of it"
          % (result.testsRun, total, len(rows),
             100 * sum(d for d, _n in rows) / total))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
