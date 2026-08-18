#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""Hold every finding, and every random combination of them, to the same rules.

    python3 dev/audit.py            # every scenario, then 500 random combinations
    python3 dev/audit.py 2000       # more combinations
    python3 dev/audit.py --seed 7   # a different draw, reproducibly

deep_e2e.py walks each finding through the pipeline and checks four hand-written
compound cases. This asks a different question: do the *relationships* between
findings hold - the ones the report now draws on screen - and do they still hold
when several faults are present at once?

That last part matters because every scenario in the suite is single-fault by
construction. A fixture is written to make one thing go wrong. So the rules that
only exist between findings - exactly one cause, a consequence never also
unrelated, nothing explained by a fault facing the other way - are the least
exercised logic in the tool, and they are the logic the reader now sees.

Combinations are drawn from the real findings each scenario produces, so every
input is one the tool actually emits rather than one invented here.
"""
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.argv = ["audit"]

import faultone as nd                                        # noqa: E402
import test_faultone as T                                     # noqa: E402

FAILURES = []


def check(ok, what, detail=""):
    if not ok:
        FAILURES.append(f"{what}: {detail}")
    return ok


def invariants(verdict, findings, where):
    """The rules that only exist between findings, checked wherever they meet."""
    codes = [f.get("code") for f in findings]
    based = verdict.get("based_on") or []
    explains = set(verdict.get("explains") or [])
    unrelated = {u.get("code") for u in (verdict.get("unrelated") or [])}
    corroborating = set(based[1:])

    if based:
        check(based[0] in codes, f"{where}: the cause is not among the findings",
              f"{based[0]} not in {codes[:6]}")

    causes = [f for f in findings if f.get("relation") == "cause"]
    check(len(causes) <= 1, f"{where}: more than one finding marked as the cause",
          str([f["code"] for f in causes]))

    both = explains & unrelated
    check(not both, f"{where}: a finding is both explained and unrelated", str(sorted(both)))

    both = explains & corroborating
    check(not both, f"{where}: a finding is both evidence for the cause and caused by it",
          str(sorted(both)))

    check(based[0] not in explains if based else True,
          f"{where}: the cause explains itself", str(based[:1]))

    # Consequences run upward, with one case level with the cause: a transport
    # symptom from another family, which is the shape a fault produces at its
    # own layer rather than a second opinion agreeing with it. Loss past the
    # gateway and unusable calls are both layer 3 and the calls are what the
    # loss does. Beneath the cause there is no case at all.
    by_code = {f.get("code"): f for f in findings}
    if based:
        cause_layer = (by_code.get(based[0]) or {}).get("layer") or 0
        cause_family = nd._finding_family(based[0])
        for code in explains:
            layer = (by_code.get(code) or {}).get("layer") or 0
            detail = f"{based[0]} L{cause_layer} explains {code} L{layer}"
            if layer == cause_layer:
                check(code in nd.TRANSPORT_SYMPTOMS
                      and nd._finding_family(code) != cause_family,
                      f"{where}: a consequence level with its cause is neither a "
                      f"transport symptom nor from another family", detail)
                continue
            check(layer > cause_layer,
                  f"{where}: a consequence sits below its cause", detail)

    # Direction is absolute: a fault facing one way cannot explain one facing
    # the other, whatever the layers say.
    if based:
        side = nd.finding_side(based[0])
        for code in explains:
            check(nd._sides_can_agree(side, nd.finding_side(code)),
                  f"{where}: a cause explains a fault facing the other way",
                  f"{based[0]} ({side}) explains {code} ({nd.finding_side(code)})")

    for f in findings:
        marked = f.get("kind") == "hardware"
        should = f.get("code") in nd.HARDWARE_FINDINGS
        check(marked == should, f"{where}: hardware marking disagrees with the set",
              f"{f.get('code')} marked={marked} listed={should}")


def every_finding():
    print("=== 1. every finding, and everything the report says about it ===")
    seen = fired = 0
    corpus = {}
    for code in sorted(T.S):
        setup, kw = T.S[code]
        m = T.fresh()
        setup(m)
        try:
            rep = m.diagnose(quick=False, **T.scenario_kwargs(kw))
        except Exception as exc:                              # noqa: BLE001
            FAILURES.append(f"{code}: the run raised {type(exc).__name__}: {exc}")
            continue
        seen += 1
        findings = rep["findings"]
        if any(f.get("code") == code for f in findings):
            fired += 1
        else:
            FAILURES.append(f"{code}: its own scenario does not produce it")
        invariants(rep["verdict"], findings, code)

        # A critical verdict must move something on the strip, or the reader
        # sees an all-clear chain beside a critical answer.
        if rep["verdict"].get("severity") == "critical":
            moved = any(s["state"] in ("fail", "warn") for s in rep["stages"])
            allow = getattr(T.TestEveryFindingFires, "NOT_A_STAGE", set())
            base = (rep["verdict"].get("based_on") or [None])[0]
            check(moved or base in allow, f"{code}: critical verdict, nothing moved on the strip",
                  str([(s["stage"], s["state"]) for s in rep["stages"]]))

        # It has to survive both ways out of the box.
        try:
            nd.render_text_report(rep)
            page = nd.render_report_html(rep)
            check(nd.extract_embedded_report(page) is not None,
                  f"{code}: the page carries no readable report")
            compact = nd.compact_report(rep)
            check(compact["verdict"] == rep["verdict"],
                  f"{code}: the compact export changed the verdict")
        except Exception as exc:                              # noqa: BLE001
            FAILURES.append(f"{code}: rendering raised {type(exc).__name__}: {exc}")

        for f in findings:
            if f["severity"] != "ok":
                # Stripped, not copied whole. These already carry the relation
                # and kind their own single-fault report gave them, and every
                # one of them was the cause there - so reusing them intact made
                # every combination look like it had six causes. The harness's
                # bug, and a good demonstration of why the corpus has to be
                # inert: a finding is what was measured, not what some earlier
                # verdict concluded about it.
                clean = {k: v for k, v in f.items() if k not in ("relation", "kind")}
                corpus.setdefault(f["code"], clean)
    print(f"  {seen} scenarios ran, {fired} produced their own finding")
    print(f"  {len(corpus)} distinct real findings collected for the next pass")
    return corpus


def combinations(corpus, rounds, seed):
    print(f"\n=== 2. {rounds} random combinations of real findings (seed {seed}) ===")
    rng = random.Random(seed)
    pool = sorted(corpus)
    widest = 0
    for i in range(rounds):
        n = rng.randint(2, 6)
        picked = rng.sample(pool, min(n, len(pool)))
        findings = [dict(corpus[c]) for c in picked]
        for f in findings:
            f.pop("relation", None)
            f.pop("kind", None)
        widest = max(widest, len(findings))
        try:
            verdict = nd.build_verdict(findings)
        except Exception as exc:                              # noqa: BLE001
            FAILURES.append(f"combination {picked}: build_verdict raised "
                            f"{type(exc).__name__}: {exc}")
            continue
        for f in findings:
            rel = nd.finding_relation(f.get("code"), verdict)
            if rel:
                f["relation"] = rel
            if f.get("code") in nd.HARDWARE_FINDINGS:
                f["kind"] = "hardware"
        invariants(verdict, findings, f"combination #{i} {picked}")
    print(f"  up to {widest} simultaneous faults per draw")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    seed = 1
    if "--seed" in sys.argv:
        seed = int(sys.argv[sys.argv.index("--seed") + 1])
    rounds = int(args[0]) if args else 500

    corpus = every_finding()
    combinations(corpus, rounds, seed)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} problem(s):\n")
        for line in FAILURES[:40]:
            print(f"  {line}")
        if len(FAILURES) > 40:
            print(f"  ... and {len(FAILURES) - 40} more")
        return 1
    print("=" * 64)
    print("every finding and every combination held to the same rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
