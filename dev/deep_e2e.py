#!/usr/bin/env python3
# Copyright (c) 2026 Zachary Zamarripa. MIT licensed.
# SPDX-License-Identifier: MIT
"""End to end, every finding, every stage of the pipeline.

    python3 dev/deep_e2e.py

The suite asserts each finding fires. This asks the rest of it: does the
verdict name it, does the exit code match its severity, does the stage strip
agree, does it survive JSON and HTML, and is any of it order-dependent.

Kept out of the suite deliberately. It is slow - it renders every scenario to
HTML and re-runs the whole registry three times in subprocesses to check the
answers do not depend on hash ordering - and it is exploratory: it prints what
it found rather than asserting a fixed expectation, so it can surface something
nobody thought to write an assertion for. Run it before a release, not on every
save.
"""
import sys, json, re, subprocess, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.argv = ["x"]
import test_faultone as T
import faultone as nd

RANK = {r[0]: i for i, r in enumerate(nd.VERDICT_RULES)}
problems = []


def note(msg):
    problems.append(msg)
    print(f"    [!] {msg}")


print("=== 1. every finding: fires, ranks, exits and renders ===")
rows = []
for code in sorted(T.S):
    setup, kw = T.S[code]
    mod = T.fresh(); setup(mod)
    report = mod.diagnose(quick=False, **T.scenario_kwargs(kw))
    fired = [f for f in report["findings"] if f.get("code") == code]
    if not fired:
        note(f"{code}: did not fire in its own scenario")
        continue
    sev = fired[0]["severity"]
    findings = report["findings"]
    verdict = report["verdict"]

    # exit status must match the worst severity present
    expected_exit = (2 if any(f["severity"] == "critical" for f in findings)
                     else 1 if any(f["severity"] == "warning" for f in findings) else 0)
    actual_exit = nd.exit_status(report)
    if actual_exit != expected_exit:
        note(f"{code}: exit {actual_exit}, expected {expected_exit}")

    # a critical must move a stage; the verdict must never read clean when one fired
    states = [s["state"] for s in report["stages"]]
    if sev == "critical" and "fail" not in states:
        note(f"{code}: critical but no stage failed")
    if sev != "ok" and code not in nd.VERDICT_EXEMPT and verdict["severity"] == "ok":
        note(f"{code}: verdict reads clean while the finding stands")

    # the verdict should name this finding unless something outranks it here
    named = verdict.get("based_on", [None])[0]
    if named != code and code not in nd.VERDICT_EXEMPT:
        if code in RANK and named in RANK and RANK[named] > RANK[code]:
            note(f"{code}: outranked by {named}, which ranks LOWER - ordering inverted")
        rows.append((code, sev, named))

    # every verdict has to be actionable
    for field in ("headline", "owner", "next_step"):
        if not (verdict.get(field) or "").strip():
            note(f"{code}: verdict has an empty {field}")

    # JSON must be strict, and the page must not break out of its island
    blob = json.dumps(mod.json_safe(report))
    if "NaN" in blob or "Infinity" in blob:
        note(f"{code}: non-finite number in the JSON")
    html = mod.render_report_html(report)
    island = html.split('type="application/json"', 1)[1].split("</script>", 1)[0]
    if "</script>" in island:
        note(f"{code}: unescaped </script> in the island")
    if len(html) > 400_000:
        note(f"{code}: page is {len(html):,} bytes")
    # the text renderer must not raise on any of them
    mod.render_text_report(report, color=False, width=100)

print(f"  {len(T.S)} scenarios checked")
if rows:
    print(f"  {len(rows)} where a higher-ranked finding took the verdict (expected):")
    for code, sev, named in rows[:8]:
        print(f"    {code:<30} -> {named} (rank {RANK.get(named)} vs {RANK.get(code)})")

print("\n=== 2. compound faults: the cause wins, not the symptom ===")
COMPOUND = [
    ("physical beats the flow split",
     lambda m: (T.counters(m, d_rx_packets=1_000_000, d_rx_errors=5000, d_rx_crc_errors=5000),
                T.flows(m, T.ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                           T.ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000))),
     "link_errors_live"),
    ("backlog beats the flow split",
     lambda m: (T.kernel_drops(m, {"softnet_processed": 1_000_000, "softnet_dropped": 0},
                                  {"softnet_processed": 1_100_000, "softnet_dropped": 400}),
                T.flows(m, T.ss_flow("203.0.113.9", sent=5_000_000, retrans=300_000),
                           T.ss_flow("198.51.100.4", sent=4_000_000, retrans=250_000))),
     "nic_drops_live"),
    ("a corrupting cable beats a full backlog",
     lambda m: (T.counters(m, d_rx_packets=1_000_000, d_rx_errors=5000, d_rx_crc_errors=5000),
                T.kernel_drops(m, {"softnet_processed": 1_000_000, "softnet_dropped": 0},
                                  {"softnet_processed": 1_100_000, "softnet_dropped": 400})),
     "link_errors_live"),
    ("conntrack beats the loss it causes",
     lambda m: (T.kernel_drops(m, {"ct_count": 65_000, "ct_max": 65_536, "ct_insert_failed": 0},
                                  {"ct_count": 65_500, "ct_max": 65_536, "ct_insert_failed": 40}),
                setattr(m, "cmd_ping", lambda t, c=4, w=2: {"ok": True, "cmd": "ping", "stdout":
                    "10 packets transmitted, 7 received, 30% packet loss\n"
                    "rtt min/avg/max/mdev = 1.0/20.0/30.0/2.0 ms\n"})),
     "conntrack_drops_live"),
]
for label, setup, expected in COMPOUND:
    mod = T.fresh(); setup(mod)
    report = mod.diagnose("8.8.8.8", None, quick=False, baseline=None)
    got = report["verdict"]["based_on"][0]
    ok = got == expected
    print(f"  [{'ok' if ok else '!!'}] {label:<38} -> {got}")
    if not ok:
        note(f"compound '{label}': verdict named {got}, expected {expected}")

print("\n=== 3. the same input twice, and across hash seeds ===")
def snapshot(seed=None):
    env = dict(os.environ, PYTHONHASHSEED=str(seed)) if seed else dict(os.environ)
    script = (
        "import sys;sys.path.insert(0,%r);sys.argv=['x']\n"
        "import json,test_faultone as T\n"
        "out={}\n"
        "for code in sorted(T.S):\n"
        "    setup,kw=T.S[code]\n"
        "    m=T.fresh();setup(m)\n"
        "    r=m.diagnose(quick=False,**T.scenario_kwargs(kw))\n"
        "    out[code]=[f.get('code') for f in r['findings']]+[r['verdict']['headline']]\n"
        "print(json.dumps(out,sort_keys=True))\n" % ROOT)
    r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                       env=env, timeout=300)
    return r.stdout.strip()

runs = [snapshot(s) for s in (1, 2, 3)]
if len(set(runs)) == 1 and runs[0]:
    print("  identical across three hash seeds")
else:
    note(f"output varies between runs ({len(set(runs))} distinct results)")

print("\n=== 4. the flags that change what runs ===")
for label, kwargs in (("quick", {"quick": True}), ("full", {"quick": False}),
                      ("soak 4", {"soak": 4, "quick": False}),
                      ("inventory", {"inventory": True, "quick": False}),
                      ("ports", {"check_ports": ["22", "443"], "quick": False})):
    mod = T.fresh()
    try:
        rep = mod.diagnose("8.8.8.8", kwargs.pop("check_ports", None), **kwargs)
        stages = " ".join(f"{s['stage']}={s['state']}" for s in rep["stages"])
        print(f"  [ok] {label:<10} exit {nd.exit_status(rep)}  {stages}")
    except Exception as e:
        note(f"--{label} raised {type(e).__name__}: {e}")

print("\n" + "=" * 64)
print(f"{len(problems)} problems" if problems else "everything behaved as expected")
