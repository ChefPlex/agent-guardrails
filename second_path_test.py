#!/usr/bin/env python3
"""Tests for second_path.py. Run: python3 second_path_test.py

⛔ Every assertion must be able to FAIL. Each behaviour is exercised against BOTH an agreeing and a
disagreeing population, and the test asserts the two outcomes DIFFER — a `compare` that returned
`agree=True` unconditionally would pass the positive cases and be caught by the negative ones.
That is a defect recorded on 2026-09-02, when a test used the live repo as its own
fixture and four assertions flipped the moment the repo was fixed.
"""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("second_path", HERE / "second_path.py")
sp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sp)

FAILURES = []


def check(cond, label):
    print(("  ok   " if cond else "  FAIL ") + label)
    if not cond:
        FAILURES.append(label)


print("agreement")
r_same = sp.compare("x", [1, 2, 3], [3, 2, 1], name_a="A", name_b="B")
check(r_same.agree, "same members in a different order agree")
check(bool(r_same), "Result is truthy when the paths agree")
check(r_same.n_a == 3 and r_same.n_b == 3, "both counts are reported")
check("3 == 3" in r_same.detail, "the detail states the two counts")

print("\ndisagreement")
r_diff = sp.compare("x", [1, 2], [2, 3], name_a="A", name_b="B")
check(not r_diff.agree, "differing populations DISAGREE")
check(not bool(r_diff), "Result is falsy when the paths disagree")
check(r_same.agree != r_diff.agree, "compare discriminates — it is not a constant")
check(r_diff.only_a == [1], "only_a names what path A alone has")
check(r_diff.only_b == [3], "only_b names what path B alone has")
check("only in A" in r_diff.detail and "only in B" in r_diff.detail,
      "the detail names BOTH sides, so neither is assumed correct")

print("\nasymmetry — under-reporting is the failure this exists to catch")
r_under = sp.compare("x", [1], [1, 2, 3, 4], name_a="the narrow method", name_b="the wide method")
check(not r_under.agree, "a method that finds 1 of 4 DISAGREES")
check(r_under.only_b == [2, 3, 4], "and the three it missed are named")
check("1 vs 4" in r_under.detail, "the detail leads with the two counts")

print("\nexpected — adjudicated differences are excluded AND named")
r_ex = sp.compare("x", [1, 2], [2, 3], name_a="A", name_b="B", expected=[1, 3])
check(r_ex.agree, "an adjudicated difference no longer disagrees")
check("adjudicated" in r_ex.detail, "but the pass SAYS it excluded something")
check("1" in r_ex.detail and "3" in r_ex.detail, "and names what it excluded, so it stays visible")
check("==" not in r_ex.detail,
      "and does NOT claim the raw counts are equal — they need not be once expected is applied")
r_ex_unused = sp.compare("x", [1], [1], name_a="A", name_b="B", expected=[99])
check(r_ex_unused.agree and "==" in r_ex_unused.detail,
      "an expected entry that excluded NOTHING still reports a plain equality")
r_ex_partial = sp.compare("x", [1, 2], [2, 3], name_a="A", name_b="B", expected=[1])
check(not r_ex_partial.agree, "an unadjudicated difference still fails")
check(r_ex_partial.only_b == [3], "and only the un-excused member is reported")
check("excluded as adjudicated (1): 1" in r_ex_partial.detail,
      "and the adjudicated exclusion is still named when the paths disagree")

print("\nempty and edge populations")
check(sp.compare("x", [], []).agree, "two empty populations agree")
r_one_empty = sp.compare("x", [], [1], name_a="A", name_b="B")
check(not r_one_empty.agree, "empty vs non-empty DISAGREES — silence is not agreement")
check(r_one_empty.only_b == [1], "and the member the empty side missed is named")

print("\ntruncation — a large diff is summarised, never silently dropped")
r_big = sp.compare("x", [], list(range(20)), name_a="A", name_b="B", limit=3)
check("+17 more" in r_big.detail, "the detail says how many it did not list")
check(len(r_big.only_b) == 20, "but the Result still carries all 20 for a caller that wants them")

print("\nreport()")
rc_ok = sp.report([sp.compare("a", [1], [1]), sp.compare("b", [2], [2])])
check(rc_ok == 0, "report() exits 0 when every population agrees")
rc_bad = sp.report([sp.compare("a", [1], [1]), sp.compare("b", [2], [3])])
check(rc_bad == 1, "report() exits 1 when any population disagrees")
check(rc_ok != rc_bad, "report()'s exit code discriminates")
rc_empty = sp.report([])
check(rc_empty == 2, "report([]) is an instrument failure (2), never 'all zero agree' (0)")

print()
if FAILURES:
    print(f"🔴 {len(FAILURES)} FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("🟢 all second_path tests pass")
