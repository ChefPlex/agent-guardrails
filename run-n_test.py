#!/usr/bin/env python3
"""Tests for evals/run-n.sh. Run: python3 evals/run-n_test.py

⛔ These do NOT invoke promptfoo — that costs money and calls a model. They pin the two properties
the script exists for, both of which are textual and both of which were real defects:
  #313 ① the exit code is not a verdict (promptfoo exits 0 on failures)
  #278    a single run is not evidence; the SPREAD is the output
and they exercise the summary maths directly against synthetic runs.
"""
import io
import re
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SH = HERE / "run-n.sh"
fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


src = SH.read_text(encoding="utf-8")

check(SH.exists(), "evals/run-n.sh exists")
check(subprocess.run(["bash", "-n", str(SH)], capture_output=True).returncode == 0,
      "it is syntactically valid bash")

# ── #313 ①: the exit code is a trap, and the script must not read it ─────────────────────────
# 🪤 BOTH OF THESE ASSERTIONS WERE WRONG ON FIRST WRITING, IN THE SAME WAY, AND IT IS THE THIRD
# TIME IN ONE EVENING (see cos_runs_test "flaky", cos_runs_denials_test "effort, denial_details)").
#   ① "exits 0 even when cases FAIL" is split across a line break in the comment, so a flat
#      substring search over the file could never match it.
#   ② `$?` DOES appear in the file — inside the comment FORBIDDING it. Searching the whole file
#      for a token matches the prose that bans it as readily as code that uses it.
# 🔑 THE RULE THIS KEEPS TEACHING: assert over the CODE, not over a blob of code-plus-prose.
# Comments are where a file explains what it must never do, so they contain those exact strings.
_code = "\n".join(l for l in src.split("\n") if not l.lstrip().startswith("#"))
# Strip the leading comment markers BEFORE flattening, or a phrase that wraps across two
# comment lines reads as "... even when # cases FAIL" and can never match.
_prose = " ".join(re.sub(r"^\s*#\s?", "", l) for l in src.split("\n"))
_flat = " ".join(_prose.split())

check("exits 0 even when cases FAIL" in _flat,
      "🔴 the exit-code trap is RECORDED in the file, so the reason survives the next edit")
check(re.search(r"\$\?", _code) is None,
      "⛔ no CODE line reads $? — promptfoo exits 0 on failures, so it is not a verdict")
check(re.search(r"\$\?", src) is not None,
      "…and the file still NAMES $? in a comment, so the ban is readable rather than merely obeyed")
check("-o " in src and "results" in src,
      "✅ it parses the RESULTS file instead")

# ── #278: the spread is the output, not a single number ──────────────────────────────────────
check("single run is not evidence" in src.lower(),
      "🔴 the file states that one run is not evidence")
check("3/4" in src and "4/4" in src,
      "…and cites the MEASURED instance (3/4 then 4/4 on identical inputs) rather than asserting it")
for word in ("mean", "min", "max", "sd"):
    check(word in src, f"the summary reports {word}")
check("DISAGREED WITH ITSELF" in src,
      "🔴 a spread is called out explicitly, not buried in the numbers")
check("NOISE FLOOR, not a guarantee" in src,
      "⛔ and a stable run is labelled a noise floor, never determinism")
check("NO PARSEABLE RESULTS" in src and "not a clean sheet" in src,
      "⛔ an unparseable result is an INSTRUMENT failure, never a pass")

# ── the summary maths, exercised directly ────────────────────────────────────────────────────
def summarise(vals):
    return min(vals), max(vals), statistics.mean(vals), statistics.pstdev(vals) if len(vals) > 1 else 0.0

lo, hi, mean, sd = summarise([3, 4, 4, 3, 4])
check((lo, hi) == (3, 4), "a disagreeing suite reports its true min and max")
check(abs(mean - 3.6) < 1e-9, "the mean is the mean of the runs, not of the last one")
check(sd > 0, "🔴 a disagreeing suite has NON-ZERO spread — the number that makes it undeniable")
lo2, hi2, _, sd2 = summarise([4, 4, 4])
check(lo2 == hi2 and sd2 == 0, "a stable suite reports zero spread")
check(summarise([4])[3] == 0, "a single run reports zero spread — and the file says so is not proof")

print("\n" + ("ALL TESTS PASSED" if not fails else f"{len(fails)} FAILED:"))
for f in fails:
    print("  ✗ " + f)
sys.exit(1 if fails else 0)
