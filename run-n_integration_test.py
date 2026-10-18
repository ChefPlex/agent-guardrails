#!/usr/bin/env python3
"""Opt-in integration test: run-n.sh against REAL promptfoo, at no model cost.

run-n_test.py replaces npx with a fake, so it cannot notice if promptfoo changes the shape of its
results file. This runs the pinned promptfoo on integration/echo-suite, whose `echo` provider
returns the prompt instead of calling a model, and checks the numbers run-n.sh reports.

Needs Node (npx) and network access the first time, to fetch promptfoo. No API key, no spend.

    python3 run-n_integration_test.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITE = HERE / "integration" / "echo-suite"
sys.path.insert(0, str(HERE))
import run_n_summary as rs  # noqa: E402

fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


if not shutil.which("npx"):
    print("SKIPPED: npx not found. This test needs Node. Nothing was checked.")
    sys.exit(2)

version = subprocess.run(["bash", "-c", f'grep -o "PROMPTFOO_VERSION:-[0-9.]*" "{HERE}/run-n.sh"'],
                         capture_output=True, text=True, check=False).stdout.strip().split("-")[-1]
print(f"promptfoo@{version}, echo provider, no model call")

with tempfile.TemporaryDirectory() as d:
    out = Path(d) / "r.json"
    subprocess.run(["npx", "--yes", f"promptfoo@{version}", "eval", "--no-cache", "-o", str(out)],
                   cwd=SUITE, capture_output=True, text=True, check=False)
    parsed = rs.parse(out)
    check(parsed is not None, "the real results file parses (promptfoo's output shape still matches)")
    if parsed:
        check(parsed[:3] == (2, 3, 0), f"it reads 2 passes of 3 cases, 0 errors (got {parsed[:3]})")
        check(parsed[3] != "-", f"the real per-case rows give a suite fingerprint (got {parsed[3]})")
        if out.exists():
            rows = json.loads(out.read_text()).get("results", {}).get("results", [])
            check(len(rows) == 3, f"the per-case rows are where parse() looks for them ({len(rows)} rows)")

r = subprocess.run(["bash", str(HERE / "run-n.sh"), str(SUITE), "2"], capture_output=True, text=True, check=False)
check(r.returncode == 0, f"two identical runs agree: run-n.sh exits 0 (got {r.returncode})")
check("stable at 2 of 3" in r.stdout, "and reports 'stable at 2 of 3', a noise floor, not a pass")
check("COUNT only" not in r.stdout, "case identity was recorded, so the runs were compared by case, not only count")

print("\n" + ("ALL TESTS PASSED" if not fails else f"{len(fails)} FAILED"))
sys.exit(1 if fails else 0)
