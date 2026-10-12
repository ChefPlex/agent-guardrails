#!/usr/bin/env python3
"""Tests for run-n.sh and run_n_summary.py. Run: python3 run-n_test.py

⛔ These do NOT call a model. They run the REAL script end to end with a fake `npx` first on PATH:
the fake writes a fixture results file to wherever `-o` points and ALWAYS exits 0, whatever the
results say, so the script can only get the verdict right by reading the results. So every
assertion below is about what the script does with real input, not about which strings its source
contains.

What they pin:
  ① the exit code of promptfoo is not a verdict; the parsed results are
  ② a single run is not evidence; the SPREAD is the output
  ③ this script's own exit code carries the verdict: 0 agreed, 1 instrument failure, 3 disagreed

⚠️ NOT COVERED: real promptfoo. The results-file shapes below are the two this parser handles; if
a future promptfoo version changes its output format, these tests will still pass and the real run
will report NO PARSEABLE RESULTS (exit 1). That is the intended failure: loud, not silent.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SH = HERE / "run-n.sh"
sys.path.insert(0, str(HERE))
import run_n_summary as rs  # noqa: E402

fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def stats_shape(passes, total):
    return {"results": {"stats": {"successes": passes, "failures": total - passes}}}


def rows_shape(passes, total):
    return {"results": {"results": [{"success": i < passes} for i in range(total)]}}


FAKE_NPX = """#!/usr/bin/env python3
import os, sys, pathlib
q = pathlib.Path(os.environ["FAKE_QUEUE"])
with open(q / "argv.log", "a") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
out = sys.argv[sys.argv.index("-o") + 1]
pending = sorted(p for p in q.glob("run*.json"))
if pending:
    nxt = pending[0]
    if nxt.read_text() != "SKIP":
        pathlib.Path(out).write_text(nxt.read_text())
    nxt.unlink()
sys.exit(0)   # an exit code that says nothing about the results; the script must not read it
"""


def run_script(fixtures, n=None, suite=True):
    """Run run-n.sh with a fake npx. `fixtures` is a list of dicts, or "SKIP" for no output."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        bindir, queue, suite_dir = d / "bin", d / "queue", d / "suite"
        for p in (bindir, queue, suite_dir):
            p.mkdir()
        npx = bindir / "npx"
        npx.write_text(FAKE_NPX)
        npx.chmod(npx.stat().st_mode | stat.S_IXUSR)
        for i, fx in enumerate(fixtures):
            (queue / f"run{i:03d}.json").write_text(fx if fx == "SKIP" else json.dumps(fx))
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", FAKE_QUEUE=str(queue))
        args = ["bash", str(SH)]
        if suite:
            args.append(str(suite_dir))
        if n is not None:
            args.append(str(n))
        r = subprocess.run(args, capture_output=True, text=True, env=env, check=False)
        log = (queue / "argv.log").read_text() if (queue / "argv.log").exists() else ""
        return r.returncode, r.stdout + r.stderr, log


# ── parse(): the results file, both shapes, and garbage ──────────────────────────────────────
print("parse")
with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    (d / "a.json").write_text(json.dumps(stats_shape(3, 4)))
    (d / "b.json").write_text(json.dumps(rows_shape(2, 5)))
    (d / "c.json").write_text("not json")
    (d / "e.json").write_text(json.dumps({"results": "nope"}))
    check(rs.parse(d / "a.json") == (3, 4), "the stats shape parses to (passes, total)")
    check(rs.parse(d / "b.json") == (2, 5), "the per-row shape parses to (passes, total)")
    check(rs.parse(d / "c.json") is None, "invalid JSON is None, never zero passes")
    check(rs.parse(d / "missing.json") is None, "a missing file is None, never zero passes")
    check(rs.parse(d / "e.json") is None, "an unexpected shape is None, never zero passes")

# ── summarise(): the verdict is the exit code ────────────────────────────────────────────────
print("\nsummarise")
lines, code = rs.summarise(["3", "4", "4", "3", "4"])
text = "\n".join(lines)
check(code == rs.DISAGREED, "disagreeing runs return the DISAGREED code")
check("min 3" in text and "max 4" in text, "and report their true min and max")
check("mean 3.60" in text, "the mean is the mean of the runs, not of the last one")
check("DISAGREED WITH ITSELF" in text, "the spread is called out, not buried in the numbers")
lines, code = rs.summarise(["4", "4", "4"])
check(code == rs.OK and "sd 0.00" in "\n".join(lines), "agreeing runs return OK with zero spread")
check("NOISE FLOOR, not a guarantee" in "\n".join(lines), "and are labelled a noise floor")
lines, code = rs.summarise(["NA", "NA"])
check(code == rs.INSTRUMENT_FAILURE, "no parseable run is an INSTRUMENT FAILURE, never a pass")
lines, code = rs.summarise(["4", "NA", "4"])
check(code == rs.INSTRUMENT_FAILURE, "a partly unparsed set is an instrument failure too")
check("1 of 3" in "\n".join(lines), "and says how many runs it could not read")
check(len({rs.OK, rs.INSTRUMENT_FAILURE, rs.DISAGREED}) == 3, "the three verdicts are distinct")

# ── run-n.sh end to end, against a fake npx that always exits 0 ──────────────────────────────
print("\nrun-n.sh end to end")
check(subprocess.run(["bash", "-n", str(SH)], capture_output=True, check=False).returncode == 0,
      "run-n.sh is syntactically valid bash")

rc, out, log = run_script([stats_shape(4, 4)] * 3, n=3)
check(rc == 0, f"three agreeing runs exit 0 (got {rc})")
check("stable at 4 across 3 run(s)" in out, "and report the noise floor")
check(log.count("eval") == 3, "npx was called once per run")
check("promptfoo@0.123.1" in log and "@latest" not in log, "the promptfoo version is pinned")

rc, out, _ = run_script([stats_shape(3, 4), stats_shape(4, 4)], n=2)
check(rc == 3, f"🔴 3/4 then 4/4 exits 3 even though promptfoo exited 0 both times (got {rc})")
check("DISAGREED WITH ITSELF: 3 to 4" in out, "and names the spread")

rc, out, _ = run_script(["SKIP", "SKIP"], n=2)
check(rc == 1, f"no results file at all exits 1, never 0 (got {rc})")
check("NO PARSEABLE RESULTS" in out, "and says it is an instrument failure")

rc, out, _ = run_script([rows_shape(2, 2), "SKIP"], n=2)
check(rc == 1, f"one parsed run and one missing exits 1 (got {rc})")

rc, out, _ = run_script([], suite=False)
check(rc == 2 and "usage" in out, f"no suite argument is a usage error, exit 2 (got {rc})")
rc, out, _ = run_script([stats_shape(1, 1)], n="zero")
check(rc == 2, f"a non-numeric N is a usage error, exit 2 (got {rc})")
r = subprocess.run(["bash", str(SH), "/nonexistent/suite", "1"], capture_output=True, text=True,
                   check=False)
check(r.returncode == 2 and "not found" in r.stderr, "a missing suite directory exits 2")

print("\n" + ("ALL TESTS PASSED" if not fails else f"{len(fails)} FAILED:"))
for f in fails:
    print("  ✗ " + f)
sys.exit(1 if fails else 0)
