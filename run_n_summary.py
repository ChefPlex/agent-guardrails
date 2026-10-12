#!/usr/bin/env python3
"""The parsing and summary logic behind run-n.sh, kept here so it can be tested directly.

    python3 run_n_summary.py parse RESULTS.json      # prints "<passes> <total>" or "NA NA"
    python3 run_n_summary.py summarise P1 P2 ...     # prints the spread; exit code is the verdict

Exit codes for `summarise`:
    0  every run parsed and every run agreed (a noise floor, not a guarantee)
    1  instrument failure: no run parsed, or some runs did not parse
    3  the runs parsed and DISAGREED with each other
"""
import json
import statistics
import sys

OK, INSTRUMENT_FAILURE, DISAGREED = 0, 1, 3


def parse(path):
    """Return (passes, total) from a promptfoo results file, or None if it cannot be read.

    ⛔ This reads the RESULTS FILE. The runner's exit code is never consulted, because it
    varies with promptfoo's version and environment settings and does not separate a failed
    case from a broken runner.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    r = d.get("results", d) if isinstance(d, dict) else None
    if not isinstance(r, dict):
        return None
    stats = r.get("stats") or {}
    succ, fail = stats.get("successes"), stats.get("failures")
    if succ is None:
        rows = r.get("results")
        if not isinstance(rows, list):
            return None
        succ = sum(1 for x in rows if isinstance(x, dict) and x.get("success"))
        fail = len(rows) - succ
    return int(succ), int(succ) + int(fail or 0)


def summarise(raw):
    """Take one pass count per run (strings, "NA" for an unparsed run). Return (lines, exit_code)."""
    vals = [int(v) for v in raw if str(v).isdigit()]
    missing = len(raw) - len(vals)
    if not vals:
        return (["  ⚠️ NO PARSEABLE RESULTS: that is an instrument failure, not a clean sheet."],
                INSTRUMENT_FAILURE)
    lo, hi = min(vals), max(vals)
    mean = statistics.mean(vals)
    sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    lines = [f"  passes: mean {mean:.2f}  min {lo}  max {hi}  sd {sd:.2f}  over {len(vals)} run(s)"]
    if lo != hi:
        lines.append(f"  🔴 THE SUITE DISAGREED WITH ITSELF: {lo} to {hi} on identical inputs.")
        lines.append("     ⛔ Any before/after claim smaller than that spread is noise, not a result.")
        code = DISAGREED
    else:
        lines.append(f"  🟢 stable at {lo} across {len(vals)} run(s): a NOISE FLOOR, not a guarantee.")
        lines.append("     ⚠️ Stability over a few runs is weak evidence; it is not determinism.")
        code = OK
    if missing:
        lines.append(f"  ⚠️ {missing} of {len(raw)} run(s) produced NO PARSEABLE RESULTS. The spread "
                     "above covers only the runs that did; that is an instrument failure.")
        code = INSTRUMENT_FAILURE
    return lines, code


def main(argv):
    if len(argv) >= 3 and argv[1] == "parse":
        got = parse(argv[2])
        print("NA NA" if got is None else f"{got[0]} {got[1]}")
        return 0
    if len(argv) >= 2 and argv[1] == "summarise":
        lines, code = summarise(argv[2:])
        print("\n".join(lines))
        return code
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
