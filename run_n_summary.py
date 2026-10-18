#!/usr/bin/env python3
"""The parsing and summary logic behind run-n.sh, kept here so it can be tested directly.

    python3 run_n_summary.py parse RESULTS.json      # prints "<passes> <total> <errors> <suite>" or "NA NA NA NA"
    python3 run_n_summary.py summarise P/T/E/S ...   # one "passes/total/errors/suite" per run; exit code is the verdict

`suite` is a fingerprint of WHICH cases ran (each case's description, vars, prompt and provider),
or "-" when the results file carries no per-case rows. Equal counts are not equal suites: 3 of 4
on cases A-D and 3 of 4 on cases E-H would otherwise read as a stable result.

Exit codes for `summarise`:
    0  every run parsed, ran the same non-zero number of cases with no errors, and the pass
       counts agreed. That is AGREEMENT, not a pass: 0 of 4 every time also exits 0, and says so
       in red. A noise floor, not a guarantee.
    1  instrument failure: no run parsed, some runs did not parse, a run executed zero cases,
       the runs executed different numbers of cases, or a case errored
    3  the runs parsed, ran the same cases, and DISAGREED with each other
"""
import hashlib
import json
import statistics
import sys

OK, INSTRUMENT_FAILURE, DISAGREED = 0, 1, 3


def suite_fingerprint(rows):
    """A short hash of WHICH cases ran, independent of their order and of whether they passed.

    Returns "-" when there are no per-case rows to fingerprint. That is "unknown", and summarise()
    says so rather than treating it as a match."""
    if not isinstance(rows, list) or not rows:
        return "-"
    ids = []
    for x in rows:
        if not isinstance(x, dict):
            continue
        tc = x.get("testCase") if isinstance(x.get("testCase"), dict) else {}
        prompt = x.get("prompt") if isinstance(x.get("prompt"), dict) else {}
        provider = x.get("provider")
        provider = provider.get("id") if isinstance(provider, dict) else provider
        ids.append(json.dumps({"d": tc.get("description"), "v": x.get("vars", tc.get("vars")),
                               "p": prompt.get("label") or prompt.get("raw"), "m": provider},
                              sort_keys=True, default=str))
    if not ids:
        return "-"
    return hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()[:12]


def parse(path):
    """Return (passes, total, errors, suite) from a promptfoo results file, or None if unreadable.

    ⛔ This reads the RESULTS FILE. The runner's exit code is never consulted, because it
    varies with promptfoo's version and environment settings and does not separate a failed
    case from a broken runner.

    `errors` is promptfoo's `stats.errors`: cases where the runner broke rather than the model
    failing an assertion. They count toward the total and never toward passes. The per-row shape
    carries no separate error count, so it reports 0 errors.
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
    rows = r.get("results")
    succ, fail, err = stats.get("successes"), stats.get("failures"), stats.get("errors")
    if succ is None:
        if not isinstance(rows, list):
            return None
        succ = sum(1 for x in rows if isinstance(x, dict) and x.get("success"))
        fail, err = len(rows) - succ, 0
    succ, fail, err = int(succ), int(fail or 0), int(err or 0)
    return succ, succ + fail + err, err, suite_fingerprint(rows)


def _run(token):
    """One run's "passes/total/errors[/suite]" token as (p, t, e, suite), or None if unparsed.

    A token without a suite field (the older three-part form) gets suite "-": unknown."""
    parts = str(token).split("/")
    if len(parts) not in (3, 4) or not all(p.isdigit() for p in parts[:3]):
        return None
    suite = parts[3] if len(parts) == 4 and parts[3] not in ("", "NA") else "-"
    return int(parts[0]), int(parts[1]), int(parts[2]), suite


def summarise(raw):
    """Take one "passes/total/errors" token per run ("NA/NA/NA" for an unparsed run).

    Return (lines, exit_code). A pass count means nothing without the total it was out of, so a
    token without a total is treated as unparsed.
    """
    runs = [r for r in (_run(t) for t in raw) if r is not None]
    missing = len(raw) - len(runs)
    if not runs:
        return (["  ⚠️ NO PARSEABLE RESULTS: that is an instrument failure, not a clean sheet."],
                INSTRUMENT_FAILURE)
    vals = [p for p, _, _, _ in runs]
    totals = sorted({t for _, t, _, _ in runs})
    errors = sum(e for _, _, e, _ in runs)
    suites = {s for _, _, _, s in runs}
    lo, hi = min(vals), max(vals)
    mean = statistics.mean(vals)
    sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    of = f"of {totals[0]} case(s)" if len(totals) == 1 else f"of {totals[0]} to {totals[-1]} cases"
    lines = [f"  passes: mean {mean:.2f}  min {lo}  max {hi}  sd {sd:.2f}  {of}  "
             f"over {len(runs)} run(s)"]

    problems = []
    if 0 in totals:
        problems.append("  ⚠️ A run executed ZERO cases. Nothing was tested; that is an instrument "
                        "failure, not a pass.")
    if len(totals) > 1:
        problems.append(f"  ⚠️ THE RUNS EXECUTED DIFFERENT NUMBERS OF CASES: {totals[0]} to "
                        f"{totals[-1]}. They did not run the same suite, so their pass counts "
                        "cannot be compared; that is an instrument failure.")
    if errors:
        problems.append(f"  ⚠️ {errors} case(s) ERRORED across the runs: the runner broke, not the "
                        "model. That is an instrument failure.")
    known = suites - {"-"}
    if len(known) > 1:
        problems.append(f"  ⚠️ THE RUNS EXECUTED DIFFERENT CASES ({len(known)} distinct suites), even "
                        "where the counts match. Their pass counts cannot be compared; that is an "
                        "instrument failure.")
    elif "-" in suites:
        lines.append("  ⚠️ Case identity was not recorded for every run, so the runs are compared "
                     "by COUNT only. Equal counts do not prove the same cases ran.")

    code = OK
    if lo != hi and len(totals) == 1:
        lines.append(f"  🔴 THE SUITE DISAGREED WITH ITSELF: {lo} to {hi} on identical inputs.")
        lines.append("     ⛔ Any before/after claim smaller than that spread is noise, not a result.")
        code = DISAGREED
    elif not problems and lo == 0:
        lines.append(f"  🔴 stable at 0 of {totals[0]} across {len(runs)} run(s): EVERY CASE FAILED "
                     "in every run. The runs agreed; nothing passed.")
        lines.append("     ⚠️ Exit 0 here means AGREEMENT, not a pass.")
    elif not problems:
        lines.append(f"  🟢 stable at {lo} of {totals[0]} across {len(runs)} run(s): a NOISE FLOOR, "
                     "not a guarantee.")
        lines.append("     ⚠️ Stability over a few runs is weak evidence; it is not determinism.")
    if problems:
        lines.extend(problems)
        code = INSTRUMENT_FAILURE
    if missing:
        lines.append(f"  ⚠️ {missing} of {len(raw)} run(s) produced NO PARSEABLE RESULTS. The spread "
                     "above covers only the runs that did; that is an instrument failure.")
        code = INSTRUMENT_FAILURE
    return lines, code


def main(argv):
    if len(argv) >= 3 and argv[1] == "parse":
        got = parse(argv[2])
        print("NA NA NA NA" if got is None else f"{got[0]} {got[1]} {got[2]} {got[3]}")
        return 0
    if len(argv) >= 2 and argv[1] == "summarise":
        lines, code = summarise(argv[2:])
        print("\n".join(lines))
        return code
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
