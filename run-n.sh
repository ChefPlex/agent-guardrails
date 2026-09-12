#!/usr/bin/env bash
# run-n.sh — run the promptfoo suite N times and report the SPREAD, not one number. (#278)
#
# 🔴 WHY THIS EXISTS. Measured in the stack this came out of: one run of the suite
# scored 3/4 and an IMMEDIATE re-run, identical inputs, no code change, scored 4/4. The suite is
# non-deterministic — it calls a model — so **a single green run is not evidence of anything**, and
# a single red one is not either.
#
# 🔑 WITHOUT A MEASURED NOISE FLOOR, NO CHANGE HERE CAN HONESTLY BE CALLED AN IMPROVEMENT. A
# before/after comparison of two single runs cannot tell a real effect from sampling noise or from
# a silent model update on the provider's side.
#
# ⛔ AND IT PARSES RESULTS, NEVER THE EXIT CODE (#313 ①). `npx promptfoo eval` exits 0 even when
# cases FAIL — confirmed 2026-09-10, 3 of 4 passing, exit 0. Anything that gates on `$?` here is
# reading a number that does not mean what it looks like.
#
#     bash evals/run-n.sh [N]        # default 5
#
set -uo pipefail
N="${1:-5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/promptfoo" || { echo "⛔ evals/promptfoo not found"; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "== promptfoo × $N — spread, not a single number (#278) =="
echo "⛔ A single run is not evidence. This suite calls a model and has been measured"
echo "   scoring 3/4 and 4/4 on identical inputs with no code change."
echo

PASSES=()
for i in $(seq 1 "$N"); do
    out="$TMP/run$i.json"
    npx --yes promptfoo@latest eval --no-cache -o "$out" >/dev/null 2>&1
    # 🔑 Read the RESULTS file. The exit code is deliberately ignored — see the header.
    read -r p t < <(python3 - "$out" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("NA NA"); raise SystemExit
r = d.get("results", d)
stats = (r.get("stats") or {}) if isinstance(r, dict) else {}
succ, fail = stats.get("successes"), stats.get("failures")
if succ is None:
    rows = r.get("results") or []
    succ = sum(1 for x in rows if x.get("success"))
    fail = len(rows) - succ
print(f"{succ} {int(succ or 0) + int(fail or 0)}")
PY
)
    PASSES+=("$p")
    printf "  run %-2s  %s / %s\n" "$i" "$p" "$t"
done

echo
python3 - "${PASSES[@]}" <<'PY'
import statistics, sys
vals = [int(v) for v in sys.argv[1:] if v.isdigit()]
if not vals:
    print("  ⚠️ NO PARSEABLE RESULTS — that is an instrument failure, not a clean sheet.")
    raise SystemExit(1)
lo, hi = min(vals), max(vals)
mean = statistics.mean(vals)
sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
print(f"  passes: mean {mean:.2f}  min {lo}  max {hi}  sd {sd:.2f}  over {len(vals)} run(s)")
if lo != hi:
    print(f"  🔴 THE SUITE DISAGREED WITH ITSELF: {lo} to {hi} on identical inputs.")
    print("     ⛔ Any before/after claim smaller than that spread is noise, not a result.")
else:
    print(f"  🟢 stable at {lo} across {len(vals)} run(s) — a NOISE FLOOR, not a guarantee.")
    print("     ⚠️ Stability over a few runs is weak evidence; it is not determinism.")
PY
echo
echo "  ⛔ Exit code is NOT a verdict here and was never read — promptfoo exits 0 on failures."
