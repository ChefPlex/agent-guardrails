#!/usr/bin/env bash
# run-n.sh: run a promptfoo suite N times and report the SPREAD, not one number.
#
# 🔴 WHY THIS EXISTS. Measured in the stack this came out of: one run of the suite
# scored 3/4 and an IMMEDIATE re-run, identical inputs, no code change, scored 4/4. The suite is
# non-deterministic (it calls a model), so **a single green run is not evidence of anything**, and
# a single red one is not either.
#
# 🔑 WITHOUT A MEASURED NOISE FLOOR, NO CHANGE HERE CAN HONESTLY BE CALLED AN IMPROVEMENT. A
# before/after comparison of two single runs cannot tell a real effect from sampling noise or from
# a silent model update on the provider's side.
#
# ⛔ AND IT PARSES RESULTS, NEVER PROMPTFOO'S EXIT CODE. `npx promptfoo eval` exits 0 even when
# cases FAIL, confirmed 2026-09-10, 3 of 4 passing, exit 0. Anything that gates on `$?` from
# promptfoo is reading a number that does not mean what it looks like.
#
#     bash run-n.sh SUITE_DIR [N]        # SUITE_DIR holds promptfooconfig.yaml; N defaults to 5
#
# Requires Node (for npx) and Python 3. The promptfoo version is pinned so two runs a month apart
# measure the suite, not a runner upgrade. Override deliberately: PROMPTFOO_VERSION=x.y.z
#
# THIS SCRIPT'S OWN EXIT CODE (set from the parsed results, never from promptfoo's):
#     0  every run parsed and every run agreed
#     1  instrument failure: no run parsed, or some runs did not
#     2  usage error, or SUITE_DIR not found
#     3  the runs disagreed with each other
#
set -uo pipefail
SUITE="${1:-}"
N="${2:-5}"
PROMPTFOO_VERSION="${PROMPTFOO_VERSION:-0.123.1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "$SUITE" ]]; then
    echo "usage: bash run-n.sh SUITE_DIR [N]" >&2
    exit 2
fi
if [[ ! "$N" =~ ^[1-9][0-9]*$ ]]; then
    echo "⛔ N must be a positive integer, got: $N" >&2
    exit 2
fi
cd "$SUITE" 2>/dev/null || { echo "⛔ suite directory not found: $SUITE" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "== promptfoo@$PROMPTFOO_VERSION × $N: spread, not a single number =="
echo "⛔ A single run is not evidence. This suite calls a model and has been measured"
echo "   scoring 3/4 and 4/4 on identical inputs with no code change."
echo

PASSES=()
for i in $(seq 1 "$N"); do
    out="$TMP/run$i.json"
    npx --yes "promptfoo@$PROMPTFOO_VERSION" eval --no-cache -o "$out" >/dev/null 2>&1
    # 🔑 Read the RESULTS file. promptfoo's exit code is deliberately ignored; see the header.
    read -r p t < <(python3 "$HERE/run_n_summary.py" parse "$out")
    PASSES+=("$p")
    printf "  run %-2s  %s / %s\n" "$i" "$p" "$t"
done

echo
python3 "$HERE/run_n_summary.py" summarise "${PASSES[@]}"
rc=$?
echo
echo "  ⛔ promptfoo's exit code was never read; it exits 0 on failures. This script's exit"
echo "     code ($rc) comes from the parsed results: 0 agreed · 1 instrument failure · 3 disagreed."
exit "$rc"
