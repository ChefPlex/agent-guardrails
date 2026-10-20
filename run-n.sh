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
# ⛔ AND IT PARSES RESULTS, NEVER PROMPTFOO'S EXIT CODE. promptfoo documents exit 100 on any failed
# case, but PROMPTFOO_FAILED_TEST_EXIT_CODE and PROMPTFOO_PASS_RATE_THRESHOLD change it, and a run
# on 2026-09-10 (version not recorded) exited 0 with 3 of 4 passing. The code also cannot tell a
# failed case from a broken runner. Anything that gates on `$?` from promptfoo is reading a number
# that does not mean what it looks like.
# Exit codes and env vars: https://www.promptfoo.dev/docs/usage/command-line/ (checked 2026-10-12)
#
#     bash run-n.sh SUITE_DIR [N]        # SUITE_DIR holds promptfooconfig.yaml; N defaults to 5
#
# Requires Node (for npx) and Python 3. The promptfoo version is pinned so two runs a month apart
# measure the suite, not a runner upgrade. Override deliberately: PROMPTFOO_VERSION=x.y.z
#
# THIS SCRIPT'S OWN EXIT CODE (set from the parsed results, never from promptfoo's):
#     0  every run parsed, ran the same non-zero number of cases with no errors, and agreed.
#        Agreement, not a pass: 0 of 4 every time also exits 0, and is printed in red.
#     1  instrument failure: no run parsed, some runs did not, a run executed zero cases,
#        the runs executed different numbers of cases, or a case errored
#     2  usage error, SUITE_DIR not found, or N above RUN_N_MAX (default 25)
#     3  the runs disagreed with each other
#
# The pin covers promptfoo itself. npx resolves promptfoo's own dependencies at install time
# from their version ranges, so those are not locked by this script.
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
# Every run calls a model, so N is also a spend. A cap stops a typo (500 for 5) from becoming
# a large bill. Raise it deliberately: RUN_N_MAX=100 bash run-n.sh SUITE 60
RUN_N_MAX="${RUN_N_MAX:-25}"
# Checked as text first: (( )) would evaluate the value as arithmetic, so a malformed cap could
# run a command, or fail the comparison silently and skip the cap.
if [[ ! "$RUN_N_MAX" =~ ^[1-9][0-9]*$ ]]; then
    echo "⛔ RUN_N_MAX must be a positive integer, got: $RUN_N_MAX" >&2
    exit 2
fi
if (( N > RUN_N_MAX )); then
    echo "⛔ N=$N is above the cap of $RUN_N_MAX runs. Each run calls a model and costs money." >&2
    echo "   If you mean it: RUN_N_MAX=$N bash run-n.sh $SUITE $N" >&2
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
    # The total and the error count travel with the pass count: a pass count without the number
    # of cases it was out of cannot tell 0 of 0 from 4 of 4.
    # The fourth field fingerprints WHICH cases ran, so equal counts over different cases are caught.
    read -r p t e s < <(python3 "$HERE/run_n_summary.py" parse "$out")
    PASSES+=("$p/$t/$e/$s")
    printf "  run %-2s  %s / %s  (errors: %s)\n" "$i" "$p" "$t" "$e"
done

echo
python3 "$HERE/run_n_summary.py" summarise "${PASSES[@]}"
rc=$?
echo
echo "  ⛔ promptfoo's exit code was never read; it varies by version and settings. This script's exit"
echo "     code ($rc) comes from the parsed results: 0 agreed (not passed) · 1 instrument failure · 3 disagreed."
exit "$rc"
