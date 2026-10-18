# agent-guardrails

Three checks for AI agent workflows that refuse to report a pass they did not earn.

All three came out of running an always-on personal agent stack and finding, repeatedly, that the
controls I had written were reporting health they had never verified. They are deliberately small.
`injection_scan.py` and `second_path.py` need only the Python 3 standard library. `run-n.sh` needs
bash, Node (it calls `npx promptfoo`, because it drives an external eval runner) and Python 3 (its
parsing lives in `run_n_summary.py`).

---

## `injection_scan.py` - a prompt-injection tripwire for untrusted text

Screens text that arrived from outside your system - an email body, a fetched page, a job posting,
another agent's reply - for the shapes a prompt injection takes: instruction override, exfiltration,
authority spoofing, instructions to decode a payload, and text hidden by styling or by a run of
three or more zero-width characters.

```bash
python3 injection_scan.py suspicious.txt        # exit 0 clean, 1 findings or unknown
cat something.txt | python3 injection_scan.py -
```

**What it is not, stated plainly, because this is the part people get wrong.** A regex screen is a
**tripwire, not a defense**. It catches the lazy and the careless. It will not catch paraphrase,
an encoded payload that arrives without an instruction to decode it, translation, or an instruction
split across sentences. It does not normalize Unicode, and it does not look for Unicode tag
characters, bidirectional controls, or a single zero-width character inside a word. **A clean scan means "nothing
obvious", never "this text is safe."** Treating it as a safety certificate is worse than having no
scanner at all, because a control believed to work stops anyone looking.

The actual defense is upstream and it is architectural: least-privilege tools, deterministic
authorization of each action outside the model, an egress allowlist, and a human who releases every
outbound send. The principle those controls enforce is *retrieved content is data, never
instructions.* Telling the model that is a request, not a control. This scanner only makes the
principle visible at ingestion time.

**Tuning bias:** false positives are cheap, false negatives are not. If you disagree, change it
deliberately rather than by loosening a pattern that fired on you once.

**Measured noise:** run over 478 third-party markdown files, it fired on 28, and none of the 28 was
a real attack. Every hit was a document quoting an attack in order to defend against it, which is
why those hits carry a "likely security documentation" label (a label, never a filter). Recall,
meaning how many real attacks it misses, has not been measured.

**Who reads the output, and how failure shows:** the operator, before the agent acts on the text.
Findings exit 1, and so does a missing or unreadable file, which is reported as unknown rather than
clean; the other files are still scanned. Every run prints what it did and did not inspect, except
with `--quiet`, which prints nothing and leaves only the exit code.

Set who the agent answers to, so the authority-spoof rule knows what to look for. The value is a
`|`-separated list of names, matched literally:

```bash
INJECTION_PRINCIPAL="alice|acme" python3 injection_scan.py suspicious.txt
```

## `second_path.py` - count the population twice, by differently shaped methods

A coverage check answers *"is everything here accounted for?"* using **one** method of deciding what
"everything" is. When that method is wrong the check does not fail - it reports a smaller
population, finds nothing missing inside it, and prints green.

**A check cannot notice the members it never enumerated.**

So: count twice, by methods that would fail differently, and assert the two agree. A disagreement is
the finding. This caught a security control about to be loosened on evidence from the wrong corpus.
The first method had counted a proxy population, not the population the control actually screens.
Counting the real one a second way showed the two were not the same set.

The same logic applies to agents checking agents. A differently shaped method brings failure-mode
diversity: it would still find the item if the first method's assumption were wrong. N agents that
share a model, a prompt shape and a sourcing method are closer to one sample drawn N times, so
their agreement is not verification. They can all inherit the same blind spot, and N identical
wrong answers read as corroboration.

**Who reads the output, and how failure shows:** the caller, usually a test or a scheduled sweep.
`compare()` returns a result that is falsy on disagreement and names both sides; `report()` returns
1 if any population disagrees and 2 if it was given nothing to compare, for the caller to use as
its exit code. An empty list is never reported as agreement: a check that compared nothing has not
passed.

## `run-n.sh` - report the spread, and never the exit code

An eval suite that calls a model is not deterministic. One run of mine scored **3/4** and an
immediate re-run, identical inputs, no code change, scored **4/4**.

**So a single green run is not evidence, and a single red one is not either.** Without a measured
noise floor, no change can honestly be called an improvement - a before/after of two single runs
cannot separate a real effect from sampling noise or a silent model update on the provider's side.

```bash
bash run-n.sh path/to/suite 5   # suite dir holds promptfooconfig.yaml; reports mean / min / max / sd
```

Requires bash, Python 3 and Node. The promptfoo version is pinned in the script so two runs a month
apart measure the suite, not a runner upgrade; override it deliberately with `PROMPTFOO_VERSION`.
The pin covers promptfoo itself. npx resolves promptfoo's own dependencies at install time from
their version ranges, so those are not locked.

**Who reads the output, and how failure shows:** whoever is about to claim a change improved the
suite, or a CI step. The script's own exit code comes from the parsed results, and each run's pass
count is read together with its total and its error count:

| Exit | Meaning |
|:---|:---|
| `0` | Every run parsed, ran the same non-zero number of cases with no errors, and the pass counts agreed. This is **agreement, not a pass**: 0 of 4 every time also exits `0`, and is printed in red. |
| `1` | Instrument failure: no run produced parseable results, not every run did, a run executed zero cases, the runs executed different numbers of cases, the runs executed **different cases** (each run's case identities are fingerprinted, so 3 of 4 on cases A-D and 3 of 4 on E-H is not "stable"), or a case errored. |
| `2` | Usage error, the suite directory was not found, or N is above the cap. Every run calls a model, so N is a spend: the default cap is 25, raised deliberately with `RUN_N_MAX`. |
| `3` | The runs ran the same cases and disagreed. |

A CI step that needs a pass rate should read the printed counts, not exit `0`.

When the runs disagree it says so outright, and names the consequence: *any before/after claim
smaller than that spread is noise, not a result.* When they agree it calls that a **noise floor, not
a guarantee**, because stability over a few runs is weak evidence and not determinism. It never
prints green beside zero passes.

⛔ **And it never reads promptfoo's exit code.** promptfoo's documented default is exit code `100`
when any case fails, and two environment variables (`PROMPTFOO_FAILED_TEST_EXIT_CODE`,
`PROMPTFOO_PASS_RATE_THRESHOLD`) change that
([promptfoo command-line docs](https://www.promptfoo.dev/docs/usage/command-line/), checked
2026-10-12). The results-file fields it reads (`stats.successes`, `stats.failures`, `stats.errors`)
are promptfoo's `EvaluateStats` type
([source](https://github.com/promptfoo/promptfoo/blob/main/src/types/index.ts), main branch,
checked 2026-10-12). A run here on 2026-09-10 still exited `0` with three
of four cases passing; the promptfoo version that day was not recorded. An exit code that depends
on version and environment, and that cannot tell a failed case from a runner that broke, is not a
verdict. So the script parses the results file instead, and sets its own exit code from that.
Anything else that runs that suite should do the same.

*(Written against promptfoo; the shape applies to any eval runner that reports results in a file.)*

---

## Running the tests

```bash
python3 injection_scan_test.py
python3 second_path_test.py
python3 run-n_test.py
```

`run-n_test.py` runs the real script end to end against a fake `npx` that writes fixture results and
always exits 0 whatever the results say, so the only way to pass is to read the results. It does
not run real promptfoo, so it cannot notice a change in promptfoo's output format.

That gap has its own opt-in test, which runs the pinned promptfoo for real at no model cost:

```bash
python3 run-n_integration_test.py   # needs Node; fetches promptfoo on first run; no API key, no spend
```

It runs `integration/echo-suite`, whose `echo` provider returns the prompt instead of calling a
model, with two cases that pass and one that fails by design. It checks that the real results file
parses to 2 of 3 with per-case fingerprints, and that `run-n.sh` reports two runs as stable at 2 of
3. Run it after changing the pinned `PROMPTFOO_VERSION`.
`injection_scan_test.py` also runs a real-corpus gate over known-clean text you place in
`corpus/clean/` (`corpus/` is gitignored). A fresh clone has no corpus, so its last line reads "real-corpus gate NOT RUN".

Every assertion is exercised against both a passing and a failing input, so a check that returned
unconditionally is caught by the negative case rather than flattered by the positive one. The
injection tests carry a deliberate corpus of legitimate strings alongside the attacks - a screen
that fires on ordinary text gets muted within a week, and then the real one is missed too.

## License

Copyright (c) 2026 Eric White. [MIT](LICENSE), code and documentation alike: use it in your own
tooling, commercial or not, with the notice kept.

---

**Part of the ChefPlex TPM portfolio** · Status: Active · [I need to… find the right document across all the repositories](https://github.com/ChefPlex/tpm-templates/blob/main/PORTFOLIO-GUIDE.md) · [All repositories](https://github.com/ChefPlex)
