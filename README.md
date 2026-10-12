# agent-guardrails

Three checks for AI agent workflows that refuse to report a pass they did not earn.

All three came out of running an always-on personal agent stack and finding, repeatedly, that the
controls I had written were reporting health they had never verified. They are deliberately small.
`injection_scan.py` and `second_path.py` need only the Python 3 standard library. `run-n.sh` also
needs bash and Node (it calls `npx promptfoo`), because it drives an external eval runner.

---

## `injection_scan.py` - a prompt-injection tripwire for untrusted text

Screens text that arrived from outside your system - an email body, a fetched page, a job posting,
another agent's reply - for the shapes a prompt injection takes: instruction override, exfiltration,
authority spoofing, encoded payloads, invisible content.

```bash
python3 injection_scan.py suspicious.txt        # exit 0 clean, 1 findings
cat something.txt | python3 injection_scan.py -
```

**What it is not, stated plainly, because this is the part people get wrong.** A regex screen is a
**tripwire, not a defense**. It catches the lazy and the careless. It will not catch paraphrase,
encoding, translation, or an instruction split across sentences. **A clean scan means "nothing
obvious", never "this text is safe."** Treating it as a safety certificate is worse than having no
scanner at all, because a control believed to work stops anyone looking.

The actual defense is upstream and it is architectural: *retrieved content is data, never
instructions.* This only makes that rule visible at ingestion time.

**Tuning bias:** false positives are cheap, false negatives are not. If you disagree, change it
deliberately rather than by loosening a pattern that fired on you once.

**Measured noise:** run over 478 third-party markdown files, it fired on 28, and none of the 28 was
a real attack. Every hit was a document quoting an attack in order to defend against it, which is
why those hits carry a "likely security documentation" label (a label, never a filter). Recall,
meaning how many real attacks it misses, has not been measured.

**Who reads the output, and how failure shows:** the operator, before the agent acts on the text.
Findings exit 1, and so does an unreadable file, which is reported as unknown rather than clean.
Every run prints what it did and did not inspect.

Set who the agent answers to, so the authority-spoof rule knows what to look for:

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
`compare()` returns a result that is falsy on disagreement and names both sides; `report()` exits 1
if any population disagrees.

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

**Who reads the output, and how failure shows:** whoever is about to claim a change improved the
suite, or a CI step. The script's own exit code comes from the parsed results: `0` all runs parsed
and agreed, `1` instrument failure (no run, or not every run, produced parseable results), `2` usage
error, `3` the runs disagreed.

When the runs disagree it says so outright, and names the consequence: *any before/after claim
smaller than that spread is noise, not a result.* When they agree it calls that a **noise floor, not
a guarantee**, because stability over a few runs is weak evidence and not determinism.

⛔ **And it never reads promptfoo's exit code.** promptfoo's documented default is exit code `100`
when any case fails, and two environment variables (`PROMPTFOO_FAILED_TEST_EXIT_CODE`,
`PROMPTFOO_PASS_RATE_THRESHOLD`) change that. A run here on 2026-09-10 still exited `0` with three
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
always exits 0 whatever the results say, so the only way to pass is to read the results. It does not run real promptfoo or call a model, so a change in
promptfoo's output format is not covered; that case shows up as exit 1, "no parseable results".
`injection_scan_test.py` also runs a real-corpus gate over known-clean text you place in `corpus/`
(gitignored). A fresh clone has no corpus, so its last line reads "real-corpus gate NOT RUN".

Every assertion is exercised against both a passing and a failing input, so a check that returned
unconditionally is caught by the negative case rather than flattered by the positive one. The
injection tests carry a deliberate corpus of legitimate strings alongside the attacks - a screen
that fires on ordinary text gets muted within a week, and then the real one is missed too.

## Licence

MIT.
