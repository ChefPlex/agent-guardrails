# agent-guardrails

Three checks for AI agent workflows that refuse to report a pass they did not earn.

Both came out of running an always-on personal agent stack and finding, repeatedly, that the
controls I had written were reporting health they had never verified. They are deliberately small,
have no dependencies beyond the standard library, and run anywhere Python 3 runs.

---

## `injection_scan.py` — a prompt-injection tripwire for untrusted text

Screens text that arrived from outside your system — an email body, a fetched page, a job posting,
another agent's reply — for the shapes a prompt injection takes: instruction override, exfiltration,
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

Set who the agent answers to, so the authority-spoof rule knows what to look for:

```bash
INJECTION_PRINCIPAL="alice|acme" python3 injection_scan.py suspicious.txt
```

## `second_path.py` — count the population twice, by differently shaped methods

A coverage check answers *"is everything here accounted for?"* using **one** method of deciding what
"everything" is. When that method is wrong the check does not fail — it reports a smaller
population, finds nothing missing inside it, and prints green.

**A check cannot notice the members it never enumerated.**

So: count twice, by methods that would fail differently, and assert the two agree. A disagreement is
the finding. This caught a security control being loosened on evidence from the wrong corpus — one
method measured a 5.8% false-positive rate against a proxy population, the second path measured 0 of
7 against the real one, and the conclusion reversed.

## `run-n.sh` — report the spread, and never the exit code

An eval suite that calls a model is not deterministic. One run of mine scored **3/4** and an
immediate re-run, identical inputs, no code change, scored **4/4**.

**So a single green run is not evidence, and a single red one is not either.** Without a measured
noise floor, no change can honestly be called an improvement — a before/after of two single runs
cannot separate a real effect from sampling noise or a silent model update on the provider's side.

```bash
bash run-n.sh 5        # runs N times, reports mean / min / max / sd
```

When the runs disagree it says so outright, and names the consequence: *any before/after claim
smaller than that spread is noise, not a result.* When they agree it calls that a **noise floor, not
a guarantee**, because stability over a few runs is weak evidence and not determinism.

⛔ **And it never reads the exit code.** `npx promptfoo eval` **exits 0 even when cases fail** —
confirmed, three of four passing, exit 0. It parses the results file instead. Anything else that
runs that suite should do the same.

*(Written against promptfoo; the shape applies to any eval runner that reports results in a file.)*

---

## Running the tests

```bash
python3 injection_scan_test.py
python3 second_path_test.py
python3 run-n_test.py
```

Every assertion is exercised against both a passing and a failing input, so a check that returned
unconditionally is caught by the negative case rather than flattered by the positive one. The
injection tests carry a deliberate corpus of legitimate strings alongside the attacks — a screen
that fires on ordinary text gets muted within a week, and then the real one is missed too.

## Licence

MIT.
