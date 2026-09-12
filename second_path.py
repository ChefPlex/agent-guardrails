#!/usr/bin/env python3
"""Count the population twice, by DIFFERENTLY SHAPED methods, and assert the two agree.

Improvement #137. Written 2026-09-02.

WHY THIS EXISTS
---------------
A coverage check answers "is everything here accounted for?" — and it answers using ONE method of
deciding what "everything" is. When that method is wrong, the check does not fail. It reports a
smaller population, finds nothing missing inside it, and prints green. **A check cannot notice the
members it never enumerated.**

MEASURED FIVE TIMES, and only one of the five was caught by a check rather than by a human looking:
  * `injection_scan.py` measured 5.8% false positives against `reference/` as a proxy corpus and
    **0 of 7** against the real `/pulse` output. The second path reversed the conclusion and
    stopped a security control being loosened on evidence from the wrong population.
  * `handoff-check.py`'s path scan counted **2** paths in a document naming **11** — its regex
    required a `/`, so every bare filename was invisible. It reported "all 2 exist" and passed.
  * That same file's improvement-id regex capped at four digits, so a five-digit id enumerated to
    NOTHING and an id absent from the backlog reported OK.
  * The launchd job count: `automation/launchd/*.plist` said **12** while `schedule.sh` and
    `launchctl` both said **15**. Four documents restated the wrong one for two weeks — including
    the restore doc, where verifying a rebuild against it declares success at 10 of 15.
  * The skills count: prose said **46**, the directory said **38** — in `CLAUDE.md` and in a
    résumé that goes to employers.

Every one is a single-path enumeration that UNDER-reported, and every one would have been caught
immediately by counting again a different way.

⛔ THE SECOND PATH MUST BE DIFFERENTLY SHAPED. A checksum over the same query is not a second path:
it re-derives the same blind spot and returns green with more ceremony. The test to apply is
*would this method still find the item if the first method's assumption were wrong?* Running the
same glob twice does not qualify. A filesystem walk against a git listing does; a declared list
against the credentials actually stored does.

⚖️ DISAGREEMENT IS A FINDING, NOT AUTOMATICALLY A BUG. Two paths may legitimately differ — a
gitignored directory is absent from git and present on disk on purpose. So this reports the
symmetric difference and names both sides. It does not assume which side is right; deciding that
is the caller's job, and `expected` carries the differences already adjudicated.

Usage:
    from second_path import compare
    r = compare("mail accounts", declared, keychain,
                name_a="ACCOUNTS in mailscan.py", name_b="credentials in the Keychain")
    if not r.agree:
        print(r.detail)

READ BY
-------
  * `automation/mail/mailscan_test.py`  - declared accounts vs credentials in the Keychain
  * `automation/liveness-sweep.py`      - `--only coverage`: does each DOC_GLOB match its
                                          whole directory, or is it silently under-matching?
  * `cos/cos_memory.py readers`         - memory files on disk vs memory files tracked by git
Tests: `automation/second_path_test.py`.
"""
from dataclasses import dataclass, field


@dataclass
class Result:
    label: str
    agree: bool
    only_a: list = field(default_factory=list)
    only_b: list = field(default_factory=list)
    n_a: int = 0
    n_b: int = 0
    detail: str = ""

    def __bool__(self):
        return self.agree


def compare(label, a, b, *, name_a="path A", name_b="path B", expected=(), limit=8):
    """Two independently-derived populations of the same thing.

    `a` and `b` are iterables of hashable items — normally strings. `expected` holds differences
    already adjudicated: its members are excluded from BOTH sides AND NAMED in the detail, so an
    accepted divergence stays visible instead of being silently subtracted. A suppression nobody
    ever sees is a suppression nobody re-examines — the rule `liveness-sweep.py` already applies
    to its own `EXPECTED_ABSENT`.

    Returns a `Result`, which is truthy when the two paths agree.
    """
    sa, sb, ex = set(a), set(b), set(expected)
    only_a = sorted(sa - sb - ex)
    only_b = sorted(sb - sa - ex)
    agree = not only_a and not only_b

    def _fmt(items):
        head = ", ".join(str(i) for i in items[:limit])
        return head + (f" … (+{len(items) - limit} more)" if len(items) > limit else "")

    if agree:
        # ⚠️ Do NOT write "{a} == {b}" when `expected` excluded something: the raw counts can
        # legitimately differ while the populations agree, and "38 == 39" is a false statement
        # printed by a check whose whole job is to catch false statements about counts.
        used = sorted(ex & (sa | sb))
        if used:
            detail = (f"{len(sa)} and {len(sb)}, agreeing after {len(used)} adjudicated "
                      f"difference(s): {_fmt(used)}")
        else:
            detail = f"{len(sa)} == {len(sb)} — {name_a} and {name_b} agree"
    else:
        parts = [f"{len(sa)} vs {len(sb)} — {name_a} and {name_b} DISAGREE"]
        if only_a:
            parts.append(f"  only in {name_a} ({len(only_a)}): {_fmt(only_a)}")
        if only_b:
            parts.append(f"  only in {name_b} ({len(only_b)}): {_fmt(only_b)}")
        parts.append("  ⛔ Neither side is assumed correct. Decide which is right and fix that one "
                     "— or add it to `expected`, with a reason, if the difference is deliberate.")
        detail = "\n".join(parts)

    return Result(label=label, agree=agree, only_a=only_a, only_b=only_b,
                  n_a=len(sa), n_b=len(sb), detail=detail)


def report(results, header="SECOND-PATH COMPLETENESS"):
    """Print a list of Results in the house style. Returns 0 if all agree, else 1."""
    bad = [r for r in results if not r.agree]
    print("=" * 78)
    print(f"{header} — count the population twice, by different methods (#137)")
    print("=" * 78)
    for r in results:
        print(f"\n{'🟢' if r.agree else '🔴'} {r.label}")
        for line in r.detail.splitlines():
            print(f"   {line}")
    print("\n" + "-" * 78)
    if bad:
        print(f"🔴 {len(bad)} of {len(results)} population(s) disagree across two methods.")
        return 1
    print(f"🟢 all {len(results)} population(s) agree across two independently shaped methods.")
    return 0
