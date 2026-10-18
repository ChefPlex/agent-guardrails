#!/usr/bin/env python3
"""Check that every relative link in this repository's Markdown points at a file that exists.

Covers links like [text](other-doc.md) and [text](folder/), and links to this same repository
written as https://github.com/ChefPlex/<this repo>/blob/main/<path>. External sites are not
fetched: a check that depends on someone else's server being up fails for reasons that are not
this repository's. Standard library only.

    python3 .github/check_links.py
"""
import os
import re
import subprocess
import sys

LINK = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")


def tracked_markdown():
    out = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True, check=True).stdout
    return [p for p in out.splitlines() if p]


def repo_name():
    url = subprocess.run(["git", "config", "--get", "remote.origin.url"], capture_output=True,
                         text=True, check=False).stdout.strip()
    return re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1]) if url else os.path.basename(os.getcwd())


def main():
    own = re.compile(rf"https://github\.com/ChefPlex/{re.escape(repo_name())}/(?:blob|tree)/main/([^)#?\s]*)")
    broken, checked = [], 0
    for md in tracked_markdown():
        in_fence = False
        for n, line in enumerate(open(md, encoding="utf-8"), 1):
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for target in LINK.findall(line):
                m = own.match(target)
                if m:
                    path = m.group(1)
                elif re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith("#"):
                    continue
                elif re.search(r"[<>{}\[\]]", target) or (
                        re.fullmatch(r"[A-Z_]+", target)
                        and not os.path.exists(os.path.join(os.path.dirname(md), target))):
                    continue  # an output-format placeholder such as (URL) or (<link>), not a link
                else:
                    path = os.path.normpath(os.path.join(os.path.dirname(md), target.split("#")[0]))
                checked += 1
                if not os.path.exists(path.rstrip("/") or "."):
                    broken.append(f"{md}:{n}: {target}")
    for b in broken:
        print(f"BROKEN  {b}")
    print(f"{checked} internal link(s) checked, {len(broken)} broken")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
