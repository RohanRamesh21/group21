"""Build the live-demo pull-request branches on the Uptime Kuma fork (github.com/kirankishoreV-07/uptime-kuma).

Base: `guardian-demo` = upstream tag 2.5.12 + Guardian workflows (the fork's default branch).
A  kuma/a-docs-wording   benign: documentation wording only
B  kuma/b-pin-lodash     vulnerable: pins lodash back to 4.17.20 (CVE-2021-23337 command injection and 3 more advisories)
C  kuma/c-fix-typo       attack: a typo fix that adds the `dotenvv` look-alike (local registry only) and swaps the
                         project's 14-day release-age gate in .npmrc for a registry redirect

Same safety rules as build_shiplog_demo.py (local-only fixture, unregistered name, lockfile-only edits with scripts off).
Usage: python testbed/injector/build_kuma_demo.py [--push]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_shiplog_demo as base  # noqa: E402

base.REPO = Path.home() / "Documents" / "BOSCH" / "uptime-kuma-fork"
BASE_BRANCH = "guardian-demo"


def branch(name: str, message: str, edit) -> None:
    base.sh(["git", "reset", "-q", "--hard"])  # every branch starts from a clean tree (a failed run must not leak edits)
    base.sh(["git", "checkout", "-q", BASE_BRANCH])
    base.sh(["git", "pull", "-q", "--ff-only", "origin", BASE_BRANCH])
    base.sh(["git", "checkout", "-q", "-B", name])
    edit()
    base.sh(["git", "add", "-A"])
    base.sh(["git", "commit", "-q", "-m", message])
    print("built", name, base.sh(["git", "log", "--oneline", "-1"]).strip(), base.sh(["git", "diff", "--shortstat", BASE_BRANCH]).strip())


def edit_a() -> None:
    p = base.REPO / "SECURITY.md"
    p.write_text(p.read_text().replace("Please report", "Please responsibly report", 1) if "Please report" in p.read_text()
                 else p.read_text() + "\nThank you for helping keep Uptime Kuma users safe.\n")


def edit_b() -> None:
    base.lock_add("lodash@4.17.20")


def edit_c() -> None:
    # The project's 14-day release-age gate would refuse a brand-new package, so the attacker also swaps that line
    # for the registry redirect (legacy-peer-deps stays). Both are .npmrc changes Guardian must flag.
    rc = base.REPO / ".npmrc"
    rc.write_text(rc.read_text().replace("min-release-age=14", "registry=http://127.0.0.1:4873/"))
    base.lock_add("dotenvv@1.0.0", registry=base.REG)
    rd = base.REPO / "README.md"
    rd.write_text(rd.read_text().replace("It is a self-hosted monitoring tool", "It is a self-hosted monitoring tool", 1).replace("  \n", "\n", 1))


def main() -> None:
    base.publish_fixture()
    branch("kuma/a-docs-wording", "docs: clarify security reporting wording", edit_a)
    branch("kuma/b-pin-lodash", "fix: pin lodash for redbean-node compatibility", edit_b)
    branch("kuma/c-fix-typo", "fix typo", edit_c)
    base.sh(["git", "checkout", "-q", BASE_BRANCH])
    if "--push" in sys.argv:
        for b in ("kuma/a-docs-wording", "kuma/b-pin-lodash", "kuma/c-fix-typo"):
            base.sh(["git", "push", "-q", "-f", "-u", "origin", b])
            print("pushed", b)


if __name__ == "__main__":
    main()
