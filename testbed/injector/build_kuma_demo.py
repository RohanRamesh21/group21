"""Build the live-demo pull-request branches on the Uptime Kuma fork (github.com/kirankishoreV-07/uptime-kuma).

Base: `guardian-demo` = upstream tag 2.5.12 + Guardian workflows (the fork's default branch).
A  kuma/a-docs-wording   benign: documentation wording only
B  kuma/b-pin-lodash     vulnerable: pins lodash back to 4.17.20 (CVE-2021-23337 command injection and 3 more advisories)
D  kuma/d-dependency-maintenance   LIVE DEMO: lodash 4.17.20 + minimist 1.2.5 + node-fetch 2.6.0 + the C attack (4 cases)
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


def edit_d() -> None:
    """The live-demo PR: looks like routine maintenance, hides 3 vulnerable dependency changes and 1 supply-chain attack.
    No code uses the new packages, so the computed fix leaves Uptime Kuma working (validation can end 'verified')."""
    base.lock_add("lodash@4.17.20")         # GHSA-35jh (CVE-2021-23337 command injection) + 3 more
    base.lock_add("minimist@1.2.5")         # GHSA-xvch-5gv4-984h (critical prototype pollution)
    base.lock_add("node-fetch@2.6.0")       # GHSA-r683-j2x4-v87g (high: forwards secure headers to untrusted sites)
    edit_c()                                # dotenvv look-alike from the local registry + .npmrc age gate swapped for a redirect


def edit_e() -> None:
    """CI drift: a workflow action loses its commit-SHA pin and follows a movable tag (the tj-actions/changed-files
    pattern, March 2025). Detected by the contextual-scoring detector D11 (action_sha_to_tag)."""
    wf = base.REPO / ".github" / "workflows" / "auto-test.yml"
    wf.write_text(wf.read_text().replace("actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1", "actions/checkout@v6"))


def edit_live1() -> None:
    """BLOCK: .npmrc registry redirect (source_change, critical) + lodash 4.17.20 (CVE-2021-23337)."""
    rc = base.REPO / ".npmrc"
    rc.write_text(rc.read_text().replace("min-release-age=14", "registry=http://127.0.0.1:4873/"))
    base.lock_add("lodash@4.17.20")


def edit_live2() -> None:
    """BLOCK: dotenvv look-alike from an off-allow-list server, with an install script (critical) + minimist 1.2.5."""
    base.sh(["npm", "install", "--package-lock-only", "--ignore-scripts", "--save-exact", "--min-release-age=0",
             "--registry", base.REG, "dotenvv@1.0.0"])  # .npmrc stays unchanged: only the lockfile shows the attack
    base.lock_add("minimist@1.2.5")


def edit_live4() -> None:
    """BLOCK: an existing package (express) silently re-pointed to another download host with a different integrity
    hash (lockfile_tamper, critical) + node-fetch 2.6.0 + checkout action unpinned from its commit SHA."""
    import base64
    import hashlib
    import re
    base.lock_add("node-fetch@2.6.0")
    edit_e()
    lock = base.REPO / "package-lock.json"
    txt = lock.read_text()
    m = re.search(r'("node_modules/express": \{.*?\n        \})', txt, re.S)
    if not m:
        raise SystemExit("express entry not found in package-lock.json")
    block = m.group(1)
    fake = "sha512-" + base64.b64encode(hashlib.sha512(b"guardian-demo-swapped-express").digest()).decode()
    new = re.sub(r'"resolved": "https://registry\.npmjs\.org/', '"resolved": "http://127.0.0.1:4873/', block)
    new = re.sub(r'"integrity": "sha512-[^"]+"', f'"integrity": "{fake}"', new)
    lock.write_text(txt.replace(block, new, 1))  # last, so npm does not rewrite it


LIVE = [("live/1-faster-npm-installs", "chore: use a local npm mirror for faster installs", edit_live1),
        ("live/2-env-config-loader", "feat: load settings from .env files", edit_live2),
        ("live/3-dependency-maintenance", "chore: dependency maintenance and .env config loading", edit_d),
        ("live/4-lockfile-refresh", "chore: refresh lockfile and CI checkout tag", edit_live4)]


def main() -> None:
    if "--live" in sys.argv:  # fresh branches with NO pull request: open each PR by hand on stage
        base.publish_fixture()
        for name, msg, fn in LIVE:
            branch(name, msg, fn)
        base.sh(["git", "checkout", "-q", BASE_BRANCH])
        if "--push" in sys.argv:
            for name, _, _ in LIVE:
                base.sh(["git", "push", "-q", "-f", "-u", "origin", name])
                print("pushed", name)
        return
    base.publish_fixture()
    branch("kuma/a-docs-wording", "docs: clarify security reporting wording", edit_a)
    branch("kuma/b-pin-lodash", "fix: pin lodash for redbean-node compatibility", edit_b)
    branch("kuma/c-fix-typo", "fix typo", edit_c)
    branch("kuma/d-dependency-maintenance", "chore: dependency maintenance and .env config loading", edit_d)
    branch("kuma/e-ci-checkout-tag", "ci: use the v6 tag for actions/checkout", edit_e)
    base.sh(["git", "checkout", "-q", BASE_BRANCH])
    if "--push" in sys.argv:
        for b in ("kuma/a-docs-wording", "kuma/b-pin-lodash", "kuma/c-fix-typo", "kuma/d-dependency-maintenance", "kuma/e-ci-checkout-tag"):
            base.sh(["git", "push", "-q", "-f", "-u", "origin", b])
            print("pushed", b)


if __name__ == "__main__":
    main()
