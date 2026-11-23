"""Test Guardian on real open-source apps (testbed/corpus.yaml; CLAUDE.md §3.1 test-corpus exception).

    .venv/bin/python testbed/corpus.py fetch [name ...]   # bare, read-only fetch of each pinned commit
    .venv/bin/python testbed/corpus.py scan  [name ...]   # full scan (or base->head) of each app

Safety: repositories are fetched as *bare* repositories (no working tree, so no checkout filters, LFS or hooks),
with the same hardened git settings as "Scan a project" (guardian/projects.py: https only, allow-listed hosts,
hooks off, no submodules, no credential prompts). Only the pinned commit is fetched (depth 1), and it is verified
after the fetch: a commit that does not match the pin is refused. Scans go through guardian.universal.check_any,
so every repository-reading tool runs in the podman sandbox. Nothing is built, installed or run.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guardian.projects import GIT_ENV, SAFE_GIT, validate_git_url  # noqa: E402

CORPUS = ROOT / "sandbox" / "corpus"
OUT = ROOT / "guardian-out" / "corpus"
LEVELS = ["critical", "high", "medium", "low", "info"]


def load(names: list[str]) -> list[dict]:
    apps = yaml.safe_load((ROOT / "testbed" / "corpus.yaml").read_text())["apps"]
    unknown = set(names) - {a["name"] for a in apps}
    if unknown:
        raise SystemExit(f"unknown app(s): {', '.join(sorted(unknown))}")
    return [a for a in apps if not names or a["name"] in names]


def _git(repo: Path, *args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(SAFE_GIT + ["-C", str(repo), *args], capture_output=True, text=True, timeout=timeout, env=GIT_ENV)


def fetch(app: dict) -> str:
    """Fetch the pinned commit(s) into sandbox/corpus/<name>.git. Returns a one-line status."""
    url = validate_git_url(app["repo"])
    dest = CORPUS / f"{app['name']}.git"
    commits = [app["commit"]] + ([app["base"]["commit"]] if app.get("base") else [])
    if dest.exists() and all(_git(dest, "cat-file", "-e", f"{c}^{{commit}}").returncode == 0 for c in commits):
        return "already fetched"
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / "HEAD").exists():
        subprocess.run(SAFE_GIT + ["init", "-q", "--bare", str(dest)], check=True, env=GIT_ENV)
    for c in commits:
        r = _git(dest, "fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", url, c)
        if r.returncode != 0:
            raise RuntimeError(f"fetch of {c[:12]} failed: {r.stderr.strip()[-300:]}")
        got = _git(dest, "rev-parse", "FETCH_HEAD").stdout.strip()
        if got != c:
            raise RuntimeError(f"fetched {got[:12]} but the pin is {c[:12]}: refusing (the remote does not serve the pinned commit)")
        _git(dest, "update-ref", f"refs/guardian/{c}", c)  # keep the commit reachable in the bare repo
    return f"fetched {', '.join(c[:12] for c in commits)}"


def scan(app: dict) -> dict:
    from guardian.universal import check_any

    repo = CORPUS / f"{app['name']}.git"
    if not repo.exists():
        raise RuntimeError("not fetched: run `testbed/corpus.py fetch` first")
    out = OUT / app["name"]
    t0 = time.time()
    base = app["base"]["commit"] if app.get("base") else None
    rep = check_any(repo, base, app["commit"], out, app["name"])
    h = rep["headline"]
    findings = [s for s in rep["suspicious_changes"] if s["type"] != "tool_error"] + rep["ci_image"]
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    vulns = rep["vulnerabilities"]
    return {
        "name": app["name"], "commit": app["commit"], "ref": app["ref"], "base": app.get("base"), "seconds": round(time.time() - t0, 1),
        "verdict": h.get("verdict"), "components": h["inventory"]["packages"], "ecosystems": h["inventory"]["ecosystems"],
        "unpinned": h["inventory"]["unpinned"], "lockfiles": h["inventory"]["lockfiles"],
        "resolved_lockfiles": h["inventory"]["resolved_lockfiles"],
        "vulnerable_components": len({(v["name"], v["version"]) for v in vulns if v["label"] != "fixed"}),
        "advisories": {lv: sum(1 for v in vulns if v["severity"] == lv and v["label"] != "fixed") for lv in LEVELS},
        "introduced": {"vulns": sum(1 for v in vulns if v["label"] == "introduced"),
                       "fixed": sum(1 for v in vulns if v["label"] == "fixed"),
                       "signals": sum(1 for s in rep["suspicious_changes"] if s["label"] == "introduced")},
        "findings_by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "not_checked": [s["summary"][:200] for s in rep["suspicious_changes"] if s["type"] == "tool_error"],
        "sandbox": {k: h["sandbox"][k] for k in ("all_isolated", "tools", "failed", "egress_denied")},
        "scanner_errors": h["vulnerabilities"]["errors"], "report": rep["path"],
    }


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("fetch", "scan"):
        print(__doc__)
        return 2
    apps, failed = load(argv[1:]), 0
    results = []
    for app in apps:
        try:
            if argv[0] == "fetch":
                print(f"{app['name']:18} {fetch(app)}")
            else:
                r = scan(app)
                results.append(r)
                adv = ", ".join(f"{k} {v}" for k, v in r["advisories"].items() if v) or "none"
                print(f"{r['name']:18} {r['seconds']:>6}s  {r['components']:>5} comps {json.dumps(r['ecosystems'])}  "
                      f"advisories: {adv}  verdict {r['verdict']}  not checked: {len(r['not_checked'])}")
        except Exception as e:
            failed += 1
            print(f"{app['name']:18} ERROR {type(e).__name__}: {e}"[:400])
            results.append({"name": app["name"], "error": f"{type(e).__name__}: {e}"[:400]})
    if argv[0] == "scan":
        OUT.mkdir(parents=True, exist_ok=True)
        summary = OUT / "summary.json"
        old = {r["name"]: r for r in (json.loads(summary.read_text()) if summary.exists() else [])}
        old.update({r["name"]: r for r in results})
        summary.write_text(json.dumps(list(old.values()), indent=1))
        print(f"summary: {summary}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
