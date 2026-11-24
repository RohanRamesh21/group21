"""Pre-flight check for the live demo: is everything the PR -> Actions -> Guardian -> Buddy -> dashboard flow needs ready?

Usage:  .venv/bin/python -m guardian.demo_preflight [--clear-ai-cache]
  --clear-ai-cache   remove cached AI answers so the agents call the model live on stage (costs tokens, looks real)
Prints one line per check (OK / FIX with what to do) and exits 1 if anything blocks the demo. Never prints a secret.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from guardian import config

ROOT = Path(__file__).resolve().parents[1]
SERVER = os.environ.get("GUARDIAN_URL", "http://127.0.0.1:8765")
REPO = os.environ.get("GUARDIAN_DEMO_REPO", "kirankishoreV-07/uptime-kuma")
BRANCH = os.environ.get("GUARDIAN_DEMO_BRANCH", "kuma/d-dependency-maintenance")
BASE = "guardian-demo"


def _get(url: str, headers: dict | None = None, timeout: int = 15):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read() or b"null")


def _sh(*cmd: str) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def checks() -> list[tuple[bool, str, str]]:
    config.load_env()
    out: list[tuple[bool, str, str]] = []

    def add(ok: bool, what: str, fix: str = "") -> None:
        out.append((ok, what, fix))

    try:
        code, _ = _get(f"{SERVER}/api/pr-runs")
        add(code == 200, "Guardian server answers on 127.0.0.1:8765")
    except Exception as e:
        add(False, f"Guardian server ({type(e).__name__})", "scripts/install-services.sh  (or launchctl kickstart -k gui/$UID/com.guardian.server)")

    code, ps = _sh("pgrep", "-f", "guardian/buddy/node_modules/electron")
    log = Path.home() / "Library/Logs/guardian/com.guardian.buddy.log"
    last = next((ln for ln in reversed(log.read_text().splitlines()) if "[buddy] state" in ln), "") if log.exists() else ""
    add(code == 0 and "-> offline" not in last, f"Buddy running ({last.split('state ')[-1] if last else 'no state yet'})",
        "launchctl kickstart -k gui/$UID/com.guardian.buddy")

    code, txt = _sh("gh", "api", f"repos/{REPO}/actions/runners", "--jq", '.runners[] | "\\(.name) \\(.status)"')
    add(code == 0 and "online" in txt, f"self-hosted runner for {REPO}: {txt or 'none'}", "cd ~/actions-runner-guardian-kuma && ./svc.sh start")

    code, txt = _sh("gh", "api", f"repos/{REPO}/branches/{BRANCH}", "--jq", ".commit.sha")
    add(code == 0, f"demo branch {BRANCH} on GitHub ({txt[:8] if code == 0 else 'missing'})",
        "python testbed/injector/build_kuma_demo.py --push")
    code, txt = _sh("gh", "pr", "list", "-R", REPO, "--head", BRANCH, "--state", "open", "--json", "number", "--jq", ".[].number")
    add(code == 0 and not txt.strip(), "no open PR from the demo branch yet (you open it live)" if not txt.strip() else f"a PR from {BRANCH} is already open: #{txt}",
        f"gh pr close {txt.strip()} -R {REPO}   (then open a fresh one on stage)")

    try:
        code, d = _get("http://127.0.0.1:4873/dotenvv")
        add(code == 200 and "1.0.0" in (d.get("versions") or {}), "local registry (Verdaccio) serves the dotenvv fixture")
    except Exception:
        add(False, "local registry (Verdaccio)", "docker start verdaccio  (then python testbed/injector/build_kuma_demo.py)")

    code, imgs = _sh("docker", "images", "--format", "{{.Repository}}:{{.Tag}}")
    add(code == 0 and "node:20-bookworm" in imgs.split(), "Docker running with node:20-bookworm (validation sandbox)", "start Docker Desktop; docker pull node:20-bookworm")

    tok_name = "GUARDIAN_GITHUB_TOKEN__" + "__".join(x.upper().replace("-", "_") for x in REPO.split("/"))
    add(bool(os.environ.get(tok_name) or os.environ.get("GUARDIAN_GITHUB_TOKEN")), f"GitHub token configured for {REPO}",
        f"add {tok_name}=... to guardian/.env (Commit statuses, Pull requests, Issues: read and write)")

    k = os.environ.get("DEEPSEEK_API_KEY")
    if k:
        try:
            code, d = _get("https://api.deepseek.com/models", {"Authorization": f"Bearer {k}"})
            add(code == 200, "DeepSeek key works (agents + advisor)")
        except Exception as e:
            add(False, f"DeepSeek key ({type(e).__name__})", "check DEEPSEEK_API_KEY in guardian/.env")
    else:
        add(bool(os.environ.get("FM_API_KEY") or os.environ.get("GOOGLE_API_KEY")), "an AI provider key is configured",
            "set DEEPSEEK_API_KEY in guardian/.env")
    return out


def main() -> int:
    if "--clear-ai-cache" in sys.argv:
        cache = Path(os.environ.get("GUARDIAN_LLM_CACHE", ROOT / ".cache" / "llm"))
        n = len(list(cache.glob("*.json"))) if cache.exists() else 0
        shutil.rmtree(cache, ignore_errors=True)
        print(f"cleared {n} cached AI answers: the agents will call the model live")
    res = checks()
    for ok, what, fix in res:
        print(("  OK   " if ok else "  FIX  ") + what + ("" if ok or not fix else f"\n         -> {fix}"))
    bad = [r for r in res if not r[0]]
    print(f"\n{'READY for the live demo' if not bad else f'{len(bad)} item(s) to fix before the demo'}  "
          f"(open the PR: gh pr create -R {REPO} --base {BASE} --head {BRANCH})")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
