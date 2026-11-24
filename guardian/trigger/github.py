"""Minimal GitHub REST client for statuses and comments, plus the status and comment text.

The token is held privately and never logged or printed. GitHub commit statuses support only
pending / success / failure / error, so REVIEW maps to failure ("needs human review").
"""
from __future__ import annotations

import re

API = "https://api.github.com"
MARK = "<!-- guardian:comment -->"


def status_for(h: dict, context: str = "guardian/scan") -> dict:
    v, complete = h.get("verdict"), h.get("complete")
    if not complete or v is None:
        state, desc = "error", "Scan incomplete: a required check did not run (not a clean result)"
    elif v == "block":
        state, desc = "failure", "BLOCK: this change introduces a critical supply-chain risk"
    elif v == "review":
        state, desc = "failure", "REVIEW: needs human review (high-severity risk introduced)"
    else:
        state, desc = "success", "ALLOW: scan policy passed (no high/critical risk introduced)"
    return {"state": state, "context": context, "description": desc[:140]}


def _md(text: str) -> str:
    return re.sub(r"[<>`*_\[\]|]", lambda m: {"<": "&lt;", ">": "&gt;"}.get(m.group(0), "\\" + m.group(0)), str(text))


def comment_body(h: dict, run_url: str | None = None) -> str:
    v = (h.get("verdict") or "incomplete").upper()
    icon = {"BLOCK": "🔴", "REVIEW": "🟡", "ALLOW": "🟢"}.get(v, "⚪")
    lines = [MARK, f"### {icon} Guardian: {v}" + ("" if h.get("complete") else " · incomplete"),
             f"Commit `{(h.get('head_sha') or '')[:12]}`", ""]
    lines += [f"- {_md(r)}" for r in (h.get("verdict_reasons") or [])[:8]]
    lines += [f"- ⚠️ {_md(r)}" for r in (h.get("incomplete_reasons") or [])[:5]]
    if run_url:
        lines += ["", f"[Open the run with evidence]({run_url})"]
    lines += ["", "_Scan decision only. A fix is shown as verified only after human approval and validation "
                  "(status `guardian/validation`)._"]
    return "\n".join(lines)


class GitHub:
    def __init__(self, token: str, http=None):
        import requests
        self.__token = token
        self.http = http or requests.Session()

    def __repr__(self) -> str:
        return "GitHub(token=***)"

    def _req(self, method: str, url: str, json=None) -> tuple[int, object, dict]:
        r = self.http.request(method, url, headers={"Authorization": f"Bearer {self.__token}", "Accept": "application/vnd.github+json",
                                                    "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "guardian"},
                              json=json, timeout=30)
        return r.status_code, (r.json() if r.status_code not in (204, 304) else None), dict(r.headers or {})

    def _pages(self, url: str) -> list:
        out, nxt = [], url
        while nxt:
            code, data, headers = self._req("GET", nxt)
            if code != 200:
                raise RuntimeError(f"GitHub GET failed with {code}")
            out += data or []
            m = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link", ""))
            nxt = m.group(1) if m else None
        return out

    def open_pulls(self, repo: str) -> list[dict]:
        return self._pages(f"{API}/repos/{repo}/pulls?state=open&per_page=100")

    def set_status(self, repo: str, sha: str, status: dict, target_url: str | None = None) -> None:
        body = {**status, **({"target_url": target_url} if target_url else {})}
        code, _, _ = self._req("POST", f"{API}/repos/{repo}/statuses/{sha}", json=body)
        if code not in (200, 201):
            raise RuntimeError(f"status update failed with {code}")

    def upsert_comment(self, repo: str, pr: int, body: str) -> None:
        existing = [c for c in self._pages(f"{API}/repos/{repo}/issues/{pr}/comments?per_page=100") if MARK in (c.get("body") or "")]
        if existing:
            code, _, _ = self._req("PATCH", f"{API}/repos/{repo}/issues/comments/{existing[0]['id']}", json={"body": body})
        else:
            code, _, _ = self._req("POST", f"{API}/repos/{repo}/issues/{pr}/comments", json={"body": body})
        if code not in (200, 201):
            raise RuntimeError(f"comment update failed with {code}")
