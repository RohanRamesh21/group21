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


def validation_status(v: dict) -> dict:
    """Result of validating an approved fix, as the separate guardian/validation status."""
    g = v.get("gate") or {}
    if v.get("status") != "executed":
        return {"state": "error", "context": "guardian/validation", "description": f"Validation not run: {v.get('reason') or v.get('status')}"[:140]}
    if g.get("verified"):
        return {"state": "success", "context": "guardian/validation", "description": "Fix verified: built, tested and rescanned in isolation"}
    return {"state": "failure", "context": "guardian/validation", "description": f"Fix not verified ({g.get('validation', 'failed')})"[:140]}


NIGHTLY_MARK = "<!-- guardian:nightly -->"


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


def _why(data, headers: dict) -> str:
    """GitHub's reason and the permission it expects (never the token)."""
    msg = data.get("message") if isinstance(data, dict) else None
    need = {k.lower(): v for k, v in (headers or {}).items()}.get("x-accepted-github-permissions")
    return (f": {msg}" if msg else "") + (f" (needs: {need})" if need else "")


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

    def statuses(self, repo: str, sha: str) -> list[dict]:
        return self._pages(f"{API}/repos/{repo}/commits/{sha}/statuses?per_page=100")

    def set_status(self, repo: str, sha: str, status: dict, target_url: str | None = None) -> None:
        body = {**status, **({"target_url": target_url} if target_url else {})}
        code, data, headers = self._req("POST", f"{API}/repos/{repo}/statuses/{sha}", json=body)
        if code not in (200, 201):
            raise RuntimeError(f"status update failed with {code}{_why(data, headers)}")

    def upsert_comment(self, repo: str, pr: int, body: str) -> None:
        existing = [c for c in self._pages(f"{API}/repos/{repo}/issues/{pr}/comments?per_page=100") if MARK in (c.get("body") or "")]
        if existing:
            code, data, headers = self._req("PATCH", f"{API}/repos/{repo}/issues/comments/{existing[0]['id']}", json={"body": body})
        else:
            code, data, headers = self._req("POST", f"{API}/repos/{repo}/issues/{pr}/comments", json={"body": body})
        if code not in (200, 201):
            raise RuntimeError(f"comment update failed with {code}{_why(data, headers)}")

    def upsert_issue(self, repo: str, title: str, body: str) -> None:
        """One open nightly issue per repository, updated in place (no duplicate alerts)."""
        issues = [i for i in self._pages(f"{API}/repos/{repo}/issues?state=open&per_page=100")
                  if NIGHTLY_MARK in (i.get("body") or "") and "pull_request" not in i]
        body = NIGHTLY_MARK + "\n" + body
        if issues:
            code, _, _ = self._req("PATCH", f"{API}/repos/{repo}/issues/{issues[0]['number']}", json={"title": title, "body": body})
        else:
            code, _, _ = self._req("POST", f"{API}/repos/{repo}/issues", json={"title": title, "body": body})
        if code not in (200, 201):
            raise RuntimeError(f"issue update failed with {code}")


def token_env_name(repo: str) -> str:
    """Per-repository token: GUARDIAN_GITHUB_TOKEN__<OWNER>__<REPO> (non-alphanumerics become _)."""
    owner, name = repo.split("/", 1)
    norm = lambda x: re.sub(r"[^A-Za-z0-9]", "_", x).upper()  # noqa: E731
    return f"GUARDIAN_GITHUB_TOKEN__{norm(owner)}__{norm(name)}"


class GitHubRouter:
    """Same methods as GitHub, but each call uses the token configured for that repository (falling back to
    GUARDIAN_GITHUB_TOKEN). Fine-grained tokens are scoped to repositories, so one token per repo is normal."""

    def __init__(self, env: dict, client=GitHub):
        self.__tokens = {k: v for k, v in env.items() if k.startswith("GUARDIAN_GITHUB_TOKEN") and v}
        self.__client, self.__cache, self.__good = client, {}, {}

    def __repr__(self) -> str:
        return f"GitHubRouter(tokens={len(self.__tokens)} configured, values hidden)"

    @property
    def configured(self) -> bool:
        return bool(self.__tokens)

    def _candidates(self, repo: str) -> list[str]:
        """Repo-specific token first, then the default, then any other configured token (deduplicated)."""
        order = [self.__tokens.get(token_env_name(repo)), self.__tokens.get("GUARDIAN_GITHUB_TOKEN"), *self.__tokens.values()]
        if self.__good.get(repo):
            order.insert(0, self.__good[repo])
        seen, out = set(), []
        for t in order:
            if t and t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def _client(self, tok: str):
        if tok not in self.__cache:
            self.__cache[tok] = self.__client(tok)
        return self.__cache[tok]

    def _for(self, repo: str):
        c = self._candidates(repo)
        if not c:
            raise RuntimeError(f"no GitHub token configured for {repo}")
        return self._client(c[0])

    def _call(self, method: str, repo: str, *a, **k):
        """A 403 means this token lacks permission on this repo: try the next configured token and remember the one
        that worked. Other errors are not retried with another token."""
        cands = self._candidates(repo)
        if not cands:
            raise RuntimeError(f"no GitHub token configured for {repo}")
        last = None
        for tok in cands:
            try:
                res = getattr(self._client(tok), method)(repo, *a, **k)
                self.__good[repo] = tok
                return res
            except RuntimeError as e:
                if "403" not in str(e):
                    raise
                last = e
        raise last

    def open_pulls(self, repo, *a, **k):
        return self._call("open_pulls", repo, *a, **k)

    def statuses(self, repo, *a, **k):
        return self._call("statuses", repo, *a, **k)

    def set_status(self, repo, *a, **k):
        return self._call("set_status", repo, *a, **k)

    def upsert_comment(self, repo, *a, **k):
        return self._call("upsert_comment", repo, *a, **k)

    def upsert_issue(self, repo, *a, **k):
        return self._call("upsert_issue", repo, *a, **k)
