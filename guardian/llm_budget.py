"""Token ledger, budget guard and response cache for every model call.

* Ledger: one JSON line per call in .cache/llm_usage.jsonl (purpose, run, model, tokens, cached). Never the key or prompt.
* Budget: before a call is sent, its worst case (prompt estimate + max_tokens) must fit the per-run budget and the
  rolling 30-day budget, counting calls already in flight. Otherwise BudgetExceeded is raised and nothing is sent.
* Cache: identical requests (model + effort + messages + max_tokens) are answered from .cache/llm/ with 0 tokens.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MONTH = 30 * 24 * 3600
_lock = threading.Lock()
_reserved: dict[str, int] = {}  # run_id -> tokens reserved by calls in flight


class BudgetExceeded(RuntimeError):
    pass


def _ledger() -> Path:
    return Path(os.environ.get("GUARDIAN_LEDGER", ROOT / ".cache" / "llm_usage.jsonl"))


def _cache_dir() -> Path:
    return Path(os.environ.get("GUARDIAN_LLM_CACHE", ROOT / ".cache" / "llm"))


def limits() -> dict:
    return {"run": int(os.environ.get("GUARDIAN_RUN_TOKEN_BUDGET", 25000)),
            "month": int(os.environ.get("GUARDIAN_MONTH_TOKEN_BUDGET", 300000))}


def estimate(text: str, max_tokens: int) -> int:
    """Worst case for one call: ~3 characters per input token (conservative), the output cap, and an allowance for
    hidden reasoning tokens (measured: with reasoning_effort=medium the provider can exceed max_tokens)."""
    return len(text) // 3 + 1 + max_tokens + int(os.environ.get("GUARDIAN_REASONING_ALLOWANCE", 3000))


def _rows() -> list[dict]:
    p = _ledger()
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _total(rows) -> int:
    return sum(int(r.get("prompt_tokens", 0)) + int(r.get("completion_tokens", 0)) for r in rows)


def reserve(run_id: str, est: int) -> None:
    lim = limits()
    with _lock:
        rows = _rows()
        run_used = _total(r for r in rows if r.get("run_id") == run_id) + _reserved.get(run_id, 0)
        month_used = _total(r for r in rows if r.get("ts", 0) > time.time() - MONTH) + sum(_reserved.values())
        if run_used + est > lim["run"]:
            raise BudgetExceeded(f"run budget: {run_used} used + up to {est} for this call > {lim['run']} tokens")
        if month_used + est > lim["month"]:
            raise BudgetExceeded(f"month budget: {month_used} used + up to {est} for this call > {lim['month']} tokens")
        _reserved[run_id] = _reserved.get(run_id, 0) + est


def release(run_id: str, est: int) -> None:
    with _lock:
        _reserved[run_id] = max(0, _reserved.get(run_id, 0) - est)


def record(*, run_id: str, purpose: str, model: str, usage: dict | None, cached: bool, seconds: float = 0.0,
           finish_reason: str | None = None) -> None:
    u = usage or {}
    row = {"ts": time.time(), "run_id": run_id, "purpose": purpose, "model": model,
           "prompt_tokens": 0 if cached else int(u.get("prompt_tokens", 0)),
           "completion_tokens": 0 if cached else int(u.get("completion_tokens", 0)),
           "cache_hit_tokens": int(u.get("prompt_cache_hit_tokens", 0) or 0), "cached": cached, "seconds": round(seconds, 2),
           "finish_reason": finish_reason}
    p = _ledger()
    p.parent.mkdir(parents=True, exist_ok=True)
    with _lock, p.open("a") as f:
        f.write(json.dumps(row) + "\n")


def summary(run_id: str | None = None) -> dict:
    rows = _rows()
    month = [r for r in rows if r.get("ts", 0) > time.time() - MONTH]
    run = [r for r in rows if r.get("run_id") == run_id] if run_id else []

    def agg(rs):
        rs = list(rs)
        return {"calls": sum(1 for r in rs if not r.get("cached")), "cached_calls": sum(1 for r in rs if r.get("cached")),
                "tokens": _total(rs), "seconds": round(sum(r.get("seconds", 0) for r in rs), 1)}
    purposes = sorted({r.get("purpose", "?").split(":")[0] for r in month})
    by_purpose = {p: agg(r for r in month if r.get("purpose", "?").split(":")[0] == p) for p in purposes}
    return {"run": agg(run), "month": agg(month), "by_purpose": by_purpose, "budget": limits(),
            "month_left": max(0, limits()["month"] - _total(month))}


def cache_key(body: dict) -> str:
    keep = {k: body.get(k) for k in ("model", "reasoning_effort", "messages", "max_tokens", "response_format")}
    return hashlib.sha256(json.dumps(keep, sort_keys=True).encode()).hexdigest()


def cache_get(key: str) -> dict | None:
    f = _cache_dir() / f"{key[:32]}.json"
    return json.loads(f.read_text()) if f.exists() else None


def cache_put(key: str, value: dict) -> None:
    d = _cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{key[:32]}.json").write_text(json.dumps({**value, "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
