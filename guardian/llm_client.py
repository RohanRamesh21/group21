"""Small JSON-chat client for the configured OpenAI-compatible provider (FreeModel: DeepSeek V4 Flash).

Used for short structured outputs (explanations, fix-plan review). The key stays in .env and is never logged.
"""
from __future__ import annotations

import json
import os
import re
import time

from guardian import config, llm_budget
from guardian.llm_budget import BudgetExceeded  # noqa: F401  (re-exported)

FREEMODEL_URL = "https://freemodel.in/v1/chat/completions"
DEFAULT_MODEL = "deepseek-v4-flash-0731"


def _parse(text: str) -> dict:
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    raw = m.group(1) if m else text
    start, end = raw.find("{"), raw.rfind("}")
    return json.loads(raw[start:end + 1] if start >= 0 else raw)


def chat_json(prompt: str, *, system: str = "Answer with one JSON object only.", max_tokens: int = 2000, session=None,
              purpose: str = "chat", run_id: str = "adhoc", cache: bool = True, effort: str | None = None) -> tuple[dict, dict]:
    """One JSON call. Budget-checked before sending, recorded in the ledger after, cached by request hash."""
    config.load_env()
    key = os.environ.get("FM_API_KEY")
    if not key:
        raise RuntimeError("no FM_API_KEY in guardian/.env")
    model = os.environ.get("GUARDIAN_MODEL", DEFAULT_MODEL)
    body = {"model": model, "reasoning_effort": effort or os.environ.get("GUARDIAN_EFFORT", "medium"), "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}}
    ck = llm_budget.cache_key(body)
    if cache and (hit := llm_budget.cache_get(ck)):
        llm_budget.record(run_id=run_id, purpose=purpose, model=model, usage=None, cached=True)
        return hit["data"], {"model": model, "usage": hit.get("usage") or {}, "cached": True, "cached_at": hit["cached_at"]}
    est = llm_budget.estimate(system + prompt, max_tokens)
    llm_budget.reserve(run_id, est)  # raises BudgetExceeded: nothing is sent
    if session is None:
        import requests
        session = requests.Session()
    last, t0 = None, time.time()
    try:
        for attempt in range(3):
            r = session.post(FREEMODEL_URL, json=body, timeout=180, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            if r.status_code == 200:
                d = r.json()
                usage = d.get("usage") or {}
                choice = d["choices"][0]
                fr = choice.get("finish_reason")
                llm_budget.record(run_id=run_id, purpose=purpose, model=model, usage=usage, cached=False,
                                  seconds=time.time() - t0, finish_reason=fr)
                content = (choice["message"].get("content") or "").strip()
                if not content:  # e.g. all output spent on hidden reasoning: an error, never cached
                    raise RuntimeError(f"empty reply (finish_reason={fr}, completion_tokens={usage.get('completion_tokens')})")
                data = _parse(content)
                if cache:
                    llm_budget.cache_put(ck, {"data": data, "usage": usage})
                return data, {"model": model, "usage": usage, "cached": False}
            last = f"HTTP {r.status_code}"
            if r.status_code not in (429, 500, 502, 503, 504):
                break
            time.sleep(3 * (attempt + 1))
    finally:
        llm_budget.release(run_id, est)
    raise RuntimeError(f"model call failed ({last})")


def usage_summary(run_id: str | None = None) -> dict:
    return llm_budget.summary(run_id)
