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


GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
_EXHAUSTED: dict[str, float] = {}  # provider -> when it said its quota is used up (skipped for an hour, then retried)
EXHAUSTED_FOR = 3600


def _providers() -> list[dict]:
    """Main provider first (FreeModel), then the fallback (GUARDIAN_LLM_FALLBACK, default gemini when a Google key exists).
    Both speak the OpenAI chat-completions format; every call is budgeted, ledgered and cached the same way."""
    out = []
    if os.environ.get("DEEPSEEK_API_KEY"):  # DeepSeek's own API (V4 Flash), main provider when its key is set
        out.append({"name": "deepseek", "url": DEEPSEEK_URL, "key": os.environ["DEEPSEEK_API_KEY"],
                    "model": os.environ.get("GUARDIAN_DEEPSEEK_MODEL", "deepseek-flash"),
                    "token_factor": 3})  # reasoning counts toward max_tokens (measured: 1,500 cut the JSON off)
    if os.environ.get("FM_API_KEY"):
        out.append({"name": "freemodel", "url": FREEMODEL_URL, "key": os.environ["FM_API_KEY"],
                    "model": os.environ.get("GUARDIAN_MODEL", DEFAULT_MODEL)})
    fb = os.environ.get("GUARDIAN_LLM_FALLBACK", "gemini" if os.environ.get("GOOGLE_API_KEY") else "none")
    if fb == "gemini" and os.environ.get("GOOGLE_API_KEY"):
        models = os.environ.get("GUARDIAN_GEMINI_MODELS", "gemini-2.5-flash,gemini-3.5-flash")
        for m in [x.strip() for x in models.split(",") if x.strip()]:  # next model only if the previous is overloaded
            out.append({"name": "gemini", "url": GEMINI_URL, "key": os.environ["GOOGLE_API_KEY"], "model": m,
                        "token_factor": 4})  # gemini counts hidden thinking in max_tokens (measured: 1,500 ran out)
    return out


class _Quota(RuntimeError):
    pass


class _Unavailable(RuntimeError):
    """The provider kept answering 429/5xx after retries: try the next provider/model."""


def _call(p: dict, body: dict, session, run_id: str, purpose: str, cache: bool) -> tuple[dict, dict]:
    ck = llm_budget.cache_key(body)
    if cache and (hit := llm_budget.cache_get(ck)):
        llm_budget.record(run_id=run_id, purpose=purpose, model=body["model"], usage=None, cached=True)
        return hit["data"], {"model": body["model"], "provider": p["name"], "usage": hit.get("usage") or {}, "cached": True,
                             "cached_at": hit["cached_at"]}
    est = llm_budget.estimate(body["messages"][0]["content"] + body["messages"][1]["content"], body["max_tokens"])
    llm_budget.reserve(run_id, est)  # raises BudgetExceeded: nothing is sent
    last, t0 = None, time.time()
    try:
        for attempt in range(3):
            r = session.post(p["url"], json=body, timeout=180, headers={"Authorization": f"Bearer {p['key']}", "Content-Type": "application/json"})
            if r.status_code == 200:
                d = r.json()
                usage = d.get("usage") or {}
                choice = d["choices"][0]
                fr = choice.get("finish_reason")
                llm_budget.record(run_id=run_id, purpose=f"{purpose}" if p["name"] == "freemodel" else f"{purpose}:{p['name']}",
                                  model=body["model"], usage=usage, cached=False, seconds=time.time() - t0, finish_reason=fr)
                content = (choice["message"].get("content") or "").strip()
                if not content:  # e.g. all output spent on hidden reasoning: an error, never cached
                    raise RuntimeError(f"empty reply (finish_reason={fr}, completion_tokens={usage.get('completion_tokens')})")
                data = _parse(content)
                if cache:
                    llm_budget.cache_put(ck, {"data": data, "usage": usage})
                return data, {"model": body["model"], "provider": p["name"], "usage": usage, "cached": False}
            last = f"HTTP {r.status_code}"
            if r.status_code == 402:  # the provider's plan is used up: name it, retrying won't help
                try:
                    err = r.json().get("error") or {}
                except (ValueError, AttributeError):
                    err = {}
                if isinstance(err, list):
                    err = err[0] if err else {}
                raise _Quota(f"{p['name']}: {err.get('code', 'HTTP 402')}: {str(err.get('message', ''))[:120]}")
            if r.status_code not in (429, 500, 502, 503, 504):
                break
            time.sleep(3 * (attempt + 1))
        else:
            raise _Unavailable(f"{p['name']} {body['model']}: unavailable ({last}) after retries")
    finally:
        llm_budget.release(run_id, est)
    raise RuntimeError(f"{p['name']}: model call failed ({last})")


def chat_json(prompt: str, *, system: str = "Answer with one JSON object only.", max_tokens: int = 2000, session=None,
              purpose: str = "chat", run_id: str = "adhoc", cache: bool = True, effort: str | None = None) -> tuple[dict, dict]:
    """One JSON call. Budget-checked before sending, recorded in the ledger after, cached by request hash.
    If the main provider's quota is used up, the next configured provider answers (and the meta says so)."""
    config.load_env()
    providers = _providers()
    if not providers:
        raise RuntimeError("no FM_API_KEY / DEEPSEEK_API_KEY (or fallback GOOGLE_API_KEY) in guardian/.env")
    if session is None:
        import requests
        session = requests.Session()
    quota_errors, other, noted = [], None, set()
    for p in providers:
        if time.time() - _EXHAUSTED.get(p["name"], -1e12) < EXHAUSTED_FOR:
            if p["name"] not in noted:
                quota_errors.append(f"{p['name']}: quota used up earlier")
                noted.add(p["name"])
            continue
        body = {"model": p["model"], "reasoning_effort": effort or os.environ.get("GUARDIAN_EFFORT", "medium"),
                "max_tokens": max_tokens * p.get("token_factor", 1),
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"}}
        try:
            data, meta = _call(p, body, session, run_id, purpose, cache)
        except _Quota as e:
            _EXHAUSTED[p["name"]] = time.time()
            quota_errors.append(str(e))
            continue
        except _Unavailable as e:
            other = str(e)
            quota_errors.append(str(e))
            continue
        if quota_errors:
            meta["note"] = f"fell back to {p['name']} {p['model']} because: {'; '.join(quota_errors)}"
        return data, meta
    if quota_errors and not other:
        raise RuntimeError("AI quota used up at the model provider(s): " + "; ".join(quota_errors))
    raise RuntimeError("AI providers unavailable: " + "; ".join(quota_errors) if quota_errors else (other or "model call failed"))


def usage_summary(run_id: str | None = None) -> dict:
    return llm_budget.summary(run_id)
