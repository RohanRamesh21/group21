# READING GUIDE
# Model adapters for tool-using agents: normalize provider replies into a Turn containing text and ToolCall objects.
# This differs from llm_client.py, which handles the normal workflow JSON requests without a growing tool conversation.
# ScriptedBackend replays recorded turns without an AI service; a replay is demonstration data, not a live investigation.
#
"""Model back ends for the agents.

ClaudeBackend  real agents on Claude Opus 5.5 (Messages API, manual tool loop so the
               orchestrator can apply the constitution and budgets on every step).
ScriptedBackend replays recorded agent turns: lets the full loop run and be tested without
               an API key, and gives a reproducible demo replay if the venue network fails.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Protocol

MODEL = "claude-opus-5-5"


# Normalized model request: a tool name, call ID and argument object.
@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


# Normalized assistant turn, including provider-formatted history and requested tool calls.
@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    raw_content: list = field(default_factory=list)  # appended back unchanged (keeps thinking blocks intact)


# Shared interface: one step consumes history and returns a Turn, regardless of provider.
class Backend(Protocol):
    def step(self, agent: str, system: str, messages: list, tools: list[dict], effort: str) -> Turn: ...


# Adapter for Anthropic-style model responses and tool turns.
class ClaudeBackend:
    """Claude Opus 5.5: adaptive thinking is always on; depth is set with output_config.effort.
    No temperature (rejected by this model) and no forced tool_choice (rejected too)."""

    def __init__(self):
        import anthropic

        self.client = anthropic.Anthropic()  # credentials from the environment (ANTHROPIC_API_KEY or an ant profile)

    def step(self, agent, system, messages, tools, effort):
        resp = self.client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=tools,
            messages=messages,
            output_config={"effort": effort},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",  # security content can trip classifiers; let the API route a declined turn
        )
        if resp.stop_reason == "refusal":
            return Turn(text="(model declined this turn)", tool_calls=[], stop_reason="refusal", raw_content=resp.content)
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in resp.content if b.type == "tool_use"]
        text = "".join(b.text for b in resp.content if b.type == "text")
        return Turn(text=text, tool_calls=calls, stop_reason=resp.stop_reason, raw_content=resp.content)


# Adapter that converts tools/messages to an OpenAI-compatible provider request.
class OpenRouterBackend:
    """Claude Opus 5.5 through OpenRouter (OpenAI-style chat completions with tool calling).

    The agent history is kept in one neutral shape (user text, assistant blocks, tool results)
    and translated to OpenRouter's message format on every step. No temperature is sent.
    """

    URL = "https://openrouter.ai/api/v1/chat/completions"
    MODEL = "anthropic/claude-opus-5.5"

    def __init__(self, model: str | None = None, timeout: int = 180):
        import os

        import requests

        self.session = requests.Session()
        self.key = os.environ["OPENROUTER_API_KEY"]
        self.model = model or os.environ.get("GUARDIAN_MODEL", self.MODEL)
        self.timeout = timeout
        self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}

    @staticmethod
    def _to_openai(system: str, messages: list) -> list:
        out = [{"role": "system", "content": system}]
        for m in messages:
            content = m["content"]
            if m["role"] == "user" and isinstance(content, str):
                out.append({"role": "user", "content": content})
            elif m["role"] == "user":  # tool results
                for r in content:
                    out.append({"role": "tool", "tool_call_id": r["tool_use_id"], "content": r["content"]})
            else:  # assistant blocks
                text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
                calls = [{"id": b["id"], "type": "function",
                          "function": {"name": b["name"], "arguments": json.dumps(b["input"])},
                          # Gemini 3 needs its thought signature sent back with each tool call
                          **({"extra_content": b["extra_content"]} if b.get("extra_content") else {})}
                         for b in content if b.get("type") == "tool_use"]
                msg = {"role": "assistant", "content": text or None}
                if calls:
                    msg["tool_calls"] = calls
                out.append(msg)
        return out

    @staticmethod
    def _tools(tools: list[dict]) -> list[dict]:
        return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                  "parameters": t["input_schema"]}} for t in tools]

    def step(self, agent, system, messages, tools, effort):
        body = {
            "model": self.model,
            "messages": self._to_openai(system, messages),
            "tools": self._tools(tools),
            "tool_choice": "auto",
            "max_tokens": 16000,
            "reasoning": {"effort": effort},
        }
        last_err = None
        for attempt in range(3):
            r = self.session.post(self.URL, json=body, timeout=self.timeout, headers={
                "Authorization": f"Bearer {self.key}", "X-Title": "Bosch Supply Chain Guardian (hackathon)"})
            if r.status_code == 200:
                break
            last_err = f"HTTP {r.status_code}: {r.text[:300]}"
            if r.status_code not in (429, 500, 502, 503, 504):
                raise RuntimeError(f"OpenRouter error {last_err}")
            import time
            time.sleep(2 * (attempt + 1))
        else:
            raise RuntimeError(f"OpenRouter error after retries: {last_err}")
        return self._parse_openai(r.json())

    def _parse_openai(self, data: dict) -> "Turn":
        u = data.get("usage") or {}
        self.usage["calls"] += 1
        self.usage["prompt_tokens"] += u.get("prompt_tokens", 0)
        self.usage["completion_tokens"] += u.get("completion_tokens", 0)
        choice = data["choices"][0]
        msg = choice["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_invalid_json": tc["function"].get("arguments", "")[:200]}
            calls.append(ToolCall(tc["id"], tc["function"]["name"], args))
        text = msg.get("content") or ""
        extra = {tc["id"]: tc.get("extra_content") for tc in msg.get("tool_calls") or []}
        raw = ([{"type": "text", "text": text}] if text else []) + \
              [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input,
                **({"extra_content": extra[c.id]} if extra.get(c.id) else {})} for c in calls]
        stop = "tool_use" if calls else ("refusal" if choice.get("finish_reason") == "content_filter" else "end_turn")
        return Turn(text=text, tool_calls=calls, stop_reason=stop, raw_content=raw or [{"type": "text", "text": ""}])


# Provider-specific request handling built on the compatible tool-call adapter.
class FreeModelBackend(OpenRouterBackend):
    """DeepSeek V4 Flash through FreeModel's OpenAI-compatible endpoint (freemodel.in), reasoning_effort per agent."""

    URL = "https://freemodel.in/v1/chat/completions"
    MODEL = "deepseek-v4-flash-0731"
    KEY_ENV = "FM_API_KEY"
    MODEL_ENV = "GUARDIAN_MODEL"
    LABEL = "FreeModel"

    def __init__(self, model: str | None = None, timeout: int = 240):
        import os

        import requests

        from guardian import config
        config.load_env()
        self.session = requests.Session()
        self.key = os.environ[self.KEY_ENV]
        self.model = model or os.environ.get(self.MODEL_ENV, self.MODEL)
        self.timeout = timeout
        self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
        self.effort = os.environ.get("GUARDIAN_EFFORT")
        self.run_id = f"deep-{int(__import__('time').time())}"

    def step(self, agent, system, messages, tools, effort):
        import json as _json

        from guardian import llm_budget
        body = {"model": self.model, "messages": self._to_openai(system, messages), "tools": self._tools(tools),
                "tool_choice": "auto", "max_tokens": 8000, "reasoning_effort": self.effort or effort}
        est = llm_budget.estimate(_json.dumps(body["messages"]) + _json.dumps(body["tools"]), body["max_tokens"])
        llm_budget.reserve(self.run_id, est)  # deep mode is budgeted like everything else
        try:
            return self._send(agent, body)
        finally:
            llm_budget.release(self.run_id, est)

    def _send(self, agent, body):
        import time

        from guardian import llm_budget
        last, t0 = None, time.time()
        for attempt in range(4):
            r = self.session.post(self.URL, json=body, timeout=self.timeout,
                                  headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
            if r.status_code == 200:
                break
            last = f"HTTP {r.status_code}: {r.text[:200]}"
            if r.status_code not in (429, 500, 502, 503, 504):
                raise RuntimeError(f"{self.LABEL} error {last}")
            time.sleep(3 * (attempt + 1))
        else:
            raise RuntimeError(f"{self.LABEL} error after retries: {last}")
        data = r.json()
        llm_budget.record(run_id=self.run_id, purpose=f"deep:{agent}", model=self.model, usage=data.get("usage"),
                          cached=False, seconds=time.time() - t0)
        return self._parse_openai(data)


# Provider specialization that reuses compatible tool-call handling.
class DeepSeekBackend(FreeModelBackend):
    """DeepSeek's own API (OpenAI-compatible, tool calling), V4 Flash."""

    URL = "https://api.deepseek.com/chat/completions"
    MODEL = "deepseek-flash"
    KEY_ENV = "DEEPSEEK_API_KEY"
    MODEL_ENV = "GUARDIAN_DEEPSEEK_MODEL"
    LABEL = "DeepSeek"


# Try the configured tool-capable backends in order when an eligible provider fails.
class FallbackBackend:
    """Tries each back end in order; moves on only when a provider's quota is used up (HTTP 402) or it stays
    unavailable after retries (429/5xx). A provider that ran out is skipped for the rest of this run.
    Any other error (bad request, parse error) is raised, not hidden behind another provider."""

    def __init__(self, chain: list[tuple[str, object]]):
        self.chain, self.used, self.skipped = chain, [], set()

    @property
    def usage(self):
        return {"calls": sum(getattr(b, "usage", {}).get("calls", 0) for _, b in self.chain)}

    def step(self, agent, system, messages, tools, effort):
        last = None
        for name, be in self.chain:
            if name in self.skipped:
                continue
            try:
                turn = be.step(agent, system, messages, tools, effort)
                self.used.append(name)
                return turn
            except RuntimeError as e:
                msg = str(e)
                if "HTTP 402" in msg or "after retries" in msg:
                    self.skipped.add(name)
                    last = e
                    continue
                raise
        raise last or RuntimeError("no AI back end available")


# Translate tool conversations and provider-specific replies for Gemini.
class GeminiBackend(OpenRouterBackend):
    """Google Gemini through its OpenAI-compatible endpoint (same message translation as OpenRouter).

    Tries GUARDIAN_MODEL first (default gemini-3.5-flash), then the fallback models in order when Google
    reports overload (503) or quota (429). The model that answered each step is recorded in `self.used`.
    """

    URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    MODEL = "gemini-3.5-flash"
    FALLBACKS = ("gemini-2.5-flash",)

    def __init__(self, model: str | None = None, timeout: int = 180):
        import os

        import requests

        from guardian import config

        config.load_env()  # the key lives in guardian/.env (git-ignored, mode 600)
        self.session = requests.Session()
        self.key = os.environ["GOOGLE_API_KEY"]
        self.model = model or os.environ.get("GUARDIAN_MODEL", self.MODEL)
        extra = [m.strip() for m in os.environ.get("GUARDIAN_FALLBACK_MODELS", "").split(",") if m.strip()]
        self.models = [self.model] + [m for m in (extra or list(self.FALLBACKS)) if m != self.model]
        self.timeout = timeout
        self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
        self.used: dict[str, int] = {}
        self.sticky: dict[str, str] = {}

    # Gemini 3 requires a thought signature on function calls in the history. Calls produced by a model that
    # gives none (e.g. a fallback model) get Google's documented placeholder so the history stays valid.
    SKIP_SIG = {"google": {"thought_signature": "skip_thought_signature_validator"}}

    def _to_openai(self, system: str, messages: list) -> list:
        out = OpenRouterBackend._to_openai(system, messages)
        for m in out:
            for tc in m.get("tool_calls") or []:
                tc.setdefault("extra_content", self.SKIP_SIG)
        return out

    step_timeout = 120  # seconds per call before falling back to the next model

    def step(self, agent, system, messages, tools, effort):
        import time

        import requests

        effort = {"max": "high", "xhigh": "high"}.get(effort, effort)
        last_err = None
        sticky = self.sticky.get(agent)  # once an agent falls back, it stays on that model (keeps its history valid)
        order = [sticky] + [m for m in self.models if m != sticky] if sticky else self.models
        for model in order:
            body = {"model": model, "messages": self._to_openai(system, messages), "tools": self._tools(tools),
                    "tool_choice": "auto", "max_tokens": 16000, "reasoning_effort": effort}
            for attempt in range(4):
                try:
                    r = self.session.post(self.URL, json=body, timeout=self.step_timeout,
                                          headers={"Authorization": f"Bearer {self.key}"})
                except requests.RequestException as e:  # slow or dropped: move on to the next model
                    last_err = f"{model}: {type(e).__name__}"
                    break
                if r.status_code == 200:
                    self.used[model] = self.used.get(model, 0) + 1
                    if model != self.models[0]:
                        self.sticky[agent] = model
                    return self._parse(r.json())
                last_err = f"{model} HTTP {r.status_code}: {r.text[:300]}"
                if r.status_code == 404:  # model retired or not available to this key: try the next one
                    break
                if r.status_code == 429:
                    wait = self._retry_delay(r)
                    if wait is None or wait > 65:  # daily quota used up: next model
                        break
                    time.sleep(wait + 1)  # per-minute limit: wait as Google asks, then retry the same model
                    continue
                if r.status_code not in (500, 502, 503, 504):
                    raise RuntimeError(f"Gemini error {last_err}")
                time.sleep(3 * (attempt + 1))
        raise RuntimeError(f"Gemini error after trying {', '.join(order)}: {last_err}")

    @staticmethod
    def _retry_delay(r) -> float | None:
        """Seconds Google asks us to wait (RetryInfo), or None if it gives no hint."""
        try:
            body = r.json()
            err = body[0]["error"] if isinstance(body, list) else body["error"]
            for d in err.get("details", []):
                if d.get("retryDelay"):
                    return float(str(d["retryDelay"]).rstrip("s"))
        except Exception:
            return None
        return None

    def _parse(self, data: dict) -> Turn:
        u = data.get("usage") or {}
        self.usage["calls"] += 1
        self.usage["prompt_tokens"] += u.get("prompt_tokens", 0)
        self.usage["completion_tokens"] += u.get("completion_tokens", 0)
        choice = data["choices"][0]
        msg = choice["message"]
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            tc.setdefault("id", f"call_{self.usage['calls']}_{i}")
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_invalid_json": tc["function"].get("arguments", "")[:200]}
            calls.append(ToolCall(tc["id"], tc["function"]["name"], args))
        text = msg.get("content") or ""
        extra = {tc["id"]: tc.get("extra_content") for tc in msg.get("tool_calls") or []}
        raw = ([{"type": "text", "text": text}] if text else []) + \
              [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input,
                **({"extra_content": extra[c.id]} if extra.get(c.id) else {})} for c in calls]
        stop = "tool_use" if calls else ("refusal" if choice.get("finish_reason") == "content_filter" else "end_turn")
        return Turn(text=text, tool_calls=calls, stop_reason=stop, raw_content=raw or [{"type": "text", "text": ""}])


# Construct the configured live backend or fallback chain; credentials remain in configuration.
def make_backend(provider: str):
    """One place that turns the configured provider name (guardian.config.provider()) into a model back end.
    DeepSeek / FreeModel / Gemini become a fallback chain: DeepSeek first when its key is set, then FreeModel, then Gemini."""
    import os

    from guardian import config
    config.load_env()
    if provider in ("deepseek", "freemodel", "gemini", "auto"):
        chain = []
        if os.environ.get("DEEPSEEK_API_KEY"):
            chain.append(("deepseek", DeepSeekBackend()))
        if os.environ.get("FM_API_KEY"):
            chain.append(("freemodel", FreeModelBackend()))
        if os.environ.get("GOOGLE_API_KEY"):
            chain.append(("gemini", GeminiBackend()))
        if chain:
            return FallbackBackend(chain)
    if provider == "openrouter":
        return OpenRouterBackend()
    if provider == "claude":
        return ClaudeBackend()
    raise RuntimeError(f"no LLM provider configured (got '{provider}'): set a key in guardian/.env or use a scripted/rule-based mode")


# Serve prerecorded agent turns for deterministic demonstrations and tests.
class ScriptedBackend:
    """Replays a script: {agent: [turn, ...]} where a turn is a list of [tool_name, input] pairs
    (empty list = the agent ends its turn). Inputs may contain placeholders resolved at runtime:
      {E:key}        canned evidence id        {F:type}  finding id by type
      {T:assignee}   latest task for assignee  {C:last}  latest case id
      {E:human}      evidence of the last ask_human answer
    """

    def __init__(self, script: dict[str, list], resolver):
        self.queues = {k: list(v) for k, v in script.items()}
        self.resolver = resolver
        self.n = 0

    def step(self, agent, system, messages, tools, effort):
        queue = self.queues.get(agent) or []
        turn = queue.pop(0) if queue else []
        calls = []
        for name, args in turn:
            self.n += 1
            calls.append(ToolCall(f"toolu_s{self.n:04d}", name, self.resolver(args)))
        raw = [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls] or \
              [{"type": "text", "text": "done"}]
        return Turn(text="" if calls else "done", tool_calls=calls,
                    stop_reason="tool_use" if calls else "end_turn", raw_content=raw)


_PLACEHOLDER = re.compile(r"\{([ETFC]):([^}]+)\}")


# Replace replay placeholders with IDs from this Board/world/store, not invented evidence.
def make_resolver(board, world, store):
    def resolve_str(s: str) -> str:
        def sub(m):
            kind, key = m.group(1), m.group(2)
            if kind == "E" and key == "human":
                return next(e["evidence"] for e in reversed(board.audit) if e.get("event") == "ask_human")
            if kind == "E":
                return world["evidence"][key]
            if kind == "F":
                return next(f.id for f in board.findings.values() if f.type == key)
            if kind == "T":
                return [t.id for t in board.tasks.values() if t.assignee == key][-1]
            if kind == "C":
                return list(board.cases)[-1]
            return m.group(0)
        return _PLACEHOLDER.sub(sub, s)

    def resolve(obj):
        if isinstance(obj, str):
            return resolve_str(obj)
        if isinstance(obj, list):
            return [resolve(x) for x in obj]
        if isinstance(obj, dict):
            return {k: resolve(v) for k, v in obj.items()}
        return obj

    return resolve


# Load the recorded replay data used by ScriptedBackend.
def load_script(path: str) -> dict:
    return json.loads(open(path).read())
