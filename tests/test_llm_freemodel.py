"""FreeModel (OpenAI-compatible) provider: DeepSeek V4 Flash with reasoning_effort, used by agents and explanations."""
import json

import pytest


class FakeResp:
    def __init__(self, data, code=200):
        self.status_code, self._d, self.text = code, data, json.dumps(data)

    def json(self):
        return self._d


class FakeSession:
    def __init__(self, data):
        self.data, self.sent = data, []

    def post(self, url, json=None, timeout=None, headers=None):
        self.sent.append((url, json, headers))
        return FakeResp(self.data)


REPLY = {"choices": [{"message": {"content": '```json\n{"headline": "h", "sentences": []}\n```'}, "finish_reason": "stop"}],
         "usage": {"prompt_tokens": 100, "completion_tokens": 20}}


def test_chat_json_uses_freemodel_with_medium_reasoning(monkeypatch):
    from guardian import llm_client
    monkeypatch.setenv("FM_API_KEY", "fm_test")
    monkeypatch.setenv("GUARDIAN_MODEL", "deepseek-v4-flash-0731")
    monkeypatch.setenv("GUARDIAN_EFFORT", "medium")
    s = FakeSession(REPLY)
    data, meta = llm_client.chat_json("prompt", session=s)
    url, body, headers = s.sent[0]
    assert url == "https://freemodel.in/v1/chat/completions" and body["model"] == "deepseek-v4-flash-0731"
    assert body["reasoning_effort"] == "medium" and headers["Authorization"] == "Bearer fm_test"
    assert data == {"headline": "h", "sentences": []} and meta["usage"]["prompt_tokens"] == 100


def test_chat_json_without_key_raises(monkeypatch):
    from guardian import llm_client
    monkeypatch.delenv("FM_API_KEY", raising=False)
    monkeypatch.setattr(llm_client.config, "load_env", lambda: None)
    with pytest.raises(RuntimeError, match="FM_API_KEY"):
        llm_client.chat_json("p", session=FakeSession(REPLY))


def test_agent_backend_sends_tools_and_reasoning_effort(monkeypatch):
    from guardian.agents.llm import FreeModelBackend
    monkeypatch.setenv("FM_API_KEY", "fm_test")
    monkeypatch.setenv("GUARDIAN_MODEL", "deepseek-v4-flash-0731")
    b = FreeModelBackend()
    b.session = FakeSession({"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "board_view", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1}})
    t = b.step("lead", "sys", [{"role": "user", "content": "go"}],
               [{"name": "board_view", "description": "d", "input_schema": {"type": "object", "properties": {}}}], "medium")
    url, body, _ = b.session.sent[0]
    assert url == "https://freemodel.in/v1/chat/completions" and body["reasoning_effort"] == "medium" and "reasoning" not in body
    assert t.tool_calls[0].name == "board_view" and b.usage["calls"] == 1


def test_explain_routes_to_freemodel_when_selected(monkeypatch, tmp_path):
    from guardian.scoring import explain as ex
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "freemodel")
    monkeypatch.setattr(ex, "CACHE", tmp_path)
    monkeypatch.setattr(ex.llm_client, "chat_json", lambda prompt, **k: (
        {"headline": "Malware added", "sentences": [{"text": "It scored 100.", "cites": ["score"]}]}, {"model": "deepseek-v4-flash-0731"}))
    f = {"title": "axois@1.0.0: MAL-1", "kind": "vulnerability", "component": "axois@1.0.0", "label": "introduced",
         "decision": "Act", "level": "critical", "score": 100, "ssvc": None, "floor": "malware", "contributions": [],
         "counterfactuals": [], "evidence": {"advisory": "MAL-1"}, "summary": ""}
    r = ex.explain(f, force=True)
    assert r["model"] == "deepseek-v4-flash-0731" and r["sentences"][0]["status"] == "inferred"


def test_backend_loads_env_file_itself(monkeypatch):
    from guardian import config
    from guardian.agents.llm import FreeModelBackend
    monkeypatch.delenv("FM_API_KEY", raising=False)
    monkeypatch.setattr(config, "load_env", lambda: monkeypatch.setenv("FM_API_KEY", "fm_from_env_file"))
    assert FreeModelBackend().key == "fm_from_env_file"
