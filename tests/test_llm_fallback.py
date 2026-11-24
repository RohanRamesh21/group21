"""When the main AI provider's quota is used up, calls fall back to the next configured provider (Gemini)."""
import json

import pytest

from tests.test_llm_freemodel import FakeResp

OK = {"choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 10, "completion_tokens": 2}}
QUOTA = {"error": {"message": "Your plan tokens are used up.", "code": "tokens_exhausted"}}


class Session:
    def __init__(self, replies):
        self.replies, self.sent = replies, []

    def post(self, url, json=None, timeout=None, headers=None):
        self.sent.append((url, json["model"]))
        code, body = self.replies[len(self.sent) - 1]
        return FakeResp(body, code=code)


@pytest.fixture
def env(monkeypatch):
    from guardian import llm_client
    monkeypatch.setattr(llm_client.config, "load_env", lambda: None)
    monkeypatch.setenv("FM_API_KEY", "fm_x")
    monkeypatch.setenv("GOOGLE_API_KEY", "g_x")
    monkeypatch.setenv("GUARDIAN_LLM_FALLBACK", "gemini")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)  # tests choose the providers explicitly
    llm_client._EXHAUSTED.clear()
    return llm_client


def test_quota_exhausted_falls_back_to_gemini(env):
    s = Session([(402, QUOTA), (200, OK)])
    data, meta = env.chat_json("p", session=s, max_tokens=50, cache=False)
    assert data == {"ok": True} and meta["provider"] == "gemini" and "fell back" in meta["note"]
    assert "freemodel.in" in s.sent[0][0] and "generativelanguage.googleapis.com" in s.sent[1][0]
    assert s.sent[1][1] == "gemini-2.5-flash"


def test_an_exhausted_provider_is_skipped_on_later_calls(env):
    env.chat_json("p1", session=Session([(402, QUOTA), (200, OK)]), max_tokens=50, cache=False)
    s = Session([(200, OK)])
    env.chat_json("p2", session=s, max_tokens=50, cache=False)
    assert len(s.sent) == 1 and "generativelanguage" in s.sent[0][0]


def test_all_providers_exhausted_names_each(env):
    s = Session([(402, QUOTA), (402, QUOTA)])
    with pytest.raises(RuntimeError, match="AI quota used up") as e:
        env.chat_json("p", session=s, max_tokens=50, cache=False)
    assert "freemodel" in str(e.value) and "gemini" in str(e.value)


def test_no_fallback_configured_keeps_old_behaviour(env, monkeypatch):
    monkeypatch.setenv("GUARDIAN_LLM_FALLBACK", "none")
    with pytest.raises(RuntimeError, match="AI quota used up"):
        env.chat_json("p", session=Session([(402, QUOTA)]), max_tokens=50, cache=False)


def test_gemini_gets_room_for_its_thinking_tokens(env):
    """Found live: gemini-2.5-flash counts hidden thinking in max_tokens; a 1,500 cap ended with finish_reason=length."""
    s = Session([(402, QUOTA), (200, OK)])
    sent = []
    orig = s.post
    s.post = lambda url, json=None, **k: (sent.append(json["max_tokens"]), orig(url, json=json, **k))[1]
    env.chat_json("p", session=s, max_tokens=1500, cache=False)
    assert sent == [1500, 6000]


def test_overloaded_provider_falls_through_to_the_next_model(env, monkeypatch):
    monkeypatch.setattr(env.time, "sleep", lambda s: None)
    s = Session([(402, QUOTA), (503, {}), (503, {}), (503, {}), (200, OK)])
    data, meta = env.chat_json("p", session=s, max_tokens=50, cache=False)
    assert meta["model"] == "gemini-3.5-flash" and [m for _, m in s.sent][-1] == "gemini-3.5-flash"


def test_an_empty_reply_is_not_retried_on_another_provider(env):
    empty = {"choices": [{"message": {"content": ""}, "finish_reason": "length"}], "usage": {"prompt_tokens": 5, "completion_tokens": 50}}
    s = Session([(200, empty)])
    with pytest.raises(RuntimeError, match="finish_reason=length"):
        env.chat_json("p", session=s, max_tokens=50, cache=False)
    assert len(s.sent) == 1


def test_deepseek_direct_is_the_main_provider_when_its_key_is_set(env, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk_x")
    s = Session([(200, OK)])
    data, meta = env.chat_json("p", session=s, max_tokens=50, cache=False)
    assert s.sent[0] == ("https://api.deepseek.com/chat/completions", "deepseek-flash") and meta["provider"] == "deepseek"
