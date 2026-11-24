"""Tool-using agents (e.g. the AHP Scoring Advisor) use DeepSeek first and fall back on quota/outage, like chat_json."""
import pytest


class Fake:
    def __init__(self, name, error=None):
        self.name, self.error, self.calls = name, error, 0

    def step(self, agent, system, messages, tools, effort):
        self.calls += 1
        if self.error:
            raise RuntimeError(self.error)
        return f"turn from {self.name}"


def test_quota_error_moves_to_the_next_backend_and_remembers_it():
    from guardian.agents.llm import FallbackBackend
    a = Fake("freemodel", 'FreeModel error HTTP 402: {"error": {"message": "Your plan tokens are used up."}}')
    b = Fake("deepseek")
    fb = FallbackBackend([("freemodel", a), ("deepseek", b)])
    assert fb.step("x", "s", [], [], "medium") == "turn from deepseek"
    assert fb.step("x", "s", [], [], "medium") == "turn from deepseek" and a.calls == 1  # exhausted one is skipped
    assert fb.used == ["deepseek", "deepseek"]


def test_other_errors_are_not_hidden_by_a_fallback():
    from guardian.agents.llm import FallbackBackend
    fb = FallbackBackend([("deepseek", Fake("deepseek", "DeepSeek error HTTP 400: bad request")), ("gemini", Fake("gemini"))])
    with pytest.raises(RuntimeError, match="HTTP 400"):
        fb.step("x", "s", [], [], "medium")


def test_make_backend_puts_deepseek_first_when_its_key_is_set(monkeypatch):
    from guardian.agents import llm
    monkeypatch.setattr(llm, "_load_env", lambda: None, raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk_x")
    monkeypatch.setenv("FM_API_KEY", "fm_x")
    monkeypatch.setenv("GOOGLE_API_KEY", "g_x")
    be = llm.make_backend("freemodel")
    assert [n for n, _ in be.chain] == ["deepseek", "freemodel", "gemini"]
    assert be.chain[0][1].URL == "https://api.deepseek.com/chat/completions" and be.chain[0][1].model == "deepseek-flash"
