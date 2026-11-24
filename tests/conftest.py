"""Test safety net: no test may spend real model tokens.

Every test gets its own ledger and response cache, and any real HTTP request to the model provider fails.
Tests that exercise the client pass a fake session, which this guard does not touch.
"""
import pytest

MODEL_HOSTS = ("freemodel.in", "api.deepseek.com", "generativelanguage.googleapis.com", "openrouter.ai", "api.anthropic.com")


@pytest.fixture(autouse=True)
def _no_real_model_calls(monkeypatch, tmp_path):
    import requests

    monkeypatch.setenv("GUARDIAN_LEDGER", str(tmp_path / "_ledger.jsonl"))
    # Real AI keys from guardian/.env must not leak into tests: load_env() only fills MISSING variables, so empty values
    # keep these providers off unless a test sets them on purpose.
    for k in ("DEEPSEEK_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.setenv(k, "")
    monkeypatch.setenv("GUARDIAN_LLM_CACHE", str(tmp_path / "_llm_cache"))
    real = requests.Session.request

    def guarded(self, method, url, *a, **k):
        if any(h in str(url) for h in MODEL_HOSTS):
            raise RuntimeError(f"test tried a real model call to {url}")
        return real(self, method, url, *a, **k)

    monkeypatch.setattr(requests.Session, "request", guarded)
    from guardian import llm_client
    llm_client._EXHAUSTED.clear()  # provider quota state must not leak between tests
