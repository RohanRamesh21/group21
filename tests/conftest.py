"""Test safety net: no test may spend real model tokens.

Every test gets its own ledger and response cache, and any real HTTP request to the model provider fails.
Tests that exercise the client pass a fake session, which this guard does not touch.
"""
import pytest

MODEL_HOSTS = ("freemodel.in", "generativelanguage.googleapis.com", "openrouter.ai", "api.anthropic.com")


@pytest.fixture(autouse=True)
def _no_real_model_calls(monkeypatch, tmp_path):
    import requests

    monkeypatch.setenv("GUARDIAN_LEDGER", str(tmp_path / "_ledger.jsonl"))
    monkeypatch.setenv("GUARDIAN_LLM_CACHE", str(tmp_path / "_llm_cache"))
    real = requests.Session.request

    def guarded(self, method, url, *a, **k):
        if any(h in str(url) for h in MODEL_HOSTS):
            raise RuntimeError(f"test tried a real model call to {url}")
        return real(self, method, url, *a, **k)

    monkeypatch.setattr(requests.Session, "request", guarded)
