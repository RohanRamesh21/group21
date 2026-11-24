# READING GUIDE
# Loads local environment configuration and selects a provider for callers that use this helper.
# Existing environment variables take precedence. Never include secret values in comments, logs or committed examples.
#
"""Load settings from guardian/.env (git-ignored, mode 600). Secrets are never printed or logged."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# Load configuration without replacing values already set in the process environment.
def load_env(path: Path = ROOT / ".env") -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


# Choose a configured backend; the demonstration fallback is explicit rather than a real scan result.
def provider() -> str:
    load_env()
    if os.environ.get("GUARDIAN_LLM_PROVIDER"):
        return os.environ["GUARDIAN_LLM_PROVIDER"]
    if os.environ.get("DEEPSEEK_API_KEY"):
        return "deepseek"
    if os.environ.get("FM_API_KEY"):
        return "freemodel"
    if os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    return "replay"
