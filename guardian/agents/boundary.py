"""Encode evidence and redact recognizable credentials at model and audit boundaries."""
from __future__ import annotations

import json
import re

MAX_EVIDENCE_CHARS = 12_000

_SECRETS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"), "[redacted private key]"),
    (re.compile(r"(?i)(https?://)[^/\s@]+:[^/\s@]+@"), r"\1[redacted]@"),
    (re.compile(r"(?i)(\b(?:bearer|basic)\s+)[a-z0-9._~+/=-]{8,}"), r"\1[redacted]"),
    (re.compile(r"(?i)((?:_authToken|_auth|_password|api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|token)[\"']?\s*[:=]\s*)"
                r"(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&\]}]+)"), r"\1[redacted]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b"), "[redacted]"),
)


def redact(text: str) -> str:
    """Remove common credential formats without inspecting process credentials."""
    for pattern, replacement in _SECRETS:
        text = pattern.sub(replacement, text)
    return text


def untrusted(data: object) -> str:
    """Encode data so its text cannot close the surrounding literal delimiter."""
    body = json.dumps(redact_message(data), ensure_ascii=True)
    return "<untrusted-data>\n" + body.replace("<", "\\u003c").replace(">", "\\u003e") + "\n</untrusted-data>"


def redact_message(data: object) -> object:
    """Preserve the shape of a structured tool call while redacting logged values."""
    if isinstance(data, str):
        return redact(data)
    if isinstance(data, dict):
        return {key: "[redacted]" if isinstance(value, str) and redact(f"{key}=placeholder") != f"{key}=placeholder"
                else redact_message(value) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_message(value) for value in data]
    return data
