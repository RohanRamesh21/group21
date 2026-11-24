# READING GUIDE
# Text safety helpers used before model input and before displaying model output.
# Repository text and model replies are both untrusted. Pattern checks reduce risk; they do not prove a claim true.
#
"""Prompt-injection guardrails shared by every model path (defence in depth; the model never decides anything).

Input side (text written by third parties: package files, advisories, PR diffs, titles, READMEs):
- clean():  remove invisible / direction-override / Unicode tag characters and control bytes, neutralise any
            <untrusted-data> tag inside the text (a fake closing tag must not end the fence), cap the length.
- fence():  wrap cleaned text in a boundary-marked <untrusted-data> block. The boundary is derived from the content,
            so it is deterministic (cache + packet hashes stay stable) yet cannot be forged by the content itself.
- scan():   name injection attempts (instructions aimed at AI reviewers, role tokens, hidden characters). A hit is
            evidence for the Investigator and the human, never a reason to trust or distrust anything by itself.

Output side (what a model wrote, before anyone sees or uses it):
- check_output(): reason string when model text carries something no honest answer needs: role/fence tokens,
            markdown images or HTML (render-time exfiltration), links not present in the evidence, or directives to
            approve / merge / allow. Callers drop such text and record why.
"""
from __future__ import annotations

import hashlib
import re

INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
FENCE_TAG = re.compile(r"<\s*/?\s*untrusted-data\b[^>]*>", re.I)
ROLE_TOKENS = re.compile(r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[/?INST\]|<</?SYS>>|^\s*#{2,}\s*(?:system|assistant|developer)\b",
                         re.I | re.M)

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override_instructions", re.compile(r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,25}\b(?:instructions?|rules?|prompts?|guidelines|context|directions)\b", re.I)),
    ("role_reassignment", re.compile(r"\b(?:you are now|you're now|from now on,? you|act as (?:an?|the) |pretend (?:to be|you are)|new instructions?:|developer mode|jailbreak)", re.I)),
    ("addresses_ai", re.compile(r"\b(?:to|dear|attention|note for|message for|hey)\s+(?:the\s+)?(?:ai|llm|language model|assistant|agent|bot|reviewer|code agent|claude|gpt|chatgpt|copilot|gemini|deepseek)\b", re.I)),
    ("verdict_steering", re.compile(r"\b(?:mark|classify|report|treat|label|consider|rate)\s+(?:this|it|the\s+\w+|me)\s+(?:package\s+|change\s+|pr\s+)?as\s+(?:safe|benign|trusted|clean|harmless|legitimate|low[ -]risk)", re.I)),
    ("approval_steering", re.compile(r"\b(?:approve|merge|allow|whitelist|accept)\s+(?:this|the|my)\s+(?:pr|pull request|change|package|commit|patch|fix)\b|\bsafe to merge\b", re.I)),
    ("system_prompt_probe", re.compile(r"\b(?:system prompt|reveal (?:your|the) (?:prompt|instructions)|print (?:your|the) instructions)\b", re.I)),
    ("role_tokens", ROLE_TOKENS),
    ("fence_spoof", FENCE_TAG),
]

URL = re.compile(r"\b(?:https?|ftp|file|data|javascript):[^\s)\"'<>\]]+", re.I)
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(")
HTML_TAG = re.compile(r"<\s*(?:img|script|iframe|a|svg|object|embed|link|meta|style|form)\b", re.I)
DIRECTIVE = re.compile(r"\b(?:you should|please|we recommend|recommend(?:ed)?|go ahead and|it is safe to|safe to)\s+(?:approve|merge|allow|ship|accept|whitelist)\b|\b(?:approve|merge)\s+(?:this|the)\s+(?:pr|pull request|change|patch|fix)\b", re.I)


# Normalize untrusted text before packaging it; remove spoofed delimiters without treating content as instructions.
def clean(text: str, limit: int | None = None) -> str:
    """Untrusted text, safe to place inside a fence: no invisible characters, no fence tags, bounded size."""
    t = INVISIBLE.sub("", str(text or ""))
    t = CONTROL.sub("", t)
    t = FENCE_TAG.sub("[untrusted-data tag removed]", t)
    if limit is not None and len(t) > limit:
        t = t[:limit] + f" …[truncated, {len(t) - limit} more characters]"
    return t


# Derive a stable marker so identical evidence produces identical packet/cache identities.
def boundary(text: str) -> str:
    return hashlib.sha256(("guardian-fence|" + text).encode()).hexdigest()[:12]


# Make the trust boundary visible in a model request; this annotation is not an execution sandbox.
def fence(text: str, source: str = "third-party", limit: int | None = None) -> str:
    """Wrap untrusted text: <untrusted-data source=.. boundary=..> … </untrusted-data boundary=..>."""
    body = clean(text, limit)
    b = boundary(body)
    src = re.sub(r"[^\w.:/@-]", "_", source)[:80]
    return f'<untrusted-data source="{src}" boundary="{b}">\n{body}\n</untrusted-data boundary="{b}">'


# Return named warning signals for reviewers; a pattern match alone does not establish malicious intent.
def scan(text: str) -> list[dict]:
    """Injection attempts in third-party text: [{rule, match}] (empty when none)."""
    raw = str(text or "")
    hits = []
    if INVISIBLE.search(raw):
        hits.append({"rule": "hidden_characters", "match": f"{len(INVISIBLE.findall(raw))} invisible/format character(s)"})
    for name, rx in PATTERNS:
        m = rx.search(raw)
        if m:
            hits.append({"rule": name, "match": m.group(0)[:120]})
    return hits


# Return a rejection reason, or None; callers decide whether to omit and record the rejected text.
def check_output(text: str, evidence_text: str = "") -> str | None:
    """Why this model text must not be shown or used (None when it is fine)."""
    t = str(text or "")
    if FENCE_TAG.search(t) or ROLE_TOKENS.search(t):
        return "contains prompt-structure tokens (fence or role markers)"
    if MD_IMAGE.search(t) or HTML_TAG.search(t):
        return "contains markdown images or HTML (could load remote content when displayed)"
    for u in URL.findall(t):
        if u.rstrip(".,;:") not in evidence_text:
            return f"links to {u[:80]}, which is not in the evidence"
    if DIRECTIVE.search(t):
        return "tells the reader to approve or merge: decisions belong to the rules and the human"
    if INVISIBLE.search(t):
        return "contains invisible characters"
    return None
