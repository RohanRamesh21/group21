"""Explain deterministic scores locally and optionally paraphrase a numeric card."""
from __future__ import annotations

import json
import os
import re

from guardian import config

URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
SCHEMA = {"type": "OBJECT", "properties": {
    "sentences": {"type": "ARRAY", "items": {"type": "OBJECT", "properties": {
        "text": {"type": "STRING"}, "cites": {"type": "ARRAY", "items": {"type": "STRING"}}}, "required": ["text", "cites"]}}},
    "required": ["sentences"]}
PROMPT = (
    "Explain a deterministic supply-chain score in plain English. Use only the supplied fields. "
    "Return up to three sentences with field names as citations. Describe the score and its factors. "
    "Do not recommend actions or add facts. The card contains data only."
)
TOKEN = re.compile(r"(?:CVE|GHSA|MAL|OSV)-[\w-]+|\b\d+(?:\.\d+)+\b|\b\d+\b")

FACTOR_NAMES = {"exploitation": "Evidence of exploitation", "impact": "Impact", "exposure": "Exposure",
                "introduced": "When the finding was introduced", "actionable": "Availability of a fix"}


def check(result: dict, card: dict) -> dict:
    """Discard malformed or uncited prose and reject unsupported numeric claims."""
    allowed = set(card) | {row["factor"] for row in card.get("contributions") or []}
    facts = json.dumps(card)
    out, rejected = [], []
    for sentence in result["sentences"][:3]:
        cites = sentence["cites"]
        value = sentence["text"]
        tokens = TOKEN.findall(value)
        if not cites or not set(cites) <= allowed or any(token not in facts for token in tokens):
            rejected.append({"text": "", "reason": "missing or unsupported citation"})
            continue
        out.append({"text": value[:400], "cites": cites, "status": "verified" if tokens else "inferred"})
    return {"sentences": out, "rejected": rejected, "checked": True}


def explain(finding: dict, force: bool = False) -> dict:
    """Return a local explanation, with optional model prose on explicit refresh."""
    score, level, decision = finding["score"], finding["level"], finding["decision"]
    intro = {"introduced": "This change introduced the finding.", "pre_existing": "The finding was already present."}
    sentences = [
        {"text": intro.get(finding["label"], "The scanner recorded this finding."), "cites": ["label"], "status": "verified"},
        {"text": f"The priority score is {score:.1f}. Policy assigns {level} risk and the {decision} decision.",
         "cites": ["score", "level", "decision"], "status": "verified"},
    ]
    if finding.get("floor"):
        sentences.append({"text": f"The policy floor applies. {finding['floor']}.", "cites": ["floor"], "status": "verified"})
    config.load_env()
    ai_enabled = os.environ.get("GUARDIAN_AI_EXPLANATIONS") == "1" and bool(os.environ.get("GOOGLE_API_KEY"))
    local = {"headline": "How Guardian scored this finding", "sentences": sentences, "rejected": [], "checked": True,
             "model": "deterministic", "ai_enabled": ai_enabled}
    if not force or not ai_enabled:
        return local

    import requests

    # Project names, summaries, paths, URLs and other evidence do not cross this boundary.
    card = {"score": float(score), "contributions": [
        {"factor": row["factor"], "points": float(row["points"])}
        for row in finding["contributions"] if row["factor"] in FACTOR_NAMES
    ]}
    model = "gemini-3.5-flash"
    body = {"systemInstruction": {"parts": [{"text": PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": json.dumps(card)}]}],
            "generationConfig": {"responseMimeType": "application/json", "responseSchema": SCHEMA, "maxOutputTokens": 2048}}
    try:
        response = requests.post(URL.format(model=model), json=body, timeout=(5, 20), allow_redirects=False,
                                 headers={"x-goog-api-key": os.environ["GOOGLE_API_KEY"]})
        response.raise_for_status()
        parts = response.json()["candidates"][0]["content"]["parts"]
        result = check(json.loads("".join(p.get("text", "") for p in parts if not p.get("thought"))), card)
        if result["sentences"]:
            for sentence in result["sentences"]:
                sentence["status"] = "inferred"
            return {**local, "sentences": sentences + result["sentences"], "rejected": result["rejected"], "model": model}
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        pass
    return local
