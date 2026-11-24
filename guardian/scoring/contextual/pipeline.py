"""Attach evidence confidence, ranking sensitivity and fix forecasts to score cards."""
from __future__ import annotations

import json
import re
import zipfile

from guardian.scoring import intel
from guardian.scoring.contextual import confidence, fixrank, sensitivity


def _affected_from_cache(ids: set[str]) -> dict:
    """Use the same local advisory data as scoring. Fix forecasts do not make additional network calls."""
    from guardian.universal import CACHE

    def affected(record: dict) -> list[dict]:
        return [{**item, "name": (item.get("package") or {}).get("name")}
                for item in record.get("affected", [])
                if (item.get("package") or {}).get("ecosystem") == "npm"]

    records = {vid: affected(intel._read_json(CACHE / f"{vid}.json", {}))
               for vid in ids if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", vid)}
    if intel.OSV_ZIP.is_file() and any(not rows for rows in records.values()):
        with zipfile.ZipFile(intel.OSV_ZIP) as archive:
            names = set(archive.namelist())
            for vid, rows in records.items():
                if not rows and f"{vid}.json" in names:
                    records[vid] = affected(json.loads(archive.read(f"{vid}.json")))
    return records


def enrich(scores: dict, report: dict) -> dict:
    findings = scores["findings"]
    # Display IDs can repeat across file locations. Use the row position to track each finding's rank.
    rows = [{**finding, "id": f"{i:08d}"} for i, finding in enumerate(findings)]
    stability = sensitivity.rank_stability(rows)
    for finding, row in zip(findings, rows, strict=True):
        finding["confidence"] = confidence.confidence(finding, scores["data"]["errors"])
        finding["rank_stability"] = stability["per_finding"][row["id"]]

    relevant = [f for f in findings if f["label"] == "introduced" or f["level"] in {"high", "critical"}]
    ids = {v["id"] for v in report.get("vulnerabilities", []) if v.get("ecosystem") in {None, "npm"}
           and v.get("label") != "fixed"}
    try:
        affected = _affected_from_cache(ids)
    except (OSError, ValueError, zipfile.BadZipFile):
        affected = {}
    inventory = report.get("inventory", [])
    packages = {p["key"]: p for p in inventory}

    def direct_parents(key: str) -> list[str]:
        path = packages.get(key, {}).get("path") or []
        parent = packages.get(path[1], {}) if len(path) > 2 else {}
        return [f"{parent['name']}@{parent['version']}"] if parent else []

    ctx = fixrank.Ctx(findings, inventory, lambda keys: {key: affected.get(key) for key in keys}, direct_parents)
    for finding in relevant:
        finding["fix_candidates"] = fixrank.generate(finding, ctx)
    scores["rank_stability_summary"] = stability["summary"]
    scores["contextual"] = {
        "confidence_ahp": confidence.AHP,
        "fix_ahp": fixrank.AHP,
        "human_checks": [f["id"] for f in relevant
                         if f["label"] == "introduced" and f["level"] in {"high", "critical"} and f["confidence"]["band"] == "low"],
    }
    return scores
