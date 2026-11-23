"""Vulnerability scan of every package: OSV-Scanner (offline DB) + Grype (on the Syft SBOM), merged.

Two independent databases cross-check each other: an advisory found by both is stronger evidence,
and either one alone still counts. Advisories are merged per package version when their IDs or
aliases overlap (GHSA / CVE / MAL). Nothing here talks to the network: both DBs are local.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OSV_DB = ROOT / ".cache" / "osv"
LEVELS = ["info", "low", "medium", "high", "critical"]
GHSA_WORDS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _level_from_score(score) -> str | None:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else None


def _max(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def run_osv(lockfile: Path) -> list[dict]:
    env = {**os.environ, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(OSV_DB)}
    r = subprocess.run(["osv-scanner", "scan", "source", "--offline", "--format", "json", "-L", str(lockfile)],
                       capture_output=True, text=True, env=env, timeout=600)
    if r.returncode not in (0, 1):  # 1 = vulnerabilities found
        raise RuntimeError(f"osv-scanner failed ({r.returncode}): {r.stderr[-400:]}")
    data = json.loads(r.stdout or "{}")
    out = []
    for res in data.get("results", []):
        for p in res.get("packages", []):
            name, version = p["package"]["name"], p["package"]["version"]
            vulns = {v["id"]: v for v in p.get("vulnerabilities", [])}
            for grp in p.get("groups", []) or [{"ids": [i]} for i in vulns]:
                ids = list(dict.fromkeys(grp["ids"] + grp.get("aliases", [])))
                level = _level_from_score(grp.get("max_severity"))
                summary, fixed, url = "", [], None
                for i in grp["ids"]:
                    v = vulns.get(i, {})
                    summary = summary or v.get("summary", "")
                    word = (v.get("database_specific") or {}).get("severity")
                    if not level and word:
                        level = GHSA_WORDS.get(str(word).upper())
                    for aff in v.get("affected", []):
                        if aff.get("package", {}).get("name") == name:
                            for rg in aff.get("ranges", []):
                                fixed += [e["fixed"] for e in rg.get("events", []) if "fixed" in e]
                    url = url or next((ref["url"] for ref in v.get("references", []) if ref.get("type") == "ADVISORY"), None)
                malicious = any(i.startswith("MAL-") for i in ids)
                out.append({"name": name, "version": version, "ids": ids, "summary": summary[:200],
                            "severity": "critical" if malicious else (level or "medium"),
                            "fixed": sorted(set(fixed)), "malicious": malicious, "url": url, "source": "osv"})
    return out


def run_grype(sbom: Path) -> list[dict]:
    env = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    r = subprocess.run(["grype", f"sbom:{sbom}", "-o", "json", "-q"], capture_output=True, text=True, env=env, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"grype failed ({r.returncode}): {r.stderr[-400:]}")
    out = []
    for m in json.loads(r.stdout or "{}").get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        if a.get("type") not in (None, "npm"):
            continue
        ids = [v["id"]] + [x["id"] for x in m.get("relatedVulnerabilities", [])]
        out.append({"name": a["name"], "version": a["version"], "ids": list(dict.fromkeys(ids)),
                    "summary": (v.get("description") or "")[:200],
                    "severity": GHSA_WORDS.get(str(v.get("severity", "")).upper(), "medium"),
                    "fixed": (v.get("fix") or {}).get("versions", []), "malicious": False,
                    "url": v.get("dataSource"), "source": "grype"})
    return out


def merge(*lists: list[dict]) -> list[dict]:
    merged: list[dict] = []
    for rec in (r for lst in lists for r in lst):
        hit = next((m for m in merged if m["name"] == rec["name"] and m["version"] == rec["version"]
                    and set(m["ids"]) & set(rec["ids"])), None)
        if hit is None:
            merged.append({**rec, "sources": [rec["source"]]})
            continue
        hit["ids"] = list(dict.fromkeys(hit["ids"] + rec["ids"]))
        hit["severity"] = _max(hit["severity"], rec["severity"])
        hit["fixed"] = sorted(set(hit["fixed"]) | set(rec["fixed"]))
        hit["malicious"] = hit["malicious"] or rec["malicious"]
        hit["summary"] = hit["summary"] or rec["summary"]
        hit["url"] = hit["url"] or rec["url"]
        if rec["source"] not in hit["sources"]:
            hit["sources"].append(rec["source"])
    for m in merged:
        m.pop("source", None)
        m["id"] = next((i for i in m["ids"] if i.startswith("MAL-")), None) or \
            next((i for i in m["ids"] if i.startswith("GHSA-")), None) or m["ids"][0]
        m["key"] = f"{m['name']}@{m['version']}#{m['id']}"
    return sorted(merged, key=lambda m: (-LEVELS.index(m["severity"]), m["name"]))


def scan(lockfile: Path, sbom: Path | None, inventory: list[dict] | None = None) -> dict:
    errors = {}
    osv, grype = [], []
    try:
        osv = run_osv(lockfile)
    except Exception as e:  # report, don't hide: the UI shows which scanner failed
        errors["osv"] = str(e)
    if sbom:
        try:
            grype = run_grype(sbom)
        except Exception as e:
            errors["grype"] = str(e)
    vulns = merge(osv, grype)
    if inventory:
        idx = {(p["name"], p["version"]): p for p in inventory}
        for v in vulns:
            p = idx.get((v["name"], v["version"]), {})
            v["direct"], v["runtime"] = bool(p.get("direct")), bool(p.get("runtime"))
    return {"vulnerabilities": vulns, "errors": errors,
            "counts": {"osv": len(osv), "grype": len(grype), "merged": len(vulns),
                       "both": sum(1 for v in vulns if len(v["sources"]) == 2),
                       "packages": len({(v["name"], v["version"]) for v in vulns}),
                       "by_severity": {lv: sum(1 for v in vulns if v["severity"] == lv) for lv in LEVELS[::-1]}}}


def label(base: list[dict], head: list[dict]) -> list[dict]:
    """introduced / pre_existing for head findings; fixed for base-only findings."""
    bkeys = {v["key"] for v in base}
    hkeys = {v["key"] for v in head}
    out = [{**v, "label": "pre_existing" if v["key"] in bkeys else "introduced"} for v in head]
    out += [{**v, "label": "fixed"} for v in base if v["key"] not in hkeys]
    return out
