"""OSV-Scanner on the offline DB (npm fallback when the OSV.dev API is unreachable) and the merge of
advisory lists from several scanners: records for the same package version are merged when their IDs or
aliases overlap (GHSA / CVE / MAL); an advisory found by two scanners is stronger evidence.
"""
from __future__ import annotations

import json
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
    """OSV-Scanner on one lockfile, in the sandbox, against the offline DB in .cache/osv (no network)."""
    from guardian import sandbox

    if not OSV_DB.exists():
        raise RuntimeError("offline OSV DB missing (.cache/osv)")
    # mounted under its own file name: osv-scanner picks the lockfile parser from it
    r = sandbox.run("osv-scanner", ["scan", "source", "--offline", "--format", "json", "-L", "{" + lockfile.name + "}"],
                    inputs={lockfile.name: lockfile, "db": OSV_DB}, env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "{db}"},
                    timeout=600)
    if r.error or r.returncode not in (0, 1):  # 1 = vulnerabilities found
        raise RuntimeError(r.error or f"osv-scanner failed ({r.returncode}): {r.stderr[-400:]}")
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

