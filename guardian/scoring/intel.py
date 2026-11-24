"""Threat intelligence for scoring: CVSS vectors + CVE aliases (local OSV database), EPSS and CISA KEV.

Everything is cached under .cache/ so a demo works offline after one online run. Missing data stays
"unknown"; it is never guessed.
"""
from __future__ import annotations

import json
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".cache"
OSV_ZIP = CACHE / "osv" / "osv-scalibr" / "npm" / "all.zip"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DAY = 24 * 3600


def _read_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except Exception:
        return default


def _osv_api(vid: str) -> dict | None:
    """Non-npm advisories (PyPI, Go, Maven ...): the universal scanner's OSV.dev cache, else one API call."""
    try:
        from guardian.universal import _osv_get
        return _osv_get(vid)
    except Exception:
        return None


def osv_details(ids: list[str]) -> dict[str, dict]:
    """id -> {aliases, cvss_v3, cvss_v4, severity_label}: offline OSV copy (npm) first, then the OSV.dev API (cached)."""
    cache_p = CACHE / "osv-meta.json"
    cache = _read_json(cache_p, {})
    missing = [i for i in ids if i not in cache or not any(cache[i].values())]
    if missing:
        z = zipfile.ZipFile(OSV_ZIP) if OSV_ZIP.exists() else None
        names = set(z.namelist()) if z else set()
        for i in missing:
            rec = {"aliases": [], "cvss_v3": None, "cvss_v4": None, "severity_label": None}
            d = json.loads(z.read(f"{i}.json")) if f"{i}.json" in names else _osv_api(i)
            if d:
                rec["aliases"] = d.get("aliases") or []
                for s in d.get("severity") or []:
                    if s.get("type") == "CVSS_V3":
                        rec["cvss_v3"] = s.get("score")
                    elif s.get("type") == "CVSS_V4":
                        rec["cvss_v4"] = s.get("score")
                rec["severity_label"] = (d.get("database_specific") or {}).get("severity")
            cache[i] = rec
        CACHE.mkdir(exist_ok=True)
        cache_p.write_text(json.dumps(cache))
    return {i: cache.get(i, {"aliases": [], "cvss_v3": None, "cvss_v4": None, "severity_label": None}) for i in ids}


def epss(cves: list[str], max_age: float = DAY) -> tuple[dict[str, dict], str | None]:
    """CVE -> {epss, percentile, date}. Returns (data, error). Cached for a day."""
    cache_p = CACHE / "epss.json"
    cache = _read_json(cache_p, {"fetched": {}, "data": {}})
    now = time.time()
    todo = [c for c in cves if now - cache["fetched"].get(c, 0) > max_age]
    err = None
    if todo:
        try:
            import requests
            for i in range(0, len(todo), 80):
                chunk = todo[i:i + 80]
                r = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=20)
                r.raise_for_status()
                got = {row["cve"]: {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
                       for row in r.json().get("data", [])}
                for c in chunk:
                    cache["fetched"][c] = now
                    if c in got:
                        cache["data"][c] = got[c]
            CACHE.mkdir(exist_ok=True)
            cache_p.write_text(json.dumps(cache))
        except Exception as e:  # offline: use what is cached, report the gap
            err = f"EPSS unavailable ({type(e).__name__}); using cached values only"
    return {c: cache["data"][c] for c in cves if c in cache["data"]}, err


def kev(max_age: float = DAY) -> tuple[dict[str, dict], str | None]:
    """CVE -> {date_added, ransomware, name} from the CISA KEV catalog. Cached for a day."""
    cache_p = CACHE / "kev.json"
    cache = _read_json(cache_p, {"fetched": 0, "data": {}})
    err = None
    if time.time() - cache.get("fetched", 0) > max_age:
        try:
            import requests
            r = requests.get(KEV_URL, timeout=30)
            r.raise_for_status()
            cache = {"fetched": time.time(), "data": {
                v["cveID"]: {"date_added": v.get("dateAdded"), "ransomware": v.get("knownRansomwareCampaignUse"),
                             "name": v.get("vulnerabilityName")} for v in r.json().get("vulnerabilities", [])}}
            CACHE.mkdir(exist_ok=True)
            cache_p.write_text(json.dumps(cache))
        except Exception as e:
            err = f"KEV unavailable ({type(e).__name__}); using cached catalog" if cache["data"] else f"KEV unavailable ({type(e).__name__})"
    return cache["data"], err


def osv_affected(ids: list[str]) -> dict[str, list | None]:
    """advisory id -> OSV `affected[]` entries (name, ecosystem, ranges, versions); None when it could not be fetched.

    Same sources as `osv_details` (offline OSV copy first, then the OSV.dev API) and cached, so a demo works offline
    after one online run. A failed lookup is NOT cached and stays None: callers must say "unknown", not guess.
    """
    cache_p = CACHE / "osv-affected.json"
    cache = _read_json(cache_p, {})
    missing = [i for i in ids if i not in cache]
    if missing:
        z = zipfile.ZipFile(OSV_ZIP) if OSV_ZIP.exists() else None
        names = set(z.namelist()) if z else set()
        for i in missing:
            d = json.loads(z.read(f"{i}.json")) if f"{i}.json" in names else _osv_api(i)
            if d is not None:
                cache[i] = [{"ecosystem": (a.get("package") or {}).get("ecosystem"), "name": (a.get("package") or {}).get("name"),
                             "ranges": a.get("ranges") or [], "versions": a.get("versions") or []} for a in d.get("affected") or []]
        CACHE.mkdir(exist_ok=True)
        cache_p.write_text(json.dumps(cache))
    return {i: cache.get(i) for i in ids}
