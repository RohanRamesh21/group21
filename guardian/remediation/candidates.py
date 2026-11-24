"""Deterministic fix candidates (stage ⑧). No AI: agents may explain or challenge these, never invent versions.

Each candidate covers a group of findings (all findings of one package, or one config file) and carries:
expected risk reduction (findings removed, per level: a forecast), compatibility, rollback and data sources.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from guardian.remediation.versions import jump, smallest_safe

ROOT = Path(__file__).resolve().parents[2]
REG_CACHE = ROOT / ".cache" / "registry"
SOURCE_TAMPER_TYPES = {"untrusted_source", "lockfile_tamper"}  # where it comes from / its hash, not what it is
HARD_TYPES = {"typosquat", "untrusted_source", "lockfile_tamper", "new_install_script", "install_script", "malicious",
              "unresolvable_dependency"}  # new_dependency is informational, not hard
CONFIG_TYPES = {"source_change", "sensitive_file_change", "extra_index_url", "modified_lockfile"}
JUMP_RANK = {"patch": 0, "minor": 1, "major": 2, None: 3}


@dataclass
class Sources:
    """Data access, injected so tests use fixtures and production uses the real registry and OSV."""
    versions: Callable[[str], tuple[dict, dict | None]]      # package -> ({version: meta}, {url, sha256})
    advisory: Callable[[str], tuple[dict | None, dict | None]]  # advisory id -> (OSV record, {url, sha256})


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def npm_versions(pkg: str, max_age: float = 86400) -> tuple[dict, dict | None]:
    """Published versions from registry.npmjs.org (cached one day). Returns ({version: {deprecated}}, source)."""
    import requests
    url = f"https://registry.npmjs.org/{pkg.replace('/', '%2F')}"
    f = REG_CACHE / (pkg.replace("/", "__") + ".json")
    if f.exists() and time.time() - f.stat().st_mtime < max_age:
        text = f.read_text()
    else:
        r = requests.get(url, timeout=30, headers={"Accept": "application/json"})
        if r.status_code != 200:
            return {}, None
        text = r.text
        REG_CACHE.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    data = json.loads(text)
    vers = {v: {"deprecated": meta.get("deprecated")} for v, meta in (data.get("versions") or {}).items()}
    return vers, {"url": url, "sha256": _sha(text), "cached_at": int(f.stat().st_mtime)}


def osv_advisory(vid: str) -> tuple[dict | None, dict | None]:
    from guardian.universal import _osv_get
    rec = _osv_get(vid)
    if not rec:
        return None, None
    return rec, {"url": f"https://api.osv.dev/v1/vulns/{vid}", "sha256": _sha(json.dumps(rec, sort_keys=True))}


def live_sources() -> Sources:
    return Sources(versions=npm_versions, advisory=osv_advisory)


def _split(component: str) -> tuple[str, str]:
    comp = component.replace("pkg:npm/", "").replace("%40", "@")
    if "@" in comp[1:]:
        name, ver = comp.rsplit("@", 1)
        return name, ver
    return comp, ""


def _reduction(findings: list[dict]) -> dict:
    out = {lv: 0 for lv in ("critical", "high", "medium", "low")}
    for f in findings:
        if f["level"] in out:
            out[f["level"]] += 1
    return out


def _base(ctype: str, group: list[dict], **kw) -> dict:
    ids = sorted(f["id"] for f in group)
    c = {"id": "FIX-" + hashlib.sha256("|".join([ctype] + ids).encode()).hexdigest()[:10], "type": ctype,
         "finding_ids": ids, "expected_risk_reduction": _reduction(group), "forecast": True,
         "approval_required": True, "resolves_target": ctype != "escalate", "semver_jump": None,
         "lock_changes": 1, "rollback_ease": 1, "sources": []}
    c.update(kw)
    return c


def _package_candidate(name: str, ver: str, group: list[dict], report: dict, src: Sources) -> dict:
    inv = {(p["name"], p.get("version")): p for p in report.get("inventory", [])}
    p = inv.get((name, ver), {})
    added = any(a.rsplit("@", 1)[0] == name for a in (report.get("package_changes") or {}).get("added", []))
    types = {f.get("type") for f in group}
    malicious = any(f["kind"] == "vulnerability" and str((f.get("evidence") or {}).get("advisory", "")).startswith("MAL-") for f in group)
    if malicious or (types & HARD_TYPES and any(f["label"] == "introduced" for f in group)):
        if added or malicious:
            return _base("remove_package", group, package=name, version=ver,
                         rationale="the change adds a package with hard supply-chain signals"
                                   + (" and a known-malware record" if malicious else "") + "; remove it",
                         compatibility={"note": "nothing in the base revision depends on it" if added else "check usages before removing"},
                         rollback="git revert the fix commit (restores package.json and package-lock.json)")
        if types <= SOURCE_TAMPER_TYPES:
            # same package and version as before, only its download source / integrity hash changed: put back the
            # lockfile entry the base commit had (the reviewed state). No new version, nothing guessed.
            return _base("restore_lock_entry", group, package=name, version=ver,
                         rationale=f"{name}@{ver} existed before this change; the change only re-pointed where it is "
                                   "downloaded from and its integrity hash, so restore its lockfile entry from the base commit",
                         compatibility={"note": "same version as before: no code change"},
                         rollback="git revert the fix commit (restores the PR's package-lock.json entry)", lock_changes=1, rollback_ease=1)
        return _base("escalate", group, package=name, version=ver,
                     rationale="an existing package shows hard supply-chain signals; a human must choose between pinning and removal",
                     rollback="none needed (no change applied)")
    vulns = [f for f in group if f["kind"] == "vulnerability"]
    if not vulns:
        return _base("escalate", group, package=name, version=ver, rationale="no automatic action for this signal",
                     rollback="none needed (no change applied)")
    advisories, sources = [], []
    for f in vulns:
        rec, s = src.advisory((f.get("evidence") or {}).get("advisory", ""))
        if rec is None:
            return _base("escalate", group, package=name, version=ver,
                         rationale=f"advisory {(f.get('evidence') or {}).get('advisory')} could not be retrieved, so a safe range can't be computed",
                         rollback="none needed (no change applied)")
        advisories.append(rec)
        sources.append(s)
    versions, vs = src.versions(name)
    if vs:
        sources.append(vs)
    target = smallest_safe(name, ver, versions, advisories) if versions else None
    if not target:
        return _base("escalate", group, package=name, version=ver, sources=sources,
                     rationale="no published version is outside every affected range of these advisories",
                     rollback="none needed (no change applied)")
    direct = bool(p.get("direct", True))
    ctype = "upgrade_to_fixed" if direct else "override_transitive"
    j = jump(ver, target)
    return _base(ctype, group, package=name, **{"from": ver, "to": target}, semver_jump=j, sources=sources,
                 rationale=f"{target} is the smallest published version outside every affected range"
                           + (" (same major version)" if j != "major" else " (requires a major upgrade)"),
                 compatibility={"semver_jump": j, "note": {"patch": "bug-fix release; API should be unchanged",
                                                          "minor": "new features; existing API should still work",
                                                          "major": "breaking changes possible; review the changelog"}[j]},
                 rollback="git revert the fix commit (restores the previous version in package.json/package-lock.json)",
                 lock_changes=1 if direct else 2, rollback_ease=1 if direct else 2)


def generate(findings: list[dict], report: dict, src: Sources) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        if f["kind"] == "ci_image":
            groups.setdefault(("ci", f["id"]), []).append(f)
        elif f.get("type") in CONFIG_TYPES:
            groups.setdefault(("config", (f.get("evidence") or {}).get("file") or f["component"]), []).append(f)
        else:
            name, ver = _split(f["component"])
            groups.setdefault(("pkg", name, ver), []).append(f)
    out = []
    for key, group in groups.items():
        if key[0] == "config":
            out.append(_base("revert_change", group, file=key[1],
                             rationale=f"restore {key[1]} to its content in the base revision",
                             compatibility={"note": "returns the build configuration to its previous, reviewed state"},
                             rollback="git revert the fix commit"))
        elif key[0] == "ci":
            f = group[0]
            out.append(_base("escalate", group, file=(f.get("evidence") or {}).get("file"),
                             rationale="pinning needs the commit SHA / image digest of the reviewed version; "
                                       "not resolved automatically yet",
                             rollback="none needed (no change applied)"))
        else:
            out.append(_package_candidate(key[1], key[2], group, report, src))
    return order(out)


def order(cands: list[dict]) -> list[dict]:
    """First difference wins: resolves the target, smaller semver jump, fewer lockfile changes, easier rollback."""
    return sorted(cands, key=lambda c: (not c.get("resolves_target"), JUMP_RANK.get(c.get("semver_jump"), 3),
                                        c.get("lock_changes", 99), c.get("rollback_ease", 99)))
