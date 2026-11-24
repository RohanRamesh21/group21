"""Upgrade-safety predictor: "how likely is this upgrade to break the app?" for a fix candidate. Deterministic.

Reads only registry METADATA for the current and the target version (one small JSON per version from
registry.npmjs.org, cached); no tarball is downloaded and nothing is executed. Every field that cannot be
determined is "unknown" and is listed in `checks_not_run`: unknown is never reported as safe.

Fields: semver_jump, also_fixes, new_issues (advisories that still affect the target version, from OSV.dev),
engines_check, peer_conflicts, api_changes + uses_changed_api (package.json `exports`/`main`/`type`/`bin`
differences, matched against the import specifiers first-party code really uses), install_script_added, risk.
`risk` is rule-based (points below). It is a forecast; only the sandbox rescan and the build/tests verify a fix.
"""
from __future__ import annotations

import fnmatch
import functools
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from guardian.scoring.contextual import reachability, semver

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".cache" / "npm-meta"
REGISTRY = "https://registry.npmjs.org"
OSV_QUERY = "https://api.osv.dev/v1/query"
DAY = 24 * 3600
INSTALL_HOOKS = ("preinstall", "install", "postinstall")


# ----------------------------------------------------------------------------- providers (network, injectable for tests)
def _cached(path: Path, fetch: Callable[[], dict | None], max_age: float = DAY):
    try:
        if path.exists() and time.time() - path.stat().st_mtime < max_age:
            return json.loads(path.read_text())
    except Exception:
        pass
    data = fetch()
    if data is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data))
        except OSError:
            pass
    return data


def npm_manifest(name: str, version: str) -> dict | None:
    """The package.json-like manifest of one published version, or None when unavailable (offline, unknown)."""
    def fetch():
        import requests
        r = requests.get(f"{REGISTRY}/{name.replace('/', '%2F')}/{version}", timeout=15, headers={"Accept": "application/json"})
        return r.json() if r.status_code == 200 else None
    try:
        return _cached(CACHE / f"{name.replace('/', '__')}@{version}.json", fetch)
    except Exception:
        return None


def osv_query(name: str, version: str) -> list[str] | None:
    """Advisory ids that affect exactly name@version (OSV.dev), or None when the lookup failed."""
    def fetch():
        import requests
        r = requests.post(OSV_QUERY, json={"package": {"name": name, "ecosystem": "npm"}, "version": version}, timeout=15)
        return {"ids": sorted(v["id"] for v in r.json().get("vulns", []))} if r.status_code == 200 else None
    try:
        got = _cached(CACHE / f"osv-{name.replace('/', '__')}@{version}.json", fetch)
        return got["ids"] if got else None
    except Exception:
        return None


@dataclass
class Providers:
    manifest: Callable[[str, str], dict | None] = npm_manifest
    osv: Callable[[str, str], list[str] | None] = osv_query
    specs: Callable[[Path | None], dict[str, set[str]]] | None = None  # first-party import specifiers by package


# ----------------------------------------------------------------------------- semver ranges (small, undecidable -> None)
def _partial(tok: str) -> tuple[int, int | None, int | None] | None:
    m = re.match(r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:[-+].*)?$", tok)
    if not m:
        return None
    g = [None if (x is None or x in "xX*") else int(x) for x in m.groups()]
    return g[0], g[1], g[2]


def _bounds(p: tuple) -> tuple[tuple, tuple]:
    """[lo, hi) covered by a (possibly partial) version such as 1, 1.2 or 1.2.3."""
    M, m, pa = p
    if pa is not None:
        return (M, m or 0, pa), (M, m or 0, pa + 1)
    if m is not None:
        return (M, m, 0), (M, m + 1, 0)
    return (M, 0, 0), (M + 1, 0, 0)


def _cmp_range(pv: tuple, tok: str) -> bool | None:
    m = re.match(r"^(\^|~>?|>=|<=|>|<|=)?\s*(.*)$", tok)
    op, rest = (m.group(1) or "="), m.group(2)
    p = _partial(rest) if rest not in ("", "*", "x", "X") else (None, None, None)
    if p is None:
        return None
    if p[0] is None:
        return True
    v = pv[:3]
    lo, hi = _bounds(p)
    if op == "=":
        return lo <= v < hi
    if op == ">=":
        return v >= lo
    if op == ">":
        return v >= hi
    if op == "<=":
        return v < hi
    if op == "<":
        return v < lo
    if op == "^":
        M, mi, pa = p
        top = (M + 1, 0, 0) if M > 0 else ((1, 0, 0) if mi is None else ((0, mi + 1, 0) if mi > 0 else ((0, 1, 0) if pa is None else (0, 0, pa + 1))))
        return lo <= v < top
    if op.startswith("~"):
        return lo <= v < ((p[0], p[1] + 1, 0) if p[1] is not None else (p[0] + 1, 0, 0))
    return None


def satisfies(version: str, rng: str | None) -> bool | None:
    """Does `version` satisfy the npm range `rng`? None when the range is not understood (never a guess)."""
    pv = semver.parse(version)
    if pv is None or rng is None:
        return None
    rng = rng.strip()
    if rng in ("", "*", "latest"):
        return True
    for alt in rng.split("||"):
        alt = alt.strip()
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        toks = [f">={hy.group(1)}", f"<={hy.group(2)}"] if hy else re.sub(r"(>=|<=|>|<|=|\^|~>?)\s+", r"\1", alt).split()
        results = [_cmp_range(pv, t) for t in toks] if toks else [True]
        if any(r is None for r in results):
            return None
        if all(results):
            return True
    return False


def lower_bound(rng: str | None) -> str | None:
    """The smallest version a range admits (approximate: first comparator of the most permissive alternative)."""
    if not rng:
        return None
    best: tuple | None = None
    best_s = None
    for alt in rng.split("||"):
        m = re.search(r"(?:>=|\^|~>?|=)?\s*v?(\d+(?:\.\d+){0,2})", alt)
        if not m:
            continue
        s = ".".join((m.group(1).split(".") + ["0", "0"])[:3])
        p = semver.parse(s)
        if p and (best is None or p < best):
            best, best_s = p, s
    return best_s


# ----------------------------------------------------------------------------- first-party import specifiers
@functools.lru_cache(maxsize=8)
def _scan_specs(src: str) -> dict[str, frozenset[str]]:
    out: dict[str, set[str]] = {}
    base = Path(src)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in reachability.SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix not in reachability.EXTS or p.is_symlink():
                continue
            try:
                if p.stat().st_size > reachability.MAX_FILE:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for pat in reachability.PATTERNS:
                for m in pat.finditer(text):
                    spec = m.group(1)
                    pkg = reachability.package_of(spec)
                    if pkg:
                        out.setdefault(pkg, set()).add(spec)
    return {k: frozenset(v) for k, v in out.items()}


def first_party_specs(src: Path | None) -> dict[str, set[str]]:
    return {k: set(v) for k, v in _scan_specs(str(src)).items()} if src and Path(src).is_dir() else {}


# ----------------------------------------------------------------------------- manifest comparison
def _export_paths(m: dict) -> set[str] | None:
    """Public subpaths declared by `exports` ('.', './sub', './*'); None when the package has no exports map (all files reachable)."""
    ex = m.get("exports")
    if ex is None:
        return None
    if isinstance(ex, dict) and any(isinstance(k, str) and k.startswith(".") for k in ex):
        return set(ex)
    return {"."}


def _api_changes(cur: dict, tgt: dict, name: str, used: set[str]) -> dict:
    ce, te = _export_paths(cur), _export_paths(tgt)
    removed: list[str] = []
    restricted = ce is None and te is not None
    if ce is not None and te is not None:
        removed = sorted(p for p in ce if p not in te and not any(fnmatch.fnmatch(p, t) for t in te if "*" in t))
    sub_used = sorted(s for s in used if s != name and s.startswith(name + "/"))
    hit = []
    for s in sub_used:
        path = "./" + s[len(name) + 1:]
        if (te is not None and path not in te and not any("*" in t and fnmatch.fnmatch(path, t) for t in te)) and (ce is None or path in ce or True):
            hit.append(s)
    cbin = set((cur.get("bin") or {}).keys()) if isinstance(cur.get("bin"), dict) else ({name} if cur.get("bin") else set())
    tbin = set((tgt.get("bin") or {}).keys()) if isinstance(tgt.get("bin"), dict) else ({name} if tgt.get("bin") else set())
    return {"removed_exports": removed, "exports_now_restricted": restricted,
            "main_changed": (cur.get("main"), tgt.get("main")) if cur.get("main") != tgt.get("main") else None,
            "type_changed": (cur.get("type") or "commonjs", tgt.get("type") or "commonjs") if (cur.get("type") or "commonjs") != (tgt.get("type") or "commonjs") else None,
            "bin_removed": sorted(cbin - tbin),
            "first_party_subpath_imports_broken": hit}


def _hooks(m: dict) -> set[str]:
    return {h for h in INSTALL_HOOKS if (m.get("scripts") or {}).get(h)} | ({"install"} if m.get("gypfile") else set())


def not_applicable(candidate: dict) -> dict:
    return {"applicable": False, "reason": f"upgrade safety applies to version changes; '{candidate['type']}' does not change a version",
            "risk": "n/a", "checks_not_run": []}


def compute(candidate: dict, finding: dict, inventory: list[dict], app_manifest: dict | None, src: Path | None = None,
            prov: Providers | None = None) -> dict:
    """Upgrade-safety record for one candidate of one finding. Never raises: failures become `checks_not_run`."""
    if candidate["type"] not in ("upgrade_to_fixed", "override_transitive") or not candidate.get("target"):
        return not_applicable(candidate)
    prov = prov or Providers()
    p = finding["package"]
    name, cur_v, tgt_v = p["name"], p["version"], candidate["target"]
    not_run: list[str] = []
    jump = (candidate.get("compat") or {}).get("semver") or semver.jump(cur_v, tgt_v)
    pts, reasons = 0, []

    if jump == "major":
        pts += 3
        reasons.append(f"major version jump {cur_v} -> {tgt_v}: breaking changes are expected")
    elif jump == "minor":
        pts += 1
        reasons.append("minor jump: new features, breaking changes unlikely but possible")
    elif jump is None:
        pts += 1
        reasons.append("versions are not plain semver: the size of the jump is unknown")
        not_run.append("semver_jump (unparseable version)")
    if candidate["type"] == "override_transitive":
        pts += 1
        reasons.append(f"override forces {name}@{tgt_v} on dependents that did not ask for it "
                       f"(parents: {', '.join((candidate.get('compat') or {}).get('via_direct_parents') or ['unknown'])})")

    also = [r for r in candidate.get("resolves", []) if r != finding["id"]]
    cur_m, tgt_m = prov.manifest(name, cur_v), prov.manifest(name, tgt_v)
    if tgt_m is None:
        not_run += ["engines (target manifest unavailable)", "peer_dependencies (target manifest unavailable)", "api_changes (target manifest unavailable)"]
    if cur_m is None and tgt_m is not None:
        not_run.append("api_changes (current manifest unavailable)")

    new_issues = prov.osv(name, tgt_v)
    if new_issues is None:
        not_run.append("new_issues (OSV.dev lookup failed)")
    elif new_issues:
        pts += 2
        reasons.append(f"{name}@{tgt_v} is still affected by {len(new_issues)} advisory(ies): {', '.join(new_issues[:4])}")

    engines = {"status": "unknown", "detail": "not checked"}
    peers: list[dict] = []
    api: dict | None = None
    uses_changed: bool | None = None
    install_added = None
    if tgt_m is not None:
        app_node = ((app_manifest or {}).get("engines") or {}).get("node")
        tgt_node = (tgt_m.get("engines") or {}).get("node")
        if tgt_node is None:
            engines = {"status": "ok", "detail": f"{name}@{tgt_v} declares no engines.node requirement"}
        elif not app_node:
            engines = {"status": "unknown", "detail": f"{name}@{tgt_v} needs node {tgt_node}; the app declares no engines.node to compare with"}
            not_run.append("engines (the app declares no engines.node)")
        else:
            lb = lower_bound(app_node)
            ok = satisfies(lb, tgt_node) if lb else None
            engines = ({"status": "ok" if ok else "conflict", "detail": f"app supports node {app_node} (lowest {lb}); {name}@{tgt_v} needs {tgt_node}"}
                       if ok is not None else {"status": "unknown", "detail": f"could not compare node ranges '{app_node}' and '{tgt_node}'"})
            if ok is None:
                not_run.append("engines (range not understood)")
        if engines["status"] == "conflict":
            pts += 3
            reasons.append("engines.node: " + engines["detail"])

        meta_opt = {k for k, v in (tgt_m.get("peerDependenciesMeta") or {}).items() if (v or {}).get("optional")}
        for pn, pr in (tgt_m.get("peerDependencies") or {}).items():
            have = sorted({x["version"] for x in inventory if x["name"] == pn})
            if not have:
                st = "optional_missing" if pn in meta_opt else "missing"
            else:
                res = [satisfies(v, pr) for v in have]
                st = "ok" if any(r is True for r in res) else ("unknown" if any(r is None for r in res) else "conflict")
            peers.append({"peer": pn, "range": pr, "installed": have, "status": st})
            if st == "conflict":
                pts += 2
                reasons.append(f"peer dependency {pn} {pr} is not satisfied by installed {', '.join(have)}")
            elif st == "missing":
                pts += 1
                reasons.append(f"peer dependency {pn} {pr} is not installed")
            elif st == "unknown":
                not_run.append(f"peer_dependencies ({pn} range not understood)")

        if cur_m is not None:
            specs = (prov.specs or first_party_specs)(src)
            if src is None:
                not_run.append("uses_changed_api (no source tree to scan for import specifiers)")
            api = _api_changes(cur_m, tgt_m, name, specs.get(name, set()))
            uses_changed = bool(api["first_party_subpath_imports_broken"]) if src is not None else None
            if uses_changed:
                pts += 3
                reasons.append("first-party code imports subpath(s) the new version no longer exports: " + ", ".join(api["first_party_subpath_imports_broken"]))
            elif api["removed_exports"]:
                pts += 1
                reasons.append("public export path(s) removed (no first-party import found): " + ", ".join(api["removed_exports"][:5]))
            if api["type_changed"]:
                pts += 2
                reasons.append(f"module type changed {api['type_changed'][0]} -> {api['type_changed'][1]} (require()/import interop may break)")
            if api["exports_now_restricted"] and not uses_changed:
                pts += 1
                reasons.append("the package now declares an exports map: deep imports of internal files stop working")
            if api["bin_removed"]:
                pts += 1
                reasons.append("CLI binaries removed: " + ", ".join(api["bin_removed"]))
            install_added = sorted(_hooks(tgt_m) - _hooks(cur_m))
            if install_added:
                pts += 3
                reasons.append("the target version adds install-time script(s): " + ", ".join(install_added) + " (supply-chain signal, review before approving)")

    not_run += ["api_symbol_diff (only package.json exports are compared, no tarball is read)", "release_notes (no approved source is fetched)"]
    risk = "high" if pts >= 3 else ("medium" if pts >= 1 else "low")
    partial = any("unavailable" in x or "failed" in x or "no source" in x for x in not_run)
    return {"applicable": True, "semver_jump": jump, "risk": risk, "points": pts, "reasons": reasons or ["patch-level change with no breaking signal found"],
            "also_fixes": also, "new_issues": new_issues, "engines_check": engines, "peer_conflicts": peers, "api_changes": api,
            "uses_changed_api": uses_changed, "install_script_added": install_added,
            "coverage": "partial" if partial else "checked", "checks_not_run": not_run,
            "note": "forecast from registry metadata: the build and tests (sandbox) are what verify an upgrade"}
