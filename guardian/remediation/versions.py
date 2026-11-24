# READING GUIDE
# Version-range reasoning for the actual fix generator: compare versions with advisory ranges and choose an eligible target.
# Receives version/advisory data from candidates.py; the AI never invents a target version here.
#
"""Version logic for fix targets: npm-style semver ordering and OSV affected-range evaluation.

A target is "safe" only if it is outside every affected range of every advisory being fixed. Advisories often list
only the first fixed release, so later releases are evaluated against the ranges instead of a fixed-version list.
"""
from __future__ import annotations

import re

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$")


def parse(v: str) -> tuple:
    """Sortable key. Pre-releases sort before their release (2.2.0-beta.1 < 2.2.0); unparseable versions sort first."""
    m = _SEMVER.match(v.strip()) if v else None
    if not m:
        return (-1, -1, -1, 0, ())
    major, minor, patch = (int(x or 0) for x in m.group(1, 2, 3))
    pre = m.group(4)
    if pre is None:
        return (major, minor, patch, 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (major, minor, patch, 0, ids)


def is_prerelease(v: str) -> bool:
    m = _SEMVER.match(v or "")
    return bool(m and m.group(4))


def _in_events(ver: tuple, events: list[dict]) -> bool:
    """OSV range events: introduced / fixed / last_affected, evaluated in order (sorted by version)."""
    points = []
    for e in events:
        for kind in ("introduced", "fixed", "last_affected"):
            if kind in e:
                at = (-1, -1, -1, 0, ()) if e[kind] == "0" else parse(e[kind])
                points.append((at, kind))
    points.sort(key=lambda x: (x[0], {"introduced": 0, "fixed": 1, "last_affected": 2}[x[1]]))
    hit = False
    for at, kind in points:
        if kind == "introduced" and ver >= at:
            hit = True
        elif kind == "fixed" and ver >= at:
            hit = False
        elif kind == "last_affected" and ver > at:
            hit = False
    return hit


# Check whether one version lies inside an advisory range using the available version data.
def affected(version: str, package: str, advisories: list[dict], ecosystem: str = "npm") -> bool:
    ver = parse(version)
    for adv in advisories:
        for aff in adv.get("affected", []) or []:
            pkg = aff.get("package") or {}
            if pkg.get("name", "").lower() != package.lower() or (pkg.get("ecosystem") and pkg["ecosystem"].lower() != ecosystem.lower()):
                continue
            if version in (aff.get("versions") or []):
                return True
            for rg in aff.get("ranges", []) or []:
                if rg.get("type") in ("SEMVER", "ECOSYSTEM") and _in_events(ver, rg.get("events", [])):
                    return True
    return False


def jump(old: str, new: str) -> str:
    a, b = parse(old), parse(new)
    if a[0] != b[0]:
        return "major"
    if a[1] != b[1]:
        return "minor"
    return "patch"


# Choose from eligible published versions outside the relevant affected ranges and exclusions.
def smallest_safe(package: str, current: str, versions: dict[str, dict], advisories: list[dict]) -> str | None:
    """Smallest published version above `current` that no advisory affects. Same major first; no pre-releases
    (unless current is one) and no deprecated releases."""
    cur = parse(current)
    pool = [v for v, meta in versions.items()
            if parse(v) > cur and not (meta or {}).get("deprecated")
            and (is_prerelease(current) or not is_prerelease(v))
            and not affected(v, package, advisories)]
    if not pool:
        return None
    same_major = [v for v in pool if parse(v)[0] == cur[0]]
    return min(same_major or pool, key=parse)
