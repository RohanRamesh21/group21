"""Minimal semver parsing/comparison and OSV range evaluation (no dependency).

Used only to decide whether a *target* version is still affected by an advisory. For ecosystems other than npm
callers must not rely on this (PEP 440, Maven etc. order differently); `affected()` returns None when it
cannot decide, and callers then fall back to the advisory's fixed-version list and say so.
"""
from __future__ import annotations

import re

_V = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def parse(v: str) -> tuple | None:
    m = _V.match(v.strip()) if isinstance(v, str) else None
    if not m:
        return None
    pre = m.group(4)
    # semver: a release outranks any of its pre-releases; numeric identifiers compare numerically
    pre_key = (1,) if pre is None else (0, *((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")))
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), pre_key)


def cmp(a: str, b: str) -> int | None:
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    return (pa > pb) - (pa < pb)


def jump(cur: str, target: str) -> str | None:
    """'patch' | 'minor' | 'major' | 'none' (target not newer) | None (unparseable)."""
    pc, pt = parse(cur), parse(target)
    if pc is None or pt is None:
        return None
    if pt <= pc:
        return "none"
    return "major" if pt[0] != pc[0] else ("minor" if pt[1] != pc[1] else "patch")


def affected(version: str, entry: dict) -> bool | None:
    """Is `version` inside one OSV `affected[]` entry (explicit versions or SEMVER/ECOSYSTEM ranges)?

    True/False when decidable, None when the data cannot be evaluated (caller falls back, never guesses)."""
    if version in (entry.get("versions") or []):
        return True
    decided = False
    for rg in entry.get("ranges") or []:
        if rg.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        state = False
        events = rg.get("events") or []

        def key(e):
            v = e.get("introduced") or e.get("fixed") or e.get("last_affected") or e.get("limit") or "0"
            return parse("0.0.0" if v == "0" else v) or (0, 0, 0, (1,))
        for e in sorted(events, key=key):
            if "introduced" in e:
                if e["introduced"] == "0" or (cmp(version, e["introduced"]) or 0) >= 0:
                    state = True
                    decided = True
            elif "fixed" in e and (c := cmp(version, e["fixed"])) is not None:
                decided = True
                if c >= 0:
                    state = False
            elif "last_affected" in e and (c := cmp(version, e["last_affected"])) is not None:
                decided = True
                if c > 0:
                    state = False
        if state:
            return True
    return False if decided else None
