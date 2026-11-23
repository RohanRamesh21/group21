"""npm adapter: precise parsing of package-lock.json v2/v3 (FINAL_PLAN.md §11).

Edges are resolved the way Node.js resolves `require()`: look in the parent's own
node_modules first, then walk up one level at a time to the top-level node_modules.
This gives exact edges even when several versions of a package coexist.
"""
from __future__ import annotations

import json
from collections import deque

from guardian.models import Edge, Package

_DEP_FIELDS = (("dependencies", "prod"), ("optionalDependencies", "optional"), ("peerDependencies", "peer"))


def purl_for(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, pkg = name[1:].split("/", 1)
        return f"pkg:npm/%40{scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def name_from_key(key: str) -> str:
    """'node_modules/a/node_modules/@s/b' -> '@s/b'."""
    tail = key.rsplit("node_modules/", 1)[-1]
    return tail


def _parent_dir(key: str) -> str | None:
    """The folder one level up in the resolution walk; '' is the application root; None = stop."""
    if key == "":
        return None
    if "/node_modules/" in key:
        return key.rsplit("/node_modules/", 1)[0]
    return ""


def resolve(packages: dict, from_key: str, name: str) -> str | None:
    """Node-style resolution of `name` required from the package installed at `from_key`."""
    current: str | None = from_key
    while current is not None:
        candidate = f"{current}/node_modules/{name}" if current else f"node_modules/{name}"
        if candidate in packages:
            entry = packages[candidate]
            if entry.get("link") and entry.get("resolved"):
                return entry["resolved"]  # workspace link: points at the real folder key
            return candidate
        current = _parent_dir(current)
    return None


def parse_lockfile(text: str) -> tuple[dict[str, Package], list[Edge]]:
    data = json.loads(text)
    version = data.get("lockfileVersion", 1)
    if version < 2 or "packages" not in data:
        raise ValueError(f"Unsupported lockfile version {version}: regenerate with npm >= 7 (lockfile v2/v3).")
    raw: dict = data["packages"]
    root = raw.get("", {})

    pkgs: dict[str, Package] = {}
    for key, entry in raw.items():
        if key == "" or entry.get("link"):
            continue
        installed_as = name_from_key(key)
        name = entry.get("name") or installed_as  # lockfile sets `name` only when it differs (aliases)
        ver = entry.get("version", "0.0.0")
        lic = entry.get("license")
        pkgs[key] = Package(
            key=key,
            name=name,
            version=ver,
            purl=purl_for(name, ver),
            alias=installed_as if installed_as != name else None,
            dev=bool(entry.get("dev")),
            optional=bool(entry.get("optional") or entry.get("devOptional")),
            resolved=entry.get("resolved"),
            integrity=entry.get("integrity"),
            has_install_script=bool(entry.get("hasInstallScript")),
            license=lic if isinstance(lic, str) else None,
        )

    edges: list[Edge] = []

    def add_edges(parent_key: str, entry: dict, fields) -> None:
        peer_meta = entry.get("peerDependenciesMeta") or {}
        for field, kind in fields:
            for dep_name, spec in (entry.get(field) or {}).items():
                child = resolve(raw, parent_key, dep_name)
                if child is None or child not in pkgs:
                    continue  # optional/peer dependency not installed on this platform
                if kind == "peer" and (peer_meta.get(dep_name) or {}).get("optional"):
                    kind_used = "peer_optional"  # npm doesn't count optional peers as runtime
                else:
                    kind_used = kind
                edges.append(Edge(parent=parent_key, child=child, name=dep_name, spec=str(spec), kind=kind_used))

    add_edges("", root, _DEP_FIELDS + (("devDependencies", "dev"),))
    for key, entry in raw.items():
        if key and key in pkgs:
            add_edges(key, entry, _DEP_FIELDS)

    # Direct = children of the root.
    for e in edges:
        if e.parent == "":
            pkgs[e.child].direct = True

    # Runtime = reachable from the root without passing through a dev edge.
    children: dict[str, list[Edge]] = {}
    for e in edges:
        children.setdefault(e.parent, []).append(e)
    seen: set[str] = set()
    queue = deque([""])
    while queue:
        node = queue.popleft()
        for e in children.get(node, []):
            if e.kind in ("dev", "peer_optional") or e.child in seen:
                continue
            seen.add(e.child)
            queue.append(e.child)
    for key in seen:
        pkgs[key].runtime = True

    return pkgs, edges


def root_declarations(text: str) -> dict[str, dict[str, str]]:
    """Direct dependency declarations from package.json (for 'declared_in')."""
    data = json.loads(text)
    return {
        k: data.get(k, {}) or {}
        for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    }


def line_of(text: str, needle: str) -> int | None:
    """1-based line number of the first line containing `needle` (used for evidence locators)."""
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return None
