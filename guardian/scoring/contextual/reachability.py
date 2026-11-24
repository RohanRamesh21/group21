"""Feature C: reachability tiers (an ESTIMATE from a static, read-only import scan; nothing is executed).

Tiers for a vulnerable npm package:
  dev_only   only reachable through dev edges (lockfile fact)
  imported   first-party runtime code imports the package, or imports a package that depends on it
  declared   in the runtime graph, but no first-party import was found (not "unused": dynamic requires are missed)
  unknown    not an npm package, or no source tree available

A symbol-level tier is deliberately NOT implemented: npm advisories in our data do not name affected functions.

Only CVE findings use this. Malware, integrity, origin and install-script findings are never discounted.
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict, deque
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "vendor", ".cache", "out", "__pycache__"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "e2e", "cypress", "fixtures", "mocks"}
EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue"}
MAX_FILE = 2_000_000
PATTERNS = [
    re.compile(r"""\brequire\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bfrom\s+['"]([^'"]+)['"]"""),
    re.compile(r"""\bimport\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""^\s*import\s+['"]([^'"]+)['"]""", re.M),
    # Added when ported to the main branch: require.resolve("pkg") with a literal name is a static, resolvable use
    # (Uptime Kuma loads jsonata this way into a vm sandbox; missing it lowered a used, vulnerable package to 'declared').
    re.compile(r"""\brequire\.resolve\(\s*['"]([^'"]+)['"]"""),
]
DYNAMIC = re.compile(r"""\brequire\(\s*[^'"\s)]""")  # require(variable): cannot be resolved statically


def package_of(spec: str) -> str | None:
    """Import specifier -> npm package name; None for relative paths, absolute paths and Node built-ins."""
    if not spec or spec.startswith((".", "/", "node:", "#", "~", "@/")) or ":" in spec:
        return None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") and len(parts) >= 2 else parts[0]
    return name or None


def scan_imports(src: Path) -> dict:
    """{"runtime": {pkg: ["file:line"]}, "test": {pkg: [...]}, "files": n, "dynamic_requires": n}. Reads text only."""
    runtime: dict[str, list[str]] = defaultdict(list)
    test: dict[str, list[str]] = defaultdict(list)
    files = dyn = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = Path(dirpath).relative_to(src)
        in_test = any(p in TEST_DIRS for p in rel_dir.parts)
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix not in EXTS or p.is_symlink():
                continue
            try:
                if p.stat().st_size > MAX_FILE:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files += 1
            is_test = in_test or ".test." in fn or ".spec." in fn
            dyn += len(DYNAMIC.findall(text))
            for pat in PATTERNS:
                for m in pat.finditer(text):
                    pkg = package_of(m.group(1))
                    if pkg:
                        line = text.count("\n", 0, m.start()) + 1
                        (test if is_test else runtime)[pkg].append(f"{p.relative_to(src).as_posix()}:{line}")
    return {"runtime": {k: v[:5] for k, v in runtime.items()}, "test": {k: v[:5] for k, v in test.items()},
            "files": files, "dynamic_requires": dyn}


def _runtime_children(edges: list[dict]) -> dict[str, list[str]]:
    kids: dict[str, list[str]] = defaultdict(list)
    for e in edges:
        if e.get("kind") != "dev":
            kids[e["parent"]].append(e["child"])
    return kids


def tiers(inventory: list[dict], edges: list[dict], imports: dict) -> dict[str, dict]:
    """component key -> {"tier", "evidence": [file:line], "via": package that imports it, "method", "estimated": True}."""
    by_key = {p["key"]: p for p in inventory}
    by_name: dict[str, list[str]] = defaultdict(list)
    for p in inventory:
        by_name[p["name"]].append(p["key"])
    kids = _runtime_children(edges)
    # from every imported package, walk down runtime edges: everything below it is reached through it
    reached: dict[str, tuple[str, list[str]]] = {}
    for name, sites in imports["runtime"].items():
        for k in by_name.get(name, []):
            q = deque([k])
            seen = {k}
            while q:
                cur = q.popleft()
                reached.setdefault(cur, (name, sites))
                for c in kids.get(cur, []):
                    if c not in seen:
                        seen.add(c)
                        q.append(c)
    out: dict[str, dict] = {}
    for key, p in by_key.items():
        if p.get("ecosystem", "npm") != "npm":
            out[key] = {"tier": "unknown", "evidence": [], "via": None, "method": "not an npm package", "estimated": True}
        elif not p.get("runtime"):
            used = imports["runtime"].get(p["name"], [])
            out[key] = {"tier": "dev_only", "evidence": used, "via": None, "method": "lockfile: dev dependency only", "estimated": True,
                        # a dev dependency that first-party code imports may still be bundled into what ships (e.g. a
                        # frontend build): scoring keeps today's dev-only value, but a reviewer must see this flag
                        "possibly_shipped": bool(used),
                        **({"note": "declared as dev-only but imported by first-party code: it may be bundled and shipped"} if used else {})}
        elif key in reached:
            via, sites = reached[key]
            out[key] = {"tier": "imported", "evidence": sites, "via": None if via == p["name"] else via,
                        "method": "static import scan + dependency edges", "estimated": True}
        else:
            only_tests = p["name"] in imports["test"]
            out[key] = {"tier": "declared", "evidence": [], "via": None, "estimated": True,
                        "method": "static import scan: no first-party runtime import found"
                                  + (" (imported only in test code)" if only_tests else "")}
    return out


def _find_src(report: dict) -> Path | None:
    head = (report.get("runs") or {}).get("head")
    if not head:
        return None
    root = Path(__file__).resolve().parents[3]
    base = Path(head) if Path(head).is_absolute() else root / head
    for rel in ("src", "trees/head"):
        if (base / rel).is_dir():
            return base / rel
    return None


def for_report(report: dict, src: Path | None = None) -> dict[str, dict]:
    """vulnerability key -> reachability record. Empty dict when no source tree is available (never guessed)."""
    src = src or _find_src(report)
    if not src:
        return {}
    head = Path((report.get("runs") or {}).get("head", ""))
    edges_p = (head if head.is_absolute() else Path(__file__).resolve().parents[3] / head) / "edges.json"
    if not edges_p.exists():
        return {}
    comp = tiers(report.get("inventory", []), json.loads(edges_p.read_text()), scan_imports(src))
    return {v["key"]: comp[v["component_key"]] for v in report.get("vulnerabilities", [])
            if v.get("component_key") in comp and v.get("label") != "fixed"}
