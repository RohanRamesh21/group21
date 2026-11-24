"""Stretch goal 1: reachability. Is the vulnerable package actually used by the application?

Import-level analysis of shipped code (tests, docs, examples, benchmarks and tools are not shipped), deterministic:
  npm      require()/import of the package name in .js/.mjs/.cjs/.ts/.tsx/.jsx/.vue/.svelte files
  PyPI     Python imports (module name mapped to the distribution name)
  Go       import paths; OSV lists the vulnerable Go *packages*, so a Go finding can be package-precise
Each vulnerability gets `reachability`:
  imported         shipped code imports the vulnerable package (evidence: file:line)
  via_import       transitive, pulled in by a direct dependency that shipped code imports
  not_imported     a runtime dependency that no shipped code imports (still reported; priority lowered)
  dev_only         only needed for development / tests
  unknown          ecosystem not analysed, or no dependency path to decide
Scoring (scoring/score.py) lowers the exposure of `not_imported` CVEs only. Malicious packages, tampering and other
hard signals are never discounted (CLAUDE.md 3.2). Function-level call graphs are not built (docs/KNOWN_LIMITATIONS.md).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

JS_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte")
# require.resolve()/import.meta.resolve(): packages loaded by path, e.g. uptime-kuma runs jsonata in a vm via require.resolve
JS_IMPORT = re.compile(r"""(?:\brequire(?:\.resolve)?\(\s*|\bimport\.meta\.resolve\(\s*|\bimport\s*\(\s*|^\s*(?:import|export)\b[^'"`;]*?\bfrom\s*|^\s*import\s+)['"]([^'"./][^'"]*)['"]""", re.M)
GO_IMPORT = re.compile(r'^\s*(?:import\s+)?(?:[\w.]+\s+)?"([^"]+)"', re.M)
MAX_FILES = 8000


def _shipped(rel_parts: tuple[str, ...]) -> bool:
    from guardian.adapters.build_files import NON_SHIPPED_DIRS
    skip = {"node_modules", ".git", "vendor", "third_party", "__pycache__"}
    return not ({p.lower() for p in rel_parts[:-1]} & (NON_SHIPPED_DIRS | skip)) and not rel_parts[-1].endswith(("_test.go", ".test.js", ".spec.js", ".test.ts", ".spec.ts"))


def collect_imports(src: Path) -> dict[str, dict[str, list[str]]]:
    """{"npm": {package: [file:line, ...]}, "pypi": {module: [...]}, "go": {import path: [...]}} for shipped code."""
    out: dict[str, dict[str, list[str]]] = {"npm": {}, "pypi": {}, "go": {}}
    n = 0
    for p in sorted(src.rglob("*")):
        if n > MAX_FILES or not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(src)
        if not _shipped(rel.parts):
            continue
        suffix = p.suffix
        if suffix not in JS_EXT and suffix not in (".py", ".go"):
            continue
        n += 1
        try:
            text = p.read_text(errors="replace") if p.stat().st_size < 2_000_000 else ""
        except OSError:
            continue

        def add(eco, name, pos):
            locs = out[eco].setdefault(name, [])
            if len(locs) < 3:
                locs.append(f"{rel}:{text.count(chr(10), 0, pos) + 1}")
        if suffix in JS_EXT:
            for m in JS_IMPORT.finditer(text):
                spec = m.group(1)
                if spec.startswith(("node:", "@/", "~", "#", "http:", "https:", "virtual:", "$")):
                    continue
                add("npm", "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0], m.start())
        elif suffix == ".py":
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                continue
            lines = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]
            for node in ast.walk(tree):
                names = [a.name.split(".")[0] for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module.split(".")[0]] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else []
                for nm in names:
                    add("pypi", nm, lines[node.lineno - 1] if node.lineno - 1 < len(lines) else 0)
        else:  # Go: only the import declarations at the top of the file
            head = text.split("\nfunc ", 1)[0]
            for blk in re.finditer(r"^import\s*\(([^)]*)\)|^import\s+[^\n]+", head, re.M):
                for m in GO_IMPORT.finditer(blk.group(0)):
                    add("go", m.group(1), blk.start() + m.start())
    return out


def _py_module_for(dist: str) -> set[str]:
    from guardian.universal import PY_DIST
    d = dist.lower()
    mods = {d.replace("-", "_"), d.replace("-", ""), d.removeprefix("python-").replace("-", "_"), d.removeprefix("py").replace("-", "_")}
    mods |= {m.lower() for m, dd in PY_DIST.items() if dd.lower() == d}
    return mods


def _go_vulnerable_packages(v: dict) -> list[str]:
    """Vulnerable Go package paths from the OSV record (ecosystem_specific.imports[].path)."""
    from guardian.universal import _osv_get
    vid = next((i for i in v.get("ids", []) if i.startswith("GO-")), None)
    rec = _osv_get(vid) if vid else None
    out = []
    for aff in (rec or {}).get("affected", []) or []:
        if (aff.get("package") or {}).get("name") == v["name"]:
            out += [i.get("path") for i in ((aff.get("ecosystem_specific") or {}).get("imports") or []) if i.get("path")]
    return out


def classify(v: dict, row: dict | None, inventory_by_key: dict[str, dict], imports: dict[str, dict[str, list[str]]]) -> dict:
    eco = (row or {}).get("ecosystem") or v.get("ecosystem") or "npm"
    if row is not None and not row.get("runtime", True):
        return {"status": "dev_only", "why": "needed only for development or tests"}
    if eco == "npm":
        used = imports.get("npm", {})
        if v["name"] in used:
            return {"status": "imported", "why": f"shipped code imports {v['name']}", "evidence": used[v["name"]]}
        path = (row or {}).get("path") or []
        if len(path) > 2:  # app -> direct dep -> ... -> this package
            first = inventory_by_key.get(path[1], {})
            if first.get("name") in used:
                return {"status": "via_import", "why": f"pulled in by {first['name']}, which shipped code imports",
                        "evidence": used[first["name"]]}
            return {"status": "not_imported", "why": f"pulled in by {first.get('name', '?')}, which no shipped code imports"}
        if (row or {}).get("direct"):
            return {"status": "not_imported", "why": f"declared, but no shipped code imports {v['name']} (it may still be loaded by "
                                                     "name, e.g. as a plugin or CLI)"}
        return {"status": "unknown", "why": "no dependency path recorded"}
    if eco == "pypi":
        used = imports.get("pypi", {})
        hit = next((m for m in _py_module_for(v["name"]) if m in {k.lower() for k in used}), None)
        if hit:
            key = next(k for k in used if k.lower() == hit)
            return {"status": "imported", "why": f"shipped code imports {key}", "evidence": used[key]}
        if (row or {}).get("direct"):
            return {"status": "not_imported", "why": f"declared, but no shipped Python code imports {v['name']}"}
        return {"status": "unknown", "why": "transitive Python dependency (no import graph)"}
    if eco == "golang":
        used = imports.get("go", {})
        vuln_pkgs = _go_vulnerable_packages(v)
        hit = [p for p in vuln_pkgs if p in used]
        if hit:
            return {"status": "imported", "why": f"shipped code imports the vulnerable package {hit[0]}", "evidence": used[hit[0]]}
        if any(i == v["name"] or i.startswith(v["name"] + "/") for i in used):
            return {"status": "via_import", "why": f"shipped code imports {v['name']}, but not the vulnerable package(s) "
                                                   f"{', '.join(vuln_pkgs[:3]) or '(not listed)'} directly"}
        return {"status": "unknown", "why": "not imported directly; may be used inside another module (no call graph)"}
    return {"status": "unknown", "why": f"no import analysis for {eco}"}


def annotate(vulns: list[dict], inventory: list[dict], imports: dict) -> dict:
    """Set v['reachability'] on every head vulnerability; return counts for the report."""
    by_key = {p["key"]: p for p in inventory}
    by_nv: dict[tuple, dict] = {}
    for p in inventory:
        by_nv.setdefault((p["name"], p["version"]), p)
    counts: dict[str, int] = {}
    for v in vulns:
        if v.get("label") == "fixed":
            continue
        row = by_key.get(v.get("component_key") or "") or by_nv.get((v["name"], v["version"]))
        try:
            v["reachability"] = classify(v, row, by_key, imports)
        except Exception as e:  # noqa: BLE001 never let reachability break a scan
            v["reachability"] = {"status": "unknown", "why": f"analysis failed: {type(e).__name__}"}
        counts[v["reachability"]["status"]] = counts.get(v["reachability"]["status"], 0) + 1
    return {"method": "import-level (shipped code only)", "counts": counts,
            "imports": {k: len(x) for k, x in imports.items()}}
