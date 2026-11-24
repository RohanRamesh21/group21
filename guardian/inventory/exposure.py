"""Shipped-frontend exposure (T11).

Bundlers such as Vite ship packages that are listed as devDependencies (Uptime Kuma: vue, chart.js, dompurify ...)
to every user's browser. A dev flag alone would discount their vulnerabilities as "dev only".

Rule: an npm package imported by first-party frontend code, and everything it pulls in through non-dev edges,
is treated as shipped. This is a static, inferred signal (label "shipped_frontend_inferred"); it becomes
"observed in artifact" only when the built bundle/image is scanned (validation stage). Files are read as text only.
"""
from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path

FRONTEND_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte")
COMPONENT_EXT = (".vue", ".svelte", ".jsx", ".tsx")  # frontend by nature, wherever they live
SKIP_PARTS = {"node_modules", "dist", "build", "test", "tests", "__tests__", "e2e", ".git"}
MAX_BYTES = 1_500_000

IMPORT = re.compile(r"""(?:\brequire\(\s*|\bimport\s*\(\s*|^\s*(?:import|export)\b[^'"`;]*?\bfrom\s*|^\s*import\s+)['"]([^'"]+)['"]""", re.M)


def is_frontend_file(rel: str) -> bool:
    parts = rel.split("/")
    if not rel.endswith(FRONTEND_EXT) or SKIP_PARTS & set(parts[:-1]) or rel.endswith(".min.js"):
        return False
    return "src" in parts[:-1] or rel.endswith(COMPONENT_EXT)


def package_of(spec: str) -> str | None:
    """'dayjs/plugin/utc' -> 'dayjs'; '@scope/pkg/x' -> '@scope/pkg'; relative, absolute, aliases and node: builtins -> None."""
    if not spec or spec.startswith((".", "/", "node:", "~", "#", "virtual:")) or "://" in spec:
        return None
    if spec.startswith("@"):
        bits = spec.split("/")
        return "/".join(bits[:2]) if len(bits) >= 2 and bits[1] else None
    return spec.split("/")[0] or None


def frontend_imports(files: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    """package name -> ['file:line', ...] for imports in first-party frontend files."""
    hits: dict[str, list[str]] = {}
    for rel, text in files:
        if not is_frontend_file(rel):
            continue
        for m in IMPORT.finditer(text):
            pkg = package_of(m.group(1))
            if pkg:
                hits.setdefault(pkg, []).append(f"{rel}:{text.count(chr(10), 0, m.start(1)) + 1}")
    return hits


def mark_shipped(inventory: list[dict], edges: list[dict], imports: dict[str, list[str]]) -> list[str]:
    """Mark imported dev packages (and their non-dev dependency closure) as shipped. Returns sorted names marked."""
    by_key = {p["key"]: p for p in inventory}
    children: dict[str, list[str]] = {}
    for e in edges:
        if e.get("kind") in ("prod", "optional", "peer"):
            children.setdefault(e["parent"], []).append(e["child"])
    queue: list[tuple[str, list[str]]] = [(p["key"], imports[p["name"]][:3]) for p in inventory
                                           if p.get("ecosystem", "npm") == "npm" and p["name"] in imports]
    seen: set[str] = set()
    marked: set[str] = set()
    while queue:
        key, evidence = queue.pop(0)
        if key in seen or key not in by_key:
            continue
        seen.add(key)
        p = by_key[key]
        if not p.get("runtime"):
            p["runtime"] = True
            p["exposure"] = "shipped_frontend_inferred"
            p["exposure_evidence"] = evidence
            marked.add(p["name"])
        queue += [(c, [f"via {p['name']}"]) for c in children.get(key, [])]
    return sorted(marked)


def iter_tree(root: Path) -> Iterator[tuple[str, str]]:
    """Frontend files from an exported directory tree."""
    for p in root.rglob("*"):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and is_frontend_file(rel) and p.stat().st_size <= MAX_BYTES:
            yield rel, p.read_text(errors="replace")


def iter_git(repo: Path, commit: str) -> Iterator[tuple[str, str]]:
    """Frontend files read straight from git objects (no checkout, nothing executed)."""
    ls = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", commit],
                        capture_output=True, text=True, check=True).stdout.splitlines()
    rels = [r for r in ls if is_frontend_file(r)]
    if not rels:
        return
    # one `git cat-file --batch` process for all files (fast on large frontends)
    out = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch"], input="".join(f"{commit}:{r}\n" for r in rels).encode(),
                         capture_output=True, check=True).stdout
    pos = 0
    for rel in rels:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].split()
        pos = nl + 1
        if len(header) < 3 or header[1] != b"blob":
            continue
        size = int(header[2])
        data, pos = out[pos:pos + size], pos + size + 1
        if size <= MAX_BYTES:
            yield rel, data.decode(errors="replace")
