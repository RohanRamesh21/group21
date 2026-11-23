"""Integration check: our dependency edges must match npm's own resolution exactly.

Uses `npm ls --all --json --package-lock-only`, which reads the lockfile only (no install,
no scripts). Skipped if the sandbox repo or npm isn't available.
"""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from guardian.adapters.npm import parse_lockfile
from guardian.universal import git_show

REPO = Path(__file__).resolve().parents[1] / "sandbox" / "uptime-kuma"


def _npm_edges(tree: dict, parent: str = "ROOT") -> set[tuple[str, str]]:
    out = set()
    for name, node in (tree.get("dependencies") or {}).items():
        if "version" not in node:
            continue  # missing optional dependency
        child = f"{name}@{node['version']}"
        out.add((parent, child))
        out |= _npm_edges(node, child)
    return out


@pytest.mark.skipif(not REPO.exists() or not shutil.which("npm"), reason="sandbox repo or npm missing")
@pytest.mark.parametrize("ref", ["2.5.12", "scenario/s3-s9"])
def test_edges_match_npm_ls(ref):
    files = {f: git_show(REPO, ref, f) for f in ("package.json", "package-lock.json")}
    if None in files.values():
        pytest.skip(f"{ref} not available")
    with tempfile.TemporaryDirectory() as tmp:
        for f, text in files.items():
            (Path(tmp) / f).write_text(text)
        res = subprocess.run(["npm", "ls", "--all", "--json", "--package-lock-only"],
                             cwd=tmp, capture_output=True, text=True, timeout=300)
        tree = json.loads(res.stdout)
    npm_edges = _npm_edges(tree)

    pkgs, edges = parse_lockfile(files["package-lock.json"])
    # npm ls labels aliased packages by the alias ("string-width-cjs"), we keep the real name.
    label = {k: f"{p.alias or p.name}@{p.version}" for k, p in pkgs.items()}
    aliases = sorted({f"{p.alias} -> {p.name}" for p in pkgs.values() if p.alias})
    print("aliases:", aliases)
    ours = {("ROOT" if e.parent == "" else label[e.parent], label[e.child]) for e in edges}

    missing = npm_edges - ours
    extra = ours - npm_edges
    print(f"npm edges={len(npm_edges)} ours={len(ours)} missing={len(missing)} extra={len(extra)}")
    print("missing examples:", sorted(missing)[:5])
    print("extra examples:", sorted(extra)[:5])
    assert not missing, f"{len(missing)} npm edges not found by the Guardian"
    assert not extra, f"{len(extra)} edges the Guardian reports that npm does not"
