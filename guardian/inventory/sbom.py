"""SBOM generation and cross-checking (stage S2).

Syft and cdxgen produce CycloneDX SBOMs; both are compared against the lockfile, which is
the ground truth. Disagreements are reported, never silently ignored.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def tool_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        return out.strip().splitlines()[0] if out.strip() else "unknown"
    except Exception:
        return "unavailable"


def run_syft(src: Path, out_dir: Path) -> dict[str, str]:
    """CycloneDX + SPDX from the exported source folder. No network, no install."""
    if not shutil.which("syft"):
        raise RuntimeError("syft not installed")
    cdx = out_dir / "sbom.syft.cdx.json"
    spdx = out_dir / "sbom.syft.spdx.json"
    subprocess.run(
        ["syft", f"dir:{src}", "-q", "-o", f"cyclonedx-json={cdx}", "-o", f"spdx-json={spdx}"],
        # Syft skips npm dev dependencies by default (a scope assumption that silently drops ~half
        # of this app's packages). Install scripts in dev packages still run on laptops and CI,
        # so the Guardian always includes them.
        check=True, timeout=600,
        env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"},
    )
    return {"cyclonedx": str(cdx), "spdx": str(spdx)}


def run_cdxgen(src: Path, out_dir: Path) -> str | None:
    """Second opinion from cdxgen, reading the lockfile only (never installs dependencies)."""
    if not shutil.which("cdxgen"):
        return None
    out = out_dir / "sbom.cdxgen.cdx.json"
    env = {**os.environ, "FETCH_LICENSE": "false", "CDXGEN_DEBUG_MODE": "", "NODE_NO_WARNINGS": "1"}
    try:
        subprocess.run(
            ["cdxgen", "-t", "js", "--no-install-deps", "--no-recurse", "-o", str(out), str(src)],
            check=True, timeout=600, env=env, capture_output=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return str(out) if out.exists() else None


def _components(path: str) -> set[tuple[str, str]]:
    doc = json.loads(Path(path).read_text())
    out = set()
    for c in doc.get("components", []):
        purl = c.get("purl") or ""
        if not purl.startswith("pkg:npm/"):
            continue
        name = (c.get("group") + "/" + c["name"]) if c.get("group") else c.get("name")
        out.add((name, c.get("version", "")))
    return out


def agreement(lockfile_set: set[tuple[str, str]], sboms: dict[str, str]) -> dict:
    """Compare each SBOM's npm components with the lockfile (unique name@version)."""
    report = {"lockfile_unique": len(lockfile_set), "tools": {}}
    for tool, path in sboms.items():
        if not path:
            continue
        comps = _components(path)
        missing = sorted(lockfile_set - comps)
        extra = sorted(comps - lockfile_set)
        report["tools"][tool] = {
            "components": len(comps),
            "matched": len(lockfile_set & comps),
            "agreement_pct": round(100 * len(lockfile_set & comps) / max(1, len(lockfile_set)), 1),
            "missing_examples": [f"{n}@{v}" for n, v in missing[:10]],
            "missing_count": len(missing),
            "extra_examples": [f"{n}@{v}" for n, v in extra[:10]],
            "extra_count": len(extra),
        }
    return report
