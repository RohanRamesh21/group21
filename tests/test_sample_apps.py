"""Ground truth for the synthetic sample apps (testbed/apps/expected.json): JavaScript, Python, Go, Java, C/C++.

Offline: Syft, OSV and Grype are stubbed, so this checks Guardian's own readers and detectors. The sandboxed
tools are covered by tests/test_sandbox.py.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from guardian import universal as u

APPS = Path(__file__).resolve().parents[1] / "testbed" / "apps"
EXPECTED = {k: v for k, v in json.loads((APPS / "expected.json").read_text()).items() if not k.startswith("_")}


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr(u, "run_syft", lambda src, out: ({}, None))
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(u, "grype_all", lambda sbom: ([], None))
    from guardian.scoring import intel
    monkeypatch.setattr(intel, "epss", lambda cves: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    from guardian import policy, registry_intel
    monkeypatch.setattr(registry_intel, "analyse", lambda b, h, c, p, log=None: ([], {"checked": 0, "packages": [], "errors": []}))
    monkeypatch.setattr(policy, "evaluate", lambda r: {"engine": "stub", "policies": [], "decision": None, "deny": [], "warn": [], "error": None})


def _scan(app: str, tmp_path: Path) -> dict:
    repo = tmp_path / app
    shutil.copytree(APPS / app, repo)
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "sample"], check=True)
    return u.check_any(repo, None, "HEAD", tmp_path / "out", app)


@pytest.mark.parametrize("app", sorted(EXPECTED))
def test_sample_app_ground_truth(app, tmp_path, offline):
    exp = EXPECTED[app]
    rep = _scan(app, tmp_path)
    found = [s for s in rep["suspicious_changes"] if s["type"] != "tool_error"]
    if exp.get("control"):
        assert found == [], f"control app {app} must be clean, got {[(s['type'], s['component']) for s in found]}"
    for typ, needle in exp["findings"]:
        assert any(s["type"] == typ and needle in s["component"] + " " + (s.get("file") or "") for s in found), \
            f"{app}: expected {typ} on {needle}; got {sorted((s['type'], s['component']) for s in found)}"
        assert all(s.get("file") for s in found if s["type"] == typ), f"{app}: {typ} must cite a file"
    inv = {f"{p['ecosystem']}:{p['name']}": p for p in rep["inventory"]}
    for comp, version in exp["components"]:
        assert comp in inv, f"{app}: component {comp} missing; have {sorted(inv)}"
        assert (inv[comp]["version"] or None) == version, f"{app}: {comp} version {inv[comp]['version']!r} != {version!r}"
