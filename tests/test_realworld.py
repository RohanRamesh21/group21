"""Stage B: real tools on the sandbox scenario. Skipped when the sandbox, Verdaccio or the network is missing."""
import json
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "sandbox" / "uptime-kuma"


def _ready() -> bool:
    try:
        return REPO.exists() and requests.get("http://localhost:4873/-/ping", timeout=3).ok \
            and requests.get("https://api.osv.dev", timeout=5).status_code < 500
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="sandbox scenario, Verdaccio or network not available")


@pytest.fixture(scope="module")
def facts(tmp_path_factory):
    from guardian.agents.realworld import RealFacts
    from guardian.store.evidence import EvidenceStore
    store = EvidenceStore(tmp_path_factory.mktemp("ev"))
    return RealFacts(REPO, "scenario/base", "scenario/s3-s9", store, ROOT / "guardian.yaml", ROOT / ".cache" / "tarballs")


def test_diff_and_coverage(facts):
    assert facts.diff["packages_added"] == ["axois@1.0.0"]
    assert facts.diff["packages_updated"] == ["kuma-helper 1.0.0 -> 1.0.1"]
    assert facts.diff["sensitive_files_changed"] == [".npmrc"]
    req = facts.coverage_required()
    assert {"file:.npmrc", "file:package-lock.json", "pkg:pkg:npm/axois@1.0.0", "pkg:pkg:npm/kuma-helper@1.0.1"} <= req


def test_detectors(facts):
    sig = {d: facts.detector(d) for d in ("D0", "D1", "D3", "D4", "D7")}
    assert any(s["type"] == "lockfile_tamper" and "axois" in s["component"] and s["hard_signal"] for s in sig["D3"])
    assert not any("kuma-helper" in s["component"] for s in sig["D3"])  # approved registry -> no tamper signal
    assert any(s["type"] == "source_change" and s["hard_signal"] for s in sig["D7"])
    assert [s["component"] for s in sig["D1"]] == ["pkg:npm/axois@1.0.0"]
    assert all(not s["hard_signal"] for s in sig["D4"])  # routine bump stays soft


def test_package_reads_never_execute(facts):
    hooks = json.loads(facts.store.content(facts.answer("install_hooks", "pkg:npm/axois@1.0.0")))
    assert hooks["lifecycle_scripts"] == {"postinstall": "node setup.js"}
    readme = facts.store.content(facts.answer("read_package_file", "pkg:npm/axois@1.0.0#README.md"))
    assert "AI reviewers" in readme
    import tempfile
    assert not (Path(tempfile.gettempdir()) / "guardian-canary-axois.txt").exists()
