"""Opt-in end-to-end test against the REAL npm registry, OSV.dev and a real git + npm: GUARDIAN_NETWORK_TESTS=1.

Only the rescan is stubbed (osv-scanner/syft/grype are not assumed to be installed). Everything else is real: candidate generation from
OSV affected ranges, upgrade-safety metadata from the registry, the sandbox copy, and `npm install --package-lock-only --ignore-scripts`.
"""
import json
import os
import shutil
import subprocess

import pytest

from guardian.remediation import validate
from guardian.remediation.context import RemediationContext
from guardian.remediation.service import Remediator
from guardian.remediation.store import RemediationStore
from guardian.scoring import intel
from guardian.scoring.contextual.pipeline import enrich
from guardian.scoring.score import score_report

pytestmark = pytest.mark.skipif(os.environ.get("GUARDIAN_NETWORK_TESTS") != "1" or not shutil.which("npm") or not shutil.which("git"),
                                reason="set GUARDIAN_NETWORK_TESTS=1 (needs network, npm, git)")


def test_real_upgrade_end_to_end(tmp_path):
    head = tmp_path / "head"
    head.mkdir()
    (head / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0", "private": True, "dependencies": {"minimist": "1.2.0"}}, indent=2) + "\n")
    subprocess.run([shutil.which("npm"), "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=head, check=True, capture_output=True)
    inv = [{"key": "node_modules/minimist", "name": "minimist", "version": "1.2.0", "direct": True, "runtime": True, "dev": False, "lockfile_line": 14,
            "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz", "source_file": "package-lock.json", "ecosystem": "npm"}]
    vul = [{"name": "minimist", "version": "1.2.0", "id": "GHSA-xvch-5gv4-984h", "ids": ["GHSA-xvch-5gv4-984h"], "key": "minimist@1.2.0#GHSA-xvch-5gv4-984h",
            "severity": "critical", "fixed": ["1.2.6"], "malicious": False, "direct": True, "runtime": True, "label": "introduced", "summary": "x",
            "sources": ["osv", "grype"], "component_key": "node_modules/minimist"}]
    report = {"inventory": inv, "vulnerabilities": vul, "suspicious_changes": [], "ci_image": [], "runs": {}}
    scores = enrich(score_report(report), report, fix_for="all", affected_lookup=intel.osv_affected)
    ctx = RemediationContext(scores, report, src=head)
    store = RemediationStore("REM-NET", base=tmp_path / "rem")
    rem = Remediator(ctx, store)
    plan = rem.rule_based(1)[0]
    assert plan.type == "upgrade_to_fixed" and plan.upgrade_safety["semver_jump"] == "patch" and '"minimist": "1.2.6"' in plan.patch.diff
    rem.decide(plan.id, "approve", "ci")

    def rescan(repo, b, h, out):
        rep = json.loads(json.dumps(report))
        rep["vulnerabilities"][0]["label"] = "fixed"
        return score_report(rep), rep
    res = validate.validate(store, plan.id, ctx, rescan=rescan)
    lock = json.loads((tmp_path / "rem" / "REM-NET" / "work" / plan.id / "repo" / "package-lock.json").read_text())
    assert lock["packages"]["node_modules/minimist"]["version"] == "1.2.6"
    assert res.outcome == "remediated_tests_not_run" and json.loads((head / "package.json").read_text())["dependencies"]["minimist"] == "1.2.0"
