"""Shared fixtures: a small report scored offline (no network, no scanners)."""
import pytest

from guardian.scoring import intel
from guardian.scoring.score import score_report


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": [], "cvss_v3": None, "cvss_v4": None, "severity_label": None} for i in ids})
    monkeypatch.setattr(intel, "epss", lambda cves: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))


def pkg(key, name, version, direct=True, runtime=True, line=1):
    return {"key": key, "name": name, "version": version, "direct": direct, "runtime": runtime, "dev": not runtime,
            "lockfile_line": line, "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz", "source_file": "package-lock.json"}


def vuln(name, version, adv, severity="high", fixed=(), label="pre_existing", direct=True, runtime=True, malicious=False,
         sources=("osv", "grype")):
    return {"name": name, "version": version, "id": adv, "ids": [adv], "key": f"{name}@{version}#{adv}", "severity": severity,
            "fixed": list(fixed), "malicious": malicious, "direct": direct, "runtime": runtime, "label": label,
            "summary": f"{adv} in {name}", "sources": list(sources), "component_key": f"node_modules/{name}"}


@pytest.fixture
def report():
    inv = [pkg("node_modules/foo", "foo", "1.2.0"), pkg("node_modules/bar", "bar", "3.0.0", direct=False),
           pkg("node_modules/devtool", "devtool", "0.5.0", runtime=False), pkg("node_modules/axois", "axois", "1.0.0")]
    vulns = [vuln("foo", "1.2.0", "GHSA-1", "critical", ["1.2.4"]), vuln("foo", "1.2.0", "GHSA-2", "high", ["2.0.0"]),
             vuln("bar", "3.0.0", "GHSA-3", "high", ["3.0.1"], direct=False), vuln("devtool", "0.5.0", "GHSA-4", "high", ["0.5.1"], runtime=False),
             vuln("axois", "1.0.0", "MAL-1", "low", [], label="introduced", malicious=True, sources=("osv",))]
    sus = [{"detector": "D1", "type": "typosquat", "component": "pkg:npm/axois@1.0.0", "summary": "look-alike", "severity": "high",
            "hard_signal": False, "label": "introduced"}]
    return {"inventory": inv, "vulnerabilities": vulns, "suspicious_changes": sus, "ci_image": [], "runs": {}}


@pytest.fixture
def scores(report):
    return score_report(report)


FAKE_AFFECTED = {
    "GHSA-1": [{"name": "foo", "ecosystem": "npm", "versions": [], "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}],
    "GHSA-2": [{"name": "foo", "ecosystem": "npm", "versions": [], "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
    "GHSA-3": [{"name": "bar", "ecosystem": "npm", "versions": [], "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.1"}]}]}],
    "GHSA-4": [{"name": "devtool", "ecosystem": "npm", "versions": [], "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.5.1"}]}]}],
}


def fake_lookup(ids):
    return {i: FAKE_AFFECTED.get(i) for i in ids}


# ---- advisor fixtures (the branch built `ctx` from its remediation package; the advisor needs only scores + src)
import json as _json  # noqa: E402
from types import SimpleNamespace  # noqa: E402


@pytest.fixture
def ctx(report, tmp_path):  # noqa: F811
    from guardian.scoring.contextual.pipeline import enrich
    head = tmp_path / "head"
    head.mkdir()
    (head / "package.json").write_text(_json.dumps({"name": "demo-app", "version": "1.0.0", "dependencies": {"foo": "^1.2.0", "axois": "1.0.0"},
                                                    "devDependencies": {"devtool": "~0.5.0"}}))
    (head / "src").mkdir()
    (head / "src" / "main.js").write_text("const foo = require('foo');\n")
    return SimpleNamespace(scores=enrich(score_report(report), report, affected_lookup=fake_lookup, fix_for="all"), src=head, report=report)
