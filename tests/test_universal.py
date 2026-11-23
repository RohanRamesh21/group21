"""Universal scan (any repository): discovery, detectors and the base->head pipeline. Offline: network scanners stubbed."""
import json
import subprocess

import pytest

from guardian import universal as u
from guardian.day1 import build


def _write(root, files):
    for path, text in files.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_cvss3_base_score():
    assert u.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert u.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert u.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N") == 4.3
    assert u.cvss3_score(None) is None


def test_vendored_and_cdn_scripts(tmp_path):
    _write(tmp_path, {"static/jquery.min.js": "/*! jQuery v1.12.4 | (c) jQuery Foundation */\n",
                      "static/app.js": "// our own code\n",
                      "index.html": '<script src="https://cdn.jsdelivr.net/npm/handlebars@4.0.5/dist/h.js"></script>'
                                    '<script src="https://unpkg.com/vue"></script>'
                                    '<script src="https://cdn.x.com/a.js" integrity="sha384-abc"></script>'})
    comps, finds = u.vendored_and_cdn(tmp_path)
    got = {(c["name"], c["version"]) for c in comps}
    assert ("jquery", "1.12.4") in got and ("handlebars", "4.0.5") in got and ("vue", "") in got
    types = [f["type"] for f in finds]
    assert types.count("remote_script_no_sri") == 2 and "unpinned_remote_script" in types


def test_browser_extension_permissions(tmp_path):
    _write(tmp_path, {"ext/manifest.json": json.dumps({"manifest_version": 3, "name": "X", "version": "1.0",
                                                       "permissions": ["debugger"], "host_permissions": ["<all_urls>"]})})
    comps, finds = u.browser_extensions(tmp_path, u.find_manifests(tmp_path))
    assert comps[0]["ecosystem"] == "browser-extension"
    assert {"extension_broad_host_access", "extension_sensitive_permissions"} <= {f["type"] for f in finds}


def test_undeclared_imports_without_false_positives(tmp_path):
    _write(tmp_path, {"app.py": "import os, yaml\nfrom helpers import x\n", "helpers.py": "x = 1\n",
                      "tests/test_a.py": "import pytest\n\ndef test_x():\n    from made_at_runtime import app\n",
                      "web/a.js": "// role went from 'none' to 'area'\nconst fs = require('fs'); const l = require('./lib');\nimport x from 'left-pad';\n"})
    comps = {f["component"] for f in u.undeclared_imports(tmp_path, [], u.find_manifests(tmp_path))}
    assert comps == {"pypi:pyyaml", "pypi:pytest", "npm:left-pad"}


def test_registry_config_dependency_confusion(tmp_path):
    _write(tmp_path, {"requirements.txt": "flask==2.0.0\n--extra-index-url https://pkgs.internal/simple\n"})
    assert [f["type"] for f in u.registry_config(tmp_path, u.find_manifests(tmp_path), {})] == ["extra_index_url"]


def _lock(integrity):
    return json.dumps({"name": "a", "lockfileVersion": 3, "packages": {
        "": {"name": "a", "dependencies": {"kuma-helper": "1.0.0"}},
        "node_modules/kuma-helper": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/kuma-helper/-/kuma-helper-1.0.0.tgz",
                                     "integrity": integrity}}})


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr(u, "run_syft", lambda src, out: ({}, None))
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(u, "grype_all", lambda sbom: ([], None))
    from guardian.scoring import intel
    monkeypatch.setattr(intel, "epss", lambda cves: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))


def test_base_head_pipeline_detects_lockfile_tamper_and_works_without_npm(tmp_path, offline):
    repo = tmp_path / "repo"
    _write(repo, {"package.json": '{"name":"a","dependencies":{"kuma-helper":"1.0.0"}}', "package-lock.json": _lock("sha512-AAA"),
                  "tool/run.py": "import requests\n"})
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "base"], check=True)
    (repo / "package-lock.json").write_text(_lock("sha512-BBB"))  # same version, different code: lockfile edited by hand
    subprocess.run(git + ["commit", "-qam", "head"], check=True)
    rep = u.check_any(repo, "HEAD~1", "HEAD", tmp_path / "out", "repo")
    types = {(s["type"], s["label"]) for s in rep["suspicious_changes"]}
    assert ("lockfile_tamper", "introduced") in types and ("modified_lockfile", "introduced") in types
    assert ("undeclared_dependency", "pre_existing") in types
    assert rep["headline"]["verdict"] == "block"
    sc = json.loads(open(json.loads((tmp_path / "out" / "latest.json").read_text())["scores"]).read())
    d = build(rep, sc)
    assert [s["n"] for s in d["steps"]] == [1, 2, 3, 4, 5] and d["compare"]
    assert next(c for c in d["steps"][3]["checks"] if c["check"] == "Modified lockfile")["status"] == "found"


def test_new_package_from_unapproved_host_is_critical(tmp_path, offline):
    repo = tmp_path / "repo"
    _write(repo, {"package.json": '{"name":"a","dependencies":{"kuma-helper":"1.0.0"}}', "package-lock.json": _lock("sha512-AAA")})
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "base"], check=True)
    lock = json.loads(_lock("sha512-AAA"))
    lock["packages"][""]["dependencies"]["axois"] = "1.0.0"
    lock["packages"]["node_modules/axois"] = {"version": "1.0.0", "resolved": "http://127.0.0.1:4873/axois/-/axois-1.0.0.tgz",
                                              "integrity": "sha512-CCC", "hasInstallScript": True}
    _write(repo, {"package-lock.json": json.dumps(lock)})
    subprocess.run(git + ["commit", "-qam", "fix typo"], check=True)
    assert '"axois"' in u.git_show(repo, "HEAD", "package-lock.json") and u.git_show(repo, "HEAD", "nope.txt") is None
    rep = u.check_any(repo, "HEAD~1", "HEAD", tmp_path / "out", "repo")
    axois = {(s["type"], s["severity"], s["label"]) for s in rep["suspicious_changes"] if s["component"].startswith("axois")}
    assert ("lockfile_tamper", "critical", "introduced") in axois and ("new_install_script", "high", "introduced") in axois
    assert not {t for t, _, _ in axois} & {"untrusted_source", "install_script"}  # weak duplicates dropped
    assert rep["headline"]["verdict"] == "block"


def test_repo_without_any_manifest_still_completes(tmp_path, offline):
    repo = tmp_path / "repo"
    _write(repo, {"README.md": "hi", "script.py": "import json\n"})
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)
    rep = u.check_any(repo, None, "HEAD", tmp_path / "out", "repo")
    d = build(rep, None)
    assert d["steps"][0]["status"] == "nothing_found" and rep["headline"]["verdict"] == "allow"
