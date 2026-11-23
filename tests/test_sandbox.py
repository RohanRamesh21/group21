"""Sandbox guardrails (guardian/sandbox).

Unit tests run everywhere: the podman command carries every guardrail, nothing falls back to the host, and the
egress proxy refuses what is not allow-listed. Integration tests run real containers and are skipped when podman
or the pinned images are missing (`guardian sandbox setup`). None of them needs internet access.
"""
import json
import os
import shutil
import socket
import subprocess

import pytest

from guardian import sandbox
from guardian.sandbox.egress import EgressProxy


# ------------------------------------------------------------------ unit
def _capture(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "[]", "")
    monkeypatch.setattr(sandbox.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    monkeypatch.setenv("GUARDIAN_SANDBOX", "podman")
    return calls


def test_podman_command_has_every_guardrail(monkeypatch, tmp_path):
    calls = _capture(monkeypatch)
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "do-not-leak")
    (tmp_path / "src").mkdir()
    res = sandbox.run("zizmor", ["--offline", "{src}/.github/workflows"], inputs={"src": tmp_path / "src"}, output=tmp_path / "o")
    assert res.ok and res.isolated
    cmd = calls[0]
    for flag in ("--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
                 "--userns=keep-id", "--memory", "--cpus", "--pids-limit"):
        assert flag in cmd, flag
    assert f"type=bind,source={tmp_path / 'src'},target=/in/src,readonly=true" in cmd
    assert f"type=bind,source={tmp_path / 'o'},target=/out" in cmd  # the only writable mount
    assert "/in/src/.github/workflows" in cmd
    assert not any("SUPER_SECRET_TOKEN" in c for c in cmd) and "--env-host" not in cmd
    assert any(c.startswith("ghcr.io/zizmorcore/zizmor") and "@sha256:" in c for c in cmd)


def test_missing_podman_never_falls_back_to_host(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_SANDBOX", "podman")
    monkeypatch.setattr(sandbox.shutil, "which", lambda b: None)
    ran = []
    monkeypatch.setattr(sandbox.subprocess, "run", lambda *a, **k: ran.append(a))
    res = sandbox.run("syft", ["dir:{src}"], inputs={"src": tmp_path})
    assert not res.ok and "podman is not installed" in res.error and ran == []


def test_unpinned_image_is_refused(monkeypatch):
    _capture(monkeypatch)
    cfg = sandbox.config()
    cfg["images"] = {**cfg["images"], "syft": "docker.io/anchore/syft:latest"}
    monkeypatch.setattr(sandbox, "config", lambda: cfg)
    res = sandbox.run("syft", ["version"])
    assert not res.ok and "digest-pinned" in res.error


def test_scan_records_tool_error_when_sandbox_is_missing(monkeypatch, tmp_path):
    from guardian import universal as u
    monkeypatch.setenv("GUARDIAN_SANDBOX", "podman")
    monkeypatch.setattr(sandbox.shutil, "which", lambda b: None)
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "requirements.txt").write_text("flask==2.0.0\n")
    res = u.scan_tree(tmp_path / "src", tmp_path / "out", "app", "c" * 40)
    errors = {s["component"] for s in res["suspicious"] if s["type"] == "tool_error"}
    assert {"syft", "grype"} <= errors
    assert res["sandbox"]["runs"] and not any(r["isolated"] and r["error"] is None for r in res["sandbox"]["runs"])


def test_tool_errors_are_reported_as_not_checked_never_scored(monkeypatch, tmp_path):
    from guardian import universal as u
    from guardian.day1 import build
    from guardian.scoring import intel
    monkeypatch.setenv("GUARDIAN_SANDBOX", "podman")
    monkeypatch.setattr(sandbox.shutil, "which", lambda b: None)
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(intel, "epss", lambda cves: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("flask==2.0.0\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)
    rep = u.check_any(repo, None, "HEAD", tmp_path / "out", "repo")
    assert {s["label"] for s in rep["suspicious_changes"] if s["type"] == "tool_error"} == {"not_checked"}
    sb = rep["headline"]["sandbox"]
    assert {"syft", "grype"} <= set(sb["failed"]) and sb["all_isolated"]  # did not run at all, and nothing ran on the host
    scores = json.loads(open(json.loads((tmp_path / "out" / "latest.json").read_text())["scores"]).read())
    assert not [f for f in scores["findings"] if "tool_error" in f["id"]] and scores["data"]["not_checked"]
    assert "NOT checked" in build(rep, scores)["steps"][3]["note"]


def _ask(proxy: EgressProxy, request: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(str(proxy.socket))
        s.sendall(request)
        return s.recv(200)


def test_egress_proxy_refuses_everything_not_allow_listed():
    with EgressProxy({"registry.npmjs.org"}) as px:
        assert b"403" in _ask(px, b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")
        assert b"403" in _ask(px, b"CONNECT registry.npmjs.org:22 HTTP/1.1\r\n\r\n")  # allowed host, wrong port
        assert b"403" in _ask(px, b"GET http://registry.npmjs.org/left-pad HTTP/1.1\r\n\r\n")  # plain HTTP
        assert oct(px.socket.stat().st_mode & 0o777) == "0o600"
    assert px.denied == ["evil.example.com:443", "registry.npmjs.org:22", "registry.npmjs.org:80"]
    assert not px.socket_dir.exists()


# ------------------------------------------------------------------ integration (real containers)
def _ready() -> bool:
    if not shutil.which("podman"):
        return False
    st = sandbox.status()
    return bool(st["podman"]) and all(i["present"] for k, i in st["images"].items() if k == "node")


needs_podman = pytest.mark.skipif(not _ready(), reason="podman or the pinned node image is missing (guardian sandbox setup)")


@pytest.fixture
def podman_mode(monkeypatch):
    monkeypatch.setenv("GUARDIAN_SANDBOX", "podman")


@needs_podman
def test_container_has_no_network_no_host_env_and_read_only_inputs(tmp_path, monkeypatch, podman_mode):
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "do-not-leak")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("x")
    script = """
const fs = require('fs'), out = {};
out.env = Object.keys(process.env).filter(k => k.includes('SECRET'));
try { fs.writeFileSync('/in/src/a.txt', 'changed'); out.write_input = 'ok' } catch (e) { out.write_input = e.code }
try { fs.writeFileSync('/etc/x', 'x'); out.write_root = 'ok' } catch (e) { out.write_root = e.code }
out.uid = process.getuid();
require('dns').lookup('registry.npmjs.org', (e) => { out.dns = e ? e.code : 'resolved'; console.log(JSON.stringify(out)) });
"""
    res = sandbox.run("node", ["-e", script], inputs={"src": tmp_path / "src"}, timeout=60)
    assert res.ok, res.error or res.stderr
    got = json.loads(res.stdout)
    assert got["env"] == [] and got["dns"] != "resolved" and got["uid"] == os.getuid() != 0
    assert got["write_input"] == "EROFS" and got["write_root"] == "EROFS"
    assert (tmp_path / "src" / "a.txt").read_text() == "x"


@needs_podman
def test_time_limit_kills_the_container(podman_mode):
    res = sandbox.run("node", ["-e", "setTimeout(() => {}, 60000)"], timeout=3)
    assert not res.ok and "time limit" in res.error
    names = subprocess.run(["podman", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    assert "gsbx-node-" not in names


@needs_podman
def test_memory_limit(monkeypatch, podman_mode):
    cfg = sandbox.config()
    cfg["limits"] = {**cfg["limits"], "memory": "64m"}
    monkeypatch.setattr(sandbox, "config", lambda: cfg)
    res = sandbox.run("node", ["-e", "const a = []; for (;;) a.push(Buffer.alloc(16 << 20, 1))"], timeout=60)
    assert not res.ok and "memory limit" in (res.error or "")


@needs_podman
def test_repository_npmrc_cannot_run_code_and_unapproved_hosts_are_blocked(tmp_path, podman_mode):
    """Regression: a repository's .npmrc `git=<program>` made host npm run that program, despite --ignore-scripts."""
    from guardian import universal as u
    src = tmp_path / "repo"
    src.mkdir()
    canary = tmp_path / "CANARY_RAN"
    (src / "evil.sh").write_text(f"#!/bin/sh\ntouch {canary}\nexit 1\n")
    (src / "evil.sh").chmod(0o755)
    (src / ".npmrc").write_text(f"git={src / 'evil.sh'}\n")
    (src / "package.json").write_text(json.dumps({"name": "t", "version": "1.0.0", "dependencies": {
        "x": "git+https://example.invalid/x.git", "y": "https://evil.example.com/y-1.0.0.tgz"}}))
    manifests = u.find_manifests(src)
    _, failed, blocked = u.resolve_npm_lockfiles(src, manifests, lambda m: None, tmp_path / "work", {"registry.npmjs.org"})
    assert not canary.exists()
    assert "package.json" in failed
    assert blocked == {"package.json": ["evil.example.com:443"]}
