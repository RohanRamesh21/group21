"""Faster validation without weaker evidence:
1. an allow-listed native build is compiled once per (package, version, lockfile integrity, image digest) and reused;
2. baseline sandbox, fixed-version sandbox and the source rescan run at the same time;
3. progress is reported per lane so the dashboard can show both sandboxes moving."""
import hashlib
import json
import threading
import time

from guardian import approval as ap
from guardian.validation import runner as vr
from guardian.validation import validate as vv

PKG = "@louislam/sqlite3"
ST = {"id": "hooks", "timeout": 60, "allow": [{"name": PKG, "version": "15.1.6", "integrity": "sha512-GOOD",
                                                "cmd": "npm rebuild sqlite3", "outputs": ["lib/binding"]}]}
LOCK = {"packages": {f"node_modules/{PKG}": {"version": "15.1.6", "integrity": "sha512-GOOD"}}}


def _tree(tmp_path, name):
    t = tmp_path / name
    (t / "node_modules" / PKG).mkdir(parents=True)
    return t


def _compiling_exec(calls, ok=True):
    def fake(container, cmd, timeout):
        calls.append(cmd)
        # the build writes its output into the package folder of the tree mounted in the container
        tree = fake.tree
        if ok:
            out = tree / "node_modules" / PKG / "lib" / "binding" / "napi-v6-linux-arm64"
            out.mkdir(parents=True, exist_ok=True)
            (out / "node_sqlite3.node").write_bytes(b"\x7fELF compiled")
        return (0 if ok else 1), "built", 38.0
    return fake


def test_native_build_is_compiled_once_then_reused(tmp_path, monkeypatch):
    calls = []
    fake = _compiling_exec(calls)
    monkeypatch.setattr(vr, "_exec", fake)
    cache = tmp_path / "cache"

    fake.tree = _tree(tmp_path, "baseline")
    first = vr.run_hooks("c1", ST, LOCK, fake.tree, "node@sha256:img", cache)
    assert first["status"] == "passed" and len(calls) == 1

    fake.tree = _tree(tmp_path, "candidate")
    second = vr.run_hooks("c2", ST, LOCK, fake.tree, "node@sha256:img", cache)
    assert second["status"] == "passed" and len(calls) == 1  # not compiled again
    assert (fake.tree / "node_modules" / PKG / "lib/binding/napi-v6-linux-arm64/node_sqlite3.node").read_bytes() == b"\x7fELF compiled"
    assert "reused" in second["detail"]
    assert second["hooks"][0]["cache"] == "hit" and first["hooks"][0]["cache"] == "stored"


def test_a_different_image_compiles_again(tmp_path, monkeypatch):
    calls = []
    fake = _compiling_exec(calls)
    monkeypatch.setattr(vr, "_exec", fake)
    cache = tmp_path / "cache"
    fake.tree = _tree(tmp_path, "a")
    vr.run_hooks("c1", ST, LOCK, fake.tree, "node@sha256:img1", cache)
    fake.tree = _tree(tmp_path, "b")
    vr.run_hooks("c2", ST, LOCK, fake.tree, "node@sha256:img2", cache)
    assert len(calls) == 2


def test_a_failed_build_is_never_cached(tmp_path, monkeypatch):
    calls = []
    fake = _compiling_exec(calls, ok=False)
    monkeypatch.setattr(vr, "_exec", fake)
    cache = tmp_path / "cache"
    fake.tree = _tree(tmp_path, "a")
    assert vr.run_hooks("c1", ST, LOCK, fake.tree, "img", cache)["status"] == "failed"
    fake.tree = _tree(tmp_path, "b")
    vr.run_hooks("c2", ST, LOCK, fake.tree, "img", cache)
    assert len(calls) == 2  # still compiled: nothing was stored


def test_hooks_without_declared_outputs_always_run(tmp_path, monkeypatch):
    calls = []
    fake = _compiling_exec(calls)
    monkeypatch.setattr(vr, "_exec", fake)
    st = {**ST, "allow": [{k: v for k, v in ST["allow"][0].items() if k != "outputs"}]}
    for n in ("a", "b"):
        fake.tree = _tree(tmp_path, n)
        vr.run_hooks("c", st, LOCK, fake.tree, "img", tmp_path / "cache")
    assert len(calls) == 2


def test_refused_hook_is_not_run_and_not_restored(tmp_path, monkeypatch):
    calls = []
    fake = _compiling_exec(calls)
    monkeypatch.setattr(vr, "_exec", fake)
    bad = {"packages": {f"node_modules/{PKG}": {"version": "15.1.6", "integrity": "sha512-EVIL"}}}
    fake.tree = _tree(tmp_path, "a")
    res = vr.run_hooks("c", ST, bad, fake.tree, "img", tmp_path / "cache")
    assert res["status"] == "failed" and calls == []


def test_progress_is_tracked_per_lane():
    p = {}
    for m in ["validation: source rescan of the candidate (same engine, same advisory snapshot)",
              "[baseline] install: npm ci --ignore-scripts", "[candidate] build: npm run build",
              "[baseline] finished", "validation: rescan finished", "validation: artifact SBOMs (installed dependencies + build output)"]:
        p = vv.progress_update(p, m)
    assert p == {"rescan": "done", "baseline": "finished", "candidate": "build: npm run build", "sbom": "running"}


def test_sandboxes_and_rescan_run_at_the_same_time(tmp_path, monkeypatch):
    out = tmp_path / "run"
    out.mkdir()
    patch = out / "fix.patch"
    patch.write_text("")
    plan = {"repo": str(tmp_path), "base_sha": "a" * 40, "head_sha": "b" * 40, "candidates": [],
            "patch": {"patch_sha256": hashlib.sha256(b"").hexdigest(), "patch_path": str(patch)}}
    (out / "fix-plan.json").write_text(json.dumps(plan))
    _, prof_sha, _ = vr.load_profile("uptime-kuma")
    ap.decide(out, plan, "approve", approver="k", reason="ok", ttl_seconds=3600,
              policy_sha256=vv.policy_sha256(), profile_sha256=prof_sha)

    running, peak, lock = set(), [0], threading.Lock()

    def busy(tag, result):
        with lock:
            running.add(tag)
            peak[0] = max(peak[0], len(running))
        time.sleep(0.4)
        with lock:
            running.discard(tag)
        return result

    stage = [{"id": "install", "status": "passed", "required": True}]
    monkeypatch.setattr(vr, "prepare_tree", lambda repo, sha, dest, *a, **k: dest)
    monkeypatch.setattr(vr, "run_profile", lambda tree, prof, folder, label, log=print: busy(label, {"image": "i", "container": label, "stages": stage}))
    monkeypatch.setattr(vv, "_source_rescan", lambda *a, **k: busy("rescan", {"report": {}, "scores": {"verdict": "allow", "findings": []}, "complete": True}))
    monkeypatch.setattr(vv, "_artifact_components", lambda tree, o: busy(f"sbom-{tree.name}", (set(), None)))
    monkeypatch.setattr(vv, "_grype_db", lambda: "db1")

    t0 = time.time()
    res = vv.validate(out, log=lambda m: None)
    took = time.time() - t0
    assert peak[0] >= 3, "baseline, candidate and rescan must overlap"
    assert took < 1.3, f"parallel run should take ~2 x 0.4 s, took {took:.2f} s"
    assert res["baseline"]["container"] == "baseline" and res["candidate"]["container"] == "candidate"
    assert res["gate"]["validation"] == "passed"
    assert "timings" in res and res["timings"]["total"] > 0
