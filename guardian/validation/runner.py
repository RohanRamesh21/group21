"""Validation worker (stage ⑩): run a declared profile on the baseline and on the approved candidate, in a
disposable, isolated container, then decide "verified" with deterministic gates (GUARDIAN_FINAL_PLAN.md §12.4, §13).

Isolation: no secrets, no host-home mount, no Docker socket, all capabilities dropped, no-new-privileges,
unprivileged user, CPU/memory/pids limits, and an internal Docker network on which only the local Verdaccio
registry proxy is reachable. Project and dependency code does run here (builds and tests execute it);
that is why it runs only here.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import yaml

PROFILES = Path(__file__).resolve().parent / "profiles"
NETWORK = "guardian-validate"
RETRY_STAGES = {"target_test", "unit", "integration"}  # test stages only
REGISTRY_CONTAINER = "verdaccio"


# ---------------------------------------------------------------- profile + hooks (pure)
def load_profile(name: str) -> tuple[dict, str, Path]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name or ""):
        raise FileNotFoundError(f"unknown profile {name!r}")
    folder = PROFILES / name
    f = folder / "profile.yaml"
    if not f.exists():
        raise FileNotFoundError(f"unknown profile {name!r}")
    h = hashlib.sha256()
    for p in sorted(folder.iterdir()):  # the hash covers every file the profile ships (incl. the integration script)
        if p.is_file():
            h.update(p.name.encode() + b"\0" + p.read_bytes())
    return yaml.safe_load(f.read_text()), h.hexdigest(), folder


def hook_plan(allow: list[dict], lock: dict) -> list[dict]:
    """Which lifecycle hooks may run: only exact name + version + integrity matches of the profile's exceptions."""
    pkgs = lock.get("packages") or {}
    out = []
    for a in allow:
        entry = pkgs.get(f"node_modules/{a['name']}")
        if entry is None:
            out.append({"name": a["name"], "run": False, "cmd": a["cmd"], "reason": "package not in the lockfile"})
        elif entry.get("version") != a["version"]:
            out.append({"name": a["name"], "run": False, "cmd": a["cmd"],
                        "reason": f"version {entry.get('version')} differs from the approved {a['version']}"})
        elif entry.get("integrity") != a["integrity"]:
            out.append({"name": a["name"], "run": False, "cmd": a["cmd"], "reason": "integrity hash differs from the approved one"})
        else:
            out.append({"name": a["name"], "run": True, "cmd": a["cmd"], "reason": "matches profile exception",
                        "version": a["version"], "integrity": a["integrity"], "outputs": a.get("outputs") or []})
    return out


# Native builds of allow-listed hooks, keyed by everything that determines the output. At the hooks stage only npm
# (scripts off) and this checksum-pinned build have run, so a cached output is exactly what a fresh build would make.
HOOK_CACHE = Path(os.environ.get("GUARDIAN_HOOK_CACHE", Path.home() / ".cache" / "guardian" / "native-builds"))


def _hook_key(h: dict, image_ref: str) -> str:
    return hashlib.sha256(f"{h['name']}|{h['version']}|{h['integrity']}|{image_ref}|{h['cmd']}".encode()).hexdigest()[:32]


def run_hooks(container: str, st: dict, lock: dict, tree: Path, image_ref: str, cache: Path | None = None) -> dict:
    """Run the profile's allow-listed lifecycle hooks; reuse a verified earlier build when every input is identical."""
    cache = Path(cache or HOOK_CACHE)
    rec = {"id": st["id"], "required": st.get("required", True), "security": st.get("security", False)}
    plan = hook_plan(st.get("allow", []), lock)
    outs, ok, total = [], True, 0.0
    for h in plan:
        if not h["run"]:
            ok = False
            outs.append(f"{h['name']}: refused ({h['reason']})")
            continue
        pkg = tree / "node_modules" / h["name"]
        key = _hook_key(h, image_ref) if h["outputs"] else None
        hit = key and all((cache / key / o).exists() for o in h["outputs"])
        if hit:
            for o in h["outputs"]:
                shutil.rmtree(pkg / o, ignore_errors=True)
                shutil.copytree(cache / key / o, pkg / o)
            h["cache"] = "hit"
            outs.append(f"{h['name']}: reused build {key[:12]} (same version, lockfile integrity, image and command)")
            continue
        code, out, dur = _exec(container, h["cmd"], st.get("timeout", 900))
        total += dur
        ok = ok and code == 0
        outs.append(f"{h['name']}: exit {code} in {dur}s\n{out[-1500:]}")
        h["cache"] = "miss"
        if code == 0 and key and all((pkg / o).exists() for o in h["outputs"]):
            tmp = cache / f".{key}.{uuid.uuid4().hex[:6]}"
            for o in h["outputs"]:
                shutil.copytree(pkg / o, tmp / o)
            try:
                tmp.rename(cache / key)  # atomic: a parallel lane that finished first wins, both are identical
            except OSError:
                shutil.rmtree(tmp, ignore_errors=True)
            h["cache"] = "stored"
    return {**rec, "status": "passed" if ok else "failed", "hooks": plan, "seconds": round(total, 1) or None,
            "detail": "\n".join(outs)[-4000:]}


def docker_run_args(prof: dict, name: str, tree: str, image_ref: str) -> list[str]:
    r = prof.get("resources") or {}
    args = ["docker", "run", "-d", "--name", name, "--network", prof.get("network", NETWORK),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", prof.get("user", "1000:1000"),
            "--cpus", str(r.get("cpus", "2")), "--memory", str(r.get("memory", "4g")), "--pids-limit", str(r.get("pids", 1024)),
            "--tmpfs", "/tmp:rw,exec,size=1g", "-e", "HOME=/tmp/home", "-e", f"npm_config_registry={prof['registry']}",
            "-e", "npm_config_cache=/tmp/npm-cache", "-v", f"{tree}:{prof.get('workdir', '/work')}", "-w", prof.get("workdir", "/work")]
    for k, v in (prof.get("env") or {}).items():
        args += ["-e", f"{k}={v}"]
    return args + [image_ref, "sleep", "infinity"]


# ---------------------------------------------------------------- gate (pure)
def gate(*, approval_ok: bool, approval_error: str | None, baseline: list[dict], candidate: list[dict], targets_resolved: list[str],
         targets_remaining: list[str], new_high: list[str], rescans_complete: bool, sbom_diff: dict, same_snapshot: bool,
         evidence_ok: bool, generated: list[dict] | None = None) -> dict:
    reasons, failed, incomplete = [], False, False
    for g in generated or []:  # AI-written test that passed on the PR's version and fails on the fixed one
        failed = True
        reasons.append(f"AI-written behaviour test for {g.get('package')}: {g.get('reason')}")
    if not approval_ok:
        failed = True
        reasons.append(f"approval: {approval_error}")
    if not evidence_ok:
        failed = True
        reasons.append("evidence integrity check failed")
    base = {s["id"]: s for s in baseline}
    pre_existing = []
    for s in candidate:
        if not s.get("required"):
            continue
        b = base.get(s["id"], {})
        if s["status"] == "passed":
            continue
        if s["status"] in ("not_run", "skipped", "error"):
            incomplete = True
            reasons.append(f"{s['id']}: required stage did not run ({s['status']})")
        elif s.get("security"):
            failed = True
            reasons.append(f"{s['id']}: security test failed on the candidate (a baseline failure is no excuse)")
        elif b.get("status") == "failed":
            pre_existing.append(s["id"])  # failed before the change too: reported, not blamed on the fix
        else:
            failed = True
            reasons.append(f"{s['id']}: failed on the candidate but passed on the baseline (regression)")
    if not rescans_complete:
        incomplete = True
        reasons.append("rescan of the candidate did not complete")
    if not same_snapshot:
        incomplete = True
        reasons.append("before/after scans used different advisory snapshots")
    target = "corrected" if targets_resolved and not targets_remaining else "not corrected"
    if targets_remaining:
        reasons.append(f"target findings still present: {', '.join(targets_remaining[:5])}")
    if new_high:
        reasons.append(f"new High/Critical findings: {', '.join(new_high[:5])}")
    validation = "failed" if failed else ("incomplete" if incomplete else "passed")
    verified = validation == "passed" and target == "corrected" and not new_high
    return {"verified": verified, "validation": validation, "target": target, "reasons": reasons,
            "pre_existing_failures": pre_existing, "new_high": new_high, "targets_resolved": targets_resolved,
            "targets_remaining": targets_remaining, "sbom_diff": sbom_diff}


# ---------------------------------------------------------------- docker execution
def _run(cmd: list[str], timeout: int | None = None, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def remove_orphans() -> int:
    """Remove sandbox containers left by a server process that was stopped mid-validation (its `finally` never ran).
    Called at server start, when no validation of this process can be running. Returns how many were removed."""
    try:
        r = _run(["docker", "ps", "-aq", "--filter", "name=^guardian-val-"])
        ids = r.stdout.split() if r.returncode == 0 else []
        if ids:
            _run(["docker", "rm", "-f", *ids])
        return len(ids)
    except Exception:  # Docker missing or not running: nothing to clean, never block the server
        return 0


def ensure_network() -> None:
    """Internal network (no route to the internet) that only the Verdaccio proxy shares."""
    if _run(["docker", "network", "inspect", NETWORK]).returncode != 0:
        _run(["docker", "network", "create", "--internal", NETWORK])
    nets = _run(["docker", "inspect", REGISTRY_CONTAINER, "--format", "{{json .NetworkSettings.Networks}}"]).stdout
    if NETWORK not in nets:
        r = _run(["docker", "network", "connect", "--alias", "verdaccio", NETWORK, REGISTRY_CONTAINER])
        if r.returncode != 0:
            raise RuntimeError(f"could not attach the registry proxy to {NETWORK}: {r.stderr[-200:]}")


def image_digest(image: str) -> str:
    r = _run(["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"])
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError(f"image {image} not available locally: pull it first")
    return r.stdout.strip()


def _exec(name: str, cmd: str, timeout: int) -> tuple[int, str, float]:
    t0 = time.time()
    try:
        r = _run(["docker", "exec", name, "bash", "-lc", cmd], timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)[-4000:], round(time.time() - t0, 1)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s", round(time.time() - t0, 1)


def run_profile(tree: Path, prof: dict, folder: Path, label: str, log=print) -> dict:
    """Run every stage of the profile on `tree`. A failed required stage stops later stages (marked not_run)."""
    ensure_network()
    ref = image_digest(prof["image"])
    name = f"guardian-val-{label}-{uuid.uuid4().hex[:6]}"
    if (folder / "integration.cjs").exists():  # profiles without an integration script (e.g. generic-npm) skip it
        shutil.copy(folder / "integration.cjs", tree / ".guardian-integration.cjs")
    started = _run(docker_run_args(prof, name, str(tree), ref))
    if started.returncode != 0:
        raise RuntimeError(f"could not start the worker: {started.stderr[-300:]}")
    stages, stop = [], False
    try:
        lock = json.loads((tree / "package-lock.json").read_text()) if (tree / "package-lock.json").exists() else {}
        for st in prof["stages"]:
            rec = {"id": st["id"], "required": st.get("required", True), "security": st.get("security", False)}
            if stop:
                stages.append({**rec, "status": "not_run", "detail": "an earlier required stage failed"})
                continue
            if st["id"] == "hooks":
                log(f"[{label}] hooks: " + "; ".join(a["cmd"] for a in st.get("allow", [])))
                stages.append(run_hooks(name, st, lock, tree, ref))
            else:
                cmd = st.get("cmd") or f"node .guardian-integration.cjs"
                log(f"[{label}] {st['id']}: {cmd[:90]}")
                code, out, dur = _exec(name, cmd, st.get("timeout", 600))
                if code != 0 and st["id"] in RETRY_STAGES:
                    # one retry for test stages: flaky tests are a known threat to reproducible validation (BUMP,
                    # SANER 2024). A pass on retry is labelled, never silent; install/build failures are not retried.
                    log(f"[{label}] {st['id']}: retry once (exit {code})")
                    first = code
                    code, out2, dur2 = _exec(name, cmd, st.get("timeout", 600))
                    rec.update(retried=True, first_exit=first, flaky=code == 0)
                    out, dur = out2, round(dur + dur2, 1)
                rec.update(status="passed" if code == 0 else "failed", exit=code, seconds=dur, command=cmd, output=out)
                if st["id"] == "integration":
                    line = next((ln for ln in reversed(out.splitlines()) if ln.startswith("{")), "{}")
                    try:
                        rec["integration"] = json.loads(line)
                    except ValueError:
                        rec["integration"] = {}
                stages.append(rec)
            if stages[-1]["status"] != "passed" and rec["required"]:
                stop = True
    finally:
        _run(["docker", "rm", "-f", name])
    log(f"[{label}] finished")
    return {"image": ref, "container": name, "stages": stages}


# ---------------------------------------------------------------- trees
def prepare_tree(repo: Path, sha: str, dest: Path, patch: Path | None = None, patch_sha256: str | None = None) -> Path:
    from guardian.remediation.patch import export_tree
    if dest.exists():
        shutil.rmtree(dest)
    export_tree(repo, sha, dest)
    if patch is not None:
        data = patch.read_bytes()
        if patch_sha256 and hashlib.sha256(data).hexdigest() != patch_sha256:
            raise RuntimeError("patch bytes do not match the approved hash")
        if data.strip():
            # The tree may sit inside another git repository (guardian-out/ is inside Guardian's own repo). There, `git
            # apply` treats paths as relative to THAT repo and silently skips them while returning 0. Stop git from
            # looking above the tree, then prove the patch is really in it (it must reverse cleanly).
            env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(Path(dest).resolve().parent)}
            env.pop("GIT_DIR", None)
            env.pop("GIT_WORK_TREE", None)
            r = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"], input=data, cwd=dest, capture_output=True, env=env)
            if r.returncode != 0:
                raise RuntimeError(f"approved patch does not apply: {r.stderr.decode()[-300:]}")
            v = subprocess.run(["git", "apply", "--reverse", "--check", "-"], input=data, cwd=dest, capture_output=True, env=env)
            if v.returncode != 0:
                raise RuntimeError(f"approved patch was not applied to the tree (reverse check failed): {v.stderr.decode()[-300:]}")
    return dest


def profile_for(repo: str) -> str:
    """Validation profile for a repository: the profile whose `repos:` list names it, else the default (uptime-kuma)."""
    import yaml
    for f in sorted((Path(__file__).parent / "profiles").glob("*/profile.yaml")):
        doc = yaml.safe_load(f.read_text()) or {}
        if repo in (doc.get("repos") or []):
            return doc["name"]
    return "generic-npm" if repo else "uptime-kuma"  # any other repository: the automatic npm profile
