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
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import yaml

PROFILES = Path(__file__).resolve().parent / "profiles"
NETWORK = "guardian-validate"
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
            out.append({"name": a["name"], "run": True, "cmd": a["cmd"], "reason": "matches profile exception"})
    return out


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
         evidence_ok: bool) -> dict:
    reasons, failed, incomplete = [], False, False
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
                plan = hook_plan(st.get("allow", []), lock)
                outs, ok = [], True
                for h in plan:
                    if not h["run"]:
                        ok = False
                        outs.append(f"{h['name']}: refused ({h['reason']})")
                        continue
                    code, out, dur = _exec(name, h["cmd"], st.get("timeout", 900))
                    ok = ok and code == 0
                    outs.append(f"{h['name']}: exit {code} in {dur}s\n{out[-1500:]}")
                stages.append({**rec, "status": "passed" if ok else "failed", "hooks": plan, "detail": "\n".join(outs)[-4000:]})
            else:
                cmd = st.get("cmd") or f"node .guardian-integration.cjs"
                log(f"[{label}] {st['id']}: {cmd[:90]}")
                code, out, dur = _exec(name, cmd, st.get("timeout", 600))
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
            r = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"], input=data, cwd=dest, capture_output=True)
            if r.returncode != 0:
                raise RuntimeError(f"approved patch does not apply: {r.stderr.decode()[-300:]}")
    return dest
