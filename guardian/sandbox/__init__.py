"""Sandbox for every tool that reads an untrusted repository (npm, Syft, Grype, OSV-Scanner, zizmor).

Why: a scanned repository is attacker-controlled input. Parsers have bugs, and package managers read config
from the folder they run in (we proved that a repository's own `.npmrc` can make `npm --ignore-scripts` run a
program from the repository). So these tools never run on the host. Each run is a fresh rootless podman
container with these guardrails:

  * image pinned by digest (`guardian.yaml` sandbox.images), never pulled during a scan (`--pull=never`)
  * no network at all (`--network=none`); a step that needs a registry gets the egress allow-list proxy
    (see `egress.py`), which is then its only route out
  * inputs mounted read-only, one writable output folder, read-only root file system, small /tmp
  * no host environment, home folder, SSH keys or tokens: only the variables Guardian passes
  * non-root inside (`--userns=keep-id`), all capabilities dropped, `no-new-privileges`
  * CPU, memory, process-count and wall-clock limits; the container is killed on timeout

If podman or an image is missing, the step is NOT run on the host: it fails with a clear error that the scan
reports as a `tool_error`. `GUARDIAN_SANDBOX=host` is a developer escape hatch that runs the same tools on the
host without isolation; every scan made that way says so in its report.
"""
from __future__ import annotations

import contextlib
import contextvars
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = Path(__file__).with_name("bridge.js")

# tool -> image key in guardian.yaml, binary inside the image, binary on the host (host mode only)
TOOLS: dict[str, dict] = {
    "npm": {"image": "node", "entrypoint": "npm", "host": "npm", "bridge": "node"},
    "node": {"image": "node", "entrypoint": "node", "host": "node", "bridge": "node"},  # sandbox self-tests
    "syft": {"image": "syft", "entrypoint": "/syft", "host": "syft"},
    "grype": {"image": "grype", "entrypoint": "/grype", "host": "grype"},
    "osv-scanner": {"image": "osv-scanner", "entrypoint": "/osv-scanner", "host": "osv-scanner"},
    "zizmor": {"image": "zizmor", "entrypoint": "/usr/bin/zizmor", "host": "zizmor"},
}
DEFAULT_LIMITS = {"memory": "2g", "cpus": "2", "pids": 512, "timeout_s": 900, "tmp_size": "512m"}

_log: contextvars.ContextVar[list | None] = contextvars.ContextVar("guardian_sandbox_log", default=None)


@dataclass
class Result:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    isolated: bool = True
    error: str | None = None  # set when the tool could not run at all (sandbox missing, timeout, ...)
    denied: list[str] = field(default_factory=list)  # hosts the run tried to reach and the proxy refused

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0


def config() -> dict:
    try:
        cfg = (yaml.safe_load((ROOT / "guardian.yaml").read_text()) or {}).get("sandbox") or {}
    except OSError:
        cfg = {}
    mode = os.environ.get("GUARDIAN_SANDBOX") or cfg.get("mode", "podman")
    return {**cfg, "mode": mode, "limits": {**DEFAULT_LIMITS, **(cfg.get("limits") or {})}, "images": cfg.get("images") or {}}


def mode() -> str:
    return config()["mode"]


def image_for(tool: str) -> str:
    img = config()["images"].get(TOOLS[tool]["image"])
    if not img or "@sha256:" not in img:
        raise SandboxError(f"no digest-pinned image for {tool} in guardian.yaml sandbox.images")
    return img


class SandboxError(RuntimeError):
    pass


@contextlib.contextmanager
def recording():
    """Collect one entry per tool run (for the scan report): `with recording() as runs: ...`."""
    runs: list[dict] = []
    token = _log.set(runs)
    try:
        yield runs
    finally:
        _log.reset(token)


def _record(**entry) -> None:
    runs = _log.get()
    if runs is not None:
        runs.append(entry)


def run(tool: str, args: list[str], *, inputs: dict[str, Path] | None = None, output: Path | None = None,
        env: dict[str, str] | None = None, egress: set[str] | None = None, timeout: int | None = None,
        workdir: str | None = None) -> Result:
    """Run `tool args...` in the sandbox.

    `inputs` maps a name to a host path, mounted read-only at /in/<name>; `output` is mounted read-write at /out.
    Arguments, env values and `workdir` may use `{name}` and `{out}` placeholders, which become the container
    paths (or the host paths in host mode). `egress` is the set of host names this run may reach over HTTPS.
    """
    cfg, spec = config(), TOOLS[tool]
    limits = cfg["limits"]
    timeout = timeout or int(limits["timeout_s"])
    inputs = {k: Path(v).resolve() for k, v in (inputs or {}).items()}
    started = time.time()
    if cfg["mode"] == "host":
        res = _run_host(spec, args, inputs, output, env or {}, timeout, workdir)
    elif cfg["mode"] == "podman":
        res = _run_podman(tool, spec, args, inputs, output, env or {}, egress, timeout, workdir, limits)
    else:
        res = Result(-1, isolated=False, error=f"unknown sandbox mode {cfg['mode']!r} (use podman or host)")
    _record(tool=tool, isolated=res.isolated, seconds=round(time.time() - started, 1), returncode=res.returncode,
            error=res.error, egress=sorted(egress or []), denied=res.denied,
            image=image_for(tool) if res.isolated and res.error is None else None)
    return res


def _bind(host: Path, target: str, readonly: bool) -> list[str]:
    """--mount rather than -v: host paths may contain ':' (e.g. timestamps), which -v would split on."""
    if "," in str(host):
        raise SandboxError(f"cannot mount a path containing ',': {host}")
    return ["--mount", f"type=bind,source={host},target={target}" + (",readonly=true" if readonly else "")]


def _fill(s: str, paths: dict[str, str]) -> str:
    for k, v in paths.items():
        s = s.replace("{" + k + "}", v)
    return s


def _run_podman(tool, spec, args, inputs, output, env, egress, timeout, workdir, limits) -> Result:
    if not shutil.which("podman"):
        return Result(-1, error="sandbox unavailable: podman is not installed (see docs/SETUP.md); the step was not run on the host")
    try:
        image = image_for(tool)
    except SandboxError as e:
        return Result(-1, error=str(e))
    paths = {k: f"/in/{k}" for k in inputs} | ({"out": "/out"} if output else {})
    name = f"gsbx-{tool}-{uuid.uuid4().hex[:8]}"
    cmd = ["podman", "run", "--rm", "--name", name, "--pull=never", "--network=none", "--read-only",
           "--tmpfs", f"/tmp:rw,size={limits['tmp_size']},mode=1777", "--cap-drop=all",
           "--security-opt=no-new-privileges", "--userns=keep-id", "--user", f"{os.getuid()}:{os.getgid()}",
           "--memory", str(limits["memory"]), "--memory-swap", str(limits["memory"]), "--cpus", str(limits["cpus"]),
           "--pids-limit", str(limits["pids"]), "-e", "HOME=/tmp"]
    for k, host in inputs.items():
        cmd += _bind(host, f"/in/{k}", readonly=True)
    if output:
        output.mkdir(parents=True, exist_ok=True)
        cmd += _bind(output.resolve(), "/out", readonly=False)
    for k, v in env.items():
        cmd += ["-e", f"{k}={_fill(v, paths)}"]
    if workdir:
        cmd += ["--workdir", _fill(workdir, paths)]
    argv = [_fill(a, paths) for a in args]
    with contextlib.ExitStack() as stack:
        proxy = None
        if egress:
            if spec.get("bridge") != "node":
                return Result(-1, error=f"{tool} has no egress bridge; it must run without network")
            from guardian.sandbox.egress import EgressProxy
            proxy = stack.enter_context(EgressProxy(set(egress)))
            cmd += [*_bind(proxy.socket_dir, "/gsbx-sock", readonly=True), *_bind(BRIDGE, "/gsbx/bridge.js", readonly=True),
                    "-e", "GSBX_SOCK=/gsbx-sock/egress.sock", "-e", "HTTPS_PROXY=http://127.0.0.1:3128",
                    "-e", "npm_config_https_proxy=http://127.0.0.1:3128", "-e", "npm_config_proxy=http://127.0.0.1:3128",
                    "--entrypoint", "node", image, "/gsbx/bridge.js", spec["entrypoint"], *argv]
        else:
            cmd += ["--entrypoint", spec["entrypoint"], image, *argv]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            subprocess.run(["podman", "rm", "-f", name], capture_output=True)
            return Result(-1, error=f"{tool} exceeded the sandbox time limit ({timeout} s) and was killed",
                          denied=proxy.denied if proxy else [])
        denied = proxy.denied if proxy else []
    if r.returncode == 125 and ("image not known" in r.stderr or "unable to find" in r.stderr.lower()):
        return Result(-1, r.stdout, r.stderr, error=f"sandbox image for {tool} is not pulled: run `guardian sandbox setup`")
    if r.returncode in (125, 126, 127) and not r.stdout:
        return Result(r.returncode, r.stdout, r.stderr, error=f"sandbox could not start {tool}: {r.stderr.strip()[-300:]}")
    if r.returncode == 137:
        return Result(r.returncode, r.stdout, r.stderr, error=f"{tool} was killed by the sandbox memory limit ({limits['memory']})",
                      denied=denied)
    return Result(r.returncode, r.stdout, r.stderr, denied=denied)


def _run_host(spec, args, inputs, output, env, timeout, workdir) -> Result:
    """Developer escape hatch (GUARDIAN_SANDBOX=host): same tool, no isolation. Reported as not isolated."""
    if not shutil.which(spec["host"]):
        return Result(-1, isolated=False, error=f"{spec['host']} is not installed on the host (GUARDIAN_SANDBOX=host)")
    paths = {k: str(v) for k, v in inputs.items()} | ({"out": str(output.resolve())} if output else {})
    if output:
        output.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run([spec["host"], *[_fill(a, paths) for a in args]], capture_output=True, text=True, timeout=timeout,
                           cwd=_fill(workdir, paths) if workdir else None,
                           env={**os.environ, **{k: _fill(v, paths) for k, v in env.items()}})
    except subprocess.TimeoutExpired:
        return Result(-1, isolated=False, error=f"{spec['host']} timed out after {timeout} s")
    return Result(r.returncode, r.stdout, r.stderr, isolated=False)


def status() -> dict:
    """What the sandbox can do on this machine (for `guardian sandbox status` and the report)."""
    cfg = config()
    out: dict = {"mode": cfg["mode"], "podman": None, "images": {}, "grype_db": None}
    if shutil.which("podman"):
        v = subprocess.run(["podman", "version", "--format", "{{.Client.Version}}"], capture_output=True, text=True)
        out["podman"] = v.stdout.strip() or None
        for key, ref in cfg["images"].items():
            r = subprocess.run(["podman", "image", "exists", ref], capture_output=True)
            out["images"][key] = {"ref": ref, "present": r.returncode == 0}
    meta = ROOT / ".cache" / "grype" / "guardian-db.json"
    if meta.exists():
        import json
        out["grype_db"] = json.loads(meta.read_text())
    return out
