"""Scan any project the user brings (any language / package manager): a ZIP upload, a public Git URL or a local folder.

Safety rules (the analysed project is untrusted):
  * Nothing from the project is installed or executed. Every tool that reads it runs in the podman sandbox
    (guardian/sandbox: no network, read-only, pinned images, resource limits). If an npm lockfile is missing we
    only *resolve* one from the package.json files (never the project's .npmrc), with registry access only.
  * ZIP: no absolute paths, no `..`, no symlinks, size and file-count limits.
  * Git: https only, host allow-list, read-only shallow clone, hooks disabled, no submodules, no credential prompts.
  * Local folder: only under the allowed roots (GUARDIAN_PATH_ROOTS, default: the user's home directory). A Git repository
    is cloned (no checkout, no hooks, no submodules) into the project folder, so the original is never written to; any
    other folder is copied with the same limits as a ZIP (no symlinks, no node_modules/.git, size and file-count limits).
  * Everything stays under guardian-out/projects/<id>/.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import threading
import time
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "guardian-out" / "projects"
GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
MAX_ZIP_BYTES = 200 * 1024 * 1024
MAX_FILES = 60_000
SKIP_DIRS = {"node_modules", ".git"}
GIT_ENV = {"PATH": os.defpath, "LANG": "C.UTF-8", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "false",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
SAFE_GIT = ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "protocol.file.allow=never",
            "-c", "http.followRedirects=false"]

JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()

# Pipeline stages shown by the dashboard, in order. Each progress message is mapped to one of them (first match wins);
# the stage only moves forward, so the base-version rescan stays inside "compare".
STAGES = ["fetch", "inventory", "sbom", "ci", "vulns", "compare", "registry", "policy"]
_STAGE_HINTS = [
    ("policy", ("policy-as-code",)),
    ("registry", ("on the registry",)),
    ("compare", ("previous state",)),
    ("vulns", ("looking up vulnerabilities",)),
    ("ci", ("ci workflows",)),
    ("sbom", ("building the sbom",)),
    ("inventory", ("day 1 pipeline", "reading tracked files", "resolving versions", "could not parse", "declared dependencies")),
    ("fetch", ("clon", "fetching ref", "extract", "copying", "copied", "local repository")),
]


def stage_of(msg: str, current: str | None = None) -> str | None:
    """Pipeline stage a progress message belongs to, never earlier than `current`."""
    low = msg.lower()
    found = next((st for st, keys in _STAGE_HINTS if any(k in low for k in keys)), None)
    if current and (found is None or STAGES.index(found) < STAGES.index(current)):
        return current
    return found


def _job(pid: str, **kw):
    with _LOCK:
        JOBS[pid].update(kw)
        JOBS[pid]["updated"] = time.time()
        (BASE / pid / "job.json").write_text(json.dumps(JOBS[pid], indent=1))


def _step(pid: str, msg: str):
    with _LOCK:
        stage = stage_of(msg, JOBS[pid].get("stage"))
        JOBS[pid].setdefault("steps", []).append({"t": round(time.time() - JOBS[pid]["created"], 1), "msg": msg, "stage": stage})
    _job(pid, status="running", message=msg, stage=stage)


def list_jobs() -> list[dict]:
    if BASE.exists():
        for d in BASE.iterdir():
            f = d / "job.json"
            if f.exists() and d.name not in JOBS:
                try:
                    JOBS[d.name] = json.loads(f.read_text())
                except Exception:
                    pass
    return sorted(JOBS.values(), key=lambda j: -j["created"])


def get(pid: str) -> dict | None:
    list_jobs()
    return JOBS.get(pid)


def _new(kind: str, label: str, extra: dict) -> str:
    pid = time.strftime("%H%M%S") + "-" + uuid.uuid4().hex[:6]
    (BASE / pid).mkdir(parents=True, exist_ok=True)
    JOBS[pid] = {"id": pid, "kind": kind, "label": label, "status": "queued", "message": "queued", "created": time.time(),
                 "steps": [], **extra}
    _job(pid)
    return pid


# ---------------------------------------------------------------- ZIP
def safe_extract(zip_path: Path, dest: Path) -> int:
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"archive has {len(infos)} entries (limit {MAX_FILES})")
        total = sum(i.file_size for i in infos)
        if total > MAX_ZIP_BYTES:
            raise ValueError(f"archive expands to {total // 1_000_000} MB (limit {MAX_ZIP_BYTES // 1_000_000} MB)")
        root = dest.resolve()
        n = 0
        for i in infos:
            name = i.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts or ":" in Path(name).parts[0]:
                raise ValueError(f"unsafe path in archive: {name}")
            if stat.S_ISLNK(i.external_attr >> 16):
                continue  # never materialise symlinks
            if any(p in SKIP_DIRS for p in Path(name).parts):
                continue
            target = (dest / name).resolve()
            if not str(target).startswith(str(root)):
                raise ValueError(f"unsafe path in archive: {name}")
            if i.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(i) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            n += 1
        return n


def _git_snapshot(repo: Path, message: str):
    subprocess.run(SAFE_GIT + ["init", "-q"], cwd=repo, check=True, env=GIT_ENV)
    subprocess.run(SAFE_GIT + ["add", "-A"], cwd=repo, check=True, env=GIT_ENV)
    subprocess.run(SAFE_GIT + ["-c", "user.name=guardian", "-c", "user.email=guardian@localhost", "commit", "-q",
                               "--no-verify", "-m", message], cwd=repo, check=True, env=GIT_ENV)


def start_zip(upload: Path, filename: str) -> str:
    pid = _new("zip", filename, {})
    threading.Thread(target=_run_zip, args=(pid, upload), daemon=True).start()
    return pid


def _run_zip(pid: str, upload: Path):
    try:
        src = BASE / pid / "src"
        _step(pid, "Extracting archive safely (no symlinks, no paths outside the folder, size limits)")
        n = safe_extract(upload, src)
        upload.unlink(missing_ok=True)
        tops = [p for p in src.iterdir() if not p.name.startswith(".") and p.name != "__MACOSX"]
        repo = tops[0] if len(tops) == 1 and tops[0].is_dir() else src  # zip of a single folder: use that folder
        _step(pid, f"Extracted {n} files")
        if (repo / ".git").exists():
            shutil.rmtree(repo / ".git")
        _git_snapshot(repo, "uploaded snapshot")
        _analyse(pid, repo, None, "HEAD", label=Path(JOBS[pid]["label"]).stem)
    except Exception as e:
        _job(pid, status="error", message=f"{type(e).__name__}: {e}"[:400])


# ---------------------------------------------------------------- Git URL
def validate_git_url(url: str) -> str:
    u = urlparse(url.strip())
    if u.scheme != "https" or not u.hostname or u.hostname.lower() not in GIT_HOSTS:
        raise ValueError(f"only https URLs on {', '.join(sorted(GIT_HOSTS))} are allowed")
    if u.username or u.password or u.query or u.fragment:
        raise ValueError("URL must not contain credentials, query or fragment")
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("URL must point to a repository (https://host/owner/repo)")
    return url.strip()


def start_git(url: str, base: str | None, head: str | None) -> str:
    url = validate_git_url(url)
    pid = _new("git", url.removeprefix("https://"), {"url": url, "base": base or None, "head": head or None})
    threading.Thread(target=_run_git, args=(pid, url, base, head), daemon=True).start()
    return pid


def _run_git(pid: str, url: str, base: str | None, head: str | None):
    try:
        repo = BASE / pid / "src"
        _step(pid, "Cloning read-only (shallow, no checkout, no hooks, no submodules)")
        r = subprocess.run(SAFE_GIT + ["clone", "-q", "--depth", "200", "--no-checkout", "--no-recurse-submodules", "--", url, str(repo)],
                           capture_output=True, text=True, timeout=300, env=GIT_ENV)
        if r.returncode != 0:
            raise RuntimeError("clone failed: " + r.stderr[-300:])
        for ref in [x for x in (base, head) if x]:
            if subprocess.run(SAFE_GIT + ["rev-parse", "--verify", "-q", "--end-of-options", f"{ref}^{{commit}}"], cwd=repo, env=GIT_ENV,
                              capture_output=True).returncode != 0:
                _step(pid, f"Fetching ref {ref}")
                remote_ref = f"refs/guardian/{ref}"
                if subprocess.run(SAFE_GIT + ["check-ref-format", remote_ref], cwd=repo, env=GIT_ENV).returncode:
                    raise ValueError("invalid remote ref")
                f = subprocess.run(SAFE_GIT + ["fetch", "-q", "--depth", "200", "--", "origin", f"{ref}:{remote_ref}"],
                                   cwd=repo, capture_output=True, text=True, timeout=300, env=GIT_ENV)
                if f.returncode != 0:
                    raise RuntimeError(f"ref {ref} not found: {f.stderr[-200:]}")
        head_ref = head or "HEAD"
        if not base and subprocess.run(SAFE_GIT + ["rev-parse", "--verify", "-q", "--end-of-options", f"{head_ref}~1^{{commit}}"], cwd=repo, env=GIT_ENV,
                                       capture_output=True).returncode == 0:
            base = f"{head_ref}~1"  # default "what changed": the latest commit
            _job(pid, base_default=True)
        _analyse(pid, repo, base, head_ref, label=url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))
    except Exception as e:
        _job(pid, status="error", message=f"{type(e).__name__}: {e}"[:400])


# ---------------------------------------------------------------- local folder
def path_roots() -> list[Path]:
    """Folders a local-path scan may read from. GUARDIAN_PATH_ROOTS (os.pathsep-separated) overrides the default."""
    raw = os.environ.get("GUARDIAN_PATH_ROOTS", "")
    roots = [Path(x).expanduser() for x in raw.split(os.pathsep) if x.strip()] or [Path.home()]
    return [r.resolve() for r in roots]


def validate_local_path(raw: str) -> Path:
    if not raw or not raw.strip():
        raise ValueError("enter the path of a folder on this machine")
    p = Path(raw.strip()).expanduser()
    if not p.is_absolute():
        raise ValueError("use an absolute path (for example /home/you/projects/app or ~/projects/app)")
    p = p.resolve()
    if not p.is_dir():
        raise ValueError(f"{p} is not a folder on this machine")
    roots = path_roots()
    if not any(p == r or p.is_relative_to(r) for r in roots) or p in (Path("/"), Path.home().resolve()):
        allowed = ", ".join(str(r) for r in roots)
        raise ValueError(f"pick a project folder inside {allowed} (set GUARDIAN_PATH_ROOTS to allow other folders)")
    if p.is_relative_to(ROOT / "guardian-out"):
        raise ValueError("that folder holds Guardian's own output")
    return p


def safe_copy(src: Path, dest: Path) -> int:
    """Copy a folder like safe_extract unpacks a ZIP: regular files only, no symlinks, size and file-count limits."""
    n = total = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink()]
        rel = Path(dirpath).relative_to(src)
        for name in filenames:
            f = Path(dirpath) / name
            st = f.lstat()
            if not stat.S_ISREG(st.st_mode):
                continue  # symlinks, sockets, devices: never copied
            n += 1
            total += st.st_size
            if n > MAX_FILES:
                raise ValueError(f"folder has more than {MAX_FILES} files")
            if total > MAX_ZIP_BYTES:
                raise ValueError(f"folder is larger than {MAX_ZIP_BYTES // (1024 * 1024)} MB (node_modules and .git are skipped)")
            target = dest / rel / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, target, follow_symlinks=False)
    return n


def start_path(raw: str, base: str | None, head: str | None) -> str:
    path = validate_local_path(raw)
    is_git = (path / ".git").exists() or ((path / "HEAD").is_file() and (path / "objects").is_dir() and (path / "refs").is_dir())
    pid = _new("path", path.name, {"path": str(path), "git": is_git,
                                   "base": (base or None) if is_git else None, "head": (head or None) if is_git else None})
    threading.Thread(target=_run_path, args=(pid, path, is_git, base, head), daemon=True).start()
    return pid


def _run_path(pid: str, path: Path, is_git: bool, base: str | None, head: str | None):
    try:
        repo = BASE / pid / "src"
        if is_git:
            _step(pid, f"Cloning the local repository {path} (no checkout, no hooks, no submodules; the original is not modified)")
            # A local clone uses git's "file" protocol, which SAFE_GIT disables (it guards remote clones and submodules).
            # Allowed here only, for this one source folder; submodules stay off.
            local_git = SAFE_GIT + ["-c", "protocol.file.allow=always"]
            r = subprocess.run(local_git + ["clone", "-q", "--no-checkout", "--no-hardlinks", "--no-recurse-submodules", "--", str(path), str(repo)],
                               capture_output=True, text=True, timeout=300, env=GIT_ENV)
            if r.returncode != 0:
                raise RuntimeError("clone failed: " + r.stderr[-300:])
            # local branches of the original become branches here too, so base/head can name them as usual
            f = subprocess.run(local_git + ["fetch", "-q", "--update-head-ok", "--no-recurse-submodules", "origin", "+refs/heads/*:refs/heads/*"],
                               cwd=repo, capture_output=True, text=True, timeout=300, env=GIT_ENV)
            if f.returncode != 0:
                raise RuntimeError("could not read the branches of the local repository: " + f.stderr[-300:])
            from guardian.git_snapshot import resolve_commit

            for role, ref in (("base", base), ("head", head)):
                if not ref:
                    continue
                try:
                    resolve_commit(repo, ref)
                except ValueError:
                    # A bare cache can store commits under refs outside the clone's branch and tag refspecs.
                    try:
                        commit = resolve_commit(path, ref)
                    except ValueError as exc:
                        raise ValueError(f"ref {ref} not found in {path}") from exc
                    fetched = subprocess.run(local_git + ["fetch", "-q", "--update-shallow", "--no-recurse-submodules",
                                                          "origin", f"{commit}:refs/guardian/selected-{role}"],
                                             cwd=repo, capture_output=True, text=True, timeout=300, env=GIT_ENV)
                    if fetched.returncode:
                        raise RuntimeError(f"could not copy the selected {role} commit")
                    if role == "base":
                        base = commit
                    else:
                        head = commit
            head_ref = head or "HEAD"
            if not base and subprocess.run(SAFE_GIT + ["rev-parse", "--verify", "-q", "--end-of-options", f"{head_ref}~1^{{commit}}"],
                                           cwd=repo, env=GIT_ENV, capture_output=True).returncode == 0:
                base = f"{head_ref}~1"
                _job(pid, base_default=True)
            _analyse(pid, repo, base, head_ref, label=path.name)
        else:
            _step(pid, f"Copying {path} (regular files only; symlinks, node_modules and .git skipped)")
            n = safe_copy(path, repo)
            if not n:
                raise ValueError("the folder has no files to scan")
            _step(pid, f"Copied {n} files")
            _git_snapshot(repo, "local folder snapshot")
            _analyse(pid, repo, None, "HEAD", label=path.name)
    except Exception as e:
        _job(pid, status="error", message=f"{type(e).__name__}: {e}"[:400])


# ---------------------------------------------------------------- analysis (universal: any ecosystem)
def _analyse(pid: str, repo: Path, base: str | None, head: str, label: str):
    from guardian.universal import check_any

    mode = "compare" if base else "single"
    _job(pid, mode=mode)
    _step(pid, "Day 1 pipeline: components -> SBOM -> dependency graph -> vulnerabilities -> suspicious changes -> evidence"
               + (f" (comparing {base} -> {head})" if base else " (full scan, no earlier version to compare)"))
    out = BASE / pid / "check"
    rep = check_any(repo, base, head, out, label, log=lambda m: _step(pid, m))
    latest = json.loads((out / "latest.json").read_text())
    h = rep["headline"]
    _job(pid, status="done", message="done", mode=mode, out=str(out),
         summary={"packages": h["inventory"]["packages"], "ecosystems": h["inventory"].get("ecosystems"), "verdict": h.get("verdict"),
                  "reasons": h.get("verdict_reasons", [])[:3], "head_commit": h["head_commit"], "base_commit": h["base_commit"],
                  "scores": bool(latest.get("scores"))})


def out_dir(pid: str | None) -> Path:
    if not pid:
        return ROOT / "guardian-out" / "check"
    if not get(pid):
        raise KeyError(pid)
    return BASE / pid / "check"
