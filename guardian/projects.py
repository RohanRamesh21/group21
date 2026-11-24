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
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from guardian.git_snapshot import git, resolve_commit

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
            parts = Path(name).parts
            if not parts or name.startswith("/") or ".." in parts or ":" in parts[0]:
                raise ValueError(f"unsafe path in archive: {name}")
            if stat.S_ISLNK(i.external_attr >> 16):
                continue  # never materialise symlinks
            if any(p in SKIP_DIRS for p in Path(name).parts):
                continue
            target = (dest / name).resolve()
            if not target.is_relative_to(root):
                raise ValueError(f"unsafe path in archive: {name}")
            if i.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(i) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            n += 1
        return n


def _snapshot_commit(repo: Path, source: Path, message: str, *, parent: str | None, ref: str, force: bool = False) -> str:
    """Commit a copied tree in Guardian's repository without using its ordinary index or checkout."""
    with tempfile.TemporaryDirectory(prefix="guardian-index-") as index:
        env = {**GIT_ENV, "GIT_INDEX_FILE": str(Path(index) / "index"), "GIT_NO_REPLACE_OBJECTS": "1"}
        cmd = SAFE_GIT + ["--work-tree", str(source), "-c", "user.name=guardian", "-c", "user.email=guardian@localhost",
                          "-c", "commit.gpgsign=false"]
        subprocess.run(cmd + ["add", *(["--force"] if force else []), "-A", "--", "."],
                       cwd=repo, check=True, env=env, capture_output=True)
        tree = subprocess.check_output(cmd + ["write-tree"], cwd=repo, env=env, text=True).strip()
        parents = ["-p", parent] if parent else []
        commit = subprocess.check_output(cmd + ["commit-tree", tree, *parents, "-m", message], cwd=repo, env=env, text=True).strip()
    git(repo, "update-ref", ref, commit)
    return commit


def snapshot_baseline(project: str) -> tuple[Path, str]:
    """Resolve the immutable head of a finished ZIP or plain-folder scan."""
    job = get(project)
    if not job or job["status"] != "done" or not (job["kind"] == "zip" or job["kind"] == "path" and not job.get("git")):
        raise ValueError("select a finished ZIP or plain-folder scan as the baseline")
    root = (BASE / project).resolve()
    check = root / "check"
    try:
        link = json.loads((check / "latest.json").read_text())["path"]
        report_path = (ROOT / link).resolve()
        if not report_path.is_relative_to(check):
            raise ValueError("invalid report path")
        report = json.loads(report_path.read_text())
        repo = Path(report["repo"]).resolve()
        if not repo.is_relative_to(root / "src"):
            raise ValueError("invalid snapshot path")
        return repo, resolve_commit(repo, report["headline"]["head_commit_full"])
    except (OSError, KeyError, ValueError) as exc:
        raise ValueError("the selected baseline snapshot is unavailable; scan it again") from exc


def _git_snapshot(repo: Path, message: str, baseline: str | None = None):
    subprocess.run(SAFE_GIT + ["init", "-q"], cwd=repo, check=True, env=GIT_ENV)
    parent = None
    if baseline:
        source, parent = snapshot_baseline(baseline)
        dst = "refs/guardian/previous-snapshot"
        cmd = SAFE_GIT + ["-c", "protocol.file.allow=always", "fetch", "-q", "--no-tags", "--no-recurse-submodules",
                          "--", str(source), f"{parent}:{dst}"]
        subprocess.run(cmd, cwd=repo, check=True, env=GIT_ENV, capture_output=True, timeout=120)
    _snapshot_commit(repo, repo, message, parent=parent, ref="HEAD")
    return "refs/guardian/previous-snapshot" if parent else None


def start_zip(upload: Path, filename: str, baseline: str | None = None) -> str:
    if baseline:
        snapshot_baseline(baseline)
    pid = _new("zip", filename, {"baseline_project": baseline} if baseline else {})
    threading.Thread(target=_run_zip, args=(pid, upload, baseline), daemon=True).start()
    return pid


def _run_zip(pid: str, upload: Path, baseline: str | None = None):
    try:
        src = BASE / pid / "src"
        _step(pid, "Extracting archive safely (no symlinks, no paths outside the folder, size limits)")
        n = safe_extract(upload, src)
        upload.unlink(missing_ok=True)
        tops = [p for p in src.iterdir() if not p.name.startswith(".") and p.name != "__MACOSX"]
        repo = tops[0] if len(tops) == 1 and tops[0].is_dir() else src  # zip of a single folder: use that folder
        _step(pid, f"Extracted {n} files")
        if not n:
            raise ValueError("the archive has no project files to scan")
        base = _git_snapshot(repo, "uploaded snapshot", baseline)
        _analyse(pid, repo, base, "HEAD", label=Path(JOBS[pid]["label"]).stem)
    except Exception as e:
        _job(pid, status="error", message=f"{type(e).__name__}: {e}"[:400])
    finally:
        upload.unlink(missing_ok=True)


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


def examples() -> list[dict]:
    import yaml

    corpus = ROOT / "testbed" / "corpus.yaml"
    if not corpus.is_file():
        return []
    return [app for app in yaml.safe_load(corpus.read_text())["apps"] if app.get("demo_language")]


def start_example(name: str) -> str:
    app = next((item for item in examples() if item["name"] == name), None)
    if not app:
        raise ValueError("unknown example repository")
    url = validate_git_url(app["repo"])
    pid = _new("git", app["name"], {"url": url, "base": app["base"]["ref"], "head": app["ref"], "example": name})
    threading.Thread(target=_run_example, args=(pid, app, url), daemon=True).start()
    return pid


def _run_example(pid: str, app: dict, url: str):
    try:
        repo = BASE / pid / "src"
        cache = ROOT / "sandbox" / "corpus" / f"{app['name']}.git"
        base, head = app["base"]["ref"], app["ref"]
        bc, hc = app["base"]["commit"], app["commit"]
        refs = [f"{bc}:refs/tags/{base}", f"{hc}:refs/tags/{head}"]
        _step(pid, "Fetching the pinned release pair (bare repository, no checkout)")
        subprocess.run(SAFE_GIT + ["init", "-q", "--bare", str(repo)], env=GIT_ENV, check=True, capture_output=True)
        if cache.is_dir():
            source = subprocess.run(SAFE_GIT + ["-c", "protocol.file.allow=always", "fetch", "-q", "--update-shallow", "--no-tags",
                                               "--no-recurse-submodules", "--", str(cache), *refs],
                                    cwd=repo, env=GIT_ENV, capture_output=True, timeout=90)
        else:
            source = None
        if source is None or source.returncode:
            subprocess.run(SAFE_GIT + ["fetch", "-q", "--depth=80", "--no-tags", "--no-recurse-submodules",
                                       "--", url, *refs], cwd=repo, env=GIT_ENV, check=True, capture_output=True, timeout=150)
        if resolve_commit(repo, base) != bc or resolve_commit(repo, head) != hc:
            raise ValueError("the downloaded releases do not match the pinned commits")
        if git(repo, "merge-base", "--is-ancestor", bc, hc, check=False).returncode and (
            git(repo, "rev-parse", "--is-shallow-repository").stdout.strip() == b"true"
        ):
            _step(pid, "Fetching additional release history to verify ancestry")
            try:
                fetched = subprocess.run(SAFE_GIT + ["fetch", "-q", "--deepen=120", "--no-tags", "--no-recurse-submodules",
                                                     "--", url, f"{hc}:refs/tags/{head}"], cwd=repo, env=GIT_ENV,
                                         capture_output=True, timeout=70)
                if fetched.returncode:
                    _step(pid, "Extra history is unavailable; using the pinned release trees")
            except subprocess.TimeoutExpired:
                _step(pid, "History fetch timed out; using the pinned release trees")
        _analyse(pid, repo, base, head, label=app["name"])
    except Exception as exc:
        _job(pid, status="error", message=f"{type(exc).__name__}: {exc}"[:400])


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


def _copy_worktree(src: Path, dest: Path) -> int:
    """Copy tracked and non-ignored untracked files from disk. Missing tracked paths stay deleted."""
    result = git(src, "ls-files", "-t", "--cached", "-z")
    if any(entry.startswith(b"S ") for entry in result.stdout.split(b"\0")):
        raise ValueError("working-tree scans need a complete checkout; use a committed scan for sparse checkouts")
    files = git(src, "ls-files", "--cached", "--others", "--exclude-standard", "-z").stdout.split(b"\0")
    count = size = 0
    for raw in sorted(set(filter(None, files))):
        rel = Path(os.fsdecode(raw))
        if rel.is_absolute() or ".." in rel.parts or any(p in SKIP_DIRS for p in rel.parts):
            continue
        source = src / rel
        if any((src / parent).is_symlink() for parent in rel.parents):
            continue
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            if source.is_symlink():
                continue
            raise
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode):
                continue
            count += 1
            size += st.st_size
            if count > MAX_FILES or size > MAX_ZIP_BYTES:
                raise ValueError("working tree exceeds the local scan file or size limit")
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as out:
                remaining = st.st_size
                while remaining and (chunk := stream.read(min(1 << 20, remaining))):
                    out.write(chunk)
                    remaining -= len(chunk)
            end = os.fstat(stream.fileno())
            if remaining or (end.st_size, end.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                raise ValueError("working tree changed during capture; retry when the files are saved")
            target.chmod(0o600 | (st.st_mode & 0o111))
    return count


def start_path(raw: str, base: str | None, head: str | None, *, working_tree: bool = False, baseline: str | None = None) -> str:
    path = validate_local_path(raw)
    has_worktree = (path / ".git").exists()
    is_git = has_worktree or ((path / "HEAD").is_file() and (path / "objects").is_dir() and (path / "refs").is_dir())
    if working_tree and (not has_worktree or head):
        raise ValueError("a working-tree scan needs a local Git checkout and uses its files as the head")
    if baseline:
        if is_git:
            raise ValueError("select a base commit for a Git repository; saved snapshots are for ZIPs and plain folders")
        snapshot_baseline(baseline)
    pid = _new("path", path.name, {"path": str(path), "git": is_git,
                                   "snapshot_source": "working_tree" if working_tree else "commits" if is_git else "folder",
                                   "baseline_project": baseline,
                                   "base": (base or None) if is_git else None, "head": (head or None) if is_git else None})
    threading.Thread(target=_run_path, args=(pid, path, is_git, base, head, working_tree, baseline), daemon=True).start()
    return pid


def _run_path(pid: str, path: Path, is_git: bool, base: str | None, head: str | None,
              working_tree: bool = False, baseline: str | None = None):
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
            if working_tree:
                anchor = resolve_commit(repo, "HEAD")
                _step(pid, "Copying the working tree into a private snapshot (tracked and non-ignored untracked files)")
                with tempfile.TemporaryDirectory(dir=repo.parent, prefix="worktree-") as tmp:
                    _copy_worktree(path, Path(tmp))
                    snapshot_ref = "refs/guardian/working-tree"
                    _snapshot_commit(repo, Path(tmp), "Guardian working-tree snapshot", parent=anchor, ref=snapshot_ref, force=True)
                _analyse(pid, repo, base or "HEAD", snapshot_ref, label=path.name)
                return
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
            previous = _git_snapshot(repo, "local folder snapshot", baseline)
            _analyse(pid, repo, previous, "HEAD", label=path.name)
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
