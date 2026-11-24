"""Build ONE combined patch from the chosen fix candidates (the thing a human approves).

Safety:
- works on a private export of the PR head (git archive), never on the user's repository;
- config reverts are applied first, so a malicious .npmrc can't redirect the npm commands that follow;
- npm runs with --package-lock-only --ignore-scripts and an explicit public registry: lockfile edits only,
  no package code is downloaded into node_modules or executed;
- the result is a git diff plus its SHA-256, so approval can be bound to exactly these bytes.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

PUBLIC_REGISTRY = "https://registry.npmjs.org/"
APPLY_ORDER = {"revert_change": 0, "restore_lock_entry": 1, "remove_package": 2, "upgrade_to_fixed": 3, "override_transitive": 4}


def _git(repo: Path, *args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=check, **kw)


def export_tree(repo: Path, ref: str, dest: Path) -> None:
    data = _git(repo, "archive", "--format=tar", ref).stdout
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        members = [m for m in t.getmembers() if (m.isfile() or m.isdir()) and not m.name.startswith("/") and ".." not in Path(m.name).parts]
        t.extractall(dest, members=members, filter="data")


def _npm(work: Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
    env.update(npm_config_registry=PUBLIC_REGISTRY, npm_config_ignore_scripts="true", npm_config_audit="false",
               npm_config_fund="false", npm_config_update_notifier="false")
    return subprocess.run(["npm", *args, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                           f"--registry={PUBLIC_REGISTRY}"], cwd=work, capture_output=True, text=True, env=env, timeout=600)


def write_json_like(path: Path, data: dict) -> None:
    """Rewrite JSON keeping the file's indentation and final newline (npm copies the style into the lockfile,
    so changing it would turn a one-line fix into a whole-file diff nobody can review)."""
    old = path.read_text()
    m = re.search(r"^([ \t]+)\S", old, re.M)
    indent = m.group(1) if m else "  "
    text = json.dumps(data, indent="\t" if indent.startswith("\t") else len(indent), ensure_ascii=False)
    path.write_text(text + ("\n" if old.endswith("\n") else ""))


def _spec_with_prefix(old_spec: str, version: str) -> str:
    m = re.match(r"^([~^]?)", old_spec or "")
    return f"{m.group(1) if m else ''}{version}"


def _apply(work: Path, repo: Path, base: str, c: dict) -> dict:
    t = c["type"]
    if t == "revert_change":
        rel = c["file"]
        r = _git(repo, "show", f"{base}:{rel}", check=False)
        target = work / rel
        if r.returncode == 0:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(r.stdout)
            return {"status": "applied", "detail": f"{rel} restored from base"}
        if target.exists():
            target.unlink()
        return {"status": "applied", "detail": f"{rel} did not exist in base: removed"}
    if t == "restore_lock_entry":
        return _restore_lock_entry(work, repo, base, c)
    pj = work / "package.json"
    if not pj.exists():
        return {"status": "failed", "detail": "no root package.json"}
    if t == "remove_package":
        r = _npm(work, "uninstall", c["package"])
        return {"status": "applied" if r.returncode == 0 else "failed", "detail": (r.stderr or r.stdout)[-400:]}
    data = json.loads(pj.read_text())
    if t == "upgrade_to_fixed":
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            if c["package"] in (data.get(field) or {}):
                data[field][c["package"]] = _spec_with_prefix(data[field][c["package"]], c["to"])
    elif t == "override_transitive":
        data.setdefault("overrides", {})[c["package"]] = c["to"]
    else:
        return {"status": "skipped", "detail": f"{t} is not applied automatically"}
    write_json_like(pj, data)
    r = _npm(work, "install")
    return {"status": "applied" if r.returncode == 0 else "failed", "detail": (r.stderr or r.stdout)[-400:]}


def _restore_lock_entry(work: Path, repo: Path, base: str, c: dict) -> dict:
    """Put back the base commit's resolved URL and integrity for every lockfile entry of this package at this version.
    Refused (nothing changed) when the base has no entry with the same version: then it is not a pure source swap."""
    r = _git(repo, "show", f"{base}:package-lock.json", check=False)
    lock = work / "package-lock.json"
    if r.returncode != 0 or not lock.exists():
        return {"status": "failed", "detail": "no package-lock.json in the base commit or the change"}
    old_pk = json.loads(r.stdout).get("packages") or {}
    data = json.loads(lock.read_text())
    pk = data.get("packages") or {}
    name, ver = c["package"], c["version"]
    keys = [k for k, e in pk.items() if (k == f"node_modules/{name}" or k.endswith(f"/node_modules/{name}")) and e.get("version") == ver]
    restored = []
    for k in keys:
        b = old_pk.get(k)
        if b and b.get("version") == ver:
            for field in ("resolved", "integrity"):
                if field in b:
                    pk[k][field] = b[field]
                else:
                    pk[k].pop(field, None)
            restored.append(k)
    if not restored:
        return {"status": "failed", "detail": f"the base commit has no {name}@{ver} entry to restore; a person must decide"}
    write_json_like(lock, data)
    return {"status": "applied", "detail": f"restored resolved + integrity from base for {', '.join(restored)}"}


def lock_entry_changes(old_text: str, new_text: str) -> dict:
    """Which lockfile package entries the patch adds, removes or modifies (the change footprint)."""
    old = (json.loads(old_text).get("packages") or {}) if old_text else {}
    new = (json.loads(new_text).get("packages") or {}) if new_text else {}
    keys = lambda d: {k for k in d if k}  # noqa: E731  ("" is the root project)
    return {"added": sorted(keys(new) - keys(old)), "removed": sorted(keys(old) - keys(new)),
            "changed": sorted(k for k in keys(old) & keys(new) if old[k] != new[k])}


def _lock_entries_changed(work: Path) -> dict:
    lock = work / "package-lock.json"
    before = _git(work, "show", "HEAD:package-lock.json", check=False)
    return lock_entry_changes(before.stdout.decode() if before.returncode == 0 else "",
                              lock.read_text() if lock.exists() else "")


def build_patch(repo: Path, base: str, head: str, candidates: list[dict], out: Path) -> dict:
    """Apply candidates to an export of `head`; return {patch_path, patch_sha256, files, results, lock_entries_changed}."""
    work = out / "fix-work"
    if work.exists():
        subprocess.run(["rm", "-rf", str(work)], check=True)
    export_tree(repo, head, work)
    _git(work, "init", "-q")
    _git(work, "add", "-A")
    _git(work, "-c", "user.name=guardian", "-c", "user.email=guardian@localhost", "commit", "-qm", "head", "--no-verify")
    chosen = sorted([c for c in candidates if c["type"] in APPLY_ORDER], key=lambda c: APPLY_ORDER[c["type"]])
    results = [{"id": c["id"], "type": c["type"], **_apply(work, repo, base, c)} for c in chosen]
    _git(work, "add", "-A")
    patch = _git(work, "diff", "--cached", "--binary").stdout
    files = [f for f in _git(work, "diff", "--cached", "--name-only").stdout.decode().splitlines() if f]
    sha = hashlib.sha256(patch).hexdigest()
    out.mkdir(parents=True, exist_ok=True)
    patch_path = out / f"fix-{sha[:12]}.patch"
    patch_path.write_bytes(patch)
    return {"patch_path": str(patch_path), "patch_sha256": sha, "files": files, "results": results,
            "lock_entries_changed": _lock_entries_changed(work), "base": base, "head": head,
            "complete": all(r["status"] == "applied" for r in results)}
