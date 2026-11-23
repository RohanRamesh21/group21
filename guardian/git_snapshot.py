"""Read committed blobs and diffs without applying repository export attributes or filters."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_TREE_FILES = 100_000
BATCH_BYTES = 8 * 1024 * 1024
OID = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")


def git(repo: Path, *args: str, data: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    """Run Git plumbing with isolated configuration and without inherited credentials."""
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_LITERAL_PATHSPECS": "1"}
    return subprocess.run(["git", "-C", str(repo), *args], env=env, input=data, capture_output=True,
                          check=check, timeout=120)


def resolve_commit(repo: Path, ref: str) -> str:
    """Resolve a user-provided revision to a commit object ID."""
    result = git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}", check=False)
    commit = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode or not OID.fullmatch(commit):
        raise ValueError("Git revision does not resolve to a commit")
    return commit


def changed_paths(repo: Path, base: str, head: str) -> list[str]:
    """Return literal names, including both sides of renames."""
    result = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", base, head, "--")
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def export_tree(repo: Path, ref: str, dest: Path) -> None:
    """Materialize only regular tracked files from the immutable commit tree."""
    commit = ref if OID.fullmatch(ref) else resolve_commit(repo, ref)
    listing = git(repo, "ls-tree", "-r", "-z", "-l", commit).stdout
    batch: list[tuple[bytes, Path, int]] = []
    total = batch_bytes = count = 0
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        for entry in listing.rstrip(b"\0").split(b"\0") if listing else []:
            header, _, raw_path = entry.partition(b"\t")
            mode, _, oid, length = header.split()
            if mode not in {b"100644", b"100755"}:
                continue
            parts = os.fsdecode(raw_path).split("/")
            if any(part in {"", ".", ".."} or part.casefold() == ".git" for part in parts):
                raise ValueError("invalid tracked path")
            size = int(length)
            total += size
            count += 1
            if total > MAX_TREE_BYTES or count > MAX_TREE_FILES or size > BATCH_BYTES * 4:
                raise ValueError("Git snapshot exceeds the scan size limits")
            if batch and (batch_bytes + size > BATCH_BYTES or len(batch) >= 2_000):
                _write_blobs(repo, batch)
                batch, batch_bytes = [], 0
            batch.append((oid, dest.joinpath(*parts), size))
            batch_bytes += size
        if batch:
            _write_blobs(repo, batch)
    except Exception:
        shutil.rmtree(dest)
        raise


def _write_blobs(repo: Path, batch: list[tuple[bytes, Path, int]]) -> None:
    data = git(repo, "cat-file", "--batch", data=b"".join(oid + b"\n" for oid, _, _ in batch)).stdout
    offset = 0
    for oid, path, size in batch:
        end = data.find(b"\n", offset)
        if end < 0 or data[offset:end] != oid + b" blob " + str(size).encode():
            raise ValueError("unexpected object in Git snapshot")
        start = end + 1
        offset = start + size + 1
        if data[offset - 1:offset] != b"\n":
            raise ValueError("incomplete object in Git snapshot")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data[start:offset - 1])
