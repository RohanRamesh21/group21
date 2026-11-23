"""Snapshots: read a repository at any commit/tag without checking it out (stage S0/S1).

Reading straight from git objects lets us scan a base and a head side by side, and means
we never run anything from the target repository.
"""
from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import git

from guardian.models import Snapshot

# Files the supply-chain view cares about (S1 fingerprint).
MANIFEST_PATTERNS = ["package.json", "**/package.json"]
LOCKFILE_PATTERNS = ["package-lock.json", "npm-shrinkwrap.json", "**/package-lock.json"]
DOCKERFILE_PATTERNS = ["Dockerfile", "**/Dockerfile", "**/dockerfile", "**/*.dockerfile", "dockerfile"]
WORKFLOW_PATTERNS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
SENSITIVE_PATTERNS = [
    ".npmrc", "**/.npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf",
    ".vscode/tasks.json", ".claude/settings.json", ".github/workflows/*", ".git/hooks/*",
]
SKIP_DIRS = ("node_modules/",)


@dataclass
class RepoView:
    """Read-only view of a repository at one commit."""

    repo_path: Path
    ref: str
    commit: str
    files: dict[str, bytes] = field(default_factory=dict)  # path -> content (tracked, relevant files only)

    def read(self, path: str) -> bytes | None:
        return self.files.get(path)

    def text(self, path: str) -> str | None:
        data = self.files.get(path)
        return data.decode(errors="replace") if data is not None else None

    def match(self, patterns: list[str]) -> list[str]:
        out = []
        for p in sorted(self.files):
            if any(fnmatch.fnmatch(p, pat) for pat in patterns):
                out.append(p)
        return out

    def export(self, dest: Path, paths: list[str] | None = None) -> Path:
        """Write selected files to a folder (for tools such as Syft/cdxgen that need a directory)."""
        dest.mkdir(parents=True, exist_ok=True)
        for p in paths or list(self.files):
            target = dest / p
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.files[p])
        return dest


def _relevant(path: str) -> bool:
    if any(s in path for s in SKIP_DIRS):
        return False
    pats = MANIFEST_PATTERNS + LOCKFILE_PATTERNS + DOCKERFILE_PATTERNS + WORKFLOW_PATTERNS + SENSITIVE_PATTERNS
    return any(fnmatch.fnmatch(path, pat) for pat in pats)


def open_view(repo_path: Path, ref: str = "HEAD") -> RepoView:
    repo = git.Repo(repo_path)
    commit = repo.commit(ref)
    view = RepoView(repo_path=Path(repo_path), ref=ref, commit=commit.hexsha)
    for blob in commit.tree.traverse():
        if blob.type != "blob":
            continue
        if _relevant(blob.path):
            view.files[blob.path] = blob.data_stream.read()
    return view


def take_snapshot(view: RepoView, tool_versions: dict[str, str] | None = None) -> Snapshot:
    hashes = {p: hashlib.sha256(d).hexdigest() for p, d in view.files.items()}
    return Snapshot(
        id=f"snap-{view.commit[:12]}",
        repo=str(view.repo_path),
        commit=view.commit,
        ref=view.ref,
        taken_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        file_hashes=hashes,
        tool_versions=tool_versions or {},
    )


def fingerprint(view: RepoView) -> dict[str, list[str]]:
    """S1: which ecosystems and supply-chain files exist at this commit."""
    lockfiles = view.match(LOCKFILE_PATTERNS)
    return {
        "ecosystems": ["npm"] if lockfiles or view.match(MANIFEST_PATTERNS) else [],
        "manifests": view.match(MANIFEST_PATTERNS),
        "lockfiles": lockfiles,
        "dockerfiles": view.match(DOCKERFILE_PATTERNS),
        "workflows": view.match(WORKFLOW_PATTERNS),
        "sensitive": view.match(SENSITIVE_PATTERNS),
    }
