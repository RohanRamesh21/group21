"""Shared data models: evidence records, npm packages and edges, CI actions and base images.

The agents' own message, finding and case schemas live in guardian/agents/protocol.py.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class Evidence(BaseModel):
    """A content-addressed fact. Agents may only cite these by id."""

    id: str  # "E-" + first 12 hex chars of sha256
    kind: Literal["tool_output", "file_excerpt", "diff_hunk", "registry_snapshot", "graph_path", "agent_note"]
    source: str  # tool name + pinned version, or agent name
    path: str | None = None
    lines: tuple[int, int] | None = None
    sha256: str
    blob_path: str
    db_snapshot: str | None = None
    created_at: str


class Package(BaseModel):
    """One installed package (one lockfile entry)."""

    key: str  # install path in the lockfile, e.g. "node_modules/express/node_modules/qs"
    name: str  # real package name (what advisories are keyed on)
    version: str
    purl: str
    alias: str | None = None  # installed under another name, e.g. "string-width-cjs" -> "npm:string-width"
    ecosystem: str = "npm"
    direct: bool = False
    dev: bool = False  # lockfile `dev` flag: needed only for development
    optional: bool = False
    runtime: bool = False  # computed from the graph: reachable from the root via non-dev edges
    resolved: str | None = None
    integrity: str | None = None
    has_install_script: bool = False
    license: str | None = None


class Edge(BaseModel):
    parent: str  # package key, or "" for the application root
    child: str
    name: str
    spec: str  # declared version range
    kind: Literal["prod", "dev", "optional", "peer", "peer_optional"]


class WorkflowAction(BaseModel):
    workflow: str  # file path
    job: str
    uses: str  # full `uses:` value
    owner_repo: str
    ref: str
    pinned_sha: bool  # ref is a full 40-char commit SHA
    first_party: bool  # owned by GitHub (actions/*, github/*)
    version_comment: str | None = None
    line: int | None = None


class ImageRef(BaseModel):
    dockerfile: str
    stage: str | None
    ref: str  # as written (ARG defaults substituted where possible)
    registry: str
    repository: str
    tag: str | None
    digest: str | None
    line: int

