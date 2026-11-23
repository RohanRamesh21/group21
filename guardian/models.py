"""Shared data models for the Guardian (FINAL_PLAN.md §13).

Every other module codes against these schemas.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Risk = Literal["critical", "high", "medium", "low", "info"]


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


class Snapshot(BaseModel):
    id: str
    repo: str
    commit: str
    ref: str
    taken_at: str
    file_hashes: dict[str, str] = Field(default_factory=dict)
    tag_map: dict[str, str] = Field(default_factory=dict)  # action@ref -> ref (SHA once resolved)
    image_digest: str | None = None
    sbom_paths: dict[str, str] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    detector: str
    type: Literal[
        "known_vulnerability", "malicious_package", "typosquat", "install_script", "lockfile_tamper",
        "suspicious_update", "ci_risk", "image_risk", "source_change", "dependency_confusion",
        "provenance", "artifact_mismatch", "prompt_injection",
    ]
    component: str
    layer: Literal["app", "image", "ci", "source"]
    label: Literal["introduced", "pre_existing", "fixed"] | None = None
    hard_signal: bool = False
    paths: list[list[str]] = Field(default_factory=list)
    declared_in: dict | None = None
    introduced_by: str | None = None
    advisory: dict | None = None
    fix: dict | None = None
    evidence_ids: list[str]
    status: Literal["candidate", "verified", "needs_review"] = "candidate"


class Claim(BaseModel):
    text: str
    evidence_ids: list[str]
    kind: Literal["verified", "inferred"]


class Case(BaseModel):
    id: str
    title: str
    finding_ids: list[str]
    root_cause: str | None = None
    verdict: Literal["malicious", "suspicious", "vulnerable", "benign", "unresolved"] = "unresolved"
    risk: Risk = "info"
    confidence: float = 1.0
    claims: list[Claim] = Field(default_factory=list)
    message_ids: list[str] = Field(default_factory=list)
    verifier: Literal["pass", "rejected", "not_run"] = "not_run"


class AgentMessage(BaseModel):
    id: str
    case_id: str
    sender: Literal["investigator", "skeptic", "fixer", "system"]
    recipient: Literal["investigator", "skeptic", "fixer", "system"]
    kind: Literal["assign", "hypothesis", "challenge", "answer", "corroborate", "dispute", "evidence_request", "resolve"]
    claim: str | None = Field(None, max_length=600)
    evidence_ids: list[str] = Field(default_factory=list)
    kind_of_claim: Literal["verified", "inferred"] | None = None
    confidence: float | None = Field(None, ge=0, le=1)
    proposed_risk: Risk | None = None
    in_reply_to: str | None = None
