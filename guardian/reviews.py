"""Append-only human reviews of deterministic scan findings."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict, deque
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from guardian.agents.boundary import redact

Digest = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]
Rationale = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


def today() -> date:
    """Use the same date for API writes and display status regardless of server timezone."""
    return datetime.now(UTC).date()


class ReviewInput(BaseModel):
    """The intended disposition and the exact finding revision shown to the reviewer."""

    model_config = ConfigDict(extra="forbid")

    revision: Digest
    previous_id: Annotated[int, Field(gt=0)] | None
    action: Literal["confirm", "challenge", "defer"]
    reviewer: Name
    rationale: Rationale
    owner: Name | None = None
    due_date: date | None = None

    @model_validator(mode="after")
    def check_deferral(self) -> ReviewInput:
        """A deferral needs an owner and a date ending in the future."""
        if self.action == "defer":
            if self.owner is None or self.due_date is None or self.due_date < today():
                raise ValueError("Deferring requires an owner and a due date of today or later (UTC).")
        elif self.owner is not None or self.due_date is not None:
            raise ValueError("Only deferrals have an owner and due date.")
        return self


@dataclass(frozen=True)
class ReviewTarget:
    """Server-derived identity, evidence digest, and exact scan revision for a finding."""

    key: str
    evidence_digest: str
    revision: str
    finding: dict


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def repository_scope(report: dict, directory: Path, project: dict | None) -> str:
    """Reuse history across scans of the same Git URL and isolate independent ZIP uploads."""
    if project and project.get("kind") == "git" and project.get("url"):
        url = urlsplit(project["url"])
        path = url.path.rstrip("/").removesuffix(".git")
        return f"git:{url.netloc.lower()}{path}"
    if project and project.get("kind") == "path" and project.get("path"):
        return f"local:{Path(project['path']).resolve()}"
    if project:
        return f"upload:{directory.resolve()}"
    return f"local:{Path(report.get('repo') or directory).resolve()}"


def _package_material(package: dict) -> dict:
    material = {key: package.get(key) for key in (
        "key", "purl", "version", "declared", "integrity", "resolved", "runtime", "direct", "has_install_script",
    )}
    # The first path element is the display name of the app, which is not a package edge.
    material["path"] = (package.get("path") or [])[1:]
    return material


def _summary_without_lines(summary: str, *files: str | None) -> str:
    for file in {name for name in files if name}:
        summary = re.sub(rf"{re.escape(file)}:\d+(?!\d)", file, summary)
    return summary


def targets(report: dict, findings: list[dict], scope: str) -> list[ReviewTarget]:
    """Match score rows to scan evidence. Source line numbers are display locators."""
    headline = report["headline"]
    commit = headline.get("head_commit_full")
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
        return []

    packages = {row["key"]: row for row in report.get("inventory", [])}
    by_component: dict[str, list[dict]] = defaultdict(list)
    for row in packages.values():
        by_component[f"{row['name']}@{row.get('version') or row.get('declared')}"].append(row)
    vulnerabilities = {row["key"]: row for row in report.get("vulnerabilities", []) if row.get("label") != "fixed"}
    registry = {f"{row['name']}@{row['version']}": row for row in (report.get("provenance") or {}).get("packages", [])}
    actions = {(row["workflow"], row.get("line")): row for row in report.get("actions", [])}
    images = {(row["dockerfile"], row.get("line")): row for row in report.get("images", [])}
    suspicious: dict[tuple, list[dict]] = defaultdict(list)
    for row in report.get("suspicious_changes", []):
        summary = _summary_without_lines(row["summary"], row.get("file"))
        suspicious[(row["type"], row["component"].replace("pkg:npm/", ""), row.get("detector"), summary)].append(row)
    ci: dict[str, deque[dict]] = defaultdict(deque)
    for row in report.get("ci_image", []):
        if row.get("label") != "fixed":
            ci[f"{row.get('detector')}:{row.get('file')}:{row.get('line')}:{row['type']}"].append(row)

    candidates = []
    for finding in findings:
        kind = finding["kind"]
        evidence = finding.get("evidence") or {}
        file = evidence.get("file")
        component = finding["component"]
        material = {key: finding.get(key) for key in ("component", "severity", "label", "level", "decision", "floor", "ssvc")}
        material["summary"] = _summary_without_lines(finding.get("summary", ""), file)

        if kind == "vulnerability":
            vuln = vulnerabilities.get(finding["id"], {})
            package = packages.get(vuln.get("component_key"), {})
            advisory = evidence.get("advisory")
            slot = package.get("key") if package.get("found_by") == "guardian npm lockfile parser" else None
            identity = [vuln.get("ecosystem"), vuln.get("name") or component, advisory, vuln.get("source_file") or file, slot]
            reach = evidence.get("reachability") or {}
            material.update(package=_package_material(package), advisory=advisory, cvss=evidence.get("cvss_vector"),
                            kev=bool(evidence.get("kev")), fixed=sorted(vuln.get("fixed") or []),
                            reachability={**reach, "evidence": sorted({re.sub(r":\d+$", "", item) for item in reach.get("evidence") or []})})
        elif kind == "ci_image":
            raw = ci[finding["id"]].popleft() if ci[finding["id"]] else {}
            position = (file, raw.get("line", evidence.get("line")))
            action = actions.get(position, {})
            image = images.get(position, {})
            identities = (action.get("job"), action.get("owner_repo"), image.get("stage"), image.get("repository"))
            identity = [file, raw.get("detector"), raw.get("type") or finding["id"].rsplit(":", 1)[-1],
                        identities if action or image else component]
            material.update(excerpt=raw.get("excerpt"), url=evidence.get("url"), source=raw.get("review_source"))
        else:
            alert = finding["id"].split(":", 1)[0]
            rows = suspicious[(alert, component, evidence.get("detector"), material["summary"])]
            matching = [row for row in rows if row.get("file") == file and row.get("line") == evidence.get("lockfile_line")]
            raw = matching[0] if matching else rows[0] if rows else {}
            file = raw.get("file", file)
            listed = by_component[component]
            candidates_at_file = [row for row in listed if row.get("source_file") == file]
            matched = candidates_at_file or listed
            subject = sorted({(str(row.get("ecosystem") or ""), row["name"]) for row in matched}) or component
            if alert == "action_pin_removed" and (action := actions.get((file, raw.get("line")))):
                subject = (action["job"], action["owner_repo"])
            identity = [evidence.get("detector"), alert, subject, file]
            material.update(packages=sorted(_digest(_package_material(row)) for row in matched),
                            registry=registry.get(component), hard_signal=evidence.get("hard_signal"),
                            excerpt=raw.get("excerpt"), source=raw.get("review_source"))

        candidates.append((_digest([kind, identity]), material, finding))

    multiplicity = Counter(key for key, _, _ in candidates)
    ambiguous: dict[str, list[str]] = defaultdict(list)
    for key, material, finding in candidates:
        if multiplicity[key] > 1:
            ambiguous[key].append(_digest([finding["id"], material]))
    occurrence: Counter[str] = Counter()
    result = []
    for key, material, finding in candidates:
        if multiplicity[key] > 1:
            # Ambiguous repeats are safe to review in this scan. A new commit requires a fresh decision.
            occurrence[key] += 1
            material["ambiguous"] = [commit, ambiguous[key]]
            key = _digest([key, occurrence[key]])
        evidence_digest = _digest(material)
        revision = _digest([scope, key, headline.get("base_commit_full"), commit, evidence_digest, finding])
        result.append(ReviewTarget(key, evidence_digest, revision, finding))
    return result


_SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_reviews (
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    head_commit TEXT NOT NULL,
    base_commit TEXT,
    evidence_digest TEXT NOT NULL,
    revision TEXT NOT NULL,
    finding TEXT NOT NULL,
    action TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    rationale TEXT NOT NULL,
    owner TEXT,
    due_date TEXT,
    created_at TEXT NOT NULL
)
"""


class ReviewConflict(Exception):
    """Another reviewer has already updated this finding's review history."""


class ReviewStore:
    """Read and append local review events using transactional SQLite writes."""

    def __init__(self, path: Path):
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def latest(self, scope: str, keys: set[str]) -> dict[str, dict]:
        """Read the latest review of each requested finding in this repository."""
        if not self.path.exists() or not keys:
            return {}
        result = {}
        with closing(self._connect()) as db:
            # A database opened by a first writer may exist before its schema is committed.
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name = 'finding_reviews'").fetchone():
                return {}
            key_list = list(keys)
            for offset in range(0, len(key_list), 500):
                batch = key_list[offset:offset + 500]
                placeholders = ','.join('?' for _ in batch)
                rows = db.execute(f"""SELECT r.finding_key, r.id, r.action, r.due_date, r.evidence_digest FROM finding_reviews r JOIN (
                    SELECT MAX(id) AS id FROM finding_reviews WHERE scope = ? AND finding_key IN ({placeholders})
                    GROUP BY finding_key
                ) latest ON latest.id = r.id""", [scope, *batch])
                result.update({row["finding_key"]: dict(row) for row in rows})
        return result

    def history(self, scope: str, key: str) -> list[dict]:
        """Read the timeline newest first, dropping the internal repository scope."""
        if not self.path.exists():
            return []
        with closing(self._connect()) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name = 'finding_reviews'").fetchone():
                return []
            rows = db.execute("""SELECT id, head_commit, base_commit, evidence_digest, revision, finding, action, reviewer,
                rationale, owner, due_date, created_at FROM finding_reviews WHERE scope = ? AND finding_key = ? ORDER BY id DESC""", (scope, key))
            return [{**dict(row), "finding": json.loads(row["finding"])} for row in rows]

    def append(self, scope: str, target: ReviewTarget, headline: dict, review: ReviewInput) -> None:
        """Record a review only if the client's view of the timeline is still current."""
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(_SCHEMA)
            db.execute("CREATE INDEX IF NOT EXISTS reviews_scope_key ON finding_reviews(scope, finding_key, id)")
            current = db.execute("SELECT MAX(id) FROM finding_reviews WHERE scope = ? AND finding_key = ?", (scope, target.key)).fetchone()[0]
            if current != review.previous_id:
                raise ReviewConflict
            db.execute("""INSERT INTO finding_reviews (scope, finding_key, head_commit, base_commit, evidence_digest,
                revision, finding, action, reviewer, rationale, owner, due_date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scope, target.key, headline["head_commit_full"], headline.get("base_commit_full"), target.evidence_digest,
                 target.revision, json.dumps(target.finding), review.action, redact(review.reviewer), redact(review.rationale),
                 redact(review.owner) if review.owner else None, review.due_date.isoformat() if review.due_date else None,
                 datetime.now(UTC).isoformat(timespec="seconds")))


def disposition(target: ReviewTarget, latest: dict | None) -> dict:
    """Resolve the latest event against current evidence and the deferral deadline."""
    status, reason = "unreviewed", None
    if latest:
        status = {"confirm": "confirmed", "challenge": "challenged", "defer": "deferred"}[latest["action"]]
        if latest["evidence_digest"] != target.evidence_digest:
            status, reason = "reopened", "evidence_changed"
        elif latest["due_date"] and date.fromisoformat(latest["due_date"]) < today():
            status, reason = "reopened", "deferral_expired"
    return {"key": target.key, "revision": target.revision, "status": status, "reason": reason,
            "latest_id": latest["id"] if latest else None}
