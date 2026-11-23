"""Content-addressed evidence store (SQLite index + blob files).

The same content always gets the same evidence id, so re-running a scan is idempotent
and an evidence id can be checked against its blob at any time (tamper-evidence).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from guardian.models import Evidence

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    sha256 TEXT NOT NULL,
    blob_path TEXT NOT NULL,
    db_snapshot TEXT,
    created_at TEXT NOT NULL
);
"""


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.blob_dir = self.root / "evidence"
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        # Shared across LangGraph worker threads: allow cross-thread use, serialise access with a lock.
        self.db = sqlite3.connect(self.root / "guardian.db", check_same_thread=False)
        self._lock = threading.RLock()
        self.db.execute(_SCHEMA)
        self.db.commit()

    def add(
        self,
        content: str | bytes | dict | list,
        *,
        kind: str,
        source: str,
        path: str | None = None,
        lines: tuple[int, int] | None = None,
        db_snapshot: str | None = None,
    ) -> Evidence:
        if isinstance(content, (dict, list)):
            data = json.dumps(content, sort_keys=True, indent=2).encode()
        elif isinstance(content, str):
            data = content.encode()
        else:
            data = content
        # Identity covers what the fact is, not only its bytes: the same text from two files
        # (or two line ranges) is two different pieces of evidence.
        identity = hashlib.sha256(data + f"|{kind}|{source}|{path}|{lines}".encode()).hexdigest()
        sha = hashlib.sha256(data).hexdigest()
        eid = "E-" + identity[:12]
        blob = self.blob_dir / sha
        ev = Evidence(
            id=eid,
            kind=kind,
            source=source,
            path=path,
            lines=lines,
            sha256=sha,
            blob_path=str(blob),
            db_snapshot=db_snapshot,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        with self._lock:
            if not blob.exists():
                with tempfile.NamedTemporaryFile(dir=self.blob_dir, delete=False) as temporary:
                    temporary.write(data)
                try:
                    os.replace(temporary.name, blob)
                finally:
                    Path(temporary.name).unlink(missing_ok=True)
            self.db.execute(
                "INSERT OR IGNORE INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ev.id, ev.kind, ev.source, ev.path, lines[0] if lines else None, lines[1] if lines else None,
                 ev.sha256, ev.blob_path, ev.db_snapshot, ev.created_at),
            )
            self.db.commit()
        return ev

    def get(self, eid: str) -> Evidence | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
        if not row:
            return None
        lines = (row[4], row[5]) if row[4] is not None else None
        return Evidence(id=row[0], kind=row[1], source=row[2], path=row[3], lines=lines,
                        sha256=row[6], blob_path=row[7], db_snapshot=row[8], created_at=row[9])

    def exists(self, eid: str) -> bool:
        with self._lock:
            return self.db.execute("SELECT 1 FROM evidence WHERE id=?", (eid,)).fetchone() is not None

    def content(self, eid: str) -> str:
        """Read a verified blob from this store and check its evidence locator."""
        ev = self.get(eid)
        if ev is None:
            raise KeyError(eid)
        if len(ev.sha256) != 64 or any(c not in "0123456789abcdef" for c in ev.sha256):
            raise ValueError("invalid evidence digest")
        blob = self.blob_dir / ev.sha256
        if blob.is_symlink():
            raise ValueError("invalid evidence blob")
        data = blob.read_bytes()
        identity = hashlib.sha256(data + f"|{ev.kind}|{ev.source}|{ev.path}|{ev.lines}".encode()).hexdigest()
        if hashlib.sha256(data).hexdigest() != ev.sha256 or eid != "E-" + identity[:12]:
            raise ValueError("evidence integrity check failed")
        return data.decode(errors="replace")
