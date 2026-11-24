"""Ordered, persisted run events (sequence numbers) so dashboard and Buddy can resume after a disconnect."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path


class EventStore:
    def __init__(self, root: Path):
        self.path = Path(root) / "events.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = sum(1 for ln in self.path.read_text().splitlines() if ln.strip()) if self.path.exists() else 0

    def append(self, run_id: str, kind: str, data: dict) -> dict:
        with self._lock:
            self._seq += 1
            e = {"seq": self._seq, "at": time.time(), "run": run_id, "kind": kind, "data": data}
            with self.path.open("a") as fh:
                fh.write(json.dumps(e) + "\n")
            return e

    def since(self, seq: int) -> list[dict]:
        """Events with sequence number greater than `seq` (Last-Event-ID resume)."""
        if not self.path.exists():
            return []
        out = []
        for ln in self.path.read_text().splitlines():
            if ln.strip():
                e = json.loads(ln)
                if e["seq"] > seq:
                    out.append(e)
        return out
