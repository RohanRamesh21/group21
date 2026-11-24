"""Storage for one remediation run: guardian-out/remediation/<run_id>/

    run.json          run metadata (project, producer, tool versions, data timestamps)
    plans.json        every FixPlan (rewritten atomically; plans are immutable apart from `status` and `review`)
    approvals.jsonl   APPEND-ONLY human decisions (the audit record the apply gate checks)
    audit.jsonl       APPEND-ONLY log of tool calls, rejections, applies and validations
    validation/<plan_id>.json
    report.json / report.md / report.html
    evidence/ guardian.db   content-addressed evidence the agents cite (candidates, finding cards)
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from guardian.remediation.models import Approval, FixPlan, ValidationResult
from guardian.store.evidence import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "guardian-out" / "remediation"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RemediationStore:
    def __init__(self, run_id: str, base: Path | None = None):
        self.run_id = run_id
        self.root = (base or BASE) / run_id
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "validation").mkdir(exist_ok=True)
        self._lock = threading.RLock()
        self.evidence = EvidenceStore(self.root)

    # ---- run metadata -------------------------------------------------------
    def _atomic(self, path: Path, text: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        for attempt in range(5):  # Windows refuses a replace while another thread is reading the target
            try:
                tmp.replace(path)
                return
            except PermissionError:
                time.sleep(0.02 * (attempt + 1))
        tmp.replace(path)

    def _read_json(self, path: Path, default):
        for attempt in range(5):
            try:
                return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
            except (ValueError, PermissionError):
                time.sleep(0.02 * (attempt + 1))
        return default

    def save_meta(self, meta: dict) -> None:
        with self._lock:
            self._atomic(self.root / "run.json", json.dumps(meta, indent=1, default=str))

    def meta(self) -> dict:
        with self._lock:
            return self._read_json(self.root / "run.json", {})

    # ---- plans --------------------------------------------------------------
    def _load_plans(self) -> dict[str, FixPlan]:
        return {d["id"]: FixPlan.model_validate(d) for d in self._read_json(self.root / "plans.json", [])}

    def save_plan(self, plan: FixPlan) -> None:
        with self._lock:
            plans = self._load_plans()
            plans[plan.id] = plan
            self._atomic(self.root / "plans.json", json.dumps([x.model_dump() for x in plans.values()], indent=1, default=str))

    def plans(self) -> list[FixPlan]:
        with self._lock:
            return list(self._load_plans().values())

    def get_plan(self, plan_id: str) -> FixPlan | None:
        with self._lock:
            return self._load_plans().get(plan_id)

    def next_plan_id(self) -> str:
        with self._lock:
            return f"FP-{len(self._load_plans()) + 1:03d}"

    def set_status(self, plan_id: str, status: str) -> FixPlan:
        """Status transitions are made by code paths (decision, apply, validate), never by an agent tool."""
        with self._lock:
            plan = self._load_plans()[plan_id]
            plan.status = status  # type: ignore[assignment]
            self.save_plan(plan)
            return plan

    # ---- approvals (append-only) --------------------------------------------
    def append_approval(self, a: Approval) -> None:
        with self._lock, open(self.root / "approvals.jsonl", "a", encoding="utf-8") as f:
            f.write(a.model_dump_json() + "\n")

    def approvals(self, plan_id: str | None = None) -> list[Approval]:
        p = self.root / "approvals.jsonl"
        if not p.exists():
            return []
        out = [Approval.model_validate_json(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [a for a in out if plan_id is None or a.plan_id == plan_id]

    # ---- audit (append-only) ------------------------------------------------
    def log(self, event: str, **kw) -> None:
        with self._lock, open(self.root / "audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": now(), "event": event, **kw}, default=str) + "\n")

    def audit(self) -> list[dict]:
        p = self.root / "audit.jsonl"
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []

    # ---- validation ---------------------------------------------------------
    def save_validation(self, v: ValidationResult) -> None:
        with self._lock:
            (self.root / "validation" / f"{v.plan_id}.json").write_text(v.model_dump_json(indent=1))

    def validation(self, plan_id: str) -> ValidationResult | None:
        p = self.root / "validation" / f"{plan_id}.json"
        return ValidationResult.model_validate_json(p.read_text()) if p.exists() else None
