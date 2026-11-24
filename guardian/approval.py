"""Human approval contract and audit trail (GUARDIAN_FINAL_PLAN.md §12.3).

approval = base_sha + head_sha + patch_sha256 + policy_sha256 + profile_sha256 + approver + time + expiry
Any change to any bound part, expiry, or a rejection means nothing may execute. Every decision is appended to a
hash-chained audit log (each line includes the SHA-256 of the previous line), so edits are detectable.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path

BOUND = ("base_sha", "head_sha", "patch_sha256", "policy_sha256", "profile_sha256")


class ApprovalInvalid(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _audit(out: Path, kind: str, event: dict) -> None:
    log = Path(out) / "audit.jsonl"
    prev = "0" * 64
    if log.exists():
        lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
        if lines:
            prev = hashlib.sha256(lines[-1].encode()).hexdigest()
    line = json.dumps({"kind": kind, "at": event.get("created", time.time()), "prev": prev, "event": event}, sort_keys=True)
    with log.open("a") as fh:
        fh.write(line + "\n")
    (Path(out) / "audit.head").write_text(hashlib.sha256(line.encode()).hexdigest())


def verify_audit(out: Path) -> tuple[bool, int]:
    log = Path(out) / "audit.jsonl"
    if not log.exists():
        return True, 0
    prev = "0" * 64
    lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
    for ln in lines:
        if json.loads(ln).get("prev") != prev:
            return False, len(lines)
        prev = hashlib.sha256(ln.encode()).hexdigest()
    head = Path(out) / "audit.head"  # hash of the newest line: catches edits to the last entry too
    if not head.exists() or head.read_text().strip() != prev:
        return False, len(lines)
    return True, len(lines)


def decide(out: Path, plan: dict, decision: str, *, approver: str, reason: str, ttl_seconds: int, now: float | None = None,
           policy_sha256: str, profile_sha256: str, reviewed: bool = False) -> dict:
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    if not approver.strip() or not reason.strip():
        raise ValueError("a decision needs the approver's name and a reason")
    now = time.time() if now is None else now
    rec = {"id": "APR-" + uuid.uuid4().hex[:10], "decision": decision, "approver": approver.strip(), "reason": reason.strip(),
           "created": now, "expires": now + ttl_seconds, "base_sha": plan.get("base_sha"), "head_sha": plan["head_sha"],
           "patch_sha256": plan["patch"]["patch_sha256"], "policy_sha256": policy_sha256, "profile_sha256": profile_sha256,
           "reviewed_patch": bool(reviewed)}
    d = Path(out) / "approvals"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{rec['id']}.json").write_text(json.dumps(rec, indent=1))
    _audit(out, "approval", rec)
    return rec


def check(rec: dict, plan: dict, *, now: float | None = None, policy_sha256: str, profile_sha256: str) -> None:
    """Raise ApprovalInvalid unless this approval authorises exactly this plan under this policy and profile."""
    now = time.time() if now is None else now
    if rec.get("decision") != "approve":
        raise ApprovalInvalid("the decision was rejected: nothing may execute")
    if now > rec["expires"]:
        raise ApprovalInvalid("approval expired: approve again")
    current = {"base_sha": plan.get("base_sha"), "head_sha": plan["head_sha"], "patch_sha256": plan["patch"]["patch_sha256"],
               "policy_sha256": policy_sha256, "profile_sha256": profile_sha256}
    changed = [k.replace("_sha256", "").replace("_sha", "") for k in BOUND if rec.get(k) != current[k]]
    if changed:
        raise ApprovalInvalid(f"approval no longer matches: {', '.join(changed)} changed since it was given")


def latest_approval(out: Path) -> dict | None:
    d = Path(out) / "approvals"
    recs = [json.loads(f.read_text()) for f in d.glob("APR-*.json")] if d.exists() else []
    return max(recs, key=lambda r: r["created"]) if recs else None


def accept_risk(out: Path, finding_id: str, *, owner: str, scope: str, reason: str, ttl_seconds: int, now: float | None = None) -> dict:
    if not (owner.strip() and scope.strip() and reason.strip()):
        raise ValueError("risk acceptance needs an owner, a scope and a reason")
    now = time.time() if now is None else now
    rec = {"id": "RSK-" + uuid.uuid4().hex[:10], "finding_id": finding_id, "owner": owner.strip(), "scope": scope.strip(),
           "reason": reason.strip(), "created": now, "expires": now + ttl_seconds}
    d = Path(out) / "risk_acceptances"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{rec['id']}.json").write_text(json.dumps(rec, indent=1))
    _audit(out, "risk_acceptance", rec)
    return rec


def accepted_risks(out: Path, now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    d = Path(out) / "risk_acceptances"
    recs = [json.loads(f.read_text()) for f in d.glob("RSK-*.json")] if d.exists() else []
    return sorted([r for r in recs if r["expires"] > now], key=lambda r: r["created"])
