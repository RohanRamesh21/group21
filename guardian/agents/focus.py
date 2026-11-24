"""Create review questions from scan findings and mandatory detector results."""
from __future__ import annotations

import json
from collections import defaultdict

from guardian.agents.boundary import redact
from guardian.agents.protocol import BoardFinding, RISK_ORDER


def prepare(board, store, report: dict, facts) -> str:
    advisory_evidence = report["advisory_evidence"]
    board.focused = True
    # Leave paths and commits available to the agents. Coverage measures the checks and questions
    # that can affect this verdict, rather than whether an agent opened every file in the diff.
    board.coverage_required = {key for key in board.coverage_required if key.startswith("pkg:")}
    reused = facts.reuse_scan_advisories(advisory_evidence)
    board.scan_evidence.update(reused)
    board.coverage_done.update(reused)
    headline = report["headline"]
    summary = {"base": board.base, "head": board.head, "verdict": headline.get("verdict"),
               "reasons": headline.get("verdict_reasons", []), "changes": headline.get("changes", {}),
               "inventory": headline.get("inventory", {}).get("ecosystems", {})}
    entry = store.add(redact(json.dumps(summary)), kind="tool_output", source="deterministic scan summary")
    board.coverage_required.add("scan:summary")
    board.coverage_done.add("scan:summary")
    board.scan_evidence["scan:summary"] = entry.id
    return entry.id


def queue(board, store, report: dict) -> None:
    rows = []
    seen = set()
    snapshot = board.base == board.head
    for section in ("vulnerabilities", "ci_image", "suspicious_changes"):
        for finding in report.get(section, []):
            label, severity = finding.get("label"), finding.get("severity", "info")
            if not (label == "not_checked" or label == "introduced" and (
                section == "vulnerabilities" or RISK_ORDER.get(severity, 0) >= RISK_ORDER["medium"]
            ) or snapshot and label == "pre_existing" and severity in {"high", "critical"}):
                continue
            title = finding.get("type") or ("Advisory" if section == "vulnerabilities" else "CI or image finding")
            component = finding.get("component") or " ".join(filter(None, (finding.get("name"), finding.get("version"))))
            reason = finding.get("summary") or finding.get("message") or title
            key = (title, component, finding.get("file"), tuple(finding.get("ids") or []))
            if key in seen:
                continue
            seen.add(key)
            role = ("hunter" if section == "vulnerabilities" or finding.get("detector") in {"D5", "D20", "D21"}
                    else "forensics")
            rows.append((role, title, component, reason, severity, finding))
    if report["headline"].get("verdict") != "allow" and not rows:
        reasons = report["headline"].get("verdict_reasons") or ["The scan requires manual review."]
        rows.append(("forensics", "Scan verdict", "", " ".join(reasons), "medium", {"reasons": reasons}))
    for finding in board.findings.values():
        if finding.label == "introduced" and RISK_ORDER[finding.risk] >= RISK_ORDER["medium"]:
            role = "hunter" if finding.component.startswith("pkg:") else "forensics"
            rows.append((role, finding.type, finding.component, finding.summary, finding.risk, finding.model_dump()))
    rows.sort(key=lambda row: (-RISK_ORDER.get(row[4], 0), row[1], row[2]))
    groups = defaultdict(list)
    for role, title, component, reason, severity, finding in rows:
        if title in {"image_not_pinned", "untrusted_image"}:
            # A single image repository can occur in multiple Dockerfiles and architecture variants.
            repo = component.split("@", 1)[0]
            component = repo.rsplit(":", 1)[0] if ":" in repo.rsplit("/", 1)[-1] else repo
            title = "Container image provenance"
        elif title in {"sensitive_file_change", "source_change"}:
            title = "Sensitive file change"
        groups[role, title, component].append((severity, reason, finding))
    for (role, title, component), group in groups.items():
        for start in range(0, len(group), 8):
            batch = group[start:start + 8]
            severity, reason, *_ = batch[0]
            key = "review:" + board.next_id("Q")
            entry = store.add(redact(json.dumps({"question": key, "findings": [row[2] for row in batch]})),
                              kind="tool_output", source="scan review question")
            related = [finding for _, _, finding in batch if finding.get("id") in board.findings]
            finding_ids = list(dict.fromkeys(finding["id"] for finding in related))
            if not finding_ids and any(finding.get("label") in {"introduced", "pre_existing"} for _, _, finding in batch):
                first = batch[0][2]
                hard = any(finding.get("hard_signal") or finding.get("malicious") for _, _, finding in batch)
                finding = board.add_finding(BoardFinding(
                    id=board.next_id("F"), type=title, component=redact(component), summary=redact(reason),
                    evidence_ids=[entry.id], hard_signal=hard, risk=severity, floor=severity if hard else "info",
                    label=first["label"], opened_by="scan",
                ))
                finding_ids = [finding.id]
            board.coverage_required.add(key)
            board.review_questions[key] = {
                "role": role, "title": redact(title)[:120], "component": redact(component)[:200],
                "reason": redact(reason)[:240], "severity": severity, "evidence_id": entry.id,
                "observations": len(batch),
                "finding_ids": finding_ids,
            }
