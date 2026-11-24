"""Tool registry: what each agent may call (C6 read-only allow-lists), with strict JSON schemas.

Fact tools return evidence IDs plus content. Third-party content is wrapped in
<untrusted-data> tags (C5). Board tools let agents act on the shared board; every board write
passes through the constitution.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable

from jsonschema import Draft202012Validator

from guardian.agents.board import Board, RoutingError
from guardian.agents.boundary import MAX_EVIDENCE_CHARS, redact, redact_message, untrusted
from guardian.agents.constitution import ConstitutionError, check_message, check_resolution, check_verdict
from guardian.agents.protocol import RISK_ORDER, AgentMessage, BoardFinding, CaseState, Task
from guardian.store.evidence import EvidenceStore

REQUIRED_DETECTORS = ("D3", "D7", "D0", "D4")
DETECTORS = (*REQUIRED_DETECTORS, "D1")
MAX_ARGUMENT_CHARS = 24_000
PACKAGE_NAME = re.compile(r"(?:@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+\Z")
INJECTION_MARKERS = ("ai reviewer", "ignore previous", "mark it benign", "this package is safe", "</untrusted-data")


def _s(t: str | list, desc: str = "", **extra) -> dict:
    if "string" in ([t] if isinstance(t, str) else t):
        extra.setdefault("maxLength", 2_000)
    if t == "array":
        extra.setdefault("maxItems", 40)
        extra["items"].setdefault("maxLength", 2_000)
    return {"type": t, "description": desc, **extra}


def _schema(props: dict) -> dict:
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


@dataclass
class ToolSpec:
    name: str
    description: str
    schema: dict
    agents: set[str]
    fn: Callable[[str, dict], str]
    validator: Draft202012Validator


class ToolRegistry:
    def __init__(self, board: Board, store: EvidenceStore, world: dict, human: Callable[[str, list[str]], str]):
        self.board, self.store, self.world, self.human = board, store, world, human
        self.specs: dict[str, ToolSpec] = {}
        self._local = threading.local()  # per-thread call context (parallel workers)
        self._detector_results: dict[str, list[dict]] = {}
        self._detector_lock = threading.Lock()
        self._asked_human = False
        self.pace = 0.0  # seconds to wait per tool call (dashboard replay pacing; 0 in tests and CLI)
        self._register()

    # --- helpers -------------------------------------------------------------
    def _render(self, eid: str) -> str:
        ev = self.store.get(eid)
        body = self.store.content(eid)
        self._record_injection(eid, body + "\n" + (ev.path or ""))
        return f"evidence_id: {eid}\n" + untrusted({
            "source": ev.source, "path": ev.path, "kind": ev.kind,
            "content": redact(body)[:MAX_EVIDENCE_CHARS], "truncated": len(body) > MAX_EVIDENCE_CHARS,
        })

    def _fact(self, tool: str, arg: str, coverage: str | None = None) -> str:
        facts = self.world.get("facts")
        if facts is not None:  # Stage B: real tools
            eid = facts.answer(tool, arg)
            if eid is None:
                return json.dumps({"result": "unknown tool", "tool": tool})
            rendered = self._render(eid)
            if coverage and not self._fact_failed(eid):
                self.board.coverage_done.add(facts.coverage_key(coverage))
            return rendered
        key = self.world["answers"].get((tool, arg))
        if key is None:
            return json.dumps({"result": "no data for this argument in the current snapshot", "tool": tool, "arg": arg})
        eid = self.world["evidence"][key]
        rendered = self._render(eid)
        if coverage and not self._fact_failed(eid):
            self.board.coverage_done.add(coverage)
        return rendered

    def _fact_failed(self, eid: str) -> bool:
        if self.store.get(eid).kind != "tool_output":
            return False
        try:
            content = json.loads(self.store.content(eid))
        except ValueError:
            return False
        return isinstance(content, dict) and bool(content.get("error"))

    def _valid_scope(self, scope: list[str]) -> None:
        facts = self.world.get("facts")
        for item in scope:
            canonical = f"pkg:{item}" if item.startswith("pkg:npm/") else item
            if facts is not None and canonical.startswith("commit:"):
                canonical = facts.coverage_key(canonical)
            if canonical.startswith("file:") and self._changed_path(canonical[5:]):
                continue
            if canonical not in self.board.coverage_required:
                raise ValueError("task scope must refer to a changed surface")

    def _changed_path(self, path: str) -> bool:
        facts = self.world.get("facts")
        if facts is not None:
            return path in facts.diff["files_changed"]
        return ("git_diff", path) in self.world["answers"] or f"file:{path}" in self.board.coverage_required

    def _post(self, agent: str, a: dict) -> str:
        ctx = getattr(self._local, "ctx", {})
        if not a.get("task_id") and ctx.get("task_id"):
            a = {**a, "task_id": ctx["task_id"]}
        msg = AgentMessage(
            id=self.board.next_id("M"), run_id=self.board.run_id, sender=agent,
            recipient=a["recipient"], kind=a["kind"], claim=redact(a["claim"]),
            evidence_ids=a.get("evidence_ids") or [], kind_of_claim=a.get("kind_of_claim"),
            confidence=a.get("confidence"), proposed_risk=a.get("proposed_risk"),
            case_id=a.get("case_id"), task_id=a.get("task_id"), finding_id=a.get("finding_id"),
            in_reply_to=a.get("in_reply_to"),
            payload=json.loads(a["payload_json"]) if a.get("payload_json") else {},
        )
        try:
            task = self.board.tasks.get(msg.task_id or "")
            if msg.task_id and task is None:
                raise RoutingError("unknown task")
            if task:
                expected = msg.recipient if msg.kind == "challenge" else agent
                if (agent != "skeptic" or msg.kind == "challenge") and task.assignee != expected:
                    raise RoutingError("task belongs to another agent")
                if agent != "skeptic" and msg.task_id != ctx.get("task_id"):
                    raise RoutingError("task belongs to another assignment")
            if msg.kind == "task_result" and task is None:
                raise RoutingError("task result requires the current task")
            if msg.finding_id and msg.finding_id not in self.board.findings:
                raise RoutingError("unknown finding")
            if msg.case_id and msg.case_id not in self.board.cases:
                raise RoutingError("unknown case")
            handoff = None
            if msg.kind == "handoff":
                scope = msg.payload.get("scope")
                if (set(msg.payload) - {"scope", "depth"} or not isinstance(scope, list)
                        or not 1 <= len(scope) <= 40 or not all(isinstance(item, str) for item in scope)):
                    raise RoutingError("invalid handoff payload")
                self._valid_scope(scope)
                handoff = Task(id=self.board.next_id("T"), assignee=msg.recipient, goal="Investigate the assigned scope.",
                               scope=scope, depth=msg.payload.get("depth", "standard"))
            elif msg.payload:
                raise RoutingError("payload is only accepted for a handoff")
            check_message(msg, self.board, self.store)
            self.board.post(msg, handoff)
        except (ConstitutionError, RoutingError) as e:
            self.board.log(event="rejected", agent=agent, kind=msg.kind, reason=str(e))
            return f"REJECTED: {e}"
        # Side effects of accepted messages.
        f = self.board.findings.get(msg.finding_id or "")
        if f and msg.kind == "clear":
            f.status, f.risk = "cleared", "info"
        elif f and msg.kind == "corroborate":
            f.status = "corroborated"
            if msg.proposed_risk and RISK_ORDER[msg.proposed_risk] > RISK_ORDER[f.risk]:
                f.risk = msg.proposed_risk
        elif f and msg.kind == "dispute":
            f.status = "disputed"
        if msg.kind == "task_result" and msg.task_id in self.board.tasks:
            self.board.tasks[msg.task_id].status = "done"
        if self.board.focused and msg.sender == "skeptic" and msg.kind in {"corroborate", "dispute"}:
            self._record_question_review(msg)
        return f"ACCEPTED {msg.id}"

    def _record_question_review(self, msg: AgentMessage) -> None:
        hypothesis = next((m for m in self.board.messages if m.id == msg.in_reply_to and m.kind == "hypothesis"
                           and m.recipient == "skeptic"), None)
        task = self.board.tasks.get(hypothesis.task_id or "") if hypothesis else None
        if task is None:
            return
        worker_results = {eid for m in self.board.messages if m.task_id == task.id and m.kind == "task_result"
                          and m.sender == task.assignee for eid in m.evidence_ids}
        cited = set(msg.evidence_ids) & set(hypothesis.evidence_ids)
        for key in task.scope:
            question = self.board.review_questions.get(key)
            if not question or question["role"] != task.assignee or question["evidence_id"] not in cited:
                continue
            if msg.kind == "dispute":
                self.board.coverage_done.discard(key)
            elif question["evidence_id"] in worker_results:
                self.board.coverage_done.add(key)

    # --- registry ------------------------------------------------------------
    def _add(self, name, desc, props, agents, fn, *, required=None):
        schema = _schema(props)
        if required is not None:
            schema["required"] = list(required)
        self.specs[name] = ToolSpec(name, desc, schema, set(agents), fn, Draft202012Validator(schema))

    def _register(self) -> None:
        S, A = _s, ["lead", "hunter", "forensics", "skeptic"]
        nullable_str = ["string", "null"]

        # Fact tools (Stage A: canned; Stage B: real implementations behind the same names).
        self._add("diff_summary", "Structured summary of what changed between base and head.", {}, ["lead", "skeptic", "forensics"],
                  lambda ag, a: self._fact("diff_summary", ""))
        if "scan_report" in self.world:
            from guardian.agents import scan_packages

            self._add("scan_findings", "Read the deterministic scan summary and up to 10 findings across all ecosystems. Start at offset 0.",
                      {"offset": S("integer", minimum=0)}, A, self._scan_findings)
            self._add("package_inventory", "Read scanned components across ecosystems, including nested lockfiles. Use empty ecosystem/query for all.",
                      {"ecosystem": S("string"), "query": S("string"), "offset": S("integer", minimum=0)}, A,
                      lambda ag, a: self._scan_package_fact(scan_packages.inventory, **a))
            self._add("package_advisories", "Read scanner advisories for one package by exact ecosystem and name. Use empty version for all observed versions.",
                      {"ecosystem": S("string"), "name": S("string"), "version": S("string"), "offset": S("integer", minimum=0)}, A,
                      lambda ag, a: self._scan_package_fact(scan_packages.advisories, **a))
            self._add("package_changes", "Read added, updated and removed versions across ecosystems. Use empty ecosystem for all.",
                      {"ecosystem": S("string"), "offset": S("integer", minimum=0)}, A,
                      lambda ag, a: self._scan_package_fact(scan_packages.changes, **a))
            if self.board.focused:
                self._add("review_question", "Read the finding behind one assigned review ID. Pass the ID from the task scope.",
                          {"id": S("string")}, A, self._review_question)
                self._add("record_review", "Record the Skeptic's decision on the reviewed questions from one hypothesis.", {
                    "hypothesis_id": S("string"),
                    "question_ids": S("array", items={"type": "string"}, minItems=1),
                    "decision": S("string", enum=["corroborate", "dispute"]),
                    "claim": S("string", maxLength=600),
                }, ["skeptic"], self._record_review)
            else:
                self._add("dispatch_scan_review", "Queue Dependency Hunter and Change Forensics together using verified scope IDs.",
                          {}, ["lead"], self._dispatch_scan_review)
        self._add("lockfile_diff", "Lockfile changes between base and head (new entries, version/hash/URL changes).", {},
                  ["forensics", "hunter"], lambda ag, a: self._fact("lockfile_diff", "", "file:package-lock.json"))
        self._add("git_diff", "Diff hunk for one file between base and head.", {"path": S("string")}, ["forensics"],
                  lambda ag, a: self._fact("git_diff", a["path"], f"file:{a['path']}"))
        self._add("commit_metadata", "Author, message and files of a commit.", {"sha": S("string")}, ["forensics"],
                  lambda ag, a: self._fact("commit_metadata", a["sha"], f"commit:{a['sha']}"))
        self._add("sensitive_path_check", "Which sensitive paths (.npmrc, workflows, IDE/agent configs, hooks) changed.", {},
                  ["forensics", "skeptic"], lambda ag, a: self._fact("sensitive_path_check", ""))
        self._add("registry_metadata", "Registry metadata for a package version (age, maintainers, downloads, repo, host).",
                  {"purl": S("string")}, ["hunter"], lambda ag, a: self._fact("registry_metadata", a["purl"]))
        self._add("popularity_baseline", "Popularity baseline of a well-known package name, for look-alike comparison.",
                  {"name": S("string")}, ["hunter", "skeptic"], lambda ag, a: self._fact("popularity_baseline", a["name"]))
        self._add("install_hooks", "Lifecycle scripts declared by a package version.", {"purl": S("string")}, ["hunter"],
                  lambda ag, a: self._fact("install_hooks", a["purl"]))
        self._add("read_package_file", "Read one file from a package tarball (returned as untrusted data).",
                  {"purl": S("string"), "path": S("string")}, ["hunter"],
                  lambda ag, a: self._fact("read_package_file", f"{a['purl']}#{a['path']}"))
        self._add("osv_lookup", "Known OSV advisories (CVE/GHSA/MAL) for a package version.",
                  {"purl": S("string")}, ["hunter"], lambda ag, a: self._fact("osv_lookup", a["purl"], f"pkg:{a['purl']}"))
        if self.world.get("facts") is not None:
            self._add("review_npm_advisories",
                      "Review up to 10 required changed npm versions in your assignment using exact OSV evidence. "
                      "Start at offset 0, then use next_offset until null. Do this before optional registry research.",
                      {"offset": S("integer", minimum=0)}, ["hunter"], self._review_npm_advisories)
        self._add("compare_versions_metadata", "Compare a package's new version with its previous one (hooks, maintainers, size).",
                  {"purl": S("string")}, ["hunter"], lambda ag, a: self._fact("compare_versions_metadata", a["purl"]))
        self._add("policy_lookup", "Project policy: allowed registry hosts, internal scopes, approved decisions.", {},
                  ["lead", "skeptic", "hunter"], lambda ag, a: self._fact("policy_lookup", ""))
        self._add("get_evidence", "Fetch the content of an evidence record by ID.", {"evidence_id": S("string")}, A,
                  lambda ag, a: self._render(a["evidence_id"]) if self.store.exists(a["evidence_id"]) else "unknown evidence id")
        self._add("run_detector", "Run a deterministic detector and register its signals as findings. "
                  "D0 vulns, D1 typosquat, D3 lockfile tamper, D4 suspicious update, D7 source/sensitive change.",
                  {"detector": S("string", enum=list(DETECTORS))}, ["hunter", "forensics"], self._run_detector)
        self._add("injection_scan", "Scan an evidence record for instruction-like text aimed at AI reviewers.",
                  {"evidence_id": S("string")}, ["skeptic"], self._injection_scan)
        self._add("coverage_report", "Which required evidence and changed surfaces have been examined.", {}, ["lead", "skeptic"],
                  lambda ag, a: untrusted({"required": sorted(self.board.coverage_required), "gaps": self.board.coverage_gaps(),
                                            "required_checks": self.board.required_checks}))
        self._add("board_view", "Current plan, tasks, findings, cases and coverage gaps (IDs and summaries only).", {}, A,
                  lambda ag, a: untrusted(self.board.snapshot()))

        # Board tools.
        self._add("post_message", "Post a typed message with evidence IDs. Use task_result to finish an assigned task.", {
            "recipient": S("string", enum=["lead", "hunter", "forensics", "skeptic", "human", "board"]),
            "kind": S("string", enum=["task_result", "handoff", "hypothesis", "challenge", "answer", "corroborate",
                                      "clear", "dispute", "missed_risk"]),
            "claim": S("string", "Your own words, max 600 characters.", maxLength=600),
            "evidence_ids": S("array", items={"type": "string"}),
            "kind_of_claim": S(nullable_str, enum=["verified", "inferred", None]),
            "confidence": S(["number", "null"], minimum=0, maximum=1),
            "proposed_risk": S(nullable_str, enum=["critical", "high", "medium", "low", "info", None]),
            "finding_id": S(nullable_str), "task_id": S(nullable_str), "case_id": S(nullable_str),
            "in_reply_to": S(nullable_str), "payload_json": S(nullable_str, "Only for handoff. JSON object with scope IDs and optional depth."),
        }, ["hunter", "forensics", "skeptic"], self._post, required=("recipient", "kind", "claim", "evidence_ids"))
        self._add("write_plan", "Write or replace the investigation plan (one line per step).",
                  {"steps": S("array", items={"type": "string"})}, ["lead"], self._write_plan)
        self._add("dispatch_task", "Assign a specialist changed scope IDs from coverage_report.", {
            "assignee": S("string", enum=["hunter", "forensics"]), "goal": S("string"),
            "scope": S("array", items={"type": "string"}), "depth": S("string", enum=["quick", "standard", "deep"]),
            "acceptance": S("array", items={"type": "string"}),
        }, ["lead"], self._dispatch)
        self._add("open_case", "Group findings into a case with a root cause.", {
            "title": S("string"), "finding_ids": S("array", items={"type": "string"}), "root_cause": S("string"),
        }, ["lead"], self._open_case)
        self._add("resolve_case", "Resolve a case. Risk can never be below its findings' floors (C2).", {
            "case_id": S("string"), "verdict": S("string", enum=["malicious", "suspicious", "vulnerable", "benign", "unresolved"]),
            "risk": S("string", enum=["critical", "high", "medium", "low", "info"]), "confidence": S("number", minimum=0, maximum=1),
            "rationale": S("string"), "evidence_ids": S("array", items={"type": "string"}),
        }, ["lead"], self._resolve_case)
        self._add("ask_human", "Request reviewer context about whether a registry change was expected.", {
            "question": S("string"), "options": S("array", items={"type": "string"}),
        }, ["lead"], self._ask_human)
        self._add("submit_verdict", "Submit the overall recommendation. Choose inconclusive if evidence or coverage is incomplete.", {
            "decision": S("string", enum=["block", "safe_to_merge", "inconclusive"]), "rationale": S("string"),
            "case_ids": S("array", items={"type": "string"}), "evidence_ids": S("array", items={"type": "string"}),
        }, ["lead"], self._submit_verdict)

    # --- tool implementations ------------------------------------------------
    def _review_npm_advisories(self, agent: str, args: dict) -> str:
        facts = self.world["facts"]
        task = self.board.tasks.get(getattr(self._local, "ctx", {}).get("task_id") or "")
        if task is None or task.assignee != agent:
            return "REJECTED: this review requires a Dependency Hunter assignment"
        purls = sorted(key[4:] for key in self.board.coverage_required if key.startswith("pkg:pkg:npm/") and
                       ("scan:packages" in task.scope or key in task.scope or key[4:] in task.scope))
        offset = args["offset"]
        page = []
        for purl in purls[offset:offset + 10]:
            try:
                eid = facts.answer("osv_lookup", purl)
                if not eid or self._fact_failed(eid):
                    raise ValueError("missing advisory evidence")
                result = json.loads(self.store.content(eid))
                advisories = result["advisories"]
                if not isinstance(advisories, list):
                    raise ValueError("invalid advisory evidence")
                page.append({"purl": purl, "evidence_id": eid, "advisory_count": len(advisories),
                             "advisory_ids": [a["id"] for a in advisories[:4]]})
                self.board.coverage_done.add(f"pkg:{purl}")
            except (ValueError, TypeError, KeyError, OSError) as exc:
                page.append({"purl": purl, "status": "not_checked", "error": type(exc).__name__})
        summary = {"total": len(purls), "offset": offset, "next_offset": offset + 10 if offset + 10 < len(purls) else None,
                   "packages": page}
        entry = self.store.add(json.dumps(summary), kind="tool_output", source="changed npm advisory review")
        return self._render(entry.id)

    def _scan_package_fact(self, tool, **args) -> str:
        result = tool(self.world["scan_report"], **args)
        entry = self.store.add(redact(json.dumps(result)), kind="tool_output", source="deterministic package scan")
        if args["offset"] == 0 and not args.get("ecosystem") and (
            result.get("comparison") == "base_to_head" or "packages" in result and not args.get("query")
        ):
            self.board.coverage_done.add("scan:packages")
        return self._render(entry.id)

    def _scan_findings(self, agent: str, args: dict) -> str:
        report = self.world["scan_report"]
        headline = report["headline"]
        rows = [f for key in ("vulnerabilities", "suspicious_changes", "ci_image") for f in report.get(key, [])
                if f.get("label") != "fixed"]
        levels = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(key=lambda f: (f.get("label") != "introduced", levels.get(f.get("severity"), 5)))
        offset = args["offset"]
        page = {"verdict": headline.get("verdict"), "base": headline.get("base_commit_full"),
                "head": headline.get("head_commit_full"), "inventory": headline.get("inventory", {}).get("ecosystems", {}),
                "total": len(rows), "offset": offset, "next_offset": offset + 10 if offset + 10 < len(rows) else None,
                "findings": [{k: str(f[k])[:240] for k in ("id", "name", "version", "detector", "type", "component",
                                                            "severity", "label", "file", "line") if f.get(k) is not None}
                             for f in rows[offset:offset + 10]]}
        entry = self.store.add(json.dumps(page), kind="tool_output", source="deterministic scan")
        if offset == 0:
            self.board.coverage_done.add("scan:summary")
        return self._render(entry.id)

    def _review_question(self, agent: str, args: dict) -> str:
        question = self.board.review_questions.get(args["id"])
        if question is None:
            return "REJECTED: unknown review question"
        if agent in {"hunter", "forensics"}:
            task = self.board.tasks.get(getattr(self._local, "ctx", {}).get("task_id") or "")
            if task is None or args["id"] not in task.scope:
                return "REJECTED: question is outside this assignment"
        return self._render(question["evidence_id"])

    def _record_review(self, agent: str, args: dict) -> str:
        hypothesis = next((m for m in self.board.messages if m.id == args["hypothesis_id"] and m.kind == "hypothesis"), None)
        task = self.board.tasks.get(hypothesis.task_id or "") if hypothesis else None
        questions = [self.board.review_questions.get(key) if task and key in task.scope else None for key in args["question_ids"]]
        if not all(question and question["evidence_id"] in hypothesis.evidence_ids for question in questions):
            return "REJECTED: every question must be in the cited hypothesis and assignment"
        return self._post(agent, {"recipient": "lead", "kind": args["decision"], "claim": args["claim"],
                                  "in_reply_to": hypothesis.id, "evidence_ids": [q["evidence_id"] for q in questions]})

    def run_required_checks(self) -> None:
        """Run the hard-signal detectors before a model can choose what to investigate."""
        self.board.required_checks.update(dict.fromkeys(REQUIRED_DETECTORS, "pending"))
        facts = self.world.get("facts")
        scan = self.world.get("scan_report")
        if scan is not None:
            headline = scan["headline"]
            self.board.required_checks["deterministic_scan"] = "passed" if headline.get("verdict") == "allow" else "needs_review"
            malware = [{**v, "type": "malicious", "component": f"{v['name']}@{v['version']}",
                        "hard_signal": True, "severity": "critical", "detector": "scan advisories"}
                       for v in scan.get("vulnerabilities", []) if v.get("malicious")]
            for item in [*scan.get("suspicious_changes", []), *malware]:
                if not item.get("hard_signal") or item.get("label") == "fixed" or item.get("severity") not in {"high", "critical"}:
                    continue
                entry = self.store.add(redact(json.dumps(item)), kind="tool_output", source="deterministic scan")
                self.board.add_finding(BoardFinding(
                    id=self.board.next_id("F"), type=item["type"], component=redact(item["component"]),
                    summary=redact(item.get("summary") or "The scanner reported a known malicious package."),
                    hard_signal=True, evidence_ids=[entry.id],
                    risk=item["severity"], floor=item["severity"], label=item.get("label"), opened_by=item.get("detector", "scan"),
                ))
        if facts is not None and (facts.diff["workflows_changed"] or facts.diff["dockerfiles_changed"]) and (
            scan is None or scan["headline"].get("ci_image", {}).get("errors")
        ):
            self.board.required_checks["ci_image"] = "unsupported"
            self.board.log(event="required_check", detector="ci_image", status="unsupported")
        for detector in REQUIRED_DETECTORS:
            try:
                self._detect(detector)
            except Exception as exc:
                self.board.required_checks[detector] = "failed"
                self.board.log(event="required_check", detector=detector, status="failed", error=type(exc).__name__)
            else:
                self.board.required_checks[detector] = "passed"
                self.board.log(event="required_check", detector=detector, status="passed")
        if self.board.focused:
            self.board.coverage_done.update(facts.checked_advisories)

    def dispatch_focused_review(self) -> None:
        from guardian.agents.focus import queue

        queue(self.board, self.store, self.world["scan_report"])
        for role in ("hunter", "forensics"):
            scope = [key for key, question in self.board.review_questions.items() if question["role"] == role]
            for start in range(0, min(len(scope), 24), 6):
                self._dispatch("lead", {
                    "assignee": role, "scope": scope[start:start + 6], "depth": "quick",
                    "goal": "Evaluate the assigned scan findings. Read each question first and get extra evidence only if needed.",
                    "acceptance": ["Cite each reviewed question's evidence ID in both your hypothesis and task_result."],
                })
        missing = sorted(key for key in self.board.coverage_gaps() if key.startswith("pkg:"))
        for start in range(0, min(len(missing), 40), 10):
            self._dispatch("lead", {"assignee": "hunter", "scope": missing[start:start + 10], "depth": "quick",
                                     "goal": "Investigate these missing exact-version npm advisory checks.",
                                     "acceptance": ["Use review_npm_advisories with offset 0 for this scope."]})

    def finish_advisory_checks(self) -> None:
        if (self.board.required_checks.get("D0") != "failed"
                or any(key.startswith("pkg:") for key in self.board.coverage_gaps())):
            return
        # A worker retried the missing lookups. Re-evaluate the hard-signal gate with the cached responses.
        try:
            self._detect("D0")
        except (ValueError, TypeError, KeyError, OSError):
            return
        self.board.required_checks["D0"] = "passed"
        self.board.log(event="required_check", detector="D0", status="passed")

    def _detect(self, detector: str) -> list[dict]:
        with self._detector_lock:
            if detector not in self._detector_results:
                self._detector_results[detector] = self._collect_signals(detector)
            return self._detector_results[detector]

    def _collect_signals(self, detector: str) -> list[dict]:
        out = []
        facts = self.world.get("facts")
        signals = facts.iter_signals(detector) if facts is not None else self.world["detectors"][detector]
        for sig in signals:
            if self.board.focused and detector == "D4" and sig["floor"] == "info" and not sig["hard_signal"]:
                continue
            eid = sig["evidence"] if facts is not None else self.world["evidence"][sig["evidence"]]
            self.store.content(eid)
            f = self.board.add_finding(BoardFinding(
                id=self.board.next_id("F"), type=sig["type"], component=redact(sig["component"]), summary=redact(sig["summary"]),
                evidence_ids=[eid], hard_signal=sig["hard_signal"], floor=sig["floor"], risk=sig["floor"],
                label=sig.get("label", "introduced"), opened_by=detector,
            ))
            out.append({"finding_id": f.id, "type": f.type, "component": f.component, "summary": f.summary,
                        "hard_signal": f.hard_signal, "floor": f.floor, "evidence_ids": f.evidence_ids})
        return out

    def _run_detector(self, agent: str, a: dict) -> str:
        return untrusted({"detector": a["detector"], "signals": self._detect(a["detector"])})

    def _injection_scan(self, agent: str, a: dict) -> str:
        eid = a["evidence_id"]
        if not self.store.exists(eid):
            return "unknown evidence id"
        return json.dumps(self._record_injection(eid, self.store.content(eid)))

    def _record_injection(self, eid: str, text: str) -> dict:
        normalized = " ".join(text.casefold().split())
        hits = [pattern for pattern in INJECTION_MARKERS if pattern in normalized]
        if hits:
            f = self.board.add_finding(BoardFinding(
                id=self.board.next_id("F"), type="prompt_injection", component=eid,
                summary="instruction-like text aimed at AI reviewers", evidence_ids=[eid],
                hard_signal=False, floor="high", risk="high", label="introduced", opened_by="skeptic",
            ))
            return {"injection": True, "patterns": hits, "finding_id": f.id}
        return {"injection": False}

    def _write_plan(self, agent, a):
        self.board.plan = [redact(step) for step in a["steps"]]
        return "plan saved"

    def _dispatch(self, agent, a):
        self._valid_scope(a["scope"])
        t = Task(id=self.board.next_id("T"), assignee=a["assignee"], goal=redact(a["goal"]), scope=a["scope"],
                 depth=a["depth"], acceptance=[redact(item) for item in a["acceptance"]])
        self.board.add_task(t)
        self.board.log(event="dispatch", task=t.id, assignee=t.assignee, scope=t.scope)
        return f"dispatched {t.id}"

    def _dispatch_scan_review(self, agent, args):
        if self.board.tasks:
            return "REJECTED: the initial scan review must be dispatched before other tasks"
        changes = sorted((key for key in self.board.coverage_required if key.startswith(("commit:", "file:"))),
                         key=lambda key: (not key.startswith("file:"), key))
        assignments = (
            ("hunter", ["scan:packages"], "Read the scan-wide package overview and finish the exact-version advisory batches first.",
             ["Record all available required package coverage", "Summarize material findings for Skeptic and Lead"]),
            ("forensics", ["scan:summary", *changes[:39]], "Review the saved scan, changed files and commits in scope.",
             ["Read the assigned file and commit evidence", "Summarize material findings for Skeptic and Lead"]),
        )
        return "\n".join(self._dispatch(agent, {"assignee": role, "scope": scope, "goal": goal, "depth": "quick",
                                                "acceptance": acceptance})
                         for role, scope, goal, acceptance in assignments)

    def _open_case(self, agent, a):
        unknown = [f for f in a["finding_ids"] if f not in self.board.findings]
        if unknown or not a["finding_ids"]:
            return "REJECTED: a case must contain known finding IDs"
        c = CaseState(id=self.board.next_id("C"), title=redact(a["title"]), finding_ids=a["finding_ids"],
                      root_cause=redact(a["root_cause"]))
        self.board.cases[c.id] = c
        return f"opened {c.id}"

    def _resolve_case(self, agent, a):
        if a["case_id"] not in self.board.cases:
            return "REJECTED: unknown case"
        c = self.board.cases[a["case_id"]]
        if not a["evidence_ids"] or not all(self.store.exists(eid) for eid in a["evidence_ids"]):
            return "REJECTED: C1 resolution needs valid evidence IDs"
        if not any(set(self.board.findings[fid].evidence_ids).intersection(a["evidence_ids"]) for fid in c.finding_ids):
            return "REJECTED: C1 resolution needs evidence attached to the case"
        for eid in a["evidence_ids"]:
            self.store.content(eid)
        try:
            check_resolution(self.board, a["case_id"], a["risk"], a["verdict"])
        except ConstitutionError as e:
            self.board.log(event="rejected", agent=agent, kind="resolve", reason=str(e))
            return f"REJECTED: {e}"
        c.verdict, c.risk, c.confidence, c.rationale = a["verdict"], a["risk"], a["confidence"], redact(a["rationale"])
        c.evidence_ids, c.resolved = a["evidence_ids"], True
        return f"resolved {c.id}"

    def _ask_human(self, agent, a):
        if "registry" not in a["question"].casefold():
            return "REJECTED: this workflow only supports registry context questions"
        if self._asked_human:
            return "REJECTED: reviewer question budget exhausted"
        self._asked_human = True
        question = "Was the registry change expected for this repository?"
        options = ["Yes", "No", "Unsure"]
        self.board.log(event="human_request", agent=agent, question=question, options=options)
        answer = redact(self.human(question, options))
        eid = self.store.add(f"Q: {question}\nA: {answer}", kind="tool_output", source="human (ask_human)").id
        self.board.log(event="ask_human", question=question, answer=answer, evidence=eid)
        return self._render(eid)

    def _submit_verdict(self, agent, a):
        try:
            check_verdict(self.board, a["decision"])
        except ConstitutionError as e:
            self.board.log(event="rejected", agent=agent, kind="verdict", reason=str(e))
            return f"REJECTED: {e}"
        if a["decision"] != "inconclusive" and set(a["case_ids"]) != self.board.cases.keys():
            return "REJECTED: verdict must refer to every resolved case"
        if not set(a["case_ids"]).issubset(self.board.cases):
            return "REJECTED: verdict refers to unknown cases"
        if not a["evidence_ids"] or not all(self.store.exists(eid) for eid in a["evidence_ids"]):
            return "REJECTED: verdict must cite valid evidence"
        for eid in a["evidence_ids"]:
            self.store.content(eid)
        self.board.verdict = {"decision": a["decision"], "rationale": redact(a["rationale"]), "case_ids": a["case_ids"],
                              "evidence_ids": a["evidence_ids"]}
        self.board.log(event="verdict", **self.board.verdict)
        return "verdict accepted by the constitution"

    # --- public API ----------------------------------------------------------
    def schemas_for(self, agent: str) -> list[dict]:
        facts = self.world.get("facts")
        unavailable = {"registry_metadata", "install_hooks", "read_package_file", "osv_lookup", "compare_versions_metadata"} if (
            facts is not None and facts.missing_lockfile and not facts.head_pkgs
        ) else set()
        return [{"name": s.name, "description": s.description, "input_schema": s.schema, "strict": True}
                for s in self.specs.values() if agent in s.agents and s.name not in unavailable]

    def call(self, agent: str, name: str, args: dict, ctx: dict | None = None) -> str:
        self._local.ctx = ctx or {}
        spec = self.specs.get(name)
        if spec is None or agent not in spec.agents:
            self.board.log(event="denied_tool", agent=agent, tool=name)
            return "DENIED: tool is outside the role's allow-list (C6)"
        if self.board.verdict is not None or not self.board.take_tool_slot():
            return "DENIED: run has ended or its tool budget is exhausted (C8)"
        invalid = next(spec.validator.iter_errors(args), None) if isinstance(args, dict) else None
        if not isinstance(args, dict) or invalid is not None:
            self.board.log(event="rejected", agent=agent, kind=name, reason="invalid tool arguments")
            if invalid is not None and invalid.path:
                field = ".".join(str(part) for part in invalid.path)
                return f"REJECTED: invalid tool arguments ({field} violates {invalid.validator})"
            return "REJECTED: invalid tool arguments"
        if self.pace:
            time.sleep(self.pace)
        try:
            if len(json.dumps(args, allow_nan=False)) > MAX_ARGUMENT_CHARS:
                return "REJECTED: tool input is too long"
            if "purl" in args:
                self._valid_scope([args["purl"]])
            if name == "popularity_baseline" and not PACKAGE_NAME.fullmatch(args["name"]):
                return "REJECTED: invalid npm package name"
            if name == "git_diff" and not self._changed_path(args["path"]):
                return "REJECTED: path is outside the changed surfaces"
            if name == "commit_metadata" and not re.fullmatch(r"[a-f0-9]{7,64}", args["sha"]):
                return "REJECTED: invalid commit ID"
            self.board.log(event="tool_call", agent=agent, tool=name, args=redact_message(args))
            return spec.fn(agent, args)
        except Exception as e:  # tool errors go back to the agent, not up the stack
            self.board.log(event="tool_error", agent=agent, tool=name, error=type(e).__name__)
            return f"TOOL ERROR: {type(e).__name__}"
