"""End-to-end Stage A test: the full agent loop on scenario S3+S9 with the replay back end."""
from guardian.agents.run import run


def test_s3_s9_agentic_run_blocks_with_evidence(tmp_path):
    board = run(tmp_path, backend="replay")
    events = [e["event"] for e in board.audit]
    kinds = [m.kind for m in board.messages]

    # Verdict passed the constitution.
    assert board.verdict and board.verdict["decision"] == "block"
    case = next(iter(board.cases.values()))
    assert case.resolved and case.risk == "critical" and case.verdict == "malicious"

    # Agentic behaviour happened: parallel tasks, a handoff, a challenge, a missed risk, a clear, a human question.
    assert len(board.tasks) >= 4
    for k in ("hypothesis", "handoff", "challenge", "answer", "corroborate", "missed_risk", "clear", "task_result"):
        assert k in kinds, k
    assert "ask_human" in events

    # The constitution visibly worked.
    rejections = [e for e in board.audit if e["event"] == "rejected"]
    assert any("does not appear in the cited evidence" in e["reason"] for e in rejections)  # wrong version caught (C1)
    assert "floor_intervention" in events  # too-low risk caught (C2)

    # Coverage complete, injection recorded, false alarm cleared.
    assert not board.coverage_gaps()
    assert any(f.type == "prompt_injection" for f in board.findings.values())
    assert any(f.status == "cleared" and f.type == "suspicious_update" for f in board.findings.values())
    assert all(not f.hard_signal or f.status != "cleared" for f in board.findings.values())


def test_saved_scan_package_tools_distinguish_ecosystems_and_nested_lockfiles(tmp_path):
    import json
    from guardian.agents import scan_packages
    from guardian.agents.board import Board
    from guardian.agents.tools import ToolRegistry
    from guardian.store.evidence import EvidenceStore

    go = {"key": "go:shared", "name": "shared", "ecosystem": "golang", "version": "1.1.0", "source_file": "go.mod"}
    js = {"key": "web:shared", "name": "shared", "ecosystem": "npm", "version": "1.0.0", "source_file": "web/package-lock.json"}
    changes = scan_packages.package_changes([{**go, "version": "1.0.0"}, js], [go, js])
    report = {"headline": {"base_commit_full": "a", "head_commit_full": "b"}, "inventory": [go, js],
              "package_changes_qualified": changes,
              "vulnerabilities": [{"id": "GO-TEST", "name": "shared", "version": "1.1.0", "ecosystem": "golang", "label": "introduced"}]}
    board = Board(run_id="TEST", base="a", head="b")
    store = EvidenceStore(tmp_path)
    registry = ToolRegistry(board, store, {"scan_report": report}, lambda *_: "unknown")

    def evidence(tool, args):
        text = registry.call("hunter", tool, args)
        return json.loads(store.content(text.splitlines()[0].split()[-1]))

    assert evidence("package_inventory", {"ecosystem": "npm", "query": "shared", "offset": 0})["packages"][0]["source_file"] == js["source_file"]
    assert evidence("package_advisories", {"ecosystem": "golang", "name": "shared", "version": "", "offset": 0})["advisories"][0]["id"] == "GO-TEST"
    assert evidence("package_changes", {"ecosystem": "", "offset": 0})["changes"][0]["before"] == ["1.0.0"]


def test_parallel_workers_join_before_the_next_routing_decision():
    from types import SimpleNamespace
    from guardian.agents.board import Board
    from guardian.agents.orchestrator import Orchestrator
    from guardian.agents.protocol import Task

    class Probe(Orchestrator):
        def lead_node(self, state):
            self.board.rounds += 1
            if self.board.rounds == 1:
                for name in ("hunter", "forensics"):
                    self.board.add_task(Task(id=name, assignee=name, goal="review", scope=[]))
            else:
                self.board.verdict = {"decision": "inconclusive"}
            return {}

        def worker_node(self, state):
            self.board.tasks[state["task_id"]].status = "done"
            return {"done": [state["task_id"]]}

        def route(self, state):
            if state.get("done"):
                assert set(state["done"]) == {"hunter", "forensics"}
            return super().route(state)

    board = Board(run_id="TEST", base="base", head="head")
    Probe(board, SimpleNamespace(run_required_checks=lambda: None), None).run()
    assert board.verdict == {"decision": "inconclusive"}


def test_native_deepseek_flash_returns_guardian_tool_calls(monkeypatch):
    from types import SimpleNamespace
    from guardian.agents.llm import DeepSeekBackend

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.delenv("GUARDIAN_DEEPSEEK_MODEL", raising=False)
    monkeypatch.setenv("GUARDIAN_MODEL", "other-provider-model")
    backend = DeepSeekBackend()
    request = {}

    def post(url, **kwargs):
        request.update(url=url, **kwargs)
        return SimpleNamespace(status_code=200, json=lambda: {"choices": [{"finish_reason": "tool_calls", "message": {
            "content": None, "tool_calls": [{"id": "call_1", "function": {"name": "scan_findings", "arguments": '{"offset":0}'}}]}}]})

    monkeypatch.setattr(backend.session, "post", post)
    turn = backend.step("lead", "Review evidence.", [{"role": "user", "content": "Read the saved report."}],
                        [{"name": "scan_findings", "description": "Read findings", "input_schema": {"type": "object"}}], "medium")
    assert request["url"] == "https://api.deepseek.com/chat/completions"
    assert request["json"]["model"] == "deepseek-flash"
    assert request["headers"]["Authorization"] == "Bearer test-key"
    assert turn.tool_calls[0].input == {"offset": 0}
