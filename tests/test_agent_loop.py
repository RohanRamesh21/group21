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
