import pytest

from guardian.agents.board import Board, RoutingError
from guardian.agents.constitution import ConstitutionError, check_message, check_resolution, check_verdict
from guardian.agents.protocol import AgentMessage, BoardFinding, CaseState
from guardian.store.evidence import EvidenceStore


@pytest.fixture
def env(tmp_path):
    store = EvidenceStore(tmp_path)
    board = Board(run_id="RUN-1", base="2.5.12", head="scenario")
    ev = store.add('{"name":"axois","version":"1.0.0","resolved":"http://localhost:4873/axois/-/axois-1.0.0.tgz"}',
                   kind="tool_output", source="registry_metadata")
    note = store.add("I think it is bad", kind="agent_note", source="hunter")
    board.add_finding(BoardFinding(id="F-1", type="lockfile_tamper", component="axois@1.0.0", summary="off-registry",
                                   evidence_ids=[ev.id], hard_signal=True, floor="critical", risk="critical",
                                   label="introduced"))
    board.add_finding(BoardFinding(id="F-2", type="suspicious_update", component="kuma-helper", summary="bump",
                                   evidence_ids=[ev.id], label="introduced"))
    return store, board, ev, note


def msg(**kw):
    base = dict(id="M-1", run_id="RUN-1", sender="hunter", recipient="skeptic", kind="hypothesis")
    base.update(kw)
    return AgentMessage(**base)


def test_c1_rejects_missing_or_unknown_evidence(env):
    store, board, ev, _ = env
    with pytest.raises(ConstitutionError, match="must cite"):
        check_message(msg(claim="axois is bad"), board, store)
    with pytest.raises(ConstitutionError, match="unknown evidence"):
        check_message(msg(claim="x", evidence_ids=["E-doesnotexist"]), board, store)


def test_c1_rejects_invented_versions_and_advisories(env):
    store, board, ev, _ = env
    check_message(msg(claim="axois@1.0.0 resolves off-registry", evidence_ids=[ev.id]), board, store)
    with pytest.raises(ConstitutionError, match="does not appear"):
        check_message(msg(claim="axois@9.9.9 is malicious", evidence_ids=[ev.id]), board, store)
    with pytest.raises(ConstitutionError, match="advisory"):
        check_message(msg(claim="matches CVE-2026-12345", evidence_ids=[ev.id]), board, store)


def test_c1_verified_needs_tool_output(env):
    store, board, _, note = env
    with pytest.raises(ConstitutionError, match="tool output"):
        check_message(msg(claim="bad", evidence_ids=[note.id], kind_of_claim="verified"), board, store)


def test_c9_and_c2_on_clear(env):
    store, board, ev, _ = env
    with pytest.raises(ConstitutionError, match="only the Skeptic"):
        check_message(msg(kind="clear", recipient="lead", finding_id="F-2", claim="fine", evidence_ids=[ev.id]), board, store)
    with pytest.raises(ConstitutionError, match="hard signal"):
        check_message(msg(sender="skeptic", recipient="lead", kind="clear", finding_id="F-1", claim="fine",
                          evidence_ids=[ev.id]), board, store)
    check_message(msg(sender="skeptic", recipient="lead", kind="clear", finding_id="F-2", claim="benign",
                      evidence_ids=[ev.id]), board, store)


def test_c2_floor_blocks_low_resolution(env):
    _, board, _, _ = env
    board.cases["C-1"] = CaseState(id="C-1", title="t", finding_ids=["F-1"])
    with pytest.raises(ConstitutionError, match="floor"):
        check_resolution(board, "C-1", "medium", "suspicious")
    assert board.audit[-1]["event"] == "floor_intervention"
    check_resolution(board, "C-1", "critical", "malicious")


def test_c3_coverage_and_block_rule(env):
    _, board, _, _ = env
    board.coverage_required = {"pkg:axois", "file:.npmrc"}
    board.coverage_done = {"pkg:axois"}
    with pytest.raises(ConstitutionError, match="coverage"):
        check_verdict(board, "block")
    board.coverage_done.add("file:.npmrc")
    board.cases["C-1"] = CaseState(id="C-1", title="t", finding_ids=["F-1", "F-2"], risk="critical", resolved=True)
    with pytest.raises(ConstitutionError, match="block"):
        check_verdict(board, "safe_to_merge")
    check_verdict(board, "block")


def test_routing_rules():
    board = Board(run_id="R", base="a", head="b")
    with pytest.raises(RoutingError):
        board.post(AgentMessage(id="M", run_id="R", sender="hunter", recipient="human", kind="verdict"))
