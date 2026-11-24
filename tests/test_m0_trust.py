"""M0 trust-and-correctness gate: one regression test per verified defect (docs/GUARDIAN_FINAL_PLAN.md §20)."""
import json

import pytest


# ---------- T1: static file route must not leave the dashboard build folder ----------

def test_t1_spa_route_blocks_path_traversal():
    from fastapi.testclient import TestClient

    from guardian import server
    if not server.DIST.exists():
        pytest.skip("dashboard not built")
    c = TestClient(server.app)
    for p in ("/..%2F..%2F..%2Fpyproject.toml", "/%2e%2e/%2e%2e/%2e%2e/pyproject.toml"):
        r = c.get(p)
        assert "[project]" not in r.text, f"{p} leaked a file outside dist/"


# ---------- T8 / T9 / T5: one verdict function ----------

def _f(level, label="introduced", decision="Track", severity=None, kind="vulnerability"):
    return {"title": f"x-{level}", "kind": kind, "level": level, "label": label, "decision": decision,
            "severity": severity or level, "floor": None, "ssvc": {"rule": "r"}}


def test_t8_introduced_high_severity_is_review_even_if_ssvc_lowered_the_level():
    from guardian.scoring.verdict import decide
    # CVSS high, but SSVC said Track (no attack seen) so the level became low
    d = decide([_f("low", severity="high")], [])
    assert d["verdict"] == "review"


@pytest.mark.parametrize("kind", ["supply_chain", "ci_image"])
def test_t8_applies_to_non_cve_and_ci_findings(kind):
    from guardian.scoring.verdict import decide
    assert decide([_f("medium", severity="high", kind=kind)], [])["verdict"] == "review"


def test_verdict_block_allow_and_pre_existing():
    from guardian.scoring.verdict import decide
    assert decide([_f("critical")], [])["verdict"] == "block"
    assert decide([_f("medium", decision="Act")], [])["verdict"] == "block"
    assert decide([_f("critical", label="pre_existing")], [])["verdict"] == "allow"
    assert decide([_f("medium")], [])["verdict"] == "allow"


def test_t5_scanner_failure_is_incomplete_never_clean():
    from guardian.scoring.verdict import decide
    d = decide([], ["grype failed (1): db missing"])
    assert d["verdict"] == "allow" and d["complete"] is False
    assert d["incomplete_reasons"] == ["grype failed (1): db missing"]
    assert decide([], [])["complete"] is True


def test_t5_completeness_reads_report_errors():
    from guardian.scoring.verdict import incomplete_reasons
    rep = {"inventory": [{"ecosystem": "npm"}],
           "headline": {"vulnerabilities": {"errors": {"grype": "grype failed"}}, "ci_image": {"errors": {}},
                        "suspicious_error": None}}
    assert incomplete_reasons(rep) == ["vulnerabilities/grype: grype failed"]
    # OSV API down but npm-only inventory: the offline OSV copy covered it
    rep["headline"]["vulnerabilities"]["errors"] = {"osv_api": "unreachable"}
    assert incomplete_reasons(rep) == []
    # ...but not when other ecosystems are present
    rep["inventory"].append({"ecosystem": "pypi"})
    assert incomplete_reasons(rep) == ["vulnerabilities/osv_api: unreachable"]
    rep["headline"]["suspicious_error"] = "RegistryError: offline"
    assert "suspicious_changes: RegistryError: offline" in incomplete_reasons(rep)


def test_t9_score_report_uses_the_shared_verdict(monkeypatch):
    from guardian.scoring import intel, score
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": []} for i in ids})
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    rep = {"inventory": [], "suspicious_changes": [], "ci_image": [],
           "headline": {"vulnerabilities": {"errors": {"grype": "boom"}}, "ci_image": {"errors": {}}},
           "vulnerabilities": [{"key": "npm:x@1", "id": "GHSA-1", "name": "x", "version": "1", "severity": "high",
                                "label": "introduced", "runtime": False, "direct": False, "fixed": []}]}
    s = score.score_report(rep)
    assert s["verdict"] == "review"          # high severity introduced, though dev-only + no attack seen
    assert s["complete"] is False and s["incomplete_reasons"]


# ---------- T6: CLI exit code reflects the decision ----------

@pytest.mark.parametrize("verdict,complete,code", [("allow", True, 0), ("review", True, 1), ("block", True, 2),
                                                   ("allow", False, 3), ("block", False, 2)])
def test_t6_check_exit_code(monkeypatch, capsys, tmp_path, verdict, complete, code):
    import guardian.universal
    from guardian import cli
    monkeypatch.setattr(guardian.universal, "check_any", lambda *a, **k: {
        "headline": {"verdict": verdict, "complete": complete}, "path": str(tmp_path / "r.json")})
    assert cli.main(["check", str(tmp_path), "--base", "a", "--head", "b"]) == code
    json.loads(capsys.readouterr().out.split("report:")[0])


# ---------- T2: CI findings are matched per workflow file ----------

def test_t2_same_unsafe_action_in_a_new_workflow_is_introduced():
    from guardian.inventory.ci_risk import label_ci
    f = {"type": "action_not_pinned", "component": "actions/checkout@v4", "excerpt": "uses: actions/checkout@v4"}
    base = [{**f, "file": ".github/workflows/a.yml", "line": 10}]
    head = [{**f, "file": ".github/workflows/a.yml", "line": 12},   # same workflow, line moved: still pre-existing
            {**f, "file": ".github/workflows/b.yml", "line": 5}]    # new workflow: introduced by this change
    got = {(x["file"], x["label"]) for x in label_ci(base, head)}
    assert got == {(".github/workflows/a.yml", "pre_existing"), (".github/workflows/b.yml", "introduced")}


# ---------- T3: vulnerability <-> component join respects the ecosystem ----------

def test_t3_vulnerability_attaches_to_the_component_of_its_own_ecosystem(monkeypatch, tmp_path):
    from guardian import universal as u
    inv = [{"key": "pypi:debug@1.0#requirements.txt", "name": "debug", "version": "1.0", "ecosystem": "pypi",
            "runtime": True, "direct": True, "source_file": "requirements.txt"},
           {"key": "npm:debug@1.0#package-lock.json", "name": "debug", "version": "1.0", "ecosystem": "npm",
            "runtime": False, "direct": False, "source_file": "package-lock.json"}]
    rec = {"name": "debug", "version": "1.0", "ids": ["GHSA-npm1"], "summary": "", "severity": "high", "fixed": [],
           "malicious": False, "url": None, "source": "osv", "ecosystem": "npm"}
    monkeypatch.setattr(u, "osv_api", lambda i: ([dict(rec)], None))
    monkeypatch.setattr(u, "grype_all", lambda s: ([], None))
    v = u.vulnerabilities(inv, tmp_path / "sbom.json", tmp_path)["vulnerabilities"][0]
    assert v["ecosystem"] == "npm" and v["source_file"] == "package-lock.json" and v["runtime"] is False


def test_t3_merge_never_joins_records_from_different_ecosystems():
    from guardian.vuln.scan import merge
    a = {"name": "x", "version": "1", "ids": ["GHSA-1"], "summary": "", "severity": "high", "fixed": [], "malicious": False,
         "url": None, "source": "osv", "ecosystem": "npm"}
    b = {**a, "source": "grype", "ecosystem": "pypi"}
    out = merge([a], [b])
    assert len(out) == 2 and len({m["key"] for m in out}) == 2


# ---------- T11: frontend libraries listed as devDependencies are shipped in the browser bundle ----------

def test_t11_frontend_imports_only_counts_shipped_frontend_code():
    from guardian.inventory.exposure import frontend_imports
    files = [("src/main.js", "import { createApp } from 'vue'\nimport x from './local'\n"),
             ("src/components/App.vue", "<script>\nimport utc from 'dayjs/plugin/utc'\nimport { a } from '@vuepic/vue-datepicker/dist'\n</script>"),
             ("server/index.js", "const express = require('express')\n"),
             ("src/util.ts", "import fs from 'node:fs'\n")]
    got = frontend_imports(files)
    assert set(got) == {"vue", "dayjs", "@vuepic/vue-datepicker"}
    assert got["vue"] == ["src/main.js:1"]


def test_t11_mark_shipped_follows_prod_edges_and_labels_it_inferred():
    from guardian.inventory.exposure import mark_shipped
    inv = [{"key": "node_modules/vue", "name": "vue", "ecosystem": "npm", "dev": True, "runtime": False},
           {"key": "node_modules/@vue/runtime-dom", "name": "@vue/runtime-dom", "ecosystem": "npm", "dev": True, "runtime": False},
           {"key": "node_modules/eslint", "name": "eslint", "ecosystem": "npm", "dev": True, "runtime": False}]
    edges = [{"parent": "node_modules/vue", "child": "node_modules/@vue/runtime-dom", "kind": "prod"},
             {"parent": "", "child": "node_modules/eslint", "kind": "dev"}]
    marked = mark_shipped(inv, edges, {"vue": ["src/main.js:1"]})
    assert marked == ["@vue/runtime-dom", "vue"]
    by = {p["name"]: p for p in inv}
    assert by["vue"]["runtime"] and by["vue"]["exposure"] == "shipped_frontend_inferred"
    assert by["vue"]["exposure_evidence"] == ["src/main.js:1"]
    assert by["@vue/runtime-dom"]["runtime"] and by["@vue/runtime-dom"]["exposure_evidence"] == ["via vue"]
    assert by["eslint"]["runtime"] is False and "exposure" not in by["eslint"]


# ---------- T7: verdict citations must be real, intact and relevant ----------

@pytest.fixture
def cited(tmp_path):
    from guardian.agents.board import Board
    from guardian.agents.protocol import BoardFinding, CaseState
    from guardian.store.evidence import EvidenceStore
    store = EvidenceStore(tmp_path)
    board = Board(run_id="RUN-1", base="b", head="h")
    ev = store.add('{"resolved":"http://127.0.0.1:4873/axois"}', kind="tool_output", source="lockfile_diff")
    other = store.add("unrelated tool output", kind="tool_output", source="osv_lookup")
    board.add_finding(BoardFinding(id="F-1", type="lockfile_tamper", component="axois@1.0.0", summary="off-registry",
                                   evidence_ids=[ev.id], hard_signal=True, floor="critical", risk="critical", label="introduced"))
    board.cases["C-1"] = CaseState(id="C-1", title="attack", finding_ids=["F-1"], risk="critical", verdict="malicious",
                                   evidence_ids=[ev.id], resolved=True)
    return board, store, ev, other


def test_t7_valid_citations_pass(cited):
    from guardian.agents.constitution import check_citations
    board, store, ev, _ = cited
    check_citations(board, store, ["C-1"], [ev.id])


@pytest.mark.parametrize("bad", ["unknown_case", "unknown_evidence", "unrelated_evidence", "tampered_evidence", "no_citation"])
def test_t7_bad_citations_are_rejected(cited, bad):
    from pathlib import Path

    from guardian.agents.constitution import ConstitutionError, check_citations
    board, store, ev, other = cited
    cases, evs = ["C-1"], [ev.id]
    if bad == "unknown_case":
        cases = ["C-404"]
    elif bad == "unknown_evidence":
        evs = ["E-invented"]
    elif bad == "unrelated_evidence":
        evs = [other.id]
    elif bad == "tampered_evidence":
        Path(store.get(ev.id).blob_path).write_text("swapped")
    elif bad == "no_citation":
        evs = []
    with pytest.raises(ConstitutionError):
        check_citations(board, store, cases, evs)


# ---------- T10: same version, different download host = introduced tamper (npm pipeline detector) ----------

def _lock_with(resolved: str, integrity: str = "sha512-AAA") -> str:
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"left-pad": "1.3.0"}},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": resolved, "integrity": integrity}}})


def _two_commit_repo(tmp_path, base_lock: str, head_lock: str):
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "package.json").write_text('{"name":"app","dependencies":{"left-pad":"1.3.0"}}')
    (repo / "package-lock.json").write_text(base_lock)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "base"], check=True)
    (repo / "package-lock.json").write_text(head_lock)
    subprocess.run(git + ["commit", "-qam", "head", "--allow-empty"], check=True)
    return repo


def _d3(tmp_path, base_url, head_url):
    from pathlib import Path

    from guardian.agents.realworld import RealFacts
    from guardian.store.evidence import EvidenceStore
    repo = _two_commit_repo(tmp_path, _lock_with(base_url), _lock_with(head_url))
    policy = Path(__file__).resolve().parents[1] / "guardian.yaml"
    facts = RealFacts(repo, "HEAD~1", "HEAD", EvidenceStore(tmp_path / "ev"), policy, tmp_path / "cache")
    return facts.detector("D3")


def test_t10_same_version_moved_to_unapproved_host_is_introduced(tmp_path):
    sig = _d3(tmp_path, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
              "http://127.0.0.1:4873/left-pad/-/left-pad-1.3.0.tgz")
    assert sig and all(s.get("label", "introduced") == "introduced" for s in sig)


def test_t10_same_version_host_change_between_allowed_hosts_is_still_flagged(tmp_path):
    sig = _d3(tmp_path, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
              "http://localhost:4873/left-pad/-/left-pad-1.3.0.tgz")
    assert any("download host changed" in s["summary"] and s.get("label", "introduced") == "introduced" for s in sig)


def test_t10_unchanged_lockfile_entry_on_unapproved_host_stays_pre_existing(tmp_path):
    url = "http://127.0.0.1:4873/left-pad/-/left-pad-1.3.0.tgz"
    sig = _d3(tmp_path, url, url)
    assert sig and all(s["label"] == "pre_existing" for s in sig)
