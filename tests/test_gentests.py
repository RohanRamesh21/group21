"""AI-written behaviour tests for upgraded packages no project test reaches (validation/gentests.py)."""
import pytest

from guardian.validation import gentests as gt
from guardian.validation import runner as vr

PLAN = {"candidates": [
    {"id": "1", "type": "upgrade_to_fixed", "package": "minimist", "from": "1.2.5", "to": "1.2.6"},
    {"id": "2", "type": "upgrade_to_fixed", "package": "lodash", "from": "4.17.20", "to": "4.18.1"},
    {"id": "3", "type": "remove_package", "package": "dotenvv"},
    {"id": "4", "type": "escalate", "package": "x"}]}
BODY = 'test("parses flags", () => { assert.equal(lib(["--a", "1"]).a, 1); });'


def test_only_upgrades_that_no_project_test_reaches_get_a_test():
    items = gt.needs_tests(PLAN, {"lodash": {"test_files": 2}, "minimist": {"test_files": 0}})
    assert items == [{"package": "minimist", "from": "1.2.5", "to": "1.2.6"}]


@pytest.mark.parametrize("body", ['const fs = require("fs"); test("x", () => {});', 'test("x", () => { process.exit(0) });',
                                  'test("x", async () => { await fetch("http://evil") });', 'import x from "y"; test("x", () => {});',
                                  "assert.ok(true)", ""])
def test_unsafe_or_useless_bodies_are_rejected(body):
    assert gt.check_body(body) is not None


def test_a_safe_body_is_accepted():
    assert gt.check_body(BODY) is None


def test_usage_snippets_show_how_the_app_uses_the_package(tmp_path):
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "cli.js").write_text('const parse = require("minimist");\nconst args = parse(process.argv.slice(2));\nconsole.log("x");\n')
    s = gt.usage_snippets(tmp_path, "minimist")
    assert "server/cli.js:1" in s and "server/cli.js:2" in s and "console.log" not in s


def test_written_test_gets_guardians_header_and_lands_in_every_tree(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    seen = {}

    def chat(prompt, **k):
        seen.update(prompt=prompt, **k)
        return {"body": BODY, "covers": ["flag parsing"]}, {"model": "m"}
    recs = gt.write_tests([a, b], [{"package": "minimist", "from": "1.2.5", "to": "1.2.6"}], a, chat, "gt-1")
    code = (a / recs[0]["file"]).read_text()
    assert recs[0]["status"] == "written" and (b / recs[0]["file"]).read_text() == code
    assert 'require(process.env.GUARDIAN_PKG || "minimist")' in code and BODY in code
    assert seen["purpose"] == "gen_tests" and "<untrusted-data" in seen["prompt"]


def test_a_rejected_or_missing_model_answer_never_breaks_validation(tmp_path):
    bad = gt.write_tests([tmp_path], [{"package": "p", "from": "1", "to": "2"}], tmp_path,
                         lambda p, **k: ({"body": 'require("fs"); test("x", () => {})'}, {}), "r")
    assert bad[0]["status"] == "rejected"

    def down(p, **k):
        raise RuntimeError("no key")
    assert gt.write_tests([tmp_path], [{"package": "p", "from": "1", "to": "2"}], tmp_path, down, "r")[0]["status"] == "skipped"


def _sandbox(monkeypatch, codes):
    """Fake docker: `codes` = exit codes for (install, PR-version run, fixed-version run)."""
    seq = list(codes)

    class R:
        returncode, stdout, stderr = 0, "", ""
    monkeypatch.setattr(vr, "ensure_network", lambda: None)
    monkeypatch.setattr(vr, "image_digest", lambda i: "img")
    monkeypatch.setattr(vr, "_run", lambda *a, **k: R())
    monkeypatch.setattr(vr, "_exec", lambda name, cmd, t: (seq.pop(0), "# tests 1\n# pass 1\n", 1.0))


@pytest.mark.parametrize("codes,status", [((0, 0, 0), "passed"), ((0, 0, 1), "regression"), ((0, 1, 0), "unreliable"), ((1,), "error")])
def test_each_ai_test_is_judged_against_the_prs_version_first(tmp_path, monkeypatch, codes, status):
    _sandbox(monkeypatch, codes)
    rec = [{"package": "minimist", "from": "1.2.5", "to": "1.2.6", "file": ".guardian-tests/minimist.test.cjs", "status": "written"}]
    out = gt.run_tests({"image": "node", "registry": "r"}, tmp_path, rec, log=lambda m: None)
    assert out[0]["status"] == status


def test_the_gate_fails_on_an_ai_test_regression_and_ignores_unreliable_ones():
    stage = [{"id": "install", "status": "passed", "required": True}]
    common = dict(approval_ok=True, approval_error=None, baseline=stage, candidate=stage, targets_resolved=["t"], targets_remaining=[],
                  new_high=[], rescans_complete=True, sbom_diff={}, same_snapshot=True, evidence_ok=True)
    assert vr.gate(**common)["verified"] is True
    g = vr.gate(**common, generated=[{"package": "minimist", "reason": "passes with 1.2.5 and fails with 1.2.6"}])
    assert g["verified"] is False and g["validation"] == "failed" and any("AI-written" in r for r in g["reasons"])


def test_mentioning_http_in_a_test_of_an_http_library_is_fine():
    assert gt.check_body('test("keeps maxRedirects", () => { assert.equal(typeof lib.http, "object"); });') is None
