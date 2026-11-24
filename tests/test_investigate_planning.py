"""The Lead plans the investigation by risk, not by name:
- cases are ordered by their highest level (a critical `express` must not lose its slot to `.github/...` files);
- high/critical cases get the Investigators; medium/low/info cases are covered by the rules (labelled, not "partial");
- high/critical cases beyond the deep-investigation slots go to batched triage calls;
- a failed triage batch is split and retried; a failed deep case is retried once;
- only high/critical cases that still could not be examined make the run "partial"."""
import json

import pytest

from guardian.ai import workflow as wf

LEVELS = ["critical", "high", "medium", "low", "info"]


def _case(i, comp, level):
    return {"case_id": f"K{i:03d}", "component": comp, "finding_ids": [f"F{i}"], "max_level": level,
            "evidence": [{"id": f"E{i}", "source": "lockfile_entry", "path": "package-lock.json", "content": f"{comp} entry", "sha256": "0" * 64}]}


def _packet(cases):
    return {"sha256": "ab" * 32, "repo": "/r", "base_sha": "b" * 40, "head_sha": "h" * 40, "cases": cases, "rules_verdict": "block"}


def _answer(case_id, n):
    return {"case_id": case_id, "assessment": "risky_config", "summary": "risky", "confidence": "medium",
            "claims": [{"text": "the entry changed", "evidence_ids": [f"E{n}"]}], "innocent_explanation": "", "open_questions": []}


class Fake:
    def __init__(self, fail=lambda kind, ids: False):
        self.calls, self.fail = [], fail

    def __call__(self, prompt, system=None, **k):
        if system == wf.VERIFIER_SYSTEM:
            self.calls.append(("verifier", []))
            return {"challenges": [], "missed_risks": []}, {"model": "m"}
        if system == wf.TRIAGE_SYSTEM:
            cases = json.loads(prompt.split("CASES:\n", 1)[1])
            ids = [c["case_id"] for c in cases]
            self.calls.append(("triage", ids))
            if self.fail("triage", ids):
                raise RuntimeError("provider unavailable")
            return {"cases": [_answer(c, int(c[1:])) for c in ids]}, {"model": "m"}
        view = json.loads(prompt.split("CASE:\n", 1)[1])
        self.calls.append(("deep", [view["case_id"]]))
        if self.fail("deep", [view["case_id"]]):
            raise RuntimeError("timeout")
        return _answer(view["case_id"], int(view["case_id"][1:])), {"model": "m"}


@pytest.fixture
def out(tmp_path, monkeypatch):
    def use(cases):
        monkeypatch.setattr(wf, "build_packets", lambda o, **k: _packet(cases))
    return tmp_path, use


def test_critical_cases_are_investigated_first_and_low_ones_are_rule_covered(out):
    tmp, use = out
    cases = [_case(i, f".github/workflows/w{i}.yml", "low") for i in range(1, 8)] + [_case(50, "express@4.22.3", "critical")]
    use(cases)
    fake = Fake()
    r = wf.investigate(tmp, chat=fake, max_cases=2)
    deep = [i for k, ids in fake.calls if k == "deep" for i in ids]
    assert deep == ["K050"]  # the only critical case, although alphabetically last
    by = {c["case_id"]: c for c in r["cases"]}
    assert by["K050"]["status"] == "done"
    assert all(by[f"K{i:03d}"]["status"] == "rules_only" for i in range(1, 8))
    assert r["status"] == "done"
    assert r["plan"]["rules_only"] == 7 and r["plan"]["deep"] == 1


def test_extra_high_cases_go_to_batched_triage(out):
    tmp, use = out
    use([_case(i, f"pkg{i}@1.0.0", "high") for i in range(1, 15)])
    fake = Fake()
    r = wf.investigate(tmp, chat=fake, max_cases=4)
    deep = [ids for k, ids in fake.calls if k == "deep"]
    triage = [ids for k, ids in fake.calls if k == "triage"]
    assert len(deep) == 4 and sum(len(t) for t in triage) == 10 and max(len(t) for t in triage) <= wf.TRIAGE_BATCH
    assert all(c["status"] == "done" for c in r["cases"]) and r["status"] == "done"
    assert any(c.get("depth") == "triage" for c in r["cases"])


def test_failed_triage_batch_is_split_and_retried(out):
    tmp, use = out
    use([_case(i, f"pkg{i}@1.0.0", "high") for i in range(1, 9)])
    fake = Fake(fail=lambda kind, ids: kind == "triage" and len(ids) > 2)
    r = wf.investigate(tmp, chat=fake, max_cases=2)
    assert all(c["status"] == "done" for c in r["cases"]) and r["status"] == "done"
    assert r["plan"]["retries"] > 0


def test_a_failed_deep_case_is_retried_once(out):
    tmp, use = out
    use([_case(1, "express@4.22.3", "critical")])
    seen = {"n": 0}

    def flaky(kind, ids):
        seen["n"] += 1
        return kind == "deep" and seen["n"] == 1
    r = wf.investigate(tmp, chat=Fake(fail=flaky), max_cases=2)
    assert r["cases"][0]["status"] == "done" and r["status"] == "done"


def test_high_cases_that_still_fail_make_the_run_partial(out):
    tmp, use = out
    use([_case(1, "a@1.0.0", "critical"), _case(2, "b@1.0.0", "high"), _case(3, "c@1.0.0", "high")])
    fake = Fake(fail=lambda kind, ids: kind == "triage")
    r = wf.investigate(tmp, chat=fake, max_cases=1)
    by = {c["case_id"]: c["status"] for c in r["cases"]}
    assert by["K001"] == "done" and by["K002"] == by["K003"] == "failed"
    assert r["status"] == "partial"
