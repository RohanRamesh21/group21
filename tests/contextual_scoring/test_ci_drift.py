import subprocess

from guardian.detectors.ci_drift import action_sha_to_tag, history_rewrite

SHA = "a" * 40


def _a(uses, pinned, wf=".github/workflows/ci.yml"):
    return {"workflow": wf, "uses": uses, "pinned_sha": pinned, "line": 7}


def test_sha_to_tag_detected_with_hard_signal():
    out = action_sha_to_tag([_a(f"actions/checkout@{SHA}", True)], [_a("actions/checkout@v4", False)])
    assert len(out) == 1 and out[0]["type"] == "action_sha_to_tag" and out[0]["hard_signal"] and out[0]["line"] == 7


def test_control_cases_raise_nothing():
    pinned = [_a(f"actions/checkout@{SHA}", True)]
    assert action_sha_to_tag(pinned, pinned) == []                                              # unchanged
    assert action_sha_to_tag([_a("actions/checkout@v3", False)], [_a("actions/checkout@v4", False)]) == []  # was never pinned
    assert action_sha_to_tag(pinned, [_a(f"actions/checkout@{'b' * 40}", True)]) == []           # SHA to another SHA
    assert action_sha_to_tag(pinned, [_a("actions/checkout@v4", False, wf="other.yml")]) == []   # different workflow file
    assert action_sha_to_tag(pinned, [_a("./local-action", False)]) == []


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *a], check=True, capture_output=True)


def test_history_rewrite(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "f").write_text("1")
    _git(tmp_path, "add", "f")
    _git(tmp_path, "commit", "-qm", "one")
    _git(tmp_path, "branch", "base")
    (tmp_path / "f").write_text("2")
    _git(tmp_path, "commit", "-qam", "two")
    _git(tmp_path, "branch", "ff")
    assert history_rewrite(tmp_path, "base", "ff") == []            # head is a descendant: normal
    assert history_rewrite(tmp_path, "ff", "ff") == []              # same commit
    _git(tmp_path, "checkout", "-q", "--orphan", "rewritten")
    (tmp_path / "f").write_text("evil")
    _git(tmp_path, "add", "f")
    _git(tmp_path, "commit", "-qm", "rewritten")
    out = history_rewrite(tmp_path, "ff", "rewritten")
    assert len(out) == 1 and out[0]["type"] == "history_rewrite" and out[0]["hard_signal"]
