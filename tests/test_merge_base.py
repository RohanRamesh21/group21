"""A PR is compared with its merge base (what GitHub's "Files changed" shows), not with the base branch's current tip.

With the tip, every commit that landed on the base branch after the PR branched off looked "introduced by this PR"
(PR #10: 403 findings, a fix that removed a package the app needs, validation that could never pass)."""
import subprocess

from guardian.trigger.service import Service, comparison_base

IDN = {"policy_sha256": "p" * 64, "profile_sha256": "f" * 64, "intel": "2026-11-24"}


def _repo(tmp_path):
    r = tmp_path / "mirror"
    r.mkdir()
    g = lambda *a: subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", *a],  # noqa: E731
                                  check=True, capture_output=True, text=True).stdout.strip()
    g("init", "-q", "-b", "main")
    (r / "f.txt").write_text("1")
    g("add", "-A"); g("commit", "-qm", "fork point")
    fork = g("rev-parse", "HEAD")
    g("checkout", "-qb", "feature")
    (r / "pr.txt").write_text("pr")
    g("add", "-A"); g("commit", "-qm", "the PR")
    head = g("rev-parse", "HEAD")
    g("checkout", "-q", "main")
    for i in range(3):  # the base branch moves on after the PR branched off
        (r / f"later{i}.txt").write_text(str(i))
        g("add", "-A"); g("commit", "-qm", f"later {i}")
    return r, fork, g("rev-parse", "HEAD"), head


def test_comparison_base_is_the_merge_base(tmp_path):
    r, fork, tip, head = _repo(tmp_path)
    assert comparison_base(r, tip, head) == fork


def test_up_to_date_branch_keeps_the_tip(tmp_path):
    r, fork, tip, head = _repo(tmp_path)
    assert comparison_base(r, fork, head) == fork


def test_unknown_history_falls_back_to_the_given_base(tmp_path):
    assert comparison_base(tmp_path / "missing", "a" * 40, "b" * 40) == "a" * 40


def test_service_scans_against_the_merge_base_and_records_both(tmp_path):
    r, fork, tip, head = _repo(tmp_path)
    seen = {}

    def engine(mirror, base, h, out, app):
        seen["base"] = base
        return {"headline": {"verdict": "allow", "complete": True, "verdict_reasons": [], "head_sha": h}}
    svc = Service(tmp_path, fetch=lambda repo, pr, hs, bs: (r, head), engine=engine, github=None, identity_parts=lambda: IDN)
    svc.handle({"repo": "me/app", "pr": 3, "action": "opened", "base_sha": tip, "head_sha": head, "draft": False})
    assert seen["base"] == fork
    started = [e for e in svc.events.since(0) if e["kind"] == "scan_started"][0]
    assert started["data"]["comparison_base"] == fork and started["data"]["base_tip"] == tip
