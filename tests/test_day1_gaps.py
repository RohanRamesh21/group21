"""Day 1 gaps found by running every attack scenario (docs/TESTING.md): offline regressions."""
from guardian import universal as u
from guardian.inventory.ci_risk import image_findings
from guardian.scoring import intel
from guardian.scoring.score import score_report

TRUSTED = {"trusted": ["docker.io/library/*", "docker.io/louislam/*"]}


def _img(ref, registry, repository, tag, digest=None):
    return {"ref": ref, "registry": registry, "repository": repository, "tag": tag, "digest": digest, "dockerfile": "docker/dockerfile", "line": 1}


def test_lowercase_dockerfile_and_containerfile_are_discovered(tmp_path):
    """Scenario s6: uptime-kuma's main image is docker/dockerfile (lowercase); it was not scanned at all."""
    for name in ("docker/dockerfile", "Containerfile", "build/app.containerfile", "Dockerfile.dev"):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("FROM node:22\n")
    found = {m["path"] for m in u.find_manifests(tmp_path) if m["role"] == "container"}
    assert found == {"docker/dockerfile", "Containerfile", "build/app.containerfile", "Dockerfile.dev"}


def test_untrusted_and_floating_images():
    """Scenario s6: ARG BASE_IMAGE=ghcr.io/unknown-org/uptime-kuma-base:latest."""
    got = image_findings([
        _img("ghcr.io/unknown-org/uptime-kuma-base:latest", "ghcr.io", "unknown-org/uptime-kuma-base", "latest"),
        _img("evil.example.com/base:1", "evil.example.com", "base", "1"),
        _img("node:22", "docker.io", "library/node", "22"),
        _img("louislam/uptime-kuma@sha256:" + "a" * 64, "docker.io", "louislam/uptime-kuma", None, "sha256:" + "a" * 64),
    ], TRUSTED)
    assert sorted((f["component"].split(":")[0].split("@")[0], f["type"], f["severity"]) for f in got) == [
        ("evil.example.com/base", "image_not_pinned", "medium"),
        ("evil.example.com/base", "untrusted_image", "high"),        # unknown registry
        ("ghcr.io/unknown-org/uptime-kuma-base", "image_not_pinned", "high"),  # :latest
        ("ghcr.io/unknown-org/uptime-kuma-base", "untrusted_image", "medium"),  # unknown publisher, known registry
        ("node", "image_not_pinned", "medium"),
    ]


def test_action_moved_from_sha_to_tag_is_a_hard_signal():
    """Scenario s7: actions/checkout@<sha> # v6.0.1 -> actions/checkout@v4 # v6.0.1."""
    sha = "8e8c483db84b4bee98b60c0593521ed34d9990e8"
    base = {"inventory": [], "manifests": [], "actions": [
        {"workflow": ".github/workflows/t.yml", "owner_repo": "actions/checkout", "uses": f"actions/checkout@{sha}", "ref": sha,
         "pinned_sha": True, "version_comment": "v6.0.1", "line": 5}]}
    head = {"inventory": [], "manifests": [], "actions": [
        {"workflow": ".github/workflows/t.yml", "owner_repo": "actions/checkout", "uses": "actions/checkout@v4", "ref": "v4",
         "pinned_sha": False, "version_comment": "v6.0.1", "line": 5}]}
    sig = [s for s in u.change_signals(base, head, [], {}) if s["type"] == "action_pin_removed"]
    assert len(sig) == 1 and sig[0]["hard_signal"] and sig[0]["severity"] == "high" and "v6.0.1" in sig[0]["summary"]


def test_introduced_high_severity_needs_review_even_when_ssvc_says_track(monkeypatch):
    """Scenarios s1/s2/s8: a new high-severity CVE (no EPSS/KEV) or CI finding was 'allow'."""
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": ["CVE-2021-3749"], "cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                                               "cvss_v4": None, "severity_label": "HIGH"} for i in ids})
    monkeypatch.setattr(intel, "epss", lambda cves: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    report = {"inventory": [{"key": "node_modules/axios", "name": "axios", "version": "0.21.1", "direct": True, "runtime": True}],
              "vulnerabilities": [{"key": "axios@0.21.1#GHSA-x", "id": "GHSA-x", "name": "axios", "version": "0.21.1", "severity": "high",
                                   "label": "introduced", "fixed": ["0.21.2"], "direct": True, "runtime": True}],
              "suspicious_changes": [], "ci_image": []}
    s = score_report(report)
    f = s["findings"][0]
    assert f["decision"] in ("Track", "Track*") and s["verdict"] == "review"
    assert f["evidence"]["cvss_score"] == 7.5
    assert "high severity, new in this PR" in s["reasons"][0]
