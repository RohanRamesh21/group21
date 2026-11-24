"""Validate an approved fix plan: approval check → baseline + candidate runs → source and artifact rescans → gate.

Order matters: the approval contract is checked first, and if it doesn't match exactly, nothing is executed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from guardian import approval as ap
from guardian.validation import runner as vr

ROOT = Path(__file__).resolve().parents[2]
SEVERE = ("high", "critical")
# Introduced findings, grouped the way a reviewer asks: known vulnerabilities, malware / suspicious packages,
# configuration and CI changes. A vulnerability record whose ID is MAL-… is a malware report, not an ordinary CVE.
MALWARE_KINDS = {"typosquat", "untrusted_source", "lockfile_tamper", "new_install_script", "install_script", "malware",
                 "non_registry_source"}


def _group(f: dict) -> str:
    if f.get("kind") == "vulnerability":
        return "malware_suspicious" if "MAL-" in f"{f.get('id', '')} {f.get('title', '')}" else "vulnerabilities"
    det = f.get("type") or f.get("kind") or ""  # supply-chain findings: kind "supply_chain", detector name in "type"
    if det in MALWARE_KINDS:
        return "malware_suspicious"
    if det in ("new_dependency", "suspicious_update"):  # a package added or its version changed (low, informational)
        return "other"
    return "config_ci"


def progress_update(progress: dict, msg: str) -> dict:
    """Fold one progress message into a per-lane view (both sandboxes and the rescan run at the same time, so the
    latest single message is not enough for the dashboard)."""
    p = dict(progress)
    if msg.startswith("[") and "] " in msg:
        lane, rest = msg[1:].split("] ", 1)
        p[lane] = rest
    elif msg.startswith("validation: source rescan"):
        p["rescan"] = "running"
    elif msg.startswith("validation: rescan finished"):
        p["rescan"] = "done"
    elif msg.startswith("validation: artifact SBOMs"):
        p["sbom"] = "running"
    return p


def verdict_summary(scores: dict | None) -> dict:
    """Verdict + what this change introduces, by group; pre-existing findings counted separately (never hidden)."""
    findings = (scores or {}).get("findings") or []
    intro = [f for f in findings if f.get("label") == "introduced"]
    groups = {"vulnerabilities": 0, "malware_suspicious": 0, "config_ci": 0, "other": 0}
    for f in intro:
        groups[_group(f)] += 1
    return {"verdict": (scores or {}).get("verdict"), "introduced": {**groups, "total": len(intro)},
            "high_or_critical": sum(1 for f in intro if f.get("level") in SEVERE or f.get("severity") in SEVERE),
            "pre_existing": sum(1 for f in findings if f.get("label") == "pre_existing")}


def policy_sha256() -> str:
    return ap.file_sha256(ROOT / "guardian.yaml")


def _grype_db() -> str:
    r = subprocess.run(["grype", "db", "status", "-o", "json"], capture_output=True, text=True)
    try:
        d = json.loads(r.stdout or "{}")
        return str(d.get("built") or d.get("schemaVersion") or r.stdout[:80])
    except ValueError:
        return r.stdout[:80]


def _artifact_components(tree: Path, out: Path) -> tuple[set[str], str | None]:
    """What the built candidate actually contains (installed node_modules + build output), via Syft on the tree."""
    out.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["syft", f"dir:{tree}", "-o", f"cyclonedx-json={out / 'artifact.cdx.json'}", "-q"],
                       capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        return set(), f"syft failed: {r.stderr[-200:]}"
    doc = json.loads((out / "artifact.cdx.json").read_text())
    return {f"{c.get('name')}@{c.get('version')}" for c in doc.get("components", []) if c.get("type") == "library"}, None


def _source_rescan(repo: Path, base_sha: str | None, head_sha: str, patch: Path, out: Path, app: str) -> dict:
    """Two-commit repo scanned by the same engine: BASE, then the candidate (PR head + approved patch).
    This asks the original question again: what does the PR still introduce once fixed? (Comparing PR head → candidate
    instead would flag the fix's own reverts, e.g. restoring .npmrc, as new sensitive-file changes.)"""
    from guardian.universal import check_any
    work = out / "rescan-repo"
    git = ["git", "-C", str(work), "-c", "user.name=guardian", "-c", "user.email=guardian@localhost"]
    vr.prepare_tree(repo, base_sha or head_sha, work)
    subprocess.run(["git", "init", "-q", str(work)], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "base", "--no-verify"], check=True)
    cand = out / "rescan-candidate"
    vr.prepare_tree(repo, head_sha, cand, patch)  # PR head + approved patch (applied and verified)
    for item in work.iterdir():  # replace the base files with the candidate files, keep .git
        if item.name != ".git":
            shutil.rmtree(item) if item.is_dir() and not item.is_symlink() else item.unlink()
    for item in cand.iterdir():
        shutil.move(str(item), str(work / item.name))
    shutil.rmtree(cand, ignore_errors=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "candidate", "--no-verify", "--allow-empty"], check=True)
    rep = check_any(work, "HEAD~1", "HEAD", out / "rescan", app)
    latest = json.loads((out / "rescan" / "latest.json").read_text())
    scores = json.loads(Path(latest["scores"]).read_text()) if latest.get("scores") else {"findings": []}
    return {"report": rep, "scores": scores, "complete": bool(rep["headline"].get("complete")) and bool(latest.get("scores"))}


def validate(out: Path, profile: str = "uptime-kuma", log=print) -> dict:
    out = Path(out)
    plan = json.loads((out / "fix-plan.json").read_text())
    prof, prof_sha, folder = vr.load_profile(profile)
    pol_sha = policy_sha256()
    result = {"started": time.time(), "profile": {"name": profile, "sha256": prof_sha, "version": prof.get("version")},
              "policy_sha256": pol_sha, "plan_patch_sha256": plan["patch"]["patch_sha256"]}
    rec = ap.latest_approval(out)
    try:
        if rec is None:
            raise ap.ApprovalInvalid("no approval has been given for this plan")
        ap.check(rec, plan, policy_sha256=pol_sha, profile_sha256=prof_sha)
    except ap.ApprovalInvalid as e:
        result["gate"] = vr.gate(approval_ok=False, approval_error=str(e), baseline=[], candidate=[], targets_resolved=[],
                                 targets_remaining=[], new_high=[], rescans_complete=False, sbom_diff={}, same_snapshot=True,
                                 evidence_ok=ap.verify_audit(out)[0])
        result["executed"] = False
        (out / "validation.json").write_text(json.dumps(result, indent=1))
        ap._audit(out, "validation", {"created": time.time(), "verified": False, "reason": str(e), "executed": False})
        return result

    result["approval_id"] = rec["id"]
    result["executed"] = True
    repo, patch = Path(plan["repo"]), Path(plan["patch"]["patch_path"])
    db_before = _grype_db()
    work = out / "validation"
    t0 = time.time()
    timings: dict[str, float] = {}
    base_tree = vr.prepare_tree(repo, plan["base_sha"] or plan["head_sha"], work / "baseline")
    cand_tree = vr.prepare_tree(repo, plan["head_sha"], work / "candidate", patch, plan["patch"]["patch_sha256"])
    timings["prepare"] = round(time.time() - t0, 1)

    def timed(key, fn, *a):
        s = time.time()
        try:
            return fn(*a)
        finally:
            timings[key] = round(time.time() - s, 1)

    def rescan():
        log("validation: source rescan of the candidate (same engine, same advisory snapshot)")
        r = _source_rescan(repo, plan.get("base_sha"), plan["head_sha"], patch, work, repo.name)
        log("validation: rescan finished")
        return r

    # Independent work runs at the same time: two separate locked containers and the source-only rescan
    # (the rescan reads files, runs no project code). Nothing is shared between the sandboxes.
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_base = pool.submit(timed, "baseline", vr.run_profile, base_tree, prof, folder, "baseline", log)
        f_cand = pool.submit(timed, "candidate", vr.run_profile, cand_tree, prof, folder, "candidate", log)
        f_rescan = pool.submit(timed, "rescan", rescan)
        result["baseline"], result["candidate"] = f_base.result(), f_cand.result()
        log("validation: artifact SBOMs (installed dependencies + build output)")
        s = time.time()
        f_b = pool.submit(_artifact_components, base_tree, work / "baseline-artifact")
        f_c = pool.submit(_artifact_components, cand_tree, work / "candidate-artifact")
        (b_art, b_err), (c_art, c_err) = f_b.result(), f_c.result()
        timings["sbom"] = round(time.time() - s, 1)
        rs = f_rescan.result()
    sbom_diff = {"added": sorted(c_art - b_art), "removed": sorted(b_art - c_art), "errors": [x for x in (b_err, c_err) if x]}

    timings["total"] = round(time.time() - t0, 1)
    result["timings"] = timings
    # still introduced by the fixed PR (versus base) = not corrected; pre-existing findings are not targets of this PR
    after_ids = {f["id"] for f in rs["scores"]["findings"] if f["label"] == "introduced"}
    targets = sorted({fid for c in plan["candidates"] if c["type"] != "escalate" for fid in c["finding_ids"]})
    new_high = [f["title"] for f in rs["scores"]["findings"]
                if f["label"] == "introduced" and (f["level"] in SEVERE or f.get("severity") in SEVERE)]
    try:  # contextual scoring's before/after delta: risk index and per-target status (informational; the gate decides)
        from guardian.scoring.contextual import delta
        orig = json.loads(Path(json.loads((out / "latest.json").read_text())["scores"]).read_text())
        req = [s for s in result["candidate"]["stages"] if s.get("required")]
        bt = "pass" if req and all(s["status"] == "passed" for s in req) else "fail"
        known = {f["id"] for f in orig["findings"]}
        result["delta"] = delta.before_after(orig, rs["scores"], [t for t in targets if t in known], bt)
    except Exception as e:
        result["delta"] = {"error": f"before/after delta not computed ({type(e).__name__}: {e})"[:200]}
    try:  # the PR as submitted vs the PR with the approved fix (same engine, same advisory snapshot)
        orig_scores = json.loads(Path(json.loads((out / "latest.json").read_text())["scores"]).read_text())
        result["verdict_change"] = {"before": verdict_summary(orig_scores), "after": verdict_summary(rs["scores"])}
    except Exception as e:
        result["verdict_change"] = {"error": f"before/after verdict not computed ({type(e).__name__}: {e})"[:200]}
    db_after = _grype_db()
    result["rescan"] = {"verdict": rs["scores"].get("verdict"), "complete": rs["complete"],
                        "resolved": sorted(t for t in targets if t not in after_ids),
                        "new": sorted(f["title"] for f in rs["scores"]["findings"] if f["label"] == "introduced"),
                        "advisory_snapshot": {"grype_db_before": db_before, "grype_db_after": db_after}}
    result["gate"] = vr.gate(approval_ok=True, approval_error=None, baseline=result["baseline"]["stages"],
                             candidate=result["candidate"]["stages"],
                             targets_resolved=[t for t in targets if t not in after_ids],
                             targets_remaining=[t for t in targets if t in after_ids], new_high=new_high,
                             rescans_complete=rs["complete"] and not sbom_diff["errors"], sbom_diff=sbom_diff,
                             same_snapshot=db_before == db_after, evidence_ok=ap.verify_audit(out)[0])
    result["finished"] = time.time()
    (out / "validation.json").write_text(json.dumps(result, indent=1))
    ap._audit(out, "validation", {"created": time.time(), "verified": result["gate"]["verified"],
                                  "validation": result["gate"]["validation"], "target": result["gate"]["target"]})
    return result
