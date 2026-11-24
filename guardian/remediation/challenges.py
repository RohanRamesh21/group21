"""Deterministic Skeptic checks for a proposed fix. They run for every plan, with or without an LLM.

Each check answers one adversarial question about the plan and returns {name, status: pass|warn|fail, detail}.
`fail` = the plan should not be approved without an explicit written reason; `warn` = the reviewer must look.
The LLM Skeptic (agent.py) can add concerns on top, but it can never remove a failed check here.
"""
from __future__ import annotations

from guardian.scoring.contextual import semver


def _c(name: str, status: str, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}


def run(finding: dict, candidate: dict, safety: dict | None, patch_supported: bool, affected: dict | None, flags: list[dict] | None = None) -> list[dict]:
    out: list[dict] = []
    for fl in flags or []:
        out.append(_c("prompt_injection", "fail", f"instruction-like text aimed at AI reviewers was found in {fl['evidence_id']} ({', '.join(fl['patterns'])}): it was ignored, a human must look"))
    t = candidate["type"]
    if t in ("upgrade_to_fixed", "override_transitive"):
        adv = (finding.get("evidence") or {}).get("advisory")
        entries = [e for e in ((affected or {}).get(adv) or []) if e.get("name") == (finding.get("package") or {}).get("name")]
        verdicts = [semver.affected(candidate["target"], e) for e in entries]
        if verdicts and all(v is not None for v in verdicts):
            out.append(_c("target_clears_advisory", "fail" if any(verdicts) else "pass",
                          f"{candidate['target']} is {'STILL AFFECTED by' if any(verdicts) else 'outside the affected ranges of'} {adv} (OSV affected ranges)"))
        else:
            out.append(_c("target_clears_advisory", "warn", f"OSV affected ranges for {adv} are missing or undecidable: the fixed-version list was used instead"))
        j = candidate["compat"].get("semver")
        out.append(_c("version_jump", "warn" if j == "major" else "pass", f"{j or 'unknown'} version jump"))
    if t == "override_transitive":
        parents = candidate["compat"].get("via_direct_parents") or []
        out.append(_c("override_vs_parents", "warn", "the override forces a version the parent dependencies did not ask for"
                      + (f" (parents: {', '.join(parents)})" if parents else " (parents unknown)")))
    if t == "remove_package":
        r = finding.get("reachability") or {}
        if r.get("tier") == "imported":
            out.append(_c("removal_breaks_runtime_import", "warn", f"first-party code imports this package ({', '.join((r.get('evidence') or [])[:3])}): removing it breaks those imports"))
        else:
            out.append(_c("removal_breaks_runtime_import", "pass" if r else "warn",
                          f"reachability tier is '{r.get('tier') or 'unknown'}' (an estimate from a static import scan)"))
    if safety and safety.get("applicable"):
        if safety.get("install_script_added"):
            out.append(_c("target_adds_install_script", "fail", "the target version adds install-time scripts: " + ", ".join(safety["install_script_added"])))
        else:
            out.append(_c("target_adds_install_script", "pass" if safety.get("install_script_added") is not None else "warn",
                          "no new install-time script in the target version" if safety.get("install_script_added") is not None else "could not compare install scripts"))
        ni = safety.get("new_issues")
        out.append(_c("new_advisories_at_target", "warn" if ni else ("pass" if ni is not None else "warn"),
                      f"{len(ni)} advisory(ies) still affect the target: {', '.join(ni[:4])}" if ni else
                      ("no known advisory affects the target version (OSV.dev)" if ni is not None else "OSV.dev lookup failed: unknown")))
        out.append(_c("upgrade_safety", {"high": "warn", "medium": "warn", "low": "pass"}[safety["risk"]],
                      f"predicted breaking-change risk: {safety['risk']} ({'; '.join(safety['reasons'][:2])})"))
    if finding.get("floor"):
        out.append(_c("hard_signal_floor_kept", "pass", f"hard signal '{finding['floor']}': the fix cannot lower its floor; only the rescan can clear it"))
    if not patch_supported:
        out.append(_c("patch_applicable", "warn", "recommend-only: this plan cannot be applied automatically in v1"))
    out.append(_c("lockfile_regeneration", "warn", "the lockfile change is not previewed; it is produced and rescanned in the sandbox"))
    return out


def outcome(checks: list[dict]) -> str:
    if any(c["status"] == "fail" for c in checks):
        return "block"
    return "concerns" if any(c["status"] == "warn" for c in checks if c["name"] != "lockfile_regeneration") else "accept"
