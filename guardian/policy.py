"""Stretch goal 5: policy-as-code. Conftest/OPA evaluates policies/*.rego against a policy input built from the report.

The policy runs in the podman sandbox (no network, read-only). `deny` rules block the merge, `warn` rules ask for a
human review. The final verdict is the stricter of the risk-score verdict and the policy decision. If Conftest cannot
run, that is reported (`error`) and the risk-score verdict stands; a policy that did not run never silently "allows".
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = ROOT / "policies"
ORDER = ["allow", "review", "block"]


def build_input(report: dict) -> dict:
    """A compact, stable document for the Rego rules (see policies/guardian.rego)."""
    new = {p.split(" ", 1)[0] if " " in p else p.rsplit("@", 1)[0] for p in
           report.get("package_changes", {}).get("added", []) + report.get("package_changes", {}).get("updated", [])}
    findings = []
    for v in report.get("vulnerabilities", []):
        if v.get("label") == "fixed":
            continue
        findings.append({"kind": "vulnerability", "type": "malicious_package" if v.get("malicious") else "known_vulnerability",
                         "id": v["id"], "component": f"{v['name']}@{v['version']}", "severity": v["severity"], "label": v.get("label"),
                         "malicious": bool(v.get("malicious")), "hard_signal": bool(v.get("malicious")),
                         "runtime": bool(v.get("runtime")), "direct": bool(v.get("direct")), "ecosystem": v.get("ecosystem"),
                         "reachability": (v.get("reachability") or {}).get("status")})
    for s in report.get("suspicious_changes", []):
        if s["type"] == "tool_error":
            continue
        findings.append({"kind": "supply_chain", "type": s["type"], "id": s.get("detector"), "component": s["component"],
                         "severity": s["severity"], "label": s.get("label"), "malicious": False,
                         "hard_signal": bool(s.get("hard_signal")), "runtime": True, "file": s.get("file"), "line": s.get("line")})
    for c in report.get("ci_image", []):
        if c.get("label") == "fixed":
            continue
        findings.append({"kind": "ci_image", "type": c["type"], "id": c.get("detector"), "component": c["component"],
                         "severity": c["severity"], "label": c.get("label"), "malicious": False, "hard_signal": False,
                         "runtime": False, "file": c.get("file"), "line": c.get("line")})
    components = [{"name": p["name"], "version": p.get("version"), "ecosystem": p.get("ecosystem"), "license": p.get("license"),
                   "direct": bool(p.get("direct")), "runtime": bool(p.get("runtime")), "new": p["name"] in new}
                  for p in report.get("inventory", [])]
    return {"mode": "compare" if report["headline"].get("base_commit") != report["headline"].get("head_commit") else "full",
            "findings": findings, "components": components,
            "not_checked": [s["component"] for s in report.get("suspicious_changes", []) if s["type"] == "tool_error"]}


def _data() -> dict:
    cfg = yaml.safe_load((ROOT / "guardian.yaml").read_text()) or {}
    pol = cfg.get("policy") or {}
    return {"guardian": {"license_denylist": pol.get("license_denylist") or [],
                         "trusted_images": (cfg.get("images") or {}).get("trusted") or [],
                         "install_script_allowlist": (cfg.get("install_scripts") or {}).get("allowlist") or []}}


def _rules(msgs: list[dict]) -> list[dict]:
    out = []
    for m in msgs:
        text = m.get("msg", "")
        mm = re.match(r"\[(GP-\d+)\]\s*(.*)", text)
        out.append({"id": mm.group(1) if mm else None, "message": mm.group(2) if mm else text})
    return sorted(out, key=lambda r: (r["id"] or "", r["message"]))


def evaluate(report: dict) -> dict:
    from guardian import sandbox

    result = {"engine": "conftest v0.62.0 (OPA 1.6.0)", "policies": sorted(p.name for p in POLICY_DIR.glob("*.rego")),
              "decision": None, "deny": [], "warn": [], "error": None}
    with tempfile.TemporaryDirectory(prefix="gpol-") as tmp:
        Path(tmp, "input.json").write_text(json.dumps(build_input(report)))
        Path(tmp, "data.json").write_text(json.dumps(_data()))
        res = sandbox.run("conftest", ["test", "{in}/input.json", "--policy", "{policy}", "--data", "{in}/data.json",
                                       "--output", "json", "--no-color"],
                          inputs={"in": Path(tmp), "policy": POLICY_DIR}, timeout=120)
    if res.error or not res.stdout.strip().startswith("["):
        result["error"] = res.error or f"conftest failed ({res.returncode}): {res.stderr.strip()[-300:]}"
        return result
    doc = json.loads(res.stdout)
    result["deny"] = _rules([m for d in doc for m in d.get("failures") or []])
    result["warn"] = _rules([m for d in doc for m in d.get("warnings") or []])
    result["decision"] = "block" if result["deny"] else ("review" if result["warn"] else "allow")
    return result


def combine(score_verdict: str | None, policy: dict) -> str | None:
    """The stricter of the risk-score verdict and the policy decision."""
    vs = [v for v in (score_verdict, policy.get("decision")) if v]
    return max(vs, key=ORDER.index) if vs else None
