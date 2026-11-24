"""Pre-merge check (Day 1 checkpoint): what is in the app, what changed, what appears risky.

Scans base and head with the same pinned tools, then labels every vulnerability and CI/image
finding as introduced (by this PR), pre_existing (already on base) or fixed (gone in head).
Deterministic: no LLM involved. The agents investigate on top of this report.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from guardian.cli import scan
from guardian.inventory.ci_risk import label_ci
from guardian.vuln.scan import LEVELS, label


def _load(run_dir: Path, name: str):
    return json.loads((run_dir / name).read_text())


def _pkg_diff(base_inv: list[dict], head_inv: list[dict]) -> dict:
    def idx(inv):
        out: dict[str, set] = {}
        for p in inv:
            out.setdefault(p["name"], set()).add(p["version"])
        return out
    b, h = idx(base_inv), idx(head_inv)
    return {"added": sorted(f"{n}@{v}" for n in h.keys() - b.keys() for v in h[n]),
            "removed": sorted(f"{n}@{v}" for n in b.keys() - h.keys() for v in b[n]),
            "updated": sorted(f"{n} {','.join(sorted(b[n]))} -> {','.join(sorted(h[n]))}" for n in h.keys() & b.keys() if h[n] != b[n])}


def check(repo: Path, base: str, head: str, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    rb, rh = scan(repo, base, out), scan(repo, head, out)
    db, dh = Path(rb["run_dir"]), Path(rh["run_dir"])
    vb, vh = _load(db, "vulns.json"), _load(dh, "vulns.json")
    cb, chh = _load(db, "ci_risk.json"), _load(dh, "ci_risk.json")
    inv_b, inv_h = _load(db, "inventory.json"), _load(dh, "inventory.json")
    vulns = label(vb["vulnerabilities"], vh["vulnerabilities"])
    ci = label_ci(cb["findings"], chh["findings"])
    files = [f for f in subprocess.run(["git", "-C", str(repo), "diff", "--name-only", base, head],
                                       capture_output=True, text=True, check=True).stdout.splitlines() if f]
    pkgs = _pkg_diff(inv_b, inv_h)

    def count(items, lab):
        return {lv: sum(1 for x in items if x["label"] == lab and x["severity"] == lv) for lv in LEVELS[::-1]}

    # Suspicious-change detectors (no LLM): registry redirect, lockfile tampering, look-alike names, new install hooks.
    suspicious, det_error = [], None
    try:
        from guardian.agents.realworld import RealFacts
        from guardian.store.evidence import EvidenceStore
        facts = RealFacts(repo, base, head, EvidenceStore(out / "evidence-check"), Path(__file__).resolve().parents[1] / "guardian.yaml",
                          Path(__file__).resolve().parents[1] / ".cache" / "tarballs")
        for det in ("D1", "D3", "D4", "D7"):
            for sig in facts.detector(det):
                suspicious.append({"detector": det, "type": sig["type"], "component": sig["component"], "summary": sig["summary"],
                                   "severity": sig["floor"], "hard_signal": sig["hard_signal"], "label": sig.get("label") or "introduced"})
        hooks = {}
        for item in facts.diff["packages_added"]:
            n, v = item.rsplit("@", 1)
            info = json.loads(facts.store.content(facts.answer("install_hooks", f"pkg:npm/{n}@{v}")))
            if info.get("lifecycle_scripts"):
                hooks[item] = info["lifecycle_scripts"]
                suspicious.append({"detector": "D2", "type": "new_install_script", "component": item, "severity": "high",
                                   "hard_signal": True, "label": "introduced",
                                   "summary": f"new package runs code at install: {json.dumps(info['lifecycle_scripts'])}"})
    except Exception as e:  # registry offline etc.: report it, keep the rest of the check
        det_error = f"{type(e).__name__}: {e}"[:300]

    try:  # CI drift hard signals (D11 SHA->tag, D12 history rewrite): git/JSON only, nothing is executed
        from guardian.detectors.ci_drift import action_sha_to_tag, history_rewrite
        suspicious += action_sha_to_tag(_load(db, "actions.json"), _load(dh, "actions.json")) + history_rewrite(repo, base, head)
    except Exception as e:
        det_error = ((det_error + "; ") if det_error else "") + f"ci_drift {type(e).__name__}: {e}"[:200]

    intro_v = [v for v in vulns if v["label"] == "introduced"]
    intro_c = [c for c in ci if c["label"] == "introduced"]
    headline = {
        "base": base, "head": head, "base_commit": rb["commit"][:12], "head_commit": rh["commit"][:12],
        "inventory": rh["summary"], "sbom_agreement_pct": (rh["sbom_agreement"].get("tools", {}).get("syft") or {}).get("agreement_pct"),
        "changes": {"files": files, **{k: len(v) for k, v in pkgs.items()}},
        "vulnerabilities": {"introduced": count(vulns, "introduced"), "pre_existing": count(vulns, "pre_existing"),
                            "fixed": count(vulns, "fixed"), "malicious_introduced": [v["key"] for v in intro_v if v["malicious"]],
                            "scanners": vh["counts"], "errors": vh["errors"]},
        "ci_image": {"introduced": len(intro_c), "pre_existing": sum(1 for c in ci if c["label"] == "pre_existing"),
                     "fixed": sum(1 for c in ci if c["label"] == "fixed"), "actions": chh["actions"], "images": chh["images"],
                     "errors": chh["errors"]},
        "suspicious_changes": [f"[{x['severity']}] {x['type']}: {x['component']} - {x['summary']}" for x in suspicious],
        "suspicious_error": det_error,
        "blocking": bool([x for x in suspicious if x["hard_signal"] or x["severity"] in ("high", "critical")] or
                         [v for v in intro_v if v["severity"] in ("high", "critical")] or
                         [c for c in intro_c if c["severity"] in ("high", "critical")]),
    }
    report = {"headline": headline, "package_changes": pkgs, "suspicious_changes": suspicious, "vulnerabilities": vulns, "ci_image": ci,
              "inventory": inv_h, "actions": _load(dh, "actions.json"), "images": _load(dh, "images.json"),
              "runs": {"base": str(db), "head": str(dh)}}
    path = out / f"report-{rb['commit'][:8]}-{rh['commit'][:8]}.json"
    path.write_text(json.dumps(report, indent=1))
    pointer = {"path": str(path)}
    try:  # explainable risk scoring (deterministic; EPSS/KEV cached, missing data stays "unknown")
        from guardian.scoring.contextual.pipeline import enrich, reach_for_report
        from guardian.scoring.score import score_report
        reach, reach_err = reach_for_report(report)  # contextual: static import scan of the head tree (estimated, never executes code)
        scores = enrich(score_report(report, reach=reach), report, reach_error=reach_err)  # contextual: rank stability, confidence, fix candidates
        spath = out / f"scores-{rb['commit'][:8]}-{rh['commit'][:8]}.json"
        spath.write_text(json.dumps(scores, indent=1))
        pointer["scores"] = str(spath)
        report["headline"]["verdict"] = scores["verdict"]
        report["headline"]["verdict_reasons"] = scores["reasons"]
        path.write_text(json.dumps(report, indent=1))
    except Exception as e:
        pointer["scores_error"] = f"{type(e).__name__}: {e}"[:300]
    (out / "latest.json").write_text(json.dumps(pointer))
    return {**report, "path": str(path)}
