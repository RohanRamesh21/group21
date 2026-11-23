"""Explainable risk scoring for a `guardian check` report. Deterministic: no AI changes a score.

Four layers:
  1. Hard floors      supply-chain attacks (malware, tampering, registry redirect, ...) get a minimum level
                      that no factor and no agent can lower.
  2. SSVC decision    each CVE gets Act / Attend / Track* / Track from a decision table adapted from
                      CISA's SSVC (exploitation, automatable, technical impact, how important the code is).
  3. Priority score   0-100 to order items: weighted sum of 5 factors; weights come from an AHP
                      pairwise-comparison matrix whose consistency ratio must be < 0.10.
  4. Explanation      exact per-factor contributions (the score is additive, so they sum to the score),
                      the SSVC path taken, and counterfactuals ("what would change this decision").
"""
from __future__ import annotations

from guardian.scoring import intel

# ---------------------------------------------------------------- AHP weights
CRITERIA = ["exploitation", "impact", "exposure", "introduced", "actionable"]
CRITERIA_TEXT = {
    "exploitation": "Being attacked? (KEV = attacked in the wild; EPSS = chance of attack in 30 days; hard supply-chain signals)",
    "impact": "How bad if exploited (advisory severity / CVSS)",
    "exposure": "Where it runs (shipped runtime code vs dev-only tooling)",
    "introduced": "Added by this PR (vs already present before)",
    "actionable": "A fix exists (upgrade or remove)",
}
# Saaty 1-9 scale: row criterion compared with column criterion.
AHP_MATRIX = [
    [1,     2,     3,     3,     5],
    [1 / 2, 1,     2,     2,     4],
    [1 / 3, 1 / 2, 1,     1,     3],
    [1 / 3, 1 / 2, 1,     1,     3],
    [1 / 5, 1 / 4, 1 / 3, 1 / 3, 1],
]
RANDOM_INDEX = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32}


def ahp(matrix=AHP_MATRIX) -> dict:
    """Principal eigenvector by power iteration, lambda_max, consistency index and ratio (Saaty)."""
    n = len(matrix)
    w = [1.0 / n] * n
    for _ in range(200):
        nw = [sum(matrix[i][j] * w[j] for j in range(n)) for i in range(n)]
        s = sum(nw)
        nw = [x / s for x in nw]
        if max(abs(a - b) for a, b in zip(nw, w)) < 1e-12:
            w = nw
            break
        w = nw
    aw = [sum(matrix[i][j] * w[j] for j in range(n)) for i in range(n)]
    lam = sum(aw[i] / w[i] for i in range(n)) / n
    ci = (lam - n) / (n - 1)
    cr = ci / RANDOM_INDEX[n]
    return {"weights": dict(zip(CRITERIA, [round(x, 4) for x in w])), "lambda_max": round(lam, 4),
            "consistency_index": round(ci, 4), "consistency_ratio": round(cr, 4), "consistent": cr < 0.10,
            "matrix": matrix, "criteria": CRITERIA}


AHP = ahp()
W = AHP["weights"]

# ---------------------------------------------------------------- factor values (0..1)
SEV_IMPACT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05}
EXPOSURE = {"essential": 1.0, "support": 0.7, "minimal": 0.2}
EXPOSURE_TEXT = {"essential": "shipped runtime code, direct dependency", "support": "shipped runtime code, indirect dependency",
                 "minimal": "dev-only tooling, not shipped"}
EPSS_POC = 0.088  # Shimizu & Hashimoto (2025): KEV or EPSS >= 0.088 keeps 85.6% coverage with ~95% less urgent work
LEVEL = {"Act": "critical", "Attend": "high", "Track*": "medium", "Track": "low"}
ORDER = ["low", "medium", "high", "critical"]

# Hard floors (layer 1): minimum level and SSVC-style decision that nothing can lower.
FLOORS = {
    "malicious": ("critical", "Act", "Known malicious package (OSV MAL- advisory)"),
    "lockfile_tamper": ("critical", "Act", "Package resolved from a host that is not on the allow-list / integrity changed"),
    "source_change": ("critical", "Act", "Package-manager config redirected (e.g. .npmrc registry)"),
    "new_install_script": ("high", "Attend", "New package runs code at install time"),
    "typosquat": ("high", "Attend", "Name is a near-copy of a popular package"),
}
COMBOS = [({"typosquat", "new_install_script"}, ("critical", "Act", "Look-alike name AND install-time code"))]


def parse_cvss(vector: str | None) -> dict:
    if not vector:
        return {}
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    parts["_version"] = vector.split("/")[0]
    return parts


def automatable(m: dict) -> str:
    if not m:
        return "unknown"
    net = m.get("AV") == "N" and m.get("PR") == "N" and m.get("UI") == "N"
    easy = m.get("AC", "L") == "L" and m.get("AT", "N") == "N"
    return "yes" if net and easy else "no"


def technical_impact(m: dict) -> str:
    if not m:
        return "unknown"
    c, i = m.get("C") or m.get("VC"), m.get("I") or m.get("VI")
    return "total" if c == "H" and i == "H" else "partial"


def mission(f: dict) -> str:
    if not f.get("runtime"):
        return "minimal"
    return "essential" if f.get("direct") else "support"


def ssvc(expl: str, auto: str, impact: str, mis: str) -> tuple[str, str]:
    """Decision table adapted from CISA SSVC (deployer view). Returns (decision, rule text)."""
    a, t = auto == "yes", impact == "total"
    if expl == "active":
        if (a or t) and mis != "minimal":
            return "Act", "attacked in the wild, and automatable or total impact, in shipped code"
        return "Attend", "attacked in the wild"
    if expl == "poc":
        if a and t:
            return ("Attend", "likely to be attacked, automatable and total impact") if mis != "minimal" else \
                   ("Track*", "likely to be attacked, automatable, total impact, but dev-only")
        if a or t:
            return ("Track*", "likely to be attacked, automatable or total impact") if mis != "minimal" else \
                   ("Track", "likely to be attacked but dev-only")
        return "Track", "likely to be attacked, limited impact"
    if a and t:
        if mis == "essential":
            return "Attend", "no attack seen, but automatable with total impact in a direct runtime dependency"
        if mis == "support":
            return "Track*", "no attack seen; automatable with total impact in an indirect runtime dependency"
    return "Track", "no sign of attack"


def _contrib(factors: dict) -> tuple[float, list]:
    rows = [{"factor": k, "value": round(factors[k]["value"], 3), "weight": W[k],
             "points": round(100 * W[k] * factors[k]["value"], 1), "why": factors[k]["why"]} for k in CRITERIA]
    return round(sum(r["points"] for r in rows), 1), rows


def _decide(level_from_rules: str | None, decision: str) -> str:
    lv = LEVEL[decision]
    if level_from_rules and ORDER.index(level_from_rules) > ORDER.index(lv):
        lv = level_from_rules
    return lv


def score_report(report: dict) -> dict:
    inv = {p["key"]: p for p in report.get("inventory", [])}
    by_name = {}
    for p in report.get("inventory", []):
        by_name.setdefault(p["name"], p)
    vulns = [v for v in report.get("vulnerabilities", []) if v.get("label") != "fixed"]

    ids = sorted({v["id"] for v in vulns})
    det = intel.osv_details(ids)
    cves = sorted({a for i in ids for a in [i] + det[i]["aliases"] if a.startswith("CVE-")})
    ep, ep_err = intel.epss(cves)
    kv, kev_err = intel.kev()

    findings = []

    # ---- CVE / advisory findings
    for v in vulns:
        d = det.get(v["id"], {})
        cve = next((a for a in [v["id"]] + d.get("aliases", []) if a.startswith("CVE-")), None)
        vector = d.get("cvss_v4") or d.get("cvss_v3")
        m = parse_cvss(vector)
        auto, impact, mis = automatable(m), technical_impact(m), mission(v)
        e = ep.get(cve) if cve else None
        in_kev = bool(cve and cve in kv)
        if v.get("malicious"):
            expl = "active"
        elif in_kev:
            expl = "active"
        elif e and e["epss"] >= EPSS_POC:
            expl = "poc"
        else:
            expl = "none" if e else "unknown"
        decision, rule = ssvc("active" if expl == "active" else ("poc" if expl == "poc" else "none"), auto, impact, mis)
        floor = None
        if v.get("malicious"):
            floor = FLOORS["malicious"]
            decision, rule = floor[1], floor[2]
        exp_val = 1.0 if (in_kev or v.get("malicious")) else (e["percentile"] if e else 0.3)
        exp_why = ("known malicious package" if v.get("malicious") else "in CISA KEV: attacked in the wild" if in_kev else
                   f"EPSS {e['epss']:.3f} (percentile {e['percentile']:.2f})" if e else "no EPSS data (treated as neutral 0.3)")
        factors = {
            "exploitation": {"value": exp_val, "why": exp_why},
            "impact": {"value": SEV_IMPACT.get(v["severity"], 0.5), "why": f"severity {v['severity']}" + (f" ({m.get('_version')})" if m else "")},
            "exposure": {"value": EXPOSURE[mis], "why": EXPOSURE_TEXT[mis]},
            "introduced": {"value": 1.0 if v["label"] == "introduced" else 0.3, "why": "added by this PR" if v["label"] == "introduced" else "already present before this PR"},
            "actionable": {"value": 1.0 if v.get("fixed") or v.get("malicious") else 0.4,
                           "why": f"fixed in {', '.join(v['fixed'][:2])}" if v.get("fixed") else ("remove the package" if v.get("malicious") else "no fixed version published")},
        }
        sc, rows = _contrib(factors)
        level = _decide(floor[0] if floor else None, decision)
        cf = []
        if not floor:
            for label, change in [("this were dev-only tooling", dict(mis="minimal")),
                                  ("it were a direct runtime dependency", dict(mis="essential")),
                                  ("it showed up in CISA KEV (attacked in the wild)", dict(expl="active"))]:
                args = dict(expl="active" if expl == "active" else ("poc" if expl == "poc" else "none"), auto=auto, impact=impact, mis=mis)
                args.update(change)
                d2, _ = ssvc(args["expl"], args["auto"], args["impact"], args["mis"])
                if d2 != decision:
                    cf.append({"if": label, "then": f"decision would be {d2} ({LEVEL[d2]})"})
        if v.get("fixed"):
            cf.append({"if": f"upgraded to {v['fixed'][0]}", "then": "this finding disappears"})
        if v["label"] == "introduced":
            cf.append({"if": "the package version were already present before this PR", "then": "it would be reported, but would not block the merge"})
        p = inv.get(v.get("key", "").split("#")[0]) or by_name.get(v["name"], {})
        findings.append({
            "id": v["key"], "kind": "vulnerability", "title": f"{v['name']}@{v['version']}: {v['id']}", "component": f"{v['name']}@{v['version']}",
            "label": v["label"], "summary": v.get("summary", ""), "decision": decision, "level": level, "score": sc,
            "ssvc": {"exploitation": expl, "automatable": auto, "technical_impact": impact, "mission": mis, "rule": rule},
            "floor": floor[2] if floor else None, "contributions": rows, "counterfactuals": cf,
            "evidence": {"advisory": v["id"], "aliases": d.get("aliases", []), "cvss_vector": vector, "cve": cve,
                         "epss": e, "kev": kv.get(cve) if in_kev else None, "url": f"https://osv.dev/vulnerability/{v['id']}",
                         "lockfile_line": p.get("lockfile_line"), "file": p.get("source_file"), "sources": v.get("sources", [])},
        })

    # ---- suspicious supply-chain changes (non-CVE)
    # a tool that did not run is a gap in coverage, not a risk: listed under data.not_checked, never scored
    sus = [s for s in report.get("suspicious_changes", []) if s["type"] != "tool_error"]
    not_checked = [f"{s['component']}: {s['summary']}" for s in report.get("suspicious_changes", []) if s["type"] == "tool_error"]
    types_by_comp: dict[str, set] = {}
    for s in sus:
        comp = s["component"].replace("pkg:npm/", "")
        types_by_comp.setdefault(comp, set()).add(s["type"])
    for s in sus:
        comp = s["component"].replace("pkg:npm/", "")
        name = comp.rsplit("@", 1)[0] if "@" in comp[1:] else comp
        p = by_name.get(name, {})
        floor = FLOORS.get(s["type"])
        for combo, val in COMBOS:
            if combo <= types_by_comp.get(comp, set()) and s["type"] in combo:
                floor = val
        if floor:
            decision, rule = floor[1], floor[2]
        else:
            decision, rule = ("Track", "routine change, recorded for review")
        mis = mission(p) if p else "support"
        hard = s.get("hard_signal") or bool(floor and floor[0] == "critical")
        factors = {
            "exploitation": {"value": 1.0 if hard else (0.6 if floor else 0.1), "why": "hard supply-chain attack signal" if hard else ("attack pattern" if floor else "no attack pattern")},
            "impact": {"value": SEV_IMPACT.get(s["severity"], 0.5), "why": f"severity {s['severity']}"},
            "exposure": {"value": EXPOSURE[mis] if p else 0.7, "why": EXPOSURE_TEXT[mis] if p else "build configuration (affects every install)"},
            "introduced": {"value": 1.0 if s.get("label", "introduced") == "introduced" else 0.3, "why": "added by this PR" if s.get("label", "introduced") == "introduced" else "already present"},
            "actionable": {"value": 1.0, "why": "revert the change / remove the package"},
        }
        sc, rows = _contrib(factors)
        level = _decide(floor[0] if floor else None, decision)
        findings.append({
            "id": f"{s['type']}:{comp}", "kind": "supply_chain", "title": f"{comp}: {s['type'].replace('_', ' ')}", "component": comp,
            "label": s.get("label", "introduced"), "summary": s["summary"], "decision": decision, "level": level, "score": sc,
            "ssvc": None, "floor": floor[2] if floor else None, "contributions": rows,
            "counterfactuals": [{"if": "an agent or factor argued it down", "then": "the floor keeps it at " + floor[0]}] if floor else [],
            "evidence": {"detector": s.get("detector"), "lockfile_line": s.get("line") or p.get("lockfile_line"),
                         "file": s.get("file") or p.get("source_file"), "resolved": p.get("resolved"),
                         "hard_signal": s.get("hard_signal", False)},
        })

    # ---- CI / container findings
    for c in report.get("ci_image", []):
        if c.get("label") == "fixed":
            continue
        decision = "Track*" if c["severity"] in ("high", "critical") else "Track"
        factors = {
            "exploitation": {"value": 0.3, "why": "configuration weakness, no attack seen"},
            "impact": {"value": SEV_IMPACT.get(c["severity"], 0.5), "why": f"severity {c['severity']}"},
            "exposure": {"value": 0.7, "why": "build pipeline / container"},
            "introduced": {"value": 1.0 if c["label"] == "introduced" else 0.3, "why": "added by this PR" if c["label"] == "introduced" else "already present"},
            "actionable": {"value": 1.0, "why": "pin by digest / SHA or tighten the workflow"},
        }
        sc, rows = _contrib(factors)
        findings.append({"id": f"{c.get('detector')}:{c.get('file')}:{c.get('line')}:{c.get('type')}", "kind": "ci_image",
                         "title": f"{c.get('file')}: {c.get('type')}", "component": c.get("component"), "label": c["label"],
                         "summary": c.get("summary", ""), "decision": decision, "level": LEVEL[decision], "score": sc, "ssvc": None,
                         "floor": None, "contributions": rows, "counterfactuals": [],
                         "evidence": {"file": c.get("file"), "line": c.get("line"), "url": c.get("url")}})

    findings.sort(key=lambda f: (-ORDER.index(f["level"]), -f["score"]))
    intro = [f for f in findings if f["label"] == "introduced"]
    block = [f for f in intro if f["level"] == "critical" or f["decision"] == "Act"]
    review = [f for f in intro if f not in block and f["level"] == "high"]
    verdict = "block" if block else ("review" if review or not_checked else "allow")
    reasons = [f"{f['title']} ({f['floor'] or f['ssvc']['rule']})" for f in block]
    reasons += [f"{f['title']} needs a human decision" for f in review]
    if not_checked:
        reasons.append("One or more scanner checks did not complete.")
    if not reasons:
        reasons.append("No high or critical risk introduced by this PR.")
    counts = {lv: {lab: sum(1 for f in findings if f["level"] == lv and f["label"] == lab) for lab in ("introduced", "pre_existing")}
              for lv in ORDER[::-1]}
    return {
        "verdict": verdict, "reasons": reasons, "counts": counts, "findings": findings,
        "method": {"ahp": AHP, "criteria_text": CRITERIA_TEXT, "epss_poc_threshold": EPSS_POC,
                   "floors": {k: {"level": v[0], "decision": v[1], "why": v[2]} for k, v in FLOORS.items()},
                   "levels": LEVEL, "verdict_rule": "block if this PR introduces a critical finding or an Act decision; "
                                                    "review if it introduces a high finding or scanner coverage is incomplete; otherwise allow"},
        "data": {"advisories": len(ids), "cves": len(cves), "epss_found": len(ep), "kev_matches": sum(1 for c in cves if c in kv),
                 "kev_catalog_size": len(kv), "errors": [x for x in (ep_err, kev_err) if x], "not_checked": not_checked},
    }
