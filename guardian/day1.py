"""Day 1 checkpoint view: "what is in the application, what changed, and what appears risky".

Turns a check report (universal or npm `guardian check`) + its scores into the 5 steps of the brief, each with
real numbers, the files it came from and an honest status: done / nothing found / not applicable (+ why).
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from guardian.universal import paths_to

ROOT = Path(__file__).resolve().parents[1]
LEVELS = ["critical", "high", "medium", "low", "info"]
SLIDE_CHECKS = [  # brief wording -> detector types that answer it
    ("Unexpected dependency", {"undeclared_dependency", "new_dependency", "unresolvable_dependency", "remote_script_no_sri",
                               "unpinned_remote_script", "extension_network_destinations"}),
    ("Typosquatted package", {"typosquat"}),
    ("Suspicious update", {"suspicious_update", "untrusted_source", "source_change", "extra_index_url", "non_registry_source",
                           "sensitive_file_change", "extension_untrusted_update"}),
    ("Unsafe install script", {"install_script", "new_install_script"}),
    ("Untrusted / unpinned image", {"image_not_pinned"}),
    ("Modified lockfile", {"modified_lockfile", "lockfile_tamper"}),
]


def _abs(p: str | None) -> Path | None:
    if not p:
        return None
    q = Path(p)
    return q if q.is_absolute() else ROOT / q


def build(report: dict, scores: dict | None) -> dict:
    h = report["headline"]
    inv = report.get("inventory", [])
    head_dir = _abs(report.get("runs", {}).get("head"))
    edges = json.loads((head_dir / "edges.json").read_text()) if head_dir and (head_dir / "edges.json").exists() else []
    app = h.get("app") or h.get("head") or "app"
    label = {p["key"]: f"{p.get('alias') or p['name']}@{p.get('version') or p.get('declared') or '?'}" for p in inv}
    paths = paths_to(edges, app)

    def path_of(key: str | None, name: str | None = None, version: str | None = None) -> list[str]:
        if not key and name:
            key = next((p["key"] for p in inv if p["name"] == name and (not version or p.get("version") == version)), None)
        ks = paths.get(key or "", [])
        return [app] + [label.get(k, k) for k in ks[1:]] if ks else []

    compare = h.get("base_commit") != h.get("head_commit")
    s = h["inventory"]
    manifests = report.get("manifests")
    ecos = s.get("ecosystems") or {"npm": s.get("packages", 0)}
    direct = s.get("direct", sum(1 for p in inv if p.get("direct")))
    transitive = s.get("transitive", len(inv) - direct)
    third_party = [p for p in inv if not p.get("first_party")]

    # ---- 1. discover
    if manifests is None:  # npm check report
        manifests = [{"path": "package.json", "ecosystem": "npm", "role": "manifest"},
                     {"path": "package-lock.json", "ecosystem": "npm", "role": "lockfile"}]
    dep_files = [m for m in manifests if m["role"] in ("manifest", "lockfile")]
    step1 = {
        "n": 1, "title": "Discover components", "status": "done" if third_party else "nothing_found",
        "facts": [f"{len(inv)} components ({direct} direct, {transitive} transitive) across {len(ecos)} ecosystem(s): "
                  + ", ".join(f"{k} {v}" for k, v in sorted(ecos.items(), key=lambda x: -x[1])),
                  f"{len(dep_files)} manifest/lockfile(s) read: " + (", ".join(m["path"] for m in dep_files[:8]) or "none"),
                  f"{s.get('unpinned', 0)} without an exact version (declared ranges only)" if s.get("unpinned") else "every component has an exact version"],
        "note": None if third_party else "No third-party packages: this repository declares no dependencies and vendors no known library. "
                                         "Guardian still recorded its own components (e.g. a browser extension) and checked the code for undeclared imports.",
        "unresolved": s.get("unresolved_manifests") or {},
        "sample": [{"name": p["name"], "version": p.get("version") or p.get("declared"), "ecosystem": p.get("ecosystem", "npm"),
                    "direct": p.get("direct"), "source": p.get("source_file") or "package-lock.json", "line": p.get("lockfile_line"),
                    "origin": p.get("origin") or ("registry" if p.get("resolved") else None)} for p in inv[:400]],
    }

    # ---- 2. supply-chain view
    origins: dict[str, int] = {}
    for p in inv:
        o = p.get("origin") or urlparse(p.get("resolved") or "").netloc or "registry"
        origins[o or "registry"] = origins.get(o or "registry", 0) + 1
    ci = h.get("ci_image", {})
    sboms = []
    if head_dir:
        for fmt, fn in (("guardian", "sbom.guardian.cdx.json"), ("cyclonedx", "sbom.syft.cdx.json"), ("spdx", "sbom.syft.spdx.json")):
            if (head_dir / fn).exists():
                sboms.append({"format": fmt, "file": fn})
    acts, imgs = ci.get("actions", {}), ci.get("images", {})
    step2 = {
        "n": 2, "title": "Build the supply chain view", "status": "done",
        "facts": [f"SBOM generated: {', '.join(x['file'] for x in sboms) or 'none'} (CycloneDX + SPDX)",
                  f"dependency graph: {len(edges)} edges; transitive links available for "
                  + (", ".join(s.get("graph_files") or []) or ("package-lock.json" if not report.get("manifests") else "no file (flat list)")),
                  "origin of components: " + ", ".join(f"{k} {v}" for k, v in sorted(origins.items(), key=lambda x: -x[1])[:6]),
                  f"CI/CD: {acts.get('total', 0)} GitHub Actions ({acts.get('pinned', 0)} pinned to a commit SHA) · "
                  f"containers: {imgs.get('total', 0)} base image(s) ({imgs.get('pinned', 0)} pinned by digest)"],
        "sboms": sboms, "edges": len(edges), "origins": origins,
        "note": None if (acts.get("total") or imgs.get("total")) else "No CI workflow or container image in this repository: nothing to inspect there (checked .github/workflows, .gitlab-ci.yml, Dockerfile*, compose files).",
        "images": report.get("images", [])[:20], "actions": report.get("actions", [])[:30],
    }

    # ---- 3. vulnerabilities
    vulns = [v for v in report.get("vulnerabilities", []) if v.get("label") != "fixed"]
    vh = h.get("vulnerabilities", {})
    by_sev = {lv: sum(1 for v in vulns if v["severity"] == lv) for lv in LEVELS}
    vrows = []
    for v in sorted(vulns, key=lambda v: (LEVELS.index(v["severity"]), v["name"]))[:60]:
        cves = [i for i in v.get("ids", []) if i.startswith("CVE-")]
        vrows.append({"component": f"{v['name']}@{v['version']}", "id": v["id"], "cve": cves[0] if cves else None, "severity": v["severity"],
                      "fixed": v.get("fixed", [])[:3], "malicious": v.get("malicious", False), "label": v.get("label"),
                      "direct": v.get("direct"), "sources": v.get("sources", []), "summary": v.get("summary", "")[:160],
                      "path": path_of(v.get("component_key"), v["name"], v["version"])})
    transitive_v = sum(1 for v in vulns if not v.get("direct"))
    errs = vh.get("errors") or {}
    step3 = {
        "n": 3, "title": "Detect vulnerabilities", "status": "done" if vulns else ("error" if errs and not vh.get("scanners", {}).get("merged") and errs.get("osv_api") else "nothing_found"),
        "facts": [f"{len(vulns)} advisories: " + ", ".join(f"{k} {n}" for k, n in by_sev.items() if n) if vulns else "no known vulnerabilities in any component with an exact version",
                  f"{sum(1 for v in vulns if v.get('fixed'))} have a fixed version · {sum(1 for v in vulns if v.get('malicious'))} known-malicious · "
                  f"{transitive_v} sit in transitive dependencies (path shown)",
                  "sources: OSV.dev + Grype (cross-checked; both = stronger evidence)"],
        "note": ("Scanner problems: " + "; ".join(f"{k}: {v[:120]}" for k, v in errs.items())) if errs else
                (f"{s.get('unpinned')} component(s) have no exact version, so they cannot be matched to advisories" if s.get("unpinned") else None),
        "rows": vrows, "by_severity": by_sev,
    }

    # ---- 4. suspicious changes
    sus = [x for x in report.get("suspicious_changes", []) if x.get("label") != "fixed"]
    ci_f = [c for c in report.get("ci_image", []) if c.get("label") != "fixed"]
    allf = sus + ci_f
    has_lock = any(m["role"] == "lockfile" for m in manifests)
    checks = []
    for title, types in SLIDE_CHECKS:
        hits = [x for x in allf if x["type"] in types]
        na = None
        if title == "Modified lockfile" and not hits:
            na = "no lockfile in this repository" if not has_lock else (None if compare else "needs an earlier version to compare")
        if title == "Untrusted / unpinned image" and not hits and not imgs.get("total"):
            na = "no container images"
        if title == "Unsafe install script" and not hits and not any(p.get("ecosystem", "npm") == "npm" for p in third_party):
            na = "no npm packages (install scripts are an npm feature)"
        checks.append({"check": title, "count": len(hits), "status": "found" if hits else ("n/a" if na else "clear"), "why": na,
                       "examples": [f"{x['component']}: {x['summary']}"[:220] for x in hits[:4]]})
    rows4 = [{"type": x["type"], "severity": x["severity"], "component": x["component"], "summary": x["summary"],
              "label": x.get("label"), "file": x.get("file"), "line": x.get("line"), "detector": x.get("detector")}
             for x in sorted(allf, key=lambda x: (LEVELS.index(x["severity"]) if x["severity"] in LEVELS else 9))]
    other = [x for x in rows4 if not any(x["type"] in t for _, t in SLIDE_CHECKS)]
    pc = report.get("package_changes", {})
    step4 = {
        "n": 4, "title": "Detect suspicious changes", "status": "done" if allf else "nothing_found",
        "facts": [(f"compared {h.get('base_commit', '')[:8]} -> {h.get('head_commit', '')[:8]}: {len(h.get('changes', {}).get('files', []))} files changed, "
                   f"{len(pc.get('added', []))} components added, {len(pc.get('updated', []))} updated, {len(pc.get('removed', []))} removed")
                  if compare else "full scan of one version (no earlier version given): every finding is reported as already present",
                  f"{sum(1 for c in checks if c['status'] == 'found')} of {len(checks)} attack patterns from the brief found; "
                  f"{len(other)} other risk signals (CI weaknesses, extension permissions ...)"],
        "checks": checks, "rows": rows4[:80], "package_changes": pc, "note": None,
    }

    # ---- 5. evidence
    ev = []
    for f in (scores or {}).get("findings", [])[:25]:
        e = f.get("evidence", {})
        comp = f.get("component", "")
        nm, ver = (comp.rsplit("@", 1) + [None])[:2] if "@" in comp[1:] else (comp, None)
        src = next((p for p in inv if p["name"] == nm and (not ver or p.get("version") == ver)), None)
        ev.append({"what": f["title"], "kind": f["kind"], "component": comp, "level": f["level"], "decision": f["decision"],
                   "score": f["score"], "label": f["label"], "summary": f.get("summary", "")[:240],
                   "path": path_of(src["key"] if src else None) if src else [],
                   "where": (f"{src.get('source_file') or 'package-lock.json'}:{src.get('lockfile_line')}" if src and src.get("lockfile_line") else
                             (src.get("source_file") if src else e.get("file"))) or (f"{e.get('file')}:{e.get('line')}" if e.get("file") else None),
                   "proof": {k: e[k] for k in ("advisory", "cve", "cvss_vector", "url", "detector", "resolved") if e.get(k)},
                   "why": [c["why"] for c in f.get("contributions", [])[:3]], "floor": f.get("floor")})
    step5 = {"n": 5, "title": "Present evidence", "status": "done" if ev else "nothing_found",
             "facts": [f"verdict: {(scores or {}).get('verdict', h.get('verdict', '?'))} · "
                       + "; ".join((scores or {}).get("reasons", [])[:2]),
                       "every finding: what, which component, dependency path, file:line, advisory/detector proof, initial risk level"],
             "rows": ev, "counts": (scores or {}).get("counts")}

    return {"question": "What is in the application, what changed, and what appears risky?",
            "chain": ["Repository", "SBOM", "Dependency graph", "Risk detection", "Evidence"],
            "repo": app, "head_commit": h.get("head_commit"), "base_commit": h.get("base_commit"), "compare": compare,
            "mode": h.get("mode", "npm"), "verdict": (scores or {}).get("verdict", h.get("verdict")),
            "steps": [step1, step2, step3, step4, step5]}
