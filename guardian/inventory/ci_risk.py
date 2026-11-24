"""CI and container-image risk checks (deterministic).

D8  base images referenced by tag only (no @sha256 digest): the tag can be repointed upstream.
D9  workflow weaknesses found by zizmor (offline mode: no GitHub API calls).
D10 third-party GitHub Actions not pinned to a full commit SHA.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ZIZMOR_LEVEL = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info", "Unknown": "info"}


def image_findings(images: list[dict]) -> list[dict]:
    out = []
    for i in images:
        if i.get("digest"):
            continue
        out.append({"detector": "D8", "type": "image_not_pinned", "severity": "medium",
                    "component": i["ref"], "file": i["dockerfile"], "line": i.get("line"),
                    "summary": f"{i['ref']} is pulled by tag; pin it with @sha256 so the image cannot change underneath the build"})
    return out


def action_findings(actions: list[dict]) -> list[dict]:
    return [{"detector": "D10", "type": "action_not_pinned", "severity": "high" if not a.get("first_party") else "medium",
             "component": a["uses"], "file": a["workflow"], "line": a.get("line"),
             "summary": f"{a['uses']} is referenced by tag; a moved tag would run new code in CI"}
            for a in actions if not a.get("pinned_sha") and not a["uses"].startswith("./") and not a["uses"].startswith("docker://")]


def zizmor_findings(src_dir: Path) -> tuple[list[dict], str | None]:
    wf = src_dir / ".github" / "workflows"
    if not wf.exists():
        return [], None
    r = subprocess.run(["zizmor", "--offline", "--format", "json", str(wf)], capture_output=True, text=True, timeout=300)
    if not r.stdout.strip().startswith("["):  # exit codes 10-14 mean "findings present"
        return [], f"zizmor failed ({r.returncode}): {r.stderr[-300:]}"
    out = []
    for f in json.loads(r.stdout):
        if f.get("ignored"):
            continue
        loc = (f.get("locations") or [{}])[0]
        path = loc.get("symbolic", {}).get("key", {}).get("Local", {}).get("verbatim_path", "")
        rel = path.split("/src/", 1)[-1] if "/src/" in path else path
        conc = loc.get("concrete", {})
        out.append({"detector": "D9", "type": f"ci_{f['ident'].replace('-', '_')}",
                    "severity": ZIZMOR_LEVEL.get(f["determinations"]["severity"], "info"),
                    "component": rel, "file": rel, "line": conc.get("location", {}).get("start_point", {}).get("row", 0) + 1,
                    "summary": f"{f['desc']} ({f['ident']})", "excerpt": (conc.get("feature") or "")[:400], "url": f.get("url")})
    return out, None


def ci_image_scan(src_dir: Path, actions: list[dict], images: list[dict]) -> dict:
    z, err = zizmor_findings(src_dir)
    findings = image_findings(images) + action_findings(actions) + z
    return {"findings": findings, "errors": {"zizmor": err} if err else {},
            "actions": {"total": len(actions), "pinned": sum(1 for a in actions if a.get("pinned_sha"))},
            "images": {"total": len(images), "pinned": sum(1 for i in images if i.get("digest"))}}


def label_ci(base: list[dict], head: list[dict]) -> list[dict]:
    # per workflow/Dockerfile: the same risky line added to another file is a new finding; line numbers shift, content doesn't
    key = lambda f: (f.get("file"), f["type"], f["component"], f.get("excerpt", "")[:80])  # noqa: E731
    bk, hk = {key(f) for f in base}, {key(f) for f in head}
    return [{**f, "label": "pre_existing" if key(f) in bk else "introduced"} for f in head] + \
           [{**f, "label": "fixed"} for f in base if key(f) not in hk]
