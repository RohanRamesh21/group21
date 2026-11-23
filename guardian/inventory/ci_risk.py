"""CI and container-image risk checks (deterministic).

D8  base images referenced by tag only (no @sha256 digest): the tag can be repointed upstream.
D9  workflow weaknesses found by zizmor (offline mode, in the sandbox: no network, workflows read-only).
D10 third-party GitHub Actions not pinned to a full commit SHA.
"""
from __future__ import annotations

import json
import re
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
    from guardian import sandbox

    r = sandbox.run("zizmor", ["--offline", "--format", "json", "{src}/.github/workflows"], inputs={"src": src_dir}, timeout=300)
    if r.error or not r.stdout.strip().startswith("["):  # exit codes 10-14 mean "findings present"
        return [], r.error or f"zizmor failed ({r.returncode}): {r.stderr[-300:]}"
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


def _drop_duplicate_unpinned(zizmor: list[dict], d10: list[dict]) -> list[dict]:
    """zizmor's `unpinned-uses` and D10 report the same step (found on every real repo in testbed/corpus.yaml).
    Keep D10 (it knows first-party owners). zizmor points at the step's first line (often `- name:`), D10 at the
    `uses:` line, so a pair is: same file, same action reference, D10 line at or just below zizmor's."""
    free = sorted((f["file"], f["line"] or 0, f["component"]) for f in d10)
    out = []
    for f in zizmor:
        m = re.search(r"uses:\s*['\"]?([^\s'\"#]+)", f.get("excerpt") or "")
        near = [d for d in free if f["type"] == "ci_unpinned_uses" and d[0] == f["file"] and 0 <= d[1] - (f["line"] or 0) <= 40]
        # the excerpt is cut at 400 characters: with a long `env:` block the `uses:` line is missing, take the nearest
        match = next((d for d in near if d[2] == m.group(1)), None) if m else min(near, key=lambda d: d[1], default=None)
        if match:
            free.remove(match)  # one zizmor finding per D10 finding
        else:
            out.append(f)
    return out


def ci_image_scan(src_dir: Path, actions: list[dict], images: list[dict]) -> dict:
    z, err = zizmor_findings(src_dir)
    d10 = action_findings(actions)
    findings = image_findings(images) + d10 + _drop_duplicate_unpinned(z, d10)
    return {"findings": findings, "errors": {"zizmor": err} if err else {},
            "actions": {"total": len(actions), "pinned": sum(1 for a in actions if a.get("pinned_sha"))},
            "images": {"total": len(images), "pinned": sum(1 for i in images if i.get("digest"))}}


def label_ci(base: list[dict], head: list[dict]) -> list[dict]:
    key = lambda f: (f["type"], f["component"], f.get("excerpt", "")[:80])  # noqa: E731  line numbers shift, content doesn't
    bk, hk = {key(f) for f in base}, {key(f) for f in head}
    return [{**f, "label": "pre_existing" if key(f) in bk else "introduced"} for f in head] + \
           [{**f, "label": "fixed"} for f in base if key(f) not in hk]
