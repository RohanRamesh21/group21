"""Stretch goal 2 (and the deterministic core of Day 2): recommend a fix, validate it, and prepare a branch.

    plan(report)                         -> fix actions with rationale, risk reduction, compatibility and rollback
    validate(report, ids, out)           -> apply the fixes to a copy of the code (npm runs in the sandbox, registry
                                            only), rescan before vs after, list what was fixed and anything new
    approve(report, validation, who)     -> after a HUMAN approves: a local branch `guardian/fix-<id>` with the change
                                            (git plumbing, nothing checked out). Never pushed, never merged.

Build and tests are NOT run: Guardian never executes code from the analysed project (CLAUDE.md 3.2). The validation
says so, and the PR text tells the reviewer to let CI build and test the branch.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REMOVE_TYPES = {"lockfile_tamper", "typosquat", "new_install_script", "registry_version_missing", "signature_invalid",
                "lockfile_integrity_mismatch", "provenance_mismatch", "suspicious_install_behavior", "dependency_confusion"}
REVERT_FILE_TYPES = {"source_change", "action_pin_removed", "sensitive_file_change"}


def _ver(v: str):
    from packaging.version import InvalidVersion, Version
    try:
        return Version(v.lstrip("v"))
    except InvalidVersion:
        return None


def _bump(old: str, new: str) -> str:
    a, b = _ver(old), _ver(new)
    if not a or not b:
        return "unknown"
    return "major" if b.major != a.major else "minor" if b.minor != a.minor else "patch"


def _target(current: str, fixed: list[str]) -> str | None:
    """Lowest fixed version above the current one, preferring the same major version (least disruptive)."""
    cur = _ver(current)
    cands = sorted({f for f in fixed if _ver(f) and (not cur or _ver(f) > cur)}, key=_ver)
    if not cands:
        return None
    same_major = [f for f in cands if cur and _ver(f).major == cur.major]
    return (same_major or cands)[0]


def _aid(*parts: str) -> str:
    return "FIX-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:8]


def plan(report: dict) -> list[dict]:
    inv = {p["key"]: p for p in report.get("inventory", [])}
    by_name: dict[str, dict] = {}
    for p in report.get("inventory", []):
        by_name.setdefault(p["name"], p)
    added = {x.rsplit("@", 1)[0] for x in report.get("package_changes", {}).get("added", [])}
    base_versions = {}
    for x in report.get("package_changes", {}).get("updated", []):
        name, vers = x.split(" ", 1)
        base_versions[name] = vers.split(" -> ")[0].split(",")[0]
    compare = report["headline"].get("base_commit") != report["headline"].get("head_commit")
    actions: dict[str, dict] = {}

    def put(a: dict):
        if a["id"] in actions:
            actions[a["id"]]["findings"] = sorted(set(actions[a["id"]]["findings"]) | set(a["findings"]))
        else:
            actions[a["id"]] = a

    # ---- attacks on packages introduced by this change: remove (new) or revert (updated)
    for s in report.get("suspicious_changes", []):
        name = s["component"].rsplit("@", 1)[0] if "@" in s["component"][1:] else s["component"]
        if s["type"] in REMOVE_TYPES and s.get("label") == "introduced" and name in by_name and by_name[name].get("ecosystem") == "npm":
            p = by_name[name]
            folder = str(Path(p.get("source_file") or "package-lock.json").parent)
            if name in added:
                put({"id": _aid("remove", name), "kind": "remove", "ecosystem": "npm", "component": f"{name}@{p['version']}",
                     "package": name, "from": p["version"], "to": None, "folder": folder, "automatable": True,
                     "findings": [f"{s['type']}:{s['component']}"],
                     "rationale": f"{name} was added by this change and carries attack signals ({s['type'].replace('_', ' ')}). Remove it.",
                     "compatibility": "code that imports it stops working; it was only added in this change",
                     "commands": [f"npm uninstall {name} --package-lock-only --ignore-scripts"],
                     "rollback": "revert the fix commit (git revert) - this restores the package; do not do so while the signals stand"})
            elif name in base_versions:
                put({"id": _aid("revert", name), "kind": "revert_package", "ecosystem": "npm", "component": f"{name}@{p['version']}",
                     "package": name, "from": p["version"], "to": base_versions[name], "folder": folder, "automatable": True,
                     "findings": [f"{s['type']}:{s['component']}"],
                     "rationale": f"this change moved {name} to {p['version']}, which carries attack signals; go back to {base_versions[name]}.",
                     "compatibility": f"{_bump(base_versions[name], p['version'])} downgrade back to the version used before this change",
                     "commands": [f"npm install {name}@{base_versions[name]} --package-lock-only --ignore-scripts"],
                     "rollback": "revert the fix commit"})
        elif s["type"] in REVERT_FILE_TYPES and s.get("label") == "introduced" and compare and s.get("file"):
            if s["type"] == "sensitive_file_change" and not any(x["type"] in ("source_change", "action_pin_removed") and x.get("file") == s["file"]
                                                                for x in report.get("suspicious_changes", [])):
                continue  # a changed workflow alone is a review item, not something to undo automatically
            put({"id": _aid("revert-file", s["file"]), "kind": "revert_file", "ecosystem": "file", "component": s["file"],
                 "file": s["file"], "automatable": True, "findings": [f"{s['type']}:{s['component']}"],
                 "rationale": f"{s['file']} was changed in a way that weakens the supply chain ({s['type'].replace('_', ' ')}); "
                              "restore the version from the base commit.",
                 "compatibility": "the other edits this change made to this file are undone too: re-apply the safe ones by hand",
                 "commands": [f"git checkout {report['headline']['base_commit']} -- {s['file']}"], "rollback": "revert the fix commit"})

    # ---- known-malicious packages: remove them, whether or not this change introduced them
    for v in report.get("vulnerabilities", []):
        if not v.get("malicious") or v.get("label") == "fixed":
            continue
        p = inv.get(v.get("component_key") or "") or by_name.get(v["name"]) or {}
        if p.get("ecosystem", "npm") == "npm" and p.get("found_by") == "guardian npm lockfile parser" and p.get("direct"):
            put({"id": _aid("remove", v["name"]), "kind": "remove", "ecosystem": "npm", "component": f"{v['name']}@{v['version']}",
                 "package": v["name"], "from": v["version"], "to": None, "folder": str(Path(p.get("source_file") or "package-lock.json").parent),
                 "automatable": True, "findings": [v["key"]],
                 "rationale": f"{v['name']}@{v['version']} is a known malicious package ({v['id']}). Remove it and check what it may have run.",
                 "compatibility": "code that imports it stops working; replace it with the package it imitates if one was intended",
                 "commands": [f"npm uninstall {v['name']} --package-lock-only --ignore-scripts"],
                 "rollback": "do not roll back: the package is malicious"})
        else:
            first = Path((p.get("path") or ["", ""])[1]).name if len(p.get("path") or []) > 2 else None
            put({"id": _aid("remove-manual", v["name"]), "kind": "manual", "ecosystem": p.get("ecosystem", "npm"),
                 "component": f"{v['name']}@{v['version']}", "package": v["name"], "from": v["version"], "to": None, "automatable": False,
                 "findings": [v["key"]], "rationale": f"{v['name']}@{v['version']} is a known malicious package ({v['id']})"
                 + (f", pulled in by {first}: remove or replace {first}." if first else ": remove it."),
                 "compatibility": "n/a", "commands": [], "rollback": "do not roll back: the package is malicious"})

    # ---- known vulnerabilities: ONE action per package version, to the lowest release that fixes all its advisories
    groups: dict[tuple, list[dict]] = {}
    for v in report.get("vulnerabilities", []):
        if v.get("label") == "fixed" or v.get("malicious"):
            continue
        groups.setdefault((v["name"], v["version"], v.get("component_key") or ""), []).append(v)
    for (name, version, ckey), vs in groups.items():
        p = inv.get(ckey) or by_name.get(name) or {}
        eco = p.get("ecosystem") or vs[0].get("ecosystem") or "npm"
        per = {v["key"]: _target(version, v.get("fixed") or []) for v in vs}
        fixable = {k: x for k, x in per.items() if x}
        unfixable = sorted(k for k, x in per.items() if not x)
        if unfixable:
            put({"id": _aid("nofix", name, version), "kind": "manual", "ecosystem": eco, "component": f"{name}@{version}",
                 "package": name, "from": version, "to": None, "automatable": False, "findings": unfixable,
                 "rationale": f"{len(unfixable)} advisory(ies) on {name}@{version} have no fixed release: replace the package, "
                              "mitigate, or accept the risk with a review",
                 "compatibility": "n/a", "commands": [], "rollback": "n/a"})
        if not fixable:
            continue
        target = max(fixable.values(), key=_ver)
        base = {"package": name, "from": version, "to": target, "findings": sorted(fixable),
                "compatibility": f"{_bump(version, target)} version update ({version} -> {target})",
                "rollback": f"revert the fix commit, or pin {name}@{version} again"}
        why = f"{name} {version} has {len(fixable)} fixable advisory(ies); {target} is the lowest release that fixes all of them."
        if eco == "npm" and p.get("found_by") == "guardian npm lockfile parser":
            folder = str(Path(p.get("source_file") or "package-lock.json").parent)
            if p.get("direct"):
                put({**base, "id": _aid("upgrade", name, target), "kind": "upgrade", "ecosystem": "npm", "folder": folder,
                     "component": f"{name}@{version}", "automatable": True, "rationale": why,
                     "commands": [f"npm install {name}@{target} --package-lock-only --ignore-scripts"]})
            else:
                via = " > ".join(Path(k).name for k in (p.get("path") or [])[1:-1]) or "indirect"
                put({**base, "id": _aid("override", name, target), "kind": "override", "ecosystem": "npm", "folder": folder,
                     "component": f"{name}@{version}", "automatable": True,
                     "rationale": why + f" It is transitive ({via}): force it with an npm override until its parents update.",
                     "commands": [f'add "overrides": {{"{name}": "{target}"}} to package.json',
                                  "npm install --package-lock-only --ignore-scripts"]})
        elif eco == "pypi" and re.match(r".*requirements.*\.(txt|in)$", p.get("source_file") or "") and p.get("version"):
            put({**base, "id": _aid("pin", name, target), "kind": "edit_pin", "ecosystem": "pypi", "file": p["source_file"],
                 "component": f"{name}@{version}", "automatable": True, "rationale": why,
                 "commands": [f"in {p['source_file']}: {name}=={version} -> {name}=={target}"]})
        else:
            cmd = {"golang": f"go get {name}@{target} && go mod tidy", "maven": f"set {name} to {target} in the build file",
                   "cargo": f"cargo update -p {name} --precise {target}"}.get(eco, f"update {name} to {target}")
            put({**base, "id": _aid("manual", name, target), "kind": "manual", "ecosystem": eco, "component": f"{name}@{version}",
                 "automatable": False, "commands": [cmd],
                 "rationale": why + f" Guardian does not run {eco} tooling (it would execute build code), so this step is manual."})
    out = list(actions.values())
    for a in out:
        a["risk_reduction"] = {"findings": len(a["findings"])}
    return sorted(out, key=lambda a: (not a["automatable"], a["kind"] != "remove", -len(a["findings"]), a["component"]))


# ------------------------------------------------------------------ validation
def _npm(folder: Path, args: list[str], npmrc_env: dict | None = None) -> tuple[bool, str]:
    from guardian import sandbox
    res = sandbox.run("npm", [*args, "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org/"],
                      output=folder, workdir="{out}", egress={"registry.npmjs.org"}, timeout=300,
                      env={"npm_config_update_notifier": "false", "npm_config_cache": "/tmp/npm-cache", **(npmrc_env or {})})
    msg = res.error or (res.stderr or res.stdout).strip()[-400:]
    return res.ok, (msg + (f" (blocked: {', '.join(res.denied)})" if res.denied else ""))


def _apply(tree: Path, base_tree: Path | None, actions: list[dict], log) -> list[dict]:
    """Apply automatable actions to `tree` in place. npm runs on a copy of the manifests (never the repo's .npmrc)."""
    results = []
    by_folder: dict[str, list[dict]] = {}
    for a in actions:
        if a["ecosystem"] == "npm":
            by_folder.setdefault(a.get("folder") or ".", []).append(a)
    from guardian import sandbox
    for folder, acts in by_folder.items():
        work = Path(tempfile.mkdtemp(prefix="gfix-"))
        src = tree / folder
        rc = [(d / ".npmrc").read_text(errors="replace") for d in (tree, src) if (d / ".npmrc").is_file()]
        npmrc_env = sandbox.safe_npmrc_env(*rc)  # e.g. legacy-peer-deps; never registry/git/scripts
        for p in src.rglob("package.json"):
            if "node_modules" not in p.parts:
                (work / p.relative_to(src)).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, work / p.relative_to(src))
        if (src / "package-lock.json").exists():
            shutil.copyfile(src / "package-lock.json", work / "package-lock.json")
        pj_path = work / "package.json"
        pj_text = pj_path.read_text()
        indent = len(re.search(r'\n(\s+)"', pj_text).group(1)) if re.search(r'\n(\s+)"', pj_text) else 2
        pj = json.loads(pj_text)
        overrides = {a["package"]: a["to"] for a in acts if a["kind"] == "override"}
        if overrides:
            pj["overrides"] = {**(pj.get("overrides") or {}), **overrides}
            pj_path.write_text(json.dumps(pj, indent=indent) + "\n")
        steps = []
        for a in acts:
            if a["kind"] == "remove":
                steps.append((a, ["uninstall", a["package"], "--package-lock-only", "--ignore-scripts"]))
            elif a["kind"] in ("upgrade", "revert_package"):
                steps.append((a, ["install", f"{a['package']}@{a['to']}", "--package-lock-only", "--ignore-scripts"]))
        if overrides:
            steps.append(({"id": "overrides", "component": ", ".join(overrides)}, ["install", "--package-lock-only", "--ignore-scripts"]))
        for a, args in steps:
            log(f"Fix {a['id']}: npm {' '.join(args[:2])} (sandbox, registry only)")
            ok, msg = _npm(work, args, npmrc_env)
            results.append({"id": a["id"], "component": a["component"], "ok": ok, "output": msg})
            for x in acts if a["id"] == "overrides" else []:
                results.append({"id": x["id"], "component": x["component"], "ok": ok, "output": "npm override applied" if ok else msg})
        for name in ("package.json", "package-lock.json"):
            if (work / name).exists():
                shutil.copyfile(work / name, src / name)
        shutil.rmtree(work, ignore_errors=True)
    for a in actions:
        if a["kind"] == "revert_file":
            old = (base_tree / a["file"]) if base_tree else None
            if old and old.exists():
                (tree / a["file"]).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(old, tree / a["file"])
            elif tree.joinpath(a["file"]).exists():
                (tree / a["file"]).unlink()  # the file did not exist on base
            results.append({"id": a["id"], "component": a["file"], "ok": True, "output": "restored from the base commit"})
        elif a["kind"] == "edit_pin":
            f = tree / a["file"]
            text = f.read_text()
            new = re.sub(rf"(?im)^(\s*{re.escape(a['package'])}\s*==\s*){re.escape(a['from'])}\b", rf"\g<1>{a['to']}", text)
            f.write_text(new)
            results.append({"id": a["id"], "component": a["component"], "ok": new != text,
                            "output": "pin updated" if new != text else "pin not found in the file"})
    return results


def _git(repo: Path, *args: str, env: dict | None = None, data: bytes | None = None) -> str:
    base = {"PATH": os.defpath, "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Guardian remediation", "GIT_AUTHOR_EMAIL": "guardian@localhost",
            "GIT_COMMITTER_NAME": "Guardian remediation", "GIT_COMMITTER_EMAIL": "guardian@localhost"}
    r = subprocess.run(["git", "-c", f"core.hooksPath={os.devnull}", "-C", str(repo), *args], env={**base, **(env or {})},
                       input=data, capture_output=True, check=True, timeout=300)
    return r.stdout.decode().strip()


def _snapshot_repo(before: Path, after: Path, dest: Path) -> None:
    """A throw-away git repo with two commits (before, after) so the normal pipeline can compare them."""
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    _git(dest, "init", "-q")
    for label, tree in (("before", before), ("after", after)):
        for p in dest.iterdir():
            if p.name != ".git":
                shutil.rmtree(p) if p.is_dir() else p.unlink()
        shutil.copytree(tree, dest, dirs_exist_ok=True)
        _git(dest, "add", "-A")
        _git(dest, "commit", "-q", "--allow-empty", "-m", label)
        _git(dest, "tag", label)


def validate(report: dict, ids: list[str], out: Path, log=lambda m: None) -> dict:
    """Apply the chosen fixes to a copy of the head commit and rescan before vs after."""
    from guardian.git_snapshot import export_tree, resolve_commit
    from guardian.universal import check_any

    repo = Path(report["repo"])
    actions = [a for a in plan(report) if a["id"] in ids and a["automatable"]]
    if not actions or {a["id"] for a in actions} != set(ids):
        raise ValueError("each selected fix must be available and automatable")
    vid = "VAL-" + hashlib.sha256(("|".join(sorted(ids)) + str(time.time())).encode()).hexdigest()[:8]
    work = out / "remediation" / vid
    head = resolve_commit(repo, report["headline"]["head_commit_full"])
    log(f"Exporting {head[:8]} and applying {len(actions)} fix(es)")
    export_tree(repo, head, work / "before")
    base_tree = None
    if any(a["kind"] == "revert_file" for a in actions):
        export_tree(repo, resolve_commit(repo, report["headline"]["base_commit_full"]), work / "base")
        base_tree = work / "base"
    # apply, rescan; if a chosen version has advisories of its own, move to its fixed release and retry (max 2 retries)
    attempts = []
    for attempt in range(3):
        shutil.rmtree(work / "after", ignore_errors=True)
        shutil.copytree(work / "before", work / "after")
        applied = _apply(work / "after", base_tree, actions, log)
        _snapshot_repo(work / "before", work / "after", work / "repo")
        log(f"Rescanning before vs after (attempt {attempt + 1}; same pipeline, same sandbox)")
        rep = check_any(work / "repo", "before", "after", work / "check", report["headline"].get("app") or "app", log=log)
        retry = False
        for a in actions:
            if a["kind"] not in ("upgrade", "override") or not a.get("to"):
                continue
            own = [v for v in rep["vulnerabilities"] if v["label"] == "introduced" and v["name"] == a["package"] and v["version"] == a["to"]]
            nxt = [x for x in (_target(a["to"], v.get("fixed") or []) for v in own) if x]
            if nxt and attempt < 2:
                attempts.append({"attempt": attempt + 1, "package": a["package"], "rejected": a["to"],
                                 "because": sorted({v["id"] for v in own}), "next": max(nxt, key=_ver)})
                a["to"] = max(nxt, key=_ver)
                a["rationale"] += (f" Validation rejected {attempts[-1]['rejected']} (it has {', '.join(attempts[-1]['because'][:3])}); "
                                   f"using {a['to']}.")
                a["compatibility"] = f"{_bump(a['from'], a['to'])} version update ({a['from']} -> {a['to']})"
                a["commands"] = [c.replace(attempts[-1]["rejected"], a["to"]) for c in a["commands"]]
                retry = True
        if not retry:
            break
        log("Retrying with safer versions: " + ", ".join(x["package"] + "@" + x["next"] for x in attempts if x["attempt"] == attempt + 1))
    diff = _git(work / "repo", "diff", "--stat", "before", "after")
    patch_bytes = _git_bytes(work / "repo", "diff", "--no-ext-diff", "--no-textconv", "--binary", "before", "after", "--")
    patch = patch_bytes.decode(errors="replace")
    (work / "fix.patch").write_bytes(patch_bytes)
    targeted = {f for a in actions for f in a["findings"]}
    fixed_v = [v for v in rep["vulnerabilities"] if v["label"] == "fixed"]
    fixed_keys = {v["key"] for v in fixed_v}
    targeted_vulns = targeted & {v["key"] for v in report.get("vulnerabilities", []) if v["label"] != "fixed"}
    still = targeted_vulns - fixed_keys
    new_v = [v for v in rep["vulnerabilities"] if v["label"] == "introduced"]
    restored = {a["file"] for a in actions if a["kind"] == "revert_file"}
    new_s = [s for s in rep["suspicious_changes"]
             if s["label"] == "introduced" and s["type"] not in ("new_dependency", "modified_lockfile")
             and not (s["type"] == "sensitive_file_change" and s.get("file") in restored)]
    new_ci = [c for c in rep["ci_image"] if c["label"] == "introduced"]
    coverage_gaps = [s["summary"] for s in rep["suspicious_changes"] if s["label"] == "not_checked"]
    if error := rep.get("policy", {}).get("error"):
        coverage_gaps.append(error)
    result = {
        "id": vid, "created": time.time(), "actions": actions, "applied": applied, "diffstat": diff, "attempts": attempts,
        "patch_file": str(work / "fix.patch"), "patch_preview": patch[:6000],
        "source_repo": str(repo.resolve()), "source_head": head, "patch_sha256": hashlib.sha256(patch_bytes).hexdigest(),
        "fixed": sorted({f"{v['name']}@{v['version']} {v['id']}" for v in fixed_v}),
        "targeted_fixed": sorted(targeted & fixed_keys), "still_present": sorted(still),
        "new_problems": sorted({f"{v['name']}@{v['version']} {v['id']} ({v['severity']})" for v in new_v} |
                               {f"{s['type']}: {s['component']} ({s['severity']})" for s in new_s + new_ci}),
        "coverage_gaps": coverage_gaps,
        "package_changes": rep["package_changes"], "verdict_after": rep["headline"].get("verdict"),
        "verdict_before": report["headline"].get("verdict"),
        "build_and_tests": "not run: Guardian never executes code from the analysed project; let CI build and test the branch",
        "ok": bool(patch_bytes and applied) and all(x["ok"] for x in applied) and not (new_v or new_s or new_ci or still or coverage_gaps),
        "approved": None,
    }
    result["pr"] = pr_text(report, result)
    (work / "validation.json").write_text(json.dumps(result, indent=1))
    shutil.rmtree(work / "before", ignore_errors=True)
    shutil.rmtree(work / "base", ignore_errors=True)
    return result


def pr_text(report: dict, v: dict) -> str:
    lines = [f"## Guardian fix: {', '.join(a['component'] for a in v['actions'])}", "",
             "### What and why"] + [f"- **{a['kind'].replace('_', ' ')}** `{a['component']}`" + (f" → `{a['to']}`" if a.get("to") else "")
                                    + f": {a['rationale']} _Compatibility_: {a['compatibility']}." for a in v["actions"]]
    lines += ["", "### Validation (Guardian rescan of this branch vs its parent)",
              f"- Fixed: {len(v['fixed'])} advisory(ies)" + (": " + ", ".join(v["fixed"][:10]) if v["fixed"] else ""),
              f"- New problems introduced by the fix: {', '.join(v['new_problems']) if v['new_problems'] else 'none'}",
              f"- Verdict: {v['verdict_before']} → {v['verdict_after']}",
              f"- Build and tests: {v['build_and_tests']}", "",
              "### Rollback"] + [f"- {a['rollback']}" for a in v["actions"]]
    lines += ["", f"_Generated by Guardian from report `{report['headline'].get('head_commit')}`; approved by a human before this branch "
                  "was created. Not merged or pushed automatically._"]
    return "\n".join(lines)


def approve(report: dict, validation: dict, approver: str) -> dict:
    """Human-approved: write the validated change as a commit on a new local branch. Never pushes or merges."""
    if not approver.strip():
        raise ValueError("approval needs the reviewer's name")
    if not validation.get("ok") or validation.get("approved"):
        raise ValueError("only a passing, unapproved validation can be approved")
    repo = Path(report["repo"])
    work = Path(validation["patch_file"]).parent
    from guardian.git_snapshot import resolve_commit

    head = resolve_commit(repo, report["headline"]["head_commit_full"])
    if (str(repo.resolve()), head) != (validation.get("source_repo"), validation.get("source_head")):
        raise ValueError("the repository or scanned commit changed; validate the fix again")
    patch = _git_bytes(work / "repo", "diff", "--no-ext-diff", "--no-textconv", "--binary", "before", "after", "--")
    if not patch or hashlib.sha256(patch).hexdigest() != validation.get("patch_sha256"):
        raise ValueError("the validated changes are missing or have changed")
    changed = _git_bytes(work / "repo", "diff", "--no-renames", "--name-status", "-z", "before", "after").split(b"\0")
    with tempfile.TemporaryDirectory(prefix="gidx-") as tmp:
        env = {"GIT_INDEX_FILE": str(Path(tmp) / "index")}
        _git(repo, "read-tree", head, env=env)
        for raw_status, raw_path in zip(changed[:-1:2], changed[1:-1:2], strict=True):
            path = os.fsdecode(raw_path)
            if raw_status == b"D":
                _git(repo, "update-index", "--remove", "--", path, env=env)
                continue
            blob = _git(repo, "hash-object", "-w", "--stdin", data=_git_bytes(work / "repo", "show", f"after:{path}"))
            mode = "100755" if _git_bytes(repo, "ls-tree", head, "--", path).startswith(b"100755 ") else "100644"
            _git(repo, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}", env=env)
        tree = _git(repo, "write-tree", env=env)
    msg = (f"Guardian fix: {', '.join(a['component'] for a in validation['actions'])}\n\n" + validation["pr"] +
           f"\n\nApproved-by: {approver.strip()}\nGuardian-validation: {validation['id']}\n")
    commit = _git(repo, "commit-tree", tree, "-p", head, "-F", "-", data=msg.encode())
    branch = f"guardian/fix-{validation['id'][4:].lower()}"
    _git(repo, "update-ref", f"refs/heads/{branch}", commit, "0" * len(head))
    validation["approved"] = {"by": approver.strip(), "at": time.time(), "branch": branch, "commit": commit}
    (work / "validation.json").write_text(json.dumps(validation, indent=1))
    return validation


def _git_bytes(repo: Path, *args: str) -> bytes:
    from guardian.git_snapshot import git
    return git(repo, *args).stdout


def validations(out: Path) -> list[dict]:
    return sorted((json.loads(p.read_text()) for p in (out / "remediation").glob("VAL-*/validation.json")),
                  key=lambda v: -v["created"]) if (out / "remediation").exists() else []
