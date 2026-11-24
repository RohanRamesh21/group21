"""Evidence packet: everything an investigator needs about one case, collected by code (no AI, nothing executed).

A case = the introduced findings of one component (a package or a changed file). Each piece of evidence is stored in
the content-addressed evidence store (id + SHA-256) and trimmed to a fixed size, so the model sees exactly what was
hashed. Text written by third parties (advisory summaries, package scripts) is wrapped in <untrusted-data>.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

from guardian.store.evidence import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
MAX_CHARS = 1500
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")


def _git(repo: str, *args: str) -> str:
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def _untrusted(text: str) -> str:
    return f"<untrusted-data>{text}</untrusted-data>"


def _split(component: str) -> tuple[str, str]:
    name, _, version = component.rpartition("@")
    return name, version


def _finding_view(f: dict) -> str:
    keep = {k: f.get(k) for k in ("id", "kind", "type", "label", "level", "severity", "decision", "floor", "evidence")}
    keep["summary"] = _untrusted((f.get("summary") or "")[:300])
    return json.dumps(keep, sort_keys=True)


def _lock_entries(repo: str, base: str, head: str, name: str, version: str) -> list[dict]:
    out = []
    changed = _git(repo, "diff", "--name-only", base, head).split()
    for path in [p for p in changed if Path(p).name in LOCKFILES]:
        try:
            b = json.loads(_git(repo, "show", f"{base}:{path}") or "{}").get("packages", {})
            h = json.loads(_git(repo, "show", f"{head}:{path}") or "{}").get("packages", {})
        except ValueError:
            continue
        for key, entry in h.items():
            if key.endswith(f"node_modules/{name}") and entry.get("version") == version:
                out.append({"lockfile": path, "key": key, "base": b.get(key), "head": entry})
    return out


def _package_scripts(tarballs: Path, name: str, version: str) -> tuple[dict, dict[str, str]] | None:
    """Lifecycle scripts from an already-downloaded tarball, plus the local files those scripts run
    (e.g. "node setup.js"). Read in memory only: never extracted to disk, never executed."""
    tgz = tarballs / f"{name.replace('/', '_')}-{version}.tgz"
    if not tgz.exists():
        return None
    with tarfile.open(fileobj=io.BytesIO(tgz.read_bytes()), mode="r:gz") as tar:
        files = {m.name.split("/", 1)[-1]: m for m in tar.getmembers() if m.isfile()}
        if "package.json" not in files:
            return None
        meta = json.loads(tar.extractfile(files["package.json"]).read(200_000).decode(errors="replace"))
        scripts = {k: v for k, v in (meta.get("scripts") or {}).items() if k in LIFECYCLE}
        run = {}
        for cmd in scripts.values():
            for ref in re.findall(r"\bnode\s+(?:\./)?([\w./-]+\.(?:c|m)?js)\b", str(cmd)):
                if ref in files and ref not in run:
                    run[ref] = tar.extractfile(files[ref]).read(MAX_CHARS).decode(errors="replace")
    return scripts, run


def build_packets(out: Path, tarballs: Path | None = None) -> dict:
    out = Path(out)
    latest = json.loads((out / "latest.json").read_text())
    report = json.loads(Path(latest["path"]).read_text())
    scores = json.loads(Path(latest["scores"]).read_text())
    h = report["headline"]
    repo, base, head = h["repo_path"], h.get("base_sha"), h["head_sha"]
    store = EvidenceStore(out / "evidence-ai")
    tarballs = Path(tarballs) if tarballs else ROOT / ".cache" / "tarballs"

    groups: dict[str, list[dict]] = {}
    for f in scores.get("findings", []):
        if f.get("label") == "introduced":
            groups.setdefault(f["component"], []).append(f)

    def ev(source: str, content: str, path: str | None = None) -> dict:
        content = content[:MAX_CHARS]
        e = store.add(content, kind="tool_output", source=f"packet:{source}", path=path)
        return {"id": e.id, "sha256": e.sha256, "source": source, "path": path, "content": content}

    cases = []
    for comp in sorted(groups):
        fs = sorted(groups[comp], key=lambda f: f["id"])
        evidence = [ev("engine_finding", _finding_view(f)) for f in fs]
        if "@" in comp[1:] and not comp.startswith("."):
            name, version = _split(comp)
            for entry in _lock_entries(repo, base, head, name, version) if base else []:
                evidence.append(ev("lockfile_entry", json.dumps(entry, sort_keys=True, indent=1), entry["lockfile"]))
            manifest = [ln for ln in _git(repo, "diff", base, head, "--", "package.json").splitlines()
                        if ln[:1] in "+-" and f'"{name}"' in ln] if base else []
            if manifest:
                evidence.append(ev("manifest_diff", "\n".join(manifest), "package.json"))
            found = _package_scripts(tarballs, name, version)
            if found is not None:
                scripts, run = found
                evidence.append(ev("package_scripts", _untrusted(json.dumps(scripts, sort_keys=True)), f"{name}@{version}/package.json"))
                for ref, text in sorted(run.items()):
                    evidence.append(ev("hook_file", _untrusted(text[:MAX_CHARS - 40]), f"{name}@{version}/{ref}"))
        else:
            diff = _git(repo, "diff", base, head, "--", comp) if base else ""
            if diff:
                evidence.append(ev("file_diff", diff, comp))
        cid = "C-" + hashlib.sha256(comp.encode()).hexdigest()[:8]
        cases.append({"case_id": cid, "component": comp, "finding_ids": [f["id"] for f in fs],
                      "max_level": fs[0].get("level") if fs else None, "evidence": evidence})
    sha = hashlib.sha256(json.dumps(cases, sort_keys=True).encode()).hexdigest()
    return {"sha256": sha, "repo": repo, "base_sha": base, "head_sha": head, "cases": cases,
            "rules_verdict": {"verdict": scores.get("verdict"), "reasons": scores.get("reasons", [])}}
