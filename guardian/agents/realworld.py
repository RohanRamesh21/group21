# READING GUIDE
# Read-only fact source used by the older tool-using loop: Git snapshots, lockfiles, registry data and advisories.
# Tools read files and permitted network sources; package installation scripts are inspected as text, not executed.
# Has the same fact interface as fakeworld.py so orchestration can use real evidence or a controlled fixture.
#
"""Real fact tools for Stage B: git, the lockfile, the npm registry, OSV and the policy file.

Same interface as the canned world (answer / detector / coverage_required), so the agents,
the constitution and the orchestrator do not change. Only this module touches the network,
and only hosts listed in guardian.yaml `fetch_hosts`. Package code is never executed.
"""
from __future__ import annotations

import fnmatch
import io
import json
import subprocess
import tarfile
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from rapidfuzz.distance import DamerauLevenshtein

from guardian.adapters.npm import parse_lockfile
from guardian.snapshot.snapshot import open_view
from guardian.store.evidence import EvidenceStore

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
# Names attackers imitate most (plus every direct dependency of the app, added at runtime).
POPULAR = ["axios", "express", "lodash", "react", "request", "chalk", "commander", "debug", "moment", "webpack",
           "typescript", "eslint", "jest", "dotenv", "uuid", "yargs", "socket.io", "ws", "mongoose", "redis",
           "colors", "cross-env", "electron", "nodemon", "body-parser", "jsonwebtoken", "bcrypt", "sharp", "esbuild"]


# Expose repository evidence through a small fact API, keeping network and archive reads behind helpers.
class RealFacts:
    # Read base/head views and package data once; later fact requests use these fixed snapshots.
    def __init__(self, repo: Path, base: str, head: str, store: EvidenceStore, policy_path: Path,
                 cache: Path, human_policy: str = "simulated"):
        self.repo, self.base, self.head, self.store = Path(repo), base, head, store
        self.policy = yaml.safe_load(Path(policy_path).read_text())
        self.cache = Path(cache)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.http = requests.Session()
        self.http.headers["User-Agent"] = "guardian-hackathon-scanner"
        self.base_view, self.head_view = open_view(self.repo, base), open_view(self.repo, head)
        self.base_pkgs, _ = parse_lockfile(self.base_view.text("package-lock.json"))
        self.head_pkgs, _ = parse_lockfile(self.head_view.text("package-lock.json"))
        self._memo: dict[tuple[str, str], str] = {}
        self.diff = self._compute_diff()
        self.human_policy = human_policy

    # --- plumbing ------------------------------------------------------------
    def _git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True, check=True).stdout

    def _ev(self, tool: str, content, path: str | None = None, kind: str = "tool_output") -> str:
        return self.store.add(content, kind=kind, source=f"{tool} (real)", path=path).id

    # Apply the configured fetch-host policy before requesting remote evidence.
    def _get(self, url: str, **kw):
        host = urlparse(url).netloc
        if host not in self.policy["registries"]["fetch_hosts"]:
            raise PermissionError(f"host {host} is not in fetch_hosts (guardian.yaml)")
        return self.http.get(url, timeout=30, **kw)

    def _entry(self, purl_or_name: str):
        """Head lockfile entry for a purl (pkg:npm/name@version) or a bare name."""
        name, version = _parse_purl(purl_or_name)
        for p in self.head_pkgs.values():
            if p.name == name and (version is None or p.version == version):
                return p
        return None

    def _registry_base(self, resolved: str | None) -> str:
        if resolved:
            u = urlparse(resolved)
            return f"{u.scheme}://{u.netloc}"
        return "https://registry.npmjs.org"

    def _packument(self, name: str, resolved: str | None) -> dict:
        key = ("packument", f"{self._registry_base(resolved)}/{name}")
        if key not in self._memo:
            r = self._get(f"{self._registry_base(resolved)}/{name.replace('/', '%2F')}")
            self._memo[key] = r.text if r.status_code == 200 else "{}"
        return json.loads(self._memo[key])

    # --- diff ----------------------------------------------------------------
    def _compute_diff(self) -> dict:
        def index(pkgs):
            out: dict[str, set] = {}
            for p in pkgs.values():
                out.setdefault(p.name, set()).add(p.version)
            return out
        b, h = index(self.base_pkgs), index(self.head_pkgs)
        added = sorted(f"{n}@{v}" for n in h.keys() - b.keys() for v in h[n])
        removed = sorted(f"{n}@{v}" for n in b.keys() - h.keys() for v in b[n])
        updated = sorted(f"{n} {','.join(sorted(b[n]))} -> {','.join(sorted(h[n]))}"
                         for n in h.keys() & b.keys() if h[n] != b[n])
        files = [f for f in self._git("diff", "--name-only", self.base, self.head).splitlines() if f]
        commits = [dict(zip(("sha", "subject"), line.split(" ", 1)))
                   for line in self._git("log", "--format=%h %s", f"{self.base}..{self.head}").splitlines()]
        sens = [f for f in files if any(fnmatch.fnmatch(f, p) for p in self.policy["sensitive_paths"])]
        return {"base": self.base, "head": self.head, "packages_added": added, "packages_removed": removed,
                "packages_updated": updated, "files_changed": files, "sensitive_files_changed": sens,
                "workflows_changed": [f for f in files if f.startswith(".github/workflows/")],
                "dockerfiles_changed": [f for f in files if "dockerfile" in f.lower()],
                "commits": [{"sha": c["sha"], "subject_evidence": "use commit_metadata"} for c in commits]}

    # Describe what this change requires the older agent loop to examine.
    def coverage_required(self) -> set[str]:
        req = set()
        for item in self.diff["packages_added"]:
            n, v = item.rsplit("@", 1)
            req.add(f"pkg:{_purl(n, v)}")
        for item in self.diff["packages_updated"]:
            n, vers = item.split(" ", 1)
            for v in vers.split(" -> ")[1].split(","):
                req.add(f"pkg:{_purl(n, v)}")
        if "package-lock.json" in self.diff["files_changed"]:
            req.add("file:package-lock.json")
        req |= {f"file:{f}" for f in self.diff["sensitive_files_changed"]}
        req |= {f"commit:{c['sha']}" for c in self.diff["commits"]}
        return req

    # Translate a checked surface into the same key used by coverage requirements.
    def coverage_key(self, cov: str) -> str:
        """Agents may cite a full or short commit sha; map it to the key used in coverage_required."""
        if cov.startswith("commit:"):
            sha = cov.split(":", 1)[1]
            for c in self.diff["commits"]:
                if sha.startswith(c["sha"]) or c["sha"].startswith(sha):
                    return f"commit:{c['sha']}"
        return cov

    # --- fact tools (return evidence id) -------------------------------------
    # Dispatch a named fact query and reuse memoized evidence IDs when available.
    def answer(self, tool: str, arg: str) -> str | None:
        key = (tool, arg)
        if key in self._memo:
            return self._memo[key]
        fn = getattr(self, f"t_{tool}", None)
        if fn is None:
            return None
        eid = fn(arg)
        self._memo[key] = eid
        return eid

    def t_diff_summary(self, _):
        return self._ev("diff_summary", self.diff)

    def t_lockfile_diff(self, _):
        return self._ev("lockfile_diff", self._git("diff", self.base, self.head, "--", "package-lock.json"),
                        path="package-lock.json", kind="diff_hunk")

    def t_git_diff(self, path):
        return self._ev("git_diff", self._git("diff", self.base, self.head, "--", path) or "(no change)",
                        path=path, kind="diff_hunk")

    def t_commit_metadata(self, sha):
        return self._ev("commit_metadata", self._git("show", "--stat", "--format=commit %H%nAuthor: %an <%ae>%nDate: %ad%nMessage: %s%n", sha),
                        kind="file_excerpt")

    def t_sensitive_path_check(self, _):
        return self._ev("sensitive_path_check", {"changed_sensitive_paths": self.diff["sensitive_files_changed"],
                                                 "policy_patterns": self.policy["sensitive_paths"]})

    def t_policy_lookup(self, _):
        return self._ev("policy_lookup", {"allowed_registry_hosts": self.policy["registries"]["allowed_hosts"],
                                          "internal_scopes": self.policy["internal_scopes"],
                                          "install_script_allowlist": self.policy["install_scripts"]["allowlist"]})

    def t_registry_metadata(self, purl):
        p = self._entry(purl)
        if p is None:
            return self._ev("registry_metadata", {"purl": purl, "error": "not in head lockfile"})
        doc = self._packument(p.name, p.resolved)
        host = urlparse(p.resolved or "").netloc
        allowed = host in self.policy["registries"]["allowed_hosts"]
        downloads = None
        if host == "registry.npmjs.org":
            r = self._get(f"https://api.npmjs.org/downloads/point/last-week/{p.name}")
            downloads = r.json().get("downloads") if r.status_code == 200 else None
        times = doc.get("time", {})
        return self._ev("registry_metadata", {
            "name": p.name, "version": p.version, "resolved": p.resolved, "resolved_host": host,
            "host_on_allow_list": allowed, "published": times.get(p.version), "package_created": times.get("created"),
            "versions_published": len(doc.get("versions", {})), "maintainers": len(doc.get("maintainers", [])),
            "repository": (doc.get("repository") or {}).get("url") if isinstance(doc.get("repository"), dict) else doc.get("repository"),
            "weekly_downloads": downloads, "has_install_script": p.has_install_script,
        })

    def t_popularity_baseline(self, name):
        r = self._get(f"https://api.npmjs.org/downloads/point/last-week/{name}")
        doc = self._packument(name, None)
        return self._ev("popularity_baseline", {
            "name": name, "weekly_downloads": r.json().get("downloads") if r.status_code == 200 else None,
            "package_created": doc.get("time", {}).get("created"), "versions_published": len(doc.get("versions", {})),
        })

    def t_install_hooks(self, purl):
        p = self._entry(purl)
        if p is None:
            return self._ev("install_hooks", {"purl": purl, "error": "not in head lockfile"})
        meta = self._packument(p.name, p.resolved).get("versions", {}).get(p.version, {})
        hooks = {k: v for k, v in (meta.get("scripts") or {}).items() if k in LIFECYCLE}
        return self._ev("install_hooks", {"package": f"{p.name}@{p.version}", "lifecycle_scripts": hooks,
                                          "lockfile_hasInstallScript": p.has_install_script})

    def t_read_package_file(self, arg):
        purl, path = arg.split("#", 1)
        p = self._entry(purl)
        if p is None or not p.resolved:
            return self._ev("read_package_file", {"purl": purl, "error": "no resolved tarball"})
        tgz = self.cache / f"{p.name.replace('/', '_')}-{p.version}.tgz"
        if not tgz.exists():
            tgz.write_bytes(self._get(p.resolved).content)
        with tarfile.open(tgz, "r:gz") as tar:  # read one member in memory; never extract to disk, never execute
            member = next((m for m in tar.getmembers() if m.isfile() and m.name.split("/", 1)[-1] == path), None)
            if member is None:
                return self._ev("read_package_file", {"purl": purl, "path": path, "error": "file not in tarball"})
            text = tar.extractfile(member).read(20000).decode(errors="replace")
        return self._ev("read_package_file", text, path=f"{p.name}@{p.version}/{path}", kind="file_excerpt")

    def t_osv_lookup(self, purl):
        name, version = _parse_purl(purl)
        r = self.http.post("https://api.osv.dev/v1/query", timeout=30,
                           json={"package": {"name": name, "ecosystem": "npm"}, "version": version})
        vulns = r.json().get("vulns", []) if r.status_code == 200 else []
        return self._ev("osv_lookup", {"package": f"{name}@{version}", "source": "OSV.dev",
                                       "scope": "advisories are for this name and version on the public npm registry", "advisories": [
            {"id": v["id"], "aliases": v.get("aliases", []), "summary": v.get("summary", "")[:160],
             "severity": [s.get("score") for s in v.get("severity", [])][:1]} for v in vulns]})

    def t_compare_versions_metadata(self, purl):
        p = self._entry(purl)
        if p is None:
            return self._ev("compare_versions_metadata", {"purl": purl, "error": "not in head lockfile"})
        old = next((b for b in self.base_pkgs.values() if b.name == p.name), None)
        doc = self._packument(p.name, p.resolved)
        vers = doc.get("versions", {})
        def info(v):
            m = vers.get(v, {})
            return {"version": v, "lifecycle_scripts": {k: s for k, s in (m.get("scripts") or {}).items() if k in LIFECYCLE},
                    "maintainers": sorted(x.get("name", "") for x in m.get("maintainers", [])),
                    "unpacked_size": (m.get("dist") or {}).get("unpackedSize"),
                    "published": doc.get("time", {}).get(v)}
        new_i, old_i = info(p.version), info(old.version) if old else None
        return self._ev("compare_versions_metadata", {
            "package": p.name, "from": old.version if old else None, "to": p.version, "old": old_i, "new": new_i,
            "new_install_hooks": bool(new_i["lifecycle_scripts"]) and not (old_i or {}).get("lifecycle_scripts"),
            "maintainer_change": bool(old_i) and old_i["maintainers"] != new_i["maintainers"],
        })

    # --- detectors (deterministic signals) -----------------------------------
    # Run the supported rule checks on these snapshots and return evidence-linked signals.
    def detector(self, det: str) -> list[dict]:
        out = []
        changed = {(p.name, p.version) for p in self.head_pkgs.values()} - {(p.name, p.version) for p in self.base_pkgs.values()}
        if det == "D3":
            allowed = self.policy["registries"]["allowed_hosts"]
            base_hosts = {(b.name, b.version): urlparse(b.resolved or "").netloc for b in self.base_pkgs.values() if b.resolved}
            for p in self.head_pkgs.values():
                host = urlparse(p.resolved or "").netloc
                if not p.resolved:
                    continue
                before = base_hosts.get((p.name, p.version))
                # T10: introduced when the version is new OR the same version now downloads from a different host
                moved = before is not None and before != host
                introduced = (p.name, p.version) in changed or moved
                if host not in allowed:
                    out.append({"label": "introduced" if introduced else "pre_existing", "type": "lockfile_tamper", "component": _purl(p.name, p.version),
                                "summary": f"resolved from {host}, which is not on the allow-list",
                                "evidence": self.answer("lockfile_diff", ""), "hard_signal": True, "floor": "critical"})
                elif moved:
                    out.append({"label": "introduced", "type": "lockfile_tamper", "component": _purl(p.name, p.version),
                                "summary": f"download host changed from {before} to {host} for the same version",
                                "evidence": self.answer("lockfile_diff", ""), "hard_signal": True, "floor": "critical"})
            base_int = {(b.name, b.version): b.integrity for b in self.base_pkgs.values()}
            for p in self.head_pkgs.values():
                old = base_int.get((p.name, p.version))
                if old and p.integrity and old != p.integrity:
                    out.append({"type": "lockfile_tamper", "component": _purl(p.name, p.version),
                                "summary": "same version, different integrity hash", "evidence": self.answer("lockfile_diff", ""),
                                "hard_signal": True, "floor": "critical"})
        elif det == "D7":
            for f in self.diff["sensitive_files_changed"]:
                diff = self._git("diff", self.base, self.head, "--", f)
                redirect = f.endswith(".npmrc") and any(l.startswith("+") and "registry" in l for l in diff.splitlines())
                out.append({"type": "source_change", "component": f,
                            "summary": "npm registry redirected" if redirect else "sensitive file changed",
                            "evidence": self.answer("git_diff", f), "hard_signal": redirect,
                            "floor": "critical" if redirect else "medium"})
        elif det == "D1":
            popular = set(POPULAR) | {p.name for p in self.head_pkgs.values() if p.direct}
            for name, ver in sorted(changed):
                for target in popular:
                    d = DamerauLevenshtein.distance(name, target)
                    if name != target and len(name) >= 4 and 0 < d <= self.policy["typosquat"]["max_distance"]:
                        out.append({"type": "typosquat", "component": _purl(name, ver),
                                    "summary": f"{d} edit(s) from popular package '{target}'",
                                    "evidence": self.answer("registry_metadata", _purl(name, ver)),
                                    "hard_signal": False, "floor": "high"})
                        break
        elif det == "D4":
            base_names = {b.name for b in self.base_pkgs.values()}
            for name, ver in sorted(changed):
                if name in base_names:
                    eid = self.answer("compare_versions_metadata", _purl(name, ver))
                    info = json.loads(self.store.content(eid))
                    hard = bool(info.get("new_install_hooks"))
                    out.append({"type": "suspicious_update", "component": _purl(name, ver),
                                "summary": "existing package newly adds an install script" if hard else "version changed in this PR",
                                "evidence": eid, "hard_signal": hard, "floor": "high" if hard else "info"})
        elif det == "D0":
            for name, ver in sorted(changed):
                eid = self.answer("osv_lookup", _purl(name, ver))
                adv = json.loads(self.store.content(eid))["advisories"]
                mal = [a for a in adv if a["id"].startswith("MAL-")]
                if adv:
                    out.append({"type": "malicious_package" if mal else "known_vulnerability", "component": _purl(name, ver),
                                "summary": ", ".join(a["id"] for a in adv[:5]), "evidence": eid,
                                "hard_signal": bool(mal), "floor": "critical" if mal else "medium"})
        return out

    # Supply the configured demonstration/policy answer; the dashboard can override the callback.
    def human(self, question: str, options: list[str]) -> str:
        """Day 1 CLI: simulated human answer derived from policy (the dashboard asks a real person)."""
        if "registry" in question.lower():
            hosts = ", ".join(self.policy["registries"]["allowed_hosts"])
            return f"(simulated from policy) No. Only {hosts} is approved."
        return f"(simulated) {options[-1] if options else 'No'}"


# Represent package identity as an npm package URL for fact lookup.
def _purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, pkg = name[1:].split("/", 1)
        return f"pkg:npm/%40{scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


# Recover package name/version from the package URL supplied to a fact tool.
def _parse_purl(purl: str) -> tuple[str, str | None]:
    s = purl.replace("pkg:npm/", "").replace("%40", "@")
    if s.count("@") >= (2 if s.startswith("@") else 1):
        name, ver = s.rsplit("@", 1)
        return name, ver
    return s, None
