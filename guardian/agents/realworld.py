"""Real fact tools for Stage B: git, the lockfile, the npm registry, OSV and the policy file.

Same interface as the canned world (answer / detector / coverage_required), so the agents,
the constitution and the orchestrator do not change. Only this module touches the network,
and only hosts listed in guardian.yaml `fetch_hosts`. Package code is never executed.
"""
from __future__ import annotations

import base64
import fnmatch
import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlparse

import requests
import yaml
from rapidfuzz.distance import DamerauLevenshtein

from guardian.adapters.npm import parse_lockfile
from guardian.git_snapshot import changed_paths, git, resolve_commit
from guardian.store.evidence import EvidenceStore
from guardian.universal import git_show

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
MAX_RESPONSE_BYTES = 12 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
DEMO_HTTP_HOSTS = {"localhost:4873", "127.0.0.1:4873"}
# Names attackers imitate most (plus every direct dependency of the app, added at runtime).
POPULAR = ["axios", "express", "lodash", "react", "request", "chalk", "commander", "debug", "moment", "webpack",
           "typescript", "eslint", "jest", "dotenv", "uuid", "yargs", "socket.io", "ws", "mongoose", "redis",
           "colors", "cross-env", "electron", "nodemon", "body-parser", "jsonwebtoken", "bcrypt", "sharp", "esbuild"]


class RealFacts:
    def __init__(self, repo: Path, base: str, head: str, store: EvidenceStore, policy_path: Path, cache: Path):
        self.repo, self.store = Path(repo), store
        self.base = resolve_commit(self.repo, base)
        self.head = resolve_commit(self.repo, head)
        self.policy = yaml.safe_load(Path(policy_path).read_text())
        self.cache = Path(cache)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.headers["User-Agent"] = "guardian-hackathon-scanner"
        self.deadline = time.monotonic() + 360
        self.base_pkgs, _ = parse_lockfile(self._lockfile(self.base))
        self.head_pkgs, _ = parse_lockfile(self._lockfile(self.head))
        self._memo: dict[tuple[str, str], str] = {}
        self.diff = self._compute_diff()

    # --- plumbing ------------------------------------------------------------
    def _lockfile(self, ref: str) -> str:
        text = git_show(self.repo, ref, "package-lock.json")
        if text is None:
            raise FileNotFoundError(f"no package-lock.json at {ref} in {self.repo}")
        return text

    def _git(self, *args: str) -> str:
        result = git(self.repo, *args)
        if len(result.stdout) > 16 * 1024 * 1024:
            raise ValueError("Git output exceeds the evidence size limit")
        return result.stdout.decode(errors="replace")

    def _ev(self, tool: str, content, path: str | None = None, kind: str = "tool_output") -> str:
        return self.store.add(content, kind=kind, source=f"{tool} (real)", path=path).id

    def _request(self, method: str, url: str, **kw) -> bytes:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("investigation fetch budget exhausted")
        u = urlparse(url)
        if (u.netloc not in self.policy["registries"]["fetch_hosts"]
                or u.scheme != "https" and not (u.scheme == "http" and u.netloc in DEMO_HTTP_HOSTS)
                or u.username is not None or u.password is not None or u.query or u.fragment):
            raise PermissionError("destination is outside the fetch policy")
        with self.http.request(method, url, timeout=(5, 15), stream=True, allow_redirects=False, **kw) as response:
            if response.status_code != 200:
                raise RuntimeError(f"upstream returned HTTP {response.status_code}")
            body = bytearray()
            deadline = min(self.deadline, time.monotonic() + 30)
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if time.monotonic() >= deadline:
                    raise TimeoutError("upstream response exceeded the download deadline")
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("upstream response exceeds the byte limit")
            return bytes(body)

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
            response = self._request("GET", f"{self._registry_base(resolved)}/{quote(name, safe='@')}")
            if not isinstance(json.loads(response), dict):
                raise ValueError("invalid registry document")
            self._memo[key] = response.decode()
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
        files = changed_paths(self.repo, self.base, self.head)
        commits = self._git("log", "--format=%H", f"{self.base}..{self.head}", "--").splitlines()
        sens = [f for f in files if any(fnmatch.fnmatch(f, p) for p in self.policy["sensitive_paths"])]
        return {"base": self.base, "head": self.head, "packages_added": added, "packages_removed": removed,
                "packages_updated": updated, "files_changed": files, "sensitive_files_changed": sens,
                "workflows_changed": [f for f in files if f.startswith(".github/workflows/")],
                "dockerfiles_changed": [f for f in files if "dockerfile" in f.lower()],
                "commits": [{"sha": sha, "subject_evidence": "use commit_metadata"} for sha in commits]}

    def coverage_required(self) -> set[str]:
        req = set()
        req.update(f"pkg:{_purl(name, version)}" for name, version in self._changed_packages())
        if "package-lock.json" in self.diff["files_changed"]:
            req.add("file:package-lock.json")
        req |= {f"file:{f}" for f in self.diff["sensitive_files_changed"] + self.diff["dockerfiles_changed"]}
        req |= {f"commit:{c['sha']}" for c in self.diff["commits"]}
        return req

    def coverage_key(self, cov: str) -> str:
        """Agents may cite a full or short commit sha; map it to the key used in coverage_required."""
        if cov.startswith("commit:"):
            return f"commit:{self._commit_in_range(cov.split(':', 1)[1])}"
        return cov

    def _commit_in_range(self, prefix: str) -> str:
        matches = [c["sha"] for c in self.diff["commits"] if len(prefix) >= 7 and c["sha"].startswith(prefix)]
        if len(matches) != 1:
            raise ValueError("commit is outside this comparison or ambiguous")
        return matches[0]

    def _changed_packages(self) -> set[tuple[str, str]]:
        before = {(p.name, p.version, p.resolved, p.integrity, p.has_install_script) for p in self.base_pkgs.values()}
        return {(p.name, p.version) for p in self.head_pkgs.values()
                if (p.name, p.version, p.resolved, p.integrity, p.has_install_script) not in before}

    # --- fact tools (return evidence id) -------------------------------------
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
        return self._ev("lockfile_diff", self._git("diff", "--no-ext-diff", "--no-textconv", "--no-color",
                                                   self.base, self.head, "--", "package-lock.json"),
                        path="package-lock.json", kind="diff_hunk")

    def t_git_diff(self, path):
        return self._ev("git_diff", self._git("diff", "--no-ext-diff", "--no-textconv", "--no-color", self.base, self.head, "--", path),
                        path=path, kind="diff_hunk")

    def t_commit_metadata(self, sha):
        return self._ev("commit_metadata", self._git("show", "--no-ext-diff", "--no-textconv", "--no-color", "--stat",
                                                    "--format=commit %H%nAuthor: %an <%ae>%nDate: %ad%nMessage: %s%n",
                                                    self._commit_in_range(sha), "--"),
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
            result = self._request("GET", f"https://api.npmjs.org/downloads/point/last-week/{quote(p.name, safe='@/')}")
            downloads = json.loads(result).get("downloads")
        times = doc.get("time", {})
        return self._ev("registry_metadata", {
            "name": p.name, "version": p.version, "resolved": p.resolved, "resolved_host": host,
            "host_on_allow_list": allowed, "published": times.get(p.version), "package_created": times.get("created"),
            "versions_published": len(doc.get("versions", {})), "maintainers": len(doc.get("maintainers", [])),
            "repository": (doc.get("repository") or {}).get("url") if isinstance(doc.get("repository"), dict) else doc.get("repository"),
            "weekly_downloads": downloads, "has_install_script": p.has_install_script,
        })

    def t_popularity_baseline(self, name):
        result = self._request("GET", f"https://api.npmjs.org/downloads/point/last-week/{quote(name, safe='@/')}")
        doc = self._packument(name, None)
        return self._ev("popularity_baseline", {
            "name": name, "weekly_downloads": json.loads(result).get("downloads"),
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
        if (not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                or "\\" in path or "\0" in path):
            raise ValueError("invalid package archive path")
        data = self._verified_archive(p.resolved, p.integrity or "")
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            expanded = compressed.read(MAX_ARCHIVE_BYTES + 1)
        if len(expanded) > MAX_ARCHIVE_BYTES:
            raise ValueError("package archive exceeds the expanded size limit")
        text = None
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as tar:
            for index, member in enumerate(tar, 1):
                if index > MAX_ARCHIVE_MEMBERS:
                    raise ValueError("package archive exceeds the member limit")
                if member.isfile() and not member.issparse() and member.name == f"package/{path}":
                    if text is not None:
                        raise ValueError("package archive has duplicate file entries")
                    text = tar.extractfile(member).read(20_000).decode(errors="replace")
        if text is None:
            return self._ev("read_package_file", {"purl": purl, "path": path, "error": "file not in tarball"})
        return self._ev("read_package_file", text, path=f"{p.name}@{p.version}/{path}", kind="file_excerpt")

    def _verified_archive(self, url: str, integrity: str) -> bytes:
        digests = [item.partition("-") for item in integrity.split()]
        for algorithm in ("sha512", "sha384", "sha256"):
            expected = [value for name, _, value in digests if name == algorithm]
            if expected:
                break
        else:
            raise ValueError("package archive has no supported integrity digest")
        key = hashlib.sha256(f"{url}\n{integrity}".encode()).hexdigest()
        cache_file = self.cache / f"{key}.tgz"
        if cache_file.is_symlink():
            raise ValueError("invalid package cache entry")
        cached = cache_file.exists()
        if cached:
            with cache_file.open("rb") as stream:
                data = stream.read(MAX_RESPONSE_BYTES + 1)
        else:
            data = self._request("GET", url)
        digest = base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
        if len(data) > MAX_RESPONSE_BYTES or digest not in expected:
            raise ValueError("package archive integrity check failed")
        if not cached:
            with tempfile.NamedTemporaryFile(dir=self.cache, delete=False) as temp:
                temp.write(data)
            try:
                os.replace(temp.name, cache_file)
            finally:
                Path(temp.name).unlink(missing_ok=True)
        return data

    def t_osv_lookup(self, purl):
        name, version = _parse_purl(purl)
        response = self._request("POST", "https://api.osv.dev/v1/query",
                                 json={"package": {"name": name, "ecosystem": "npm"}, "version": version})
        document = json.loads(response)
        if not isinstance(document, dict) or set(document) - {"vulns"} or not isinstance(document.get("vulns", []), list):
            raise ValueError("invalid OSV response")
        vulns = document.get("vulns", [])
        return self._ev("osv_lookup", {"package": f"{name}@{version}", "source": "OSV.dev",
                                       "scope": "advisories are for this name and version on the public npm registry", "advisories": [
            {"id": v["id"], "aliases": v.get("aliases", []), "summary": v.get("summary", "")[:160],
             "severity": [s.get("score") for s in v.get("severity", [])][:1]} for v in vulns]})

    def t_compare_versions_metadata(self, purl):
        p = self._entry(purl)
        if p is None:
            return self._ev("compare_versions_metadata", {"purl": purl, "error": "not in head lockfile"})
        old = next((b for b in self.base_pkgs.values() if b.name == p.name), None)
        def info(package):
            doc = self._packument(package.name, package.resolved)
            v = package.version
            m = doc.get("versions", {}).get(v)
            if not isinstance(m, dict):
                raise ValueError("registry version metadata is unavailable")
            return {"version": v, "lifecycle_scripts": {k: s for k, s in (m.get("scripts") or {}).items() if k in LIFECYCLE},
                    "maintainers": sorted(x.get("name", "") for x in m.get("maintainers", [])),
                    "unpacked_size": (m.get("dist") or {}).get("unpackedSize"),
                    "published": doc.get("time", {}).get(v)}
        new_i, old_i = info(p), info(old) if old else None
        return self._ev("compare_versions_metadata", {
            "package": p.name, "from": old.version if old else None, "to": p.version, "old": old_i, "new": new_i,
            "new_install_hooks": bool(new_i["lifecycle_scripts"] or p.has_install_script) and
                                 not ((old_i or {}).get("lifecycle_scripts") or (old and old.has_install_script)),
            "maintainer_change": bool(old_i) and old_i["maintainers"] != new_i["maintainers"],
        })

    # --- detectors (deterministic signals) -----------------------------------
    def detector(self, det: str) -> list[dict]:
        return list(self.iter_signals(det))

    def iter_signals(self, det: str):
        """Yield findings as they are found so an upstream failure preserves earlier evidence."""
        changed = self._changed_packages()
        if det == "D3":
            allowed = self.policy["registries"]["allowed_hosts"]
            for p in self.head_pkgs.values():
                host = urlparse(p.resolved or "").netloc
                if p.resolved and host not in allowed:
                    yield {"label": "introduced" if (p.name, p.version) in changed else "pre_existing", "type": "lockfile_tamper", "component": _purl(p.name, p.version),
                                "summary": f"resolved from {host}, which is not on the allow-list",
                                "evidence": self.answer("lockfile_diff", ""), "hard_signal": True, "floor": "critical"}
            for key, p in self.head_pkgs.items():
                old = self.base_pkgs.get(key)
                if old and old.name == p.name and old.version == p.version and old.integrity != p.integrity:
                    yield {"type": "lockfile_tamper", "component": _purl(p.name, p.version),
                                "summary": "same version, different integrity hash", "evidence": self.answer("lockfile_diff", ""),
                                "hard_signal": True, "floor": "critical"}
        elif det == "D7":
            for f in self.diff["sensitive_files_changed"]:
                eid = self.answer("git_diff", f)
                diff = self.store.content(eid)
                redirect = f.endswith(".npmrc") and any(line.startswith("+") and "registry" in line for line in diff.splitlines())
                yield {"type": "source_change", "component": f,
                            "summary": "npm registry redirected" if redirect else "sensitive file changed",
                            "evidence": eid, "hard_signal": redirect,
                            "floor": "critical" if redirect else "medium"}
        elif det == "D1":
            popular = set(POPULAR) | {p.name for p in self.head_pkgs.values() if p.direct}
            for name, ver in sorted(changed):
                for target in popular:
                    d = DamerauLevenshtein.distance(name, target)
                    if name != target and len(name) >= 4 and 0 < d <= self.policy["typosquat"]["max_distance"]:
                        yield {"type": "typosquat", "component": _purl(name, ver),
                                    "summary": f"{d} edit(s) from popular package '{target}'",
                                    "evidence": self.answer("registry_metadata", _purl(name, ver)),
                                    "hard_signal": False, "floor": "high"}
                        break
        elif det == "D4":
            base_names = {b.name for b in self.base_pkgs.values()}
            for name, ver in sorted(changed):
                if name in base_names:
                    eid = self.answer("compare_versions_metadata", _purl(name, ver))
                    info = json.loads(self.store.content(eid))
                    hard = bool(info.get("new_install_hooks"))
                    yield {"type": "suspicious_update", "component": _purl(name, ver),
                                "summary": "existing package newly adds an install script" if hard else "version changed in this PR",
                                "evidence": eid, "hard_signal": hard, "floor": "high" if hard else "info"}
        elif det == "D0":
            for name, ver in sorted(changed):
                eid = self.answer("osv_lookup", _purl(name, ver))
                adv = json.loads(self.store.content(eid))["advisories"]
                mal = [a for a in adv if a["id"].startswith("MAL-")]
                if adv:
                    yield {"type": "malicious_package" if mal else "known_vulnerability", "component": _purl(name, ver),
                                "summary": ", ".join(a["id"] for a in adv[:5]), "evidence": eid,
                                "hard_signal": bool(mal), "floor": "critical" if mal else "medium"}

    def human(self, question: str, options: list[str]) -> str:
        """Day 1 CLI: simulated human answer derived from policy (the dashboard asks a real person)."""
        if "registry" in question.lower():
            hosts = ", ".join(self.policy["registries"]["allowed_hosts"])
            return f"(simulated from policy) No. Only {hosts} is approved."
        return f"(simulated) {options[-1] if options else 'No'}"


def _purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, pkg = name[1:].split("/", 1)
        return f"pkg:npm/%40{scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def _parse_purl(purl: str) -> tuple[str, str | None]:
    s = purl.replace("pkg:npm/", "").replace("%40", "@")
    if s.count("@") >= (2 if s.startswith("@") else 1):
        name, ver = s.rsplit("@", 1)
        return name, ver
    return s, None
