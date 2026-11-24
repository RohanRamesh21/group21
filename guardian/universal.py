"""Universal scan: the Day 1 pipeline for ANY repository, not only npm projects with a root lockfile.

    Repository -> components (every ecosystem) -> SBOM -> dependency graph -> vulnerabilities
               -> suspicious changes -> evidence report (same shape as `guardian check`)

Where components come from (each one records the file it was found in):
  * lockfiles/manifests in any folder, any ecosystem (Syft): npm, yarn, pnpm, pip, poetry, pipenv, uv, Go,
    Cargo, Maven, Gradle, Ruby, PHP, .NET, Swift, Dart ...; npm lockfiles are also parsed by Guardian itself
    (direct/transitive, dev/runtime, install scripts, resolved host, lockfile line)
  * vendored third-party JavaScript copied into the repo (recognised by file name or licence banner)
  * scripts loaded from a CDN in HTML files
  * browser-extension manifests (the extension itself, its permissions and network destinations)
Vulnerabilities: OSV.dev API (all ecosystems) + Grype (local DB) on the SBOM; offline OSV DB as fallback.
Nothing from the repository is installed or executed. Missing data is reported, never guessed.
"""
from __future__ import annotations

import ast
import concurrent.futures as cf
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache" / "osv-api"
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", "site-packages", ".tox", ".mypy_cache", ".next", ".nuxt"}
MAX_TEXT_FILES = 6000
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
LEVELS = ["info", "low", "medium", "high", "critical"]
GHSA_WORDS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}

MANIFESTS = {  # file name -> (ecosystem, role)
    "package.json": ("npm", "manifest"), "package-lock.json": ("npm", "lockfile"), "npm-shrinkwrap.json": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"), "pnpm-lock.yaml": ("npm", "lockfile"), "bun.lock": ("npm", "lockfile"),
    "pyproject.toml": ("pypi", "manifest"), "setup.py": ("pypi", "manifest"), "setup.cfg": ("pypi", "manifest"),
    "Pipfile": ("pypi", "manifest"), "Pipfile.lock": ("pypi", "lockfile"), "poetry.lock": ("pypi", "lockfile"),
    "uv.lock": ("pypi", "lockfile"), "pdm.lock": ("pypi", "lockfile"),
    "go.mod": ("golang", "manifest"), "go.sum": ("golang", "lockfile"),
    "Cargo.toml": ("cargo", "manifest"), "Cargo.lock": ("cargo", "lockfile"),
    "pom.xml": ("maven", "manifest"), "build.gradle": ("maven", "manifest"), "build.gradle.kts": ("maven", "manifest"),
    "gradle.lockfile": ("maven", "lockfile"),
    "Gemfile": ("gem", "manifest"), "Gemfile.lock": ("gem", "lockfile"),
    "composer.json": ("composer", "manifest"), "composer.lock": ("composer", "lockfile"),
    "packages.lock.json": ("nuget", "lockfile"), "Package.swift": ("swift", "manifest"), "Package.resolved": ("swift", "lockfile"),
    "pubspec.yaml": ("pub", "manifest"), "pubspec.lock": ("pub", "lockfile"), "mix.exs": ("hex", "manifest"), "mix.lock": ("hex", "lockfile"),
}
PURL_ECO = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io", "maven": "Maven", "gem": "RubyGems",
            "composer": "Packagist", "nuget": "NuGet", "pub": "Pub", "hex": "Hex", "swift": "SwiftURL", "github": "GitHub Actions"}

# Well-known browser libraries people copy into repos: banner/file name -> npm package (so advisories match).
VENDORED = {"jquery": "jquery", "jquery-ui": "jquery-ui", "jquery ui": "jquery-ui", "bootstrap": "bootstrap", "lodash": "lodash",
            "underscore": "underscore", "moment": "moment", "angular": "angular", "angularjs": "angular", "vue": "vue",
            "vue.js": "vue", "react": "react", "react-dom": "react-dom", "d3": "d3", "chart.js": "chart.js", "chart": "chart.js",
            "handlebars": "handlebars", "dompurify": "dompurify", "highlight.js": "highlight.js", "three": "three",
            "socket.io": "socket.io-client", "axios": "axios", "pdf.js": "pdfjs-dist", "marked": "marked", "mustache": "mustache",
            "knockout": "knockout", "backbone": "backbone", "select2": "select2", "datatables": "datatables.net",
            "tinymce": "tinymce", "ckeditor": "ckeditor4", "popper": "@popperjs/core", "popper.js": "popper.js", "jszip": "jszip",
            "sweetalert2": "sweetalert2", "summernote": "summernote", "video.js": "video.js", "leaflet": "leaflet",
            "prismjs": "prismjs", "prism": "prismjs", "alpine": "alpinejs", "alpinejs": "alpinejs", "htmx": "htmx.org",
            "showdown": "showdown", "js-yaml": "js-yaml", "crypto-js": "crypto-js", "dayjs": "dayjs", "zepto": "zepto"}
BANNER = re.compile(r"(?:/\*!?|//)[^\n]{0,40}?\b([A-Za-z][\w.\- ]{0,25}?)\s+(?:JavaScript Library\s+)?v?(\d+\.\d+\.\d+(?:[-.][\w.]+)?)", re.I)
FILE_VER = re.compile(r"^([a-z][\w.\-]*?)[-.@]v?(\d+\.\d+\.\d+)(?:\.(?:min|slim|bundle|umd|esm))*\.js$", re.I)
CDN = [
    (re.compile(r"cdn\.jsdelivr\.net/npm/((?:@[\w.-]+/)?[\w.-]+)@([\w.\-]+)"), None),
    (re.compile(r"(?:unpkg\.com|cdn\.jsdelivr\.net/npm)/((?:@[\w.-]+/)?[\w.-]+?)()(?:/|$)"), None),
    (re.compile(r"unpkg\.com/((?:@[\w.-]+/)?[\w.-]+)@([\w.\-]+)"), None),
    (re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([\w.\-]+)/([\w.\-]+)/"), None),
    (re.compile(r"ajax\.googleapis\.com/ajax/libs/([\w.\-]+)/([\w.\-]+)/"), None),
    (re.compile(r"code\.jquery\.com/(jquery(?:-ui)?)-(\d+\.\d+\.\d+)"), None),
    (re.compile(r"stackpath\.bootstrapcdn\.com/(bootstrap)/(\d+\.\d+\.\d+)/"), None),
]
SCRIPT_TAG = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']((?:https?:)?//[^\"']+)[\"'][^>]*>", re.I)
NODE_BUILTINS = set("""assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain
events fs http http2 https inspector module net os path perf_hooks process punycode querystring readline repl stream
string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib test""".split())
PY_DIST = {"PIL": "pillow", "yaml": "pyyaml", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
           "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt", "attr": "attrs", "Crypto": "pycryptodome",
           "serial": "pyserial", "git": "gitpython", "magic": "python-magic", "docx": "python-docx", "pptx": "python-pptx",
           "fitz": "pymupdf", "skimage": "scikit-image", "OpenSSL": "pyopenssl", "google": "google", "zmq": "pyzmq"}
POPULAR_PYPI = ["requests", "numpy", "pandas", "django", "flask", "urllib3", "setuptools", "boto3", "pyyaml", "cryptography",
                "colorama", "python-dateutil", "pillow", "matplotlib", "scipy", "beautifulsoup4", "selenium", "tensorflow",
                "torch", "openai", "fastapi", "pydantic", "httpx", "aiohttp", "jinja2", "click", "pytest", "sqlalchemy"]
EXT_SENSITIVE = {"debugger": "high", "nativeMessaging": "high", "management": "medium", "proxy": "medium", "cookies": "medium",
                 "webRequestBlocking": "medium", "history": "medium", "clipboardRead": "medium", "privacy": "medium",
                 "downloads": "low", "webRequest": "low", "scripting": "low", "tabs": "low", "declarativeNetRequest": "low",
                 "identity": "low", "geolocation": "low", "pageCapture": "medium", "desktopCapture": "medium"}
BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/"}


# ------------------------------------------------------------------ helpers
def _policy() -> dict:
    try:
        return yaml.safe_load((ROOT / "guardian.yaml").read_text()) or {}
    except Exception:
        return {}


def _walk(src: Path):
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            p = Path(dirpath) / f
            if not p.is_symlink():
                yield p


def _rel(src: Path, p: Path) -> str:
    return str(p.relative_to(src))


def _read(p: Path, limit: int = 2_000_000) -> str:
    try:
        if p.stat().st_size > limit:
            return ""
        return p.read_text(errors="replace")
    except OSError:
        return ""


def _purl(eco: str, name: str, version: str | None) -> str:
    if eco == "npm" and name.startswith("@"):
        scope, n = name.split("/", 1)
        base = f"pkg:npm/%40{scope[1:]}/{n}"
    else:
        base = f"pkg:{eco}/{name}"
    return base + (f"@{version}" if version else "")


def _roundup(x: float) -> float:
    return math.ceil(x * 10 - 1e-9) / 10


def cvss3_score(vector: str | None) -> float | None:
    """CVSS v3.x base score from its vector (FIRST specification formula)."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = m["S"] == "C"
        pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if changed else {"N": 0.85, "L": 0.62, "H": 0.27})[m["PR"]]
        c, i, a = ({"H": 0.56, "L": 0.22, "N": 0}[m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    return _roundup(min(1.08 * (impact + expl) if changed else impact + expl, 10))


def _level(score: float | None) -> str | None:
    if score is None:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else None


# ------------------------------------------------------------------ step 1: discover components
def find_manifests(src: Path) -> list[dict]:
    out = []
    for p in _walk(src):
        n, rel = p.name, _rel(src, p)
        if n in MANIFESTS:
            eco, role = MANIFESTS[n]
            out.append({"path": rel, "ecosystem": eco, "role": role})
        elif re.match(r"^requirements.*\.(txt|in)$", n, re.I):
            out.append({"path": rel, "ecosystem": "pypi", "role": "lockfile" if "==" in _read(p, 500_000) else "manifest"})
        elif n.endswith((".csproj", ".fsproj")):
            out.append({"path": rel, "ecosystem": "nuget", "role": "manifest"})
        elif n == "manifest.json" and '"manifest_version"' in _read(p, 300_000):
            out.append({"path": rel, "ecosystem": "browser-extension", "role": "extension"})
        elif n.startswith("Dockerfile") or n.endswith(".dockerfile") or re.match(r"^(docker-)?compose.*\.ya?ml$", n):
            out.append({"path": rel, "ecosystem": "container", "role": "container"})
        elif rel.startswith(".github/workflows/") and n.endswith((".yml", ".yaml")) or n == ".gitlab-ci.yml":
            out.append({"path": rel, "ecosystem": "ci", "role": "ci"})
        elif n in (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", ".pypirc"):
            out.append({"path": rel, "ecosystem": "config", "role": "registry-config"})
    return sorted(out, key=lambda m: (m["role"], m["path"]))


def resolve_npm_lockfiles(src: Path, manifests: list[dict], log) -> tuple[list[str], dict[str, str]]:
    """package.json without any lockfile: resolve one from registry metadata only (--ignore-scripts, nothing runs).
    Always against the public registry: the repository's own .npmrc is untrusted and is not followed."""
    have = {str(Path(m["path"]).parent) for m in manifests if m["role"] == "lockfile" and m["ecosystem"] == "npm"}
    done, failed = [], {}
    for m in manifests:
        folder = str(Path(m["path"]).parent)
        if not m["path"].endswith("package.json") or folder in have or not shutil.which("npm"):
            continue
        try:
            pj = json.loads(_read(src / m["path"]) or "{}")
        except ValueError:
            continue
        if not (pj.get("dependencies") or pj.get("devDependencies") or pj.get("optionalDependencies")):
            continue
        if any(h == "." or folder.startswith(h + "/") for h in have):
            continue  # part of a workspace whose lockfile is higher up
        log(f"{m['path']}: no lockfile, resolving versions from registry.npmjs.org (npm --package-lock-only --ignore-scripts)")
        try:
            r = subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                                "--registry=https://registry.npmjs.org/"],
                               cwd=src / folder, capture_output=True, text=True, timeout=240)
            if r.returncode == 0 and (src / folder / "package-lock.json").exists():
                done.append(str(Path(folder) / "package-lock.json").removeprefix("./"))
                have.add(folder)
            else:
                failed[m["path"]] = (r.stderr or r.stdout)[-600:]
        except subprocess.TimeoutExpired:
            failed[m["path"]] = "npm timed out"
    return done, failed


def declared_npm(src: Path, pj_rel: str, err: str) -> tuple[list[dict], list[dict]]:
    """Lockfile could not be resolved: list what package.json declares (exact pins keep their version)."""
    pj = json.loads(_read(src / pj_rel) or "{}")
    text = _read(src / pj_rel)
    comps, findings = [], []
    for field, dev in (("dependencies", False), ("optionalDependencies", False), ("devDependencies", True)):
        for name, spec in (pj.get(field) or {}).items():
            spec = str(spec)
            exact = bool(re.match(r"^\d+\.\d+\.\d+(?:[-+][\w.]+)?$", spec))
            line = next((i for i, ln in enumerate(text.splitlines(), 1) if f'"{name}"' in ln), None)
            comps.append({"key": f"npm:{name}@{spec}#{pj_rel}", "name": name, "version": spec if exact else "", "declared": spec,
                          "purl": _purl("npm", name, spec if exact else None), "ecosystem": "npm", "direct": True, "dev": dev,
                          "runtime": not dev, "optional": False, "resolved": None, "integrity": None, "has_install_script": False,
                          "license": None, "alias": None, "lockfile_line": line, "source_file": pj_rel, "origin": "declared only",
                          "pinned": exact, "found_by": "guardian package.json reader (no lockfile could be resolved)"})
    for mm in re.finditer(r"No matching version found for (\S+?)\.?\s|404 Not Found - GET \S+/([^/\s]+) - Not found", err):
        spec = mm.group(1) or mm.group(2)
        nm = spec.rsplit("@", 1)[0] if "@" in spec[1:] else spec
        findings.append({"detector": "D14", "type": "unresolvable_dependency", "severity": "high", "hard_signal": False,
                         "component": spec, "file": pj_rel, "line": next((c["lockfile_line"] for c in comps if c["name"] == nm), None),
                         "summary": f"{spec} does not exist on registry.npmjs.org: either it was removed (npm removes malware) "
                                    "or it is a private name that an attacker could register (dependency confusion)"})
    return comps, findings


def run_syft(src: Path, out: Path) -> tuple[dict, str | None]:
    if not shutil.which("syft"):
        return {}, "syft not installed"
    cdx, spdx = out / "sbom.syft.cdx.json", out / "sbom.syft.spdx.json"
    r = subprocess.run(["syft", f"dir:{src}", "-q", "-o", f"cyclonedx-json={cdx}", "-o", f"spdx-json={spdx}",
                        "--exclude", "./**/node_modules/**", "--exclude", "./**/.git/**"],
                       capture_output=True, text=True, timeout=900,
                       env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"})
    if r.returncode != 0 or not cdx.exists():
        return {}, f"syft failed: {r.stderr[-300:]}"
    return json.loads(cdx.read_text()), None


def _npm_inventory(src: Path, lock_rel: str) -> tuple[list[dict], list[dict]]:
    from guardian.adapters.npm import line_of, parse_lockfile
    text = _read(src / lock_rel, 200_000_000)
    pkgs, edges = parse_lockfile(text)
    folder = str(Path(lock_rel).parent)
    pre = "" if folder == "." else folder + "/"
    inv = []
    for p in pkgs.values():
        row = p.model_dump()
        row.update(key=pre + p.key, lockfile_line=line_of(text, f'"{p.key}": {{'), source_file=lock_rel,
                   origin=urlparse(p.resolved or "").netloc or ("local" if (p.resolved or "").startswith("file:") else "registry"),
                   found_by="guardian npm lockfile parser")
        inv.append(row)
    edges_out = [{"parent": (pre + e.parent) if e.parent else "", "child": pre + e.child, "name": e.name, "spec": e.spec,
                  "kind": e.kind, "project": folder} for e in edges]
    return inv, edges_out


def _syft_inventory(doc: dict, skip_files: set[str]) -> tuple[list[dict], list[dict]]:
    inv, by_ref = [], {}
    for c in doc.get("components", []):
        purl = c.get("purl") or ""
        if not purl.startswith("pkg:") or c.get("type") == "file":
            continue
        eco = purl[4:].split("/", 1)[0]
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        loc = (props.get("syft:location:0:path") or "").lstrip("/")
        if loc in skip_files:
            continue
        name = (c["group"] + "/" + c["name"]) if c.get("group") and eco != "maven" else c.get("name", "")
        if eco == "maven" and c.get("group"):
            name = f"{c['group']}:{c['name']}"
        ver = c.get("version") or ""
        exact = bool(re.match(r"^v?\d[\w.+\-]*$", ver)) and not re.search(r"[\^~<>=*| ]", ver)
        dev = bool(re.search(r"(dev|test|lint|doc)", Path(loc).name, re.I)) or props.get("syft:package:dev") == "true"
        row = {"key": f"{eco}:{name}@{ver}#{loc}", "name": name, "version": ver if exact else "", "declared": ver, "purl": purl,
               "ecosystem": eco, "direct": None, "dev": dev, "runtime": not dev, "optional": False, "resolved": None,
               "integrity": None, "has_install_script": False, "license": None, "alias": None, "lockfile_line": None,
               "source_file": loc, "origin": "registry", "found_by": props.get("syft:package:foundBy", "syft"),
               "pinned": exact}
        inv.append(row)
        by_ref[c.get("bom-ref")] = row
    edges, incoming = [], set()
    for d in doc.get("dependencies", []):
        parent = by_ref.get(d.get("ref"))
        for ch in d.get("dependsOn", []) or []:
            child = by_ref.get(ch)
            if parent and child:
                edges.append({"parent": parent["key"], "child": child["key"], "name": child["name"], "spec": child["declared"],
                              "kind": "prod", "project": str(Path(child["source_file"]).parent)})
                incoming.add(child["key"])
    files_with_graph = {by_ref[d["ref"]]["source_file"] for d in doc.get("dependencies", []) if d.get("ref") in by_ref and d.get("dependsOn")}
    for row in inv:
        row["direct"] = row["key"] not in incoming
        row["graph"] = row["source_file"] in files_with_graph
        if row["direct"]:
            edges.append({"parent": "", "child": row["key"], "name": row["name"], "spec": row["declared"],
                          "kind": "dev" if row["dev"] else "prod", "project": str(Path(row["source_file"]).parent)})
    return inv, edges


def vendored_and_cdn(src: Path) -> tuple[list[dict], list[dict]]:
    """Third-party JS copied into the repo or loaded from a CDN. Returns (components, findings)."""
    comps, findings, n = [], [], 0
    for p in _walk(src):
        if n > MAX_TEXT_FILES:
            break
        low = p.name.lower()
        if low.endswith(".js"):
            n += 1
            name = ver = how = None
            m = FILE_VER.match(p.name)
            if m and m.group(1).lower().rstrip(".") in VENDORED:
                name, ver, how = VENDORED[m.group(1).lower()], m.group(2), "file name"
            else:
                head = _read(p, 8_000_000)[:600]
                b = BANNER.search(head)
                if b and b.group(1).strip().lower() in VENDORED:
                    name, ver, how = VENDORED[b.group(1).strip().lower()], b.group(2), "licence banner"
            if name:
                rel = _rel(src, p)
                comps.append({"key": f"vendored:{name}@{ver}#{rel}", "name": name, "version": ver, "declared": ver,
                              "purl": _purl("npm", name, ver), "ecosystem": "npm", "direct": True, "dev": False, "runtime": True,
                              "optional": False, "resolved": None, "integrity": None, "has_install_script": False, "license": None,
                              "alias": None, "lockfile_line": 1, "source_file": rel, "origin": "vendored copy", "pinned": True,
                              "found_by": f"guardian vendored-file check ({how})"})
        elif low.endswith((".html", ".htm")):
            n += 1
            text = _read(p, 3_000_000)
            for i, line in enumerate(text.splitlines(), 1):
                for tag in SCRIPT_TAG.finditer(line):
                    url = tag.group(1)
                    full = "https:" + url if url.startswith("//") else url
                    host = urlparse(full).netloc
                    rel = _rel(src, p)
                    name = ver = None
                    for rx, _ in CDN:
                        mm = rx.search(full)
                        if mm:
                            name, ver = mm.group(1), mm.group(2)
                            break
                    if name and name in VENDORED:
                        name = VENDORED[name]
                    pinned = bool(ver and re.match(r"^\d+\.\d+\.\d+", ver))
                    if name:
                        comps.append({"key": f"cdn:{name}@{ver}#{rel}", "name": name, "version": ver if pinned else "",
                                      "declared": ver, "purl": _purl("npm", name, ver if pinned else None), "ecosystem": "npm",
                                      "direct": True, "dev": False, "runtime": True, "optional": False, "resolved": full,
                                      "integrity": None, "has_install_script": False, "license": None, "alias": None,
                                      "lockfile_line": i, "source_file": rel, "origin": host, "pinned": pinned,
                                      "found_by": "guardian HTML <script src> check"})
                    if "integrity=" not in tag.group(0).lower():
                        findings.append({"detector": "D11", "type": "remote_script_no_sri", "severity": "medium", "hard_signal": False,
                                         "component": (name + (f"@{ver}" if ver else "")) if name else host, "file": rel, "line": i,
                                         "summary": f"{rel}:{i} loads {full} from {host} without an integrity hash: "
                                                    "whoever controls that server can change the code your users run"})
                    if name and not pinned:
                        findings.append({"detector": "D11", "type": "unpinned_remote_script", "severity": "medium", "hard_signal": False,
                                         "component": f"{name}@{ver or 'latest'}", "file": rel, "line": i,
                                         "summary": f"{rel}:{i} loads {name} without an exact version ({ver or 'none'}): it changes silently"})
    return comps, findings


def browser_extensions(src: Path, manifests: list[dict]) -> tuple[list[dict], list[dict]]:
    comps, findings = [], []
    for m in (x for x in manifests if x["role"] == "extension"):
        try:
            d = json.loads(_read(src / m["path"]))
        except ValueError:
            continue
        name = re.sub(r"[^\w.-]+", "-", str(d.get("name", "extension")).strip()).lower()
        ver = str(d.get("version", ""))
        comp = f"{name}@{ver}"
        comps.append({"key": f"extension:{comp}#{m['path']}", "name": name, "version": ver, "declared": ver,
                      "purl": f"pkg:generic/{name}@{ver}", "ecosystem": "browser-extension", "direct": True, "dev": False,
                      "runtime": True, "optional": False, "resolved": None, "integrity": None, "has_install_script": False,
                      "license": None, "alias": None, "lockfile_line": 1, "source_file": m["path"], "origin": "this repository",
                      "pinned": True, "found_by": "guardian browser-extension manifest check", "first_party": True,
                      "permissions": d.get("permissions", []), "host_permissions": d.get("host_permissions", [])})
        text = _read(src / m["path"])

        def line(needle):
            return next((i for i, ln in enumerate(text.splitlines(), 1) if needle in ln), None)

        def add(t, sev, summary, needle=None, hard=False):
            findings.append({"detector": "D12", "type": t, "severity": sev, "hard_signal": hard, "component": comp,
                             "file": m["path"], "line": line(needle) if needle else None, "summary": summary})
        hosts = list(d.get("host_permissions", [])) + [p for p in d.get("permissions", []) if "://" in p or p == "<all_urls>"]
        for cs in d.get("content_scripts", []) or []:
            hosts += cs.get("matches", [])
        broad = sorted({h for h in hosts if h in BROAD_HOSTS})
        if broad:
            add("extension_broad_host_access", "high", f"can read and change every website the user visits ({', '.join(broad)})", broad[0])
        sens = [p for p in d.get("permissions", []) if p in EXT_SENSITIVE]
        if sens:
            worst = max((EXT_SENSITIVE[p] for p in sens), key=LEVELS.index)
            add("extension_sensitive_permissions", worst, f"asks for powerful browser permissions: {', '.join(sens)}", sens[0])
        csp = d.get("content_security_policy")
        csp_text = json.dumps(csp) if csp else ""
        if "unsafe-eval" in csp_text or re.search(r"script-src[^;]*https?://", csp_text):
            add("extension_weak_csp", "high", "content security policy allows eval() or scripts from remote servers", "content_security_policy")
        if d.get("update_url") and "clients2.google.com" not in d["update_url"]:
            add("extension_untrusted_update", "high", f"updates come from {d['update_url']}, not the Chrome Web Store", "update_url", hard=True)
        if d.get("manifest_version") == 2:
            add("extension_manifest_v2", "low", "uses Manifest V2 (deprecated; weaker remote-code protections)", "manifest_version")
        ext_hosts = sorted({urlparse(h.replace("*.", "")).netloc for h in hosts if "://" in h} - {""})
        if ext_hosts:
            add("extension_network_destinations", "info",
                f"talks to: {', '.join(ext_hosts)} (check each one is expected; page data can be sent there)", "host_permissions")
    return comps, findings


def undeclared_imports(src: Path, inventory: list[dict], manifests: list[dict]) -> list[dict]:
    """Code imports a third-party package that no manifest declares: an unexpected, unpinned dependency."""
    declared = {p["name"].lower().replace("_", "-") for p in inventory}
    local_py, local_js = set(), set()
    py_files, js_files = [], []
    for dirpath, dirnames, filenames in os.walk(src):  # local module names: every folder, incl. test fixtures
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
        for f in filenames:
            if f.endswith(".py"):
                local_py.add(f[:-3])
                local_py.update(Path(dirpath).relative_to(src).parts)
    for p in _walk(src):
        if p.suffix == ".py":
            py_files.append(p)
            local_py.add(p.stem)
            local_py.update(part for part in p.relative_to(src).parts[:-1])
        elif p.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx") and not p.name.endswith(".min.js"):
            js_files.append(p)
    for m in manifests:  # names declared in package.json files (even when no lockfile could be resolved)
        if m["path"].endswith("package.json"):
            try:
                pj = json.loads(_read(src / m["path"]))
                for f in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    declared |= {k.lower() for k in (pj.get(f) or {})}
                if pj.get("name"):
                    local_js.add(pj["name"].lower())
            except ValueError:
                pass
        if m["ecosystem"] == "pypi" and m["role"] in ("manifest", "lockfile"):
            for ln in _read(src / m["path"]).splitlines():
                mm = re.match(r"^\s*\"?([A-Za-z0-9][\w.\-]*)", ln)
                if mm:
                    declared.add(mm.group(1).lower().replace("_", "-"))
    hits: dict[tuple, list] = {}
    std = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    for p in py_files[:MAX_TEXT_FILES]:
        try:
            tree = ast.parse(_read(p), filename=str(p))
        except (SyntaxError, ValueError):
            continue
        is_test = any(x in ("tests", "test", "testing") for x in p.relative_to(src).parts) or p.name.startswith("test_") \
            or p.name.endswith("_test.py") or p.name == "conftest.py"
        # tests create throw-away modules inside test functions: only their module-level imports count
        nodes = [n for top in tree.body for n in ast.walk(top) if not isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))] \
            if is_test else ast.walk(tree)
        for node in nodes:
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for nm in names:
                if nm in std or nm in local_py or nm.startswith("_"):
                    continue
                dist = PY_DIST.get(nm, nm).lower().replace("_", "-")
                if dist in declared or nm.lower() in declared:
                    continue
                hits.setdefault(("pypi", dist), []).append(f"{_rel(src, p)}:{node.lineno}")
    imp = re.compile(r"""(?:\brequire\(\s*|\bimport\s*\(\s*|^\s*(?:import|export)\b[^'"`;]*?\bfrom\s*|^\s*import\s+)['"]([^'"./][^'"]*)['"]""", re.M)
    for p in js_files[:MAX_TEXT_FILES]:
        text = _read(p, 1_500_000)
        for mm in imp.finditer(text):
            spec = mm.group(1)
            if spec.startswith(("node:", "@/", "~", "#", "http:", "https:", "virtual:", "$")) or "${" in spec:
                continue
            nm = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
            if nm in NODE_BUILTINS or nm.lower() in declared or nm.lower() in local_js or nm in ("chrome", "vscode", "electron"):
                continue
            hits.setdefault(("npm", nm), []).append(f"{_rel(src, p)}:{text.count(chr(10), 0, mm.start()) + 1}")
    out = []
    for (eco, nm), where in sorted(hits.items()):
        out.append({"detector": "D13", "type": "undeclared_dependency", "severity": "low", "hard_signal": False,
                    "component": f"{eco}:{nm}", "file": where[0].rsplit(":", 1)[0], "line": int(where[0].rsplit(":", 1)[1]),
                    "summary": f"'{nm}' is imported ({len(where)}x, e.g. {where[0]}) but no manifest declares it: "
                               "the version is whatever is installed on the machine, so it is unpinned and unchecked"})
    return out


def registry_config(src: Path, manifests: list[dict], policy: dict) -> list[dict]:
    allowed = set((policy.get("registries") or {}).get("allowed_hosts", ["registry.npmjs.org"])) | {"pypi.org", "files.pythonhosted.org"}
    out = []
    for m in manifests:
        text = _read(src / m["path"], 1_000_000)
        rel = m["path"]
        if m["role"] == "registry-config":
            for i, ln in enumerate(text.splitlines(), 1):
                mm = re.search(r"(?:registry|index-url|npmRegistryServer)\s*[=:]\s*\"?(\S+?)\"?\s*$", ln)
                if mm and urlparse(mm.group(1)).netloc not in allowed:
                    out.append({"detector": "D4", "type": "source_change", "severity": "high", "hard_signal": True,
                                "component": rel, "file": rel, "line": i,
                                "summary": f"{rel}:{i} sends package downloads to {mm.group(1)} (not an approved registry)"})
        elif m["ecosystem"] == "pypi" and Path(rel).name.lower().startswith("requirements"):
            for i, ln in enumerate(text.splitlines(), 1):
                s = ln.strip()
                if s.startswith("--extra-index-url") or s.startswith("--index-url") and "pypi.org" not in s:
                    out.append({"detector": "D4", "type": "extra_index_url", "severity": "high", "hard_signal": False,
                                "component": rel, "file": rel, "line": i,
                                "summary": f"{rel}:{i} adds a second package index ({s.split(None, 1)[-1]}): "
                                           "classic dependency-confusion setup"})
                elif re.match(r"^(git\+|https?://|-e\s+git)", s):
                    out.append({"detector": "D4", "type": "non_registry_source", "severity": "medium", "hard_signal": False,
                                "component": rel, "file": rel, "line": i,
                                "summary": f"{rel}:{i} installs straight from {s[:90]} (no registry, no version check)"})
    return out


def package_signals(inventory: list[dict], policy: dict) -> list[dict]:
    from rapidfuzz.distance import DamerauLevenshtein
    from guardian.agents.realworld import POPULAR
    allowed = set((policy.get("registries") or {}).get("allowed_hosts", ["registry.npmjs.org"]))
    allow_scripts = set((policy.get("install_scripts") or {}).get("allowlist", []))
    out, seen = [], set()
    popular = {"npm": set(POPULAR), "pypi": set(POPULAR_PYPI)}
    for p in inventory:
        comp = f"{p['name']}@{p['version'] or p.get('declared') or '?'}"
        eco = p.get("ecosystem", "npm")
        if p.get("first_party"):
            continue
        if p.get("direct") and eco in popular and (eco, p["name"]) not in seen:
            seen.add((eco, p["name"]))
            for target in popular[eco]:
                d = DamerauLevenshtein.distance(p["name"].lower(), target)
                limit = 1 if len(target) <= 6 else 2
                if 0 < d <= limit and len(p["name"]) >= 5 and p["name"] not in popular[eco]:  # short names collide by chance (test/jest)
                    out.append({"detector": "D1", "type": "typosquat", "severity": "high", "hard_signal": False, "component": comp,
                                "file": p.get("source_file"), "line": p.get("lockfile_line"),
                                "summary": f"name is {d} edit(s) away from the popular package '{target}'"})
                    break
        if p.get("has_install_script") and p["name"] not in allow_scripts:
            out.append({"detector": "D2", "type": "install_script", "severity": "low", "hard_signal": False, "component": comp,
                        "file": p.get("source_file"), "line": p.get("lockfile_line"),
                        "summary": "runs its own code during install (preinstall/install/postinstall)"})
        res = p.get("resolved") or ""
        if eco == "npm" and res and p.get("origin") not in ("vendored copy",) and not p["key"].startswith("cdn:"):
            host = urlparse(res).netloc
            if res.startswith(("git+", "git:", "github:", "file:")):
                # code from a repository or local path: unreviewed by any registry, but a common, visible choice
                out.append({"detector": "D3", "type": "non_registry_source", "severity": "medium", "hard_signal": False,
                            "component": comp, "file": p.get("source_file"), "line": p.get("lockfile_line"),
                            "summary": f"installed from {res[:60]} instead of an approved registry"})
            elif host and host not in allowed:
                # a registry tarball from a server outside the allow-list: how registry hijacks and redirects arrive
                out.append({"detector": "D3", "type": "untrusted_source", "severity": "critical", "hard_signal": True,
                            "component": comp, "file": p.get("source_file"), "line": p.get("lockfile_line"),
                            "summary": f"downloaded from {host}, which is not on the registry allow-list"})
    return out


def ci_and_images(src: Path, manifests: list[dict]) -> tuple[list[dict], list[dict], dict]:
    from guardian.inventory.ci_image import _split_image, parse_dockerfile, parse_workflow
    from guardian.inventory.ci_risk import ci_image_scan
    from guardian.models import ImageRef
    actions, images = [], []
    for m in manifests:
        text = _read(src / m["path"])
        if m["role"] == "ci" and m["path"].startswith(".github/"):
            actions += [a.model_dump() for a in parse_workflow(m["path"], text)]
        elif m["role"] == "container" and not re.search(r"compose", Path(m["path"]).name):
            images += [i.model_dump() for i in parse_dockerfile(m["path"], text)]
        if re.search(r"compose", Path(m["path"]).name) or m["path"].endswith(".gitlab-ci.yml"):
            for i, ln in enumerate(text.splitlines(), 1):
                mm = re.match(r"^\s*-?\s*image:\s*['\"]?([^\s'\"#]+)", ln)
                if mm and "$" not in mm.group(1):
                    reg, repo, tag, dig = _split_image(mm.group(1))
                    images.append(ImageRef(dockerfile=m["path"], stage=None, ref=mm.group(1), registry=reg, repository=repo,
                                           tag=tag, digest=dig, line=i).model_dump())
    ci = ci_image_scan(src, actions, images)
    root = str(src.resolve()) + "/"
    for f in ci["findings"]:  # zizmor reports absolute paths: make them repository-relative
        for k in ("file", "component"):
            if isinstance(f.get(k), str):
                f[k] = re.sub(r"^.*/trees/(?:head|base)/", "", f[k].replace(root, "").replace(str(src) + "/", ""))
    return actions, images, ci


# ------------------------------------------------------------------ step 3: vulnerabilities
def _osv_get(vid: str) -> dict | None:
    import requests
    f = CACHE / f"{vid}.json"
    if f.exists():
        return json.loads(f.read_text())
    for attempt in range(3):
        try:
            r = requests.get(OSV_VULN.format(vid), timeout=20)
            if r.status_code == 200:
                CACHE.mkdir(parents=True, exist_ok=True)
                f.write_text(r.text)
                return r.json()
            if r.status_code == 404:
                return None
        except requests.RequestException:
            time.sleep(1 + attempt)
    return None


def osv_api(inventory: list[dict]) -> tuple[list[dict], str | None]:
    import requests
    comps = {}
    for p in inventory:
        if p.get("version") and p.get("ecosystem") in PURL_ECO and not p.get("first_party"):
            comps[(p["ecosystem"], p["name"], p["version"])] = p
    if not comps:
        return [], None
    keys = list(comps)
    hits: dict[tuple, list[str]] = {}
    try:
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            body = {"queries": [{"package": {"name": n, "ecosystem": PURL_ECO[e]}, "version": v} for e, n, v in chunk]}
            r = requests.post(OSV_BATCH, json=body, timeout=60)
            r.raise_for_status()
            for k, res in zip(chunk, r.json().get("results", [])):
                ids = [v["id"] for v in res.get("vulns", []) or []]
                if ids:
                    hits[k] = ids
    except Exception as e:
        return [], f"OSV API unreachable: {type(e).__name__}: {str(e)[:160]}"
    all_ids = sorted({i for ids in hits.values() for i in ids})
    with cf.ThreadPoolExecutor(8) as ex:
        details = dict(zip(all_ids, ex.map(_osv_get, all_ids)))
    out = []
    for (eco, name, ver), ids in hits.items():
        for vid in ids:
            d = details.get(vid) or {}
            word = GHSA_WORDS.get(str((d.get("database_specific") or {}).get("severity", "")).upper())
            vec = next((s["score"] for s in d.get("severity", []) or [] if s.get("type") == "CVSS_V3"), None)
            level = word or _level(cvss3_score(vec))
            fixed = []
            for aff in d.get("affected", []) or []:
                if (aff.get("package") or {}).get("name", "").lower() == name.lower():
                    for rg in aff.get("ranges", []) or []:
                        fixed += [e["fixed"] for e in rg.get("events", []) if "fixed" in e]
            mal = vid.startswith("MAL-")
            out.append({"name": name, "version": ver, "ids": list(dict.fromkeys([vid] + (d.get("aliases") or []))),
                        "summary": (d.get("summary") or d.get("details") or "")[:200],
                        "severity": "critical" if mal else (level or "medium"), "severity_known": bool(level or mal),
                        "fixed": sorted(set(fixed)), "malicious": mal, "url": f"https://osv.dev/vulnerability/{vid}",
                        "source": "osv", "ecosystem": eco})
    return out, None


def grype_all(sbom: Path) -> tuple[list[dict], str | None]:
    if not shutil.which("grype"):
        return [], "grype not installed"
    env = {**os.environ, "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    r = subprocess.run(["grype", f"sbom:{sbom}", "-o", "json", "-q"], capture_output=True, text=True, env=env, timeout=900)
    if r.returncode != 0:
        return [], f"grype failed ({r.returncode}): {r.stderr[-200:]}"
    out = []
    for m in json.loads(r.stdout or "{}").get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        ids = [v["id"]] + [x["id"] for x in m.get("relatedVulnerabilities", [])]
        purl = a.get("purl") or ""
        out.append({"name": a["name"], "version": a["version"], "ids": list(dict.fromkeys(ids)),
                    "ecosystem": purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else None,
                    "summary": (v.get("description") or "")[:200],
                    "severity": GHSA_WORDS.get(str(v.get("severity", "")).upper(), "medium"),
                    "fixed": (v.get("fix") or {}).get("versions", []), "malicious": False, "url": v.get("dataSource"), "source": "grype"})
    return out, None


def vulnerabilities(inventory: list[dict], sbom: Path, src: Path) -> dict:
    from guardian.vuln.scan import merge, run_osv
    errors = {}
    osv, err = osv_api(inventory)
    if err:
        errors["osv_api"] = err
        for lock in {p["source_file"] for p in inventory if p.get("source_file", "").endswith("package-lock.json")}:
            try:  # offline fallback (npm only)
                osv += [{**r, "ecosystem": "npm"} for r in run_osv(src / lock)]
            except Exception as e:
                errors["osv_offline"] = str(e)[:200]
    grype, gerr = grype_all(sbom)
    if gerr:
        errors["grype"] = gerr
    vulns = merge(osv, grype)
    idx, by_nv = {}, {}
    for p in inventory:
        idx.setdefault((p.get("ecosystem"), p["name"], p["version"]), p)
        by_nv.setdefault((p["name"], p["version"]), []).append(p)
    for v in vulns:
        p = idx.get((v.get("ecosystem"), v["name"], v["version"]))
        if p is None:  # ecosystem unknown (e.g. a Grype match without purl): only join when unambiguous
            cands = by_nv.get((v["name"], v["version"]), [])
            p = cands[0] if len(cands) == 1 else {}
        v["direct"], v["runtime"] = bool(p.get("direct")), bool(p.get("runtime"))
        v["exposure"] = p.get("exposure")
        v["ecosystem"] = v.get("ecosystem") or p.get("ecosystem")
        v["source_file"], v["component_key"] = p.get("source_file"), p.get("key")
    return {"vulnerabilities": vulns, "errors": errors,
            "counts": {"osv": len(osv), "grype": len(grype), "merged": len(vulns),
                       "both": sum(1 for v in vulns if len(v["sources"]) == 2),
                       "packages": len({(v["name"], v["version"]) for v in vulns}),
                       "by_severity": {lv: sum(1 for v in vulns if v["severity"] == lv) for lv in LEVELS[::-1]}}}


# ------------------------------------------------------------------ step 2: SBOM + graph
def paths_to(edges: list[dict], app: str) -> dict[str, list[str]]:
    """Shortest dependency path root -> component, for every component reachable in the graph."""
    kids: dict[str, list[dict]] = {}
    for e in edges:
        kids.setdefault(e["parent"], []).append(e)
    best: dict[str, list[str]] = {"": [app]}
    q = deque([""])
    while q:
        n = q.popleft()
        for e in kids.get(n, []):
            if e["child"] not in best:
                best[e["child"]] = best[n] + [e["child"]]
                q.append(e["child"])
    return best


def write_sbom(inv: list[dict], edges: list[dict], app: str, commit: str, out: Path) -> Path:
    comps, seen = [], set()
    for p in inv:
        if p["key"] in seen:
            continue
        seen.add(p["key"])
        props = [{"name": f"guardian:{k}", "value": str(p.get(k))} for k in ("source_file", "origin", "found_by", "direct", "dev")]
        comps.append({"type": "application" if p.get("first_party") else "library", "bom-ref": p["key"], "name": p["name"],
                      "version": p["version"] or p.get("declared") or "", "purl": p.get("purl"), "properties": props})
    deps: dict[str, list[str]] = {}
    for e in edges:
        deps.setdefault(e["parent"] or "app", []).append(e["child"])
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tools": [{"name": "guardian"}, {"name": "syft"}],
                        "component": {"type": "application", "bom-ref": "app", "name": app, "version": commit[:12]}},
           "components": comps, "dependencies": [{"ref": k, "dependsOn": sorted(set(v))} for k, v in deps.items()]}
    f = out / "sbom.guardian.cdx.json"
    f.write_text(json.dumps(doc, indent=1))
    return f


# ------------------------------------------------------------------ one snapshot
def scan_tree(src: Path, out: Path, app: str, commit: str, log=lambda m: None, with_vulns: bool = True) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    policy = _policy()
    manifests = find_manifests(src)
    resolved, unresolved = resolve_npm_lockfiles(src, manifests, log)
    if resolved:
        manifests = find_manifests(src)
    inv, edges = [], []
    npm_locks = [m["path"] for m in manifests if Path(m["path"]).name in ("package-lock.json", "npm-shrinkwrap.json")]
    parsed = set()
    for lock in npm_locks:
        try:
            i2, e2 = _npm_inventory(src, lock)
            inv += i2
            edges += e2
            parsed.add(lock)
            for sib in ("package.json",):  # syft would list the same packages again from the sibling manifest
                parsed.add(str(Path(lock).parent / sib).removeprefix("./"))
        except Exception as e:
            log(f"{lock}: could not parse ({e}); falling back to Syft")
    log("Building the SBOM with Syft (CycloneDX + SPDX), all ecosystems")
    doc, syft_err = run_syft(src, out)
    s_inv, s_edges = _syft_inventory(doc, parsed)
    inv += s_inv
    edges += s_edges
    v_comps, script_findings = vendored_and_cdn(src)
    for pj_rel, err in unresolved.items():
        log(f"{pj_rel}: npm could not resolve a lockfile; using the declared dependencies")
        d_comps, d_find = declared_npm(src, pj_rel, err)
        v_comps += d_comps
        script_findings += d_find
    x_comps, ext_findings = browser_extensions(src, manifests)
    for c in v_comps + x_comps:
        inv.append(c)
        edges.append({"parent": "", "child": c["key"], "name": c["name"], "spec": c["declared"] or "", "kind": "prod",
                      "project": str(Path(c["source_file"]).parent)})
    paths = paths_to(edges, app)
    for p in inv:
        p.setdefault("runtime", not p.get("dev"))
    from guardian.inventory.exposure import frontend_imports, iter_tree, mark_shipped
    shipped = mark_shipped(inv, edges, frontend_imports(iter_tree(src)))  # T11: bundled devDependencies
    if shipped:
        log(f"{len(shipped)} dev-listed packages are imported by frontend code and treated as shipped (inferred)")
    for p in inv:
        p["path"] = [x for x in paths.get(p["key"], [app, p["key"]])]
        p["depth"] = len(p["path"]) - 1
    sbom = write_sbom(inv, edges, app, commit, out)

    suspicious = script_findings + ext_findings + undeclared_imports(src, inv, manifests) + \
        registry_config(src, manifests, policy) + package_signals(inv, policy)
    log("Checking CI workflows and container images")
    actions, images, ci = ci_and_images(src, manifests)
    vul = {"vulnerabilities": [], "errors": {}, "counts": {}}
    if with_vulns:
        log("Looking up vulnerabilities: OSV.dev (all ecosystems) + Grype (local DB)")
        vul = vulnerabilities(inv, sbom, src)
        for v in vul["vulnerabilities"]:
            v["path"] = paths.get(v.get("component_key") or "", [app])
    agree = None
    syft_npm = {((c["group"] + "/" + c["name"]) if c.get("group") else c.get("name"), c.get("version"))
                for c in doc.get("components", []) if (c.get("purl") or "").startswith("pkg:npm/")}
    lock_npm = {(p["name"], p["version"]) for p in inv if p.get("found_by") == "guardian npm lockfile parser"}
    if lock_npm and syft_npm:
        agree = round(100 * len(lock_npm & syft_npm) / len(lock_npm), 1)
    for name, data in (("inventory", inv), ("edges", edges), ("manifests", manifests), ("actions", actions), ("images", images),
                       ("vulns", vul), ("ci_risk", ci), ("suspicious", suspicious)):
        (out / f"{name}.json").write_text(json.dumps(data, indent=1))
    ecos: dict[str, int] = {}
    for p in inv:
        ecos[p.get("ecosystem", "?")] = ecos.get(p.get("ecosystem", "?"), 0) + 1
    summary = {"packages": len(inv), "unique_name_versions": len({(p["name"], p["version"]) for p in inv}),
               "direct": sum(1 for p in inv if p.get("direct")), "transitive": sum(1 for p in inv if not p.get("direct")),
               "runtime": sum(1 for p in inv if p.get("runtime")), "dev_only": sum(1 for p in inv if p.get("dev")),
               "install_scripts": sum(1 for p in inv if p.get("has_install_script")),
               "unpinned": sum(1 for p in inv if not p.get("version")), "ecosystems": ecos,
               "manifests": sum(1 for m in manifests if m["role"] in ("manifest", "lockfile")),
               "lockfiles": sum(1 for m in manifests if m["role"] == "lockfile"),
               "workflows": sum(1 for m in manifests if m["role"] == "ci"), "actions": len(actions), "base_images": len(images),
               "edges": len(edges), "unresolved_manifests": {k: v[-200:] for k, v in unresolved.items()}, "graph_files": sorted({p["source_file"] for p in inv if p.get("graph") or p.get("found_by") == "guardian npm lockfile parser"}),
               "resolved_lockfiles": resolved}
    return {"dir": str(out), "commit": commit, "inventory": inv, "edges": edges, "manifests": manifests, "actions": actions,
            "images": images, "vulns": vul, "ci": ci, "suspicious": suspicious, "summary": summary, "sbom_agreement": agree,
            "syft_error": syft_err, "sbom": {"guardian": str(sbom), "cyclonedx": str(out / "sbom.syft.cdx.json"),
                                             "spdx": str(out / "sbom.syft.spdx.json")}}


# ------------------------------------------------------------------ base vs head
def export_tree(repo: Path, ref: str, dest: Path):
    """`git archive` the commit into a clean folder (no hooks run; symlinks dropped)."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    tar = dest.parent / f"{dest.name}.tar"
    subprocess.run(["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", "archive", "--format=tar", "-o", str(tar), ref],
                   check=True, capture_output=True, timeout=300)
    with tarfile.open(tar) as t:
        members = [m for m in t.getmembers() if (m.isfile() or m.isdir()) and not m.name.startswith("/") and ".." not in Path(m.name).parts]
        t.extractall(dest, members=members, filter="data") if sys.version_info >= (3, 12) else t.extractall(dest, members=members)
    tar.unlink()


def _commit(repo: Path, ref: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{ref}^{{commit}}"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def _key(f: dict) -> tuple:
    return (f["type"], re.sub(r"@[^@#]*$", "", f["component"]) if f["type"] in ("install_script", "untrusted_source", "non_registry_source") else f["component"])


def change_signals(base: dict, head: dict, files: list[str], policy: dict) -> list[dict]:
    out = []
    bidx = {}
    for p in base["inventory"]:
        bidx.setdefault((p.get("ecosystem"), p["name"]), []).append(p)
    hidx = {}
    for p in head["inventory"]:
        hidx.setdefault((p.get("ecosystem"), p["name"]), []).append(p)
    allow_scripts = set((policy.get("install_scripts") or {}).get("allowlist", []))
    for k, ps in hidx.items():
        olds = bidx.get(k, [])
        for p in ps:
            comp = f"{p['name']}@{p['version'] or p.get('declared')}"
            prev = next((o for o in olds if o["version"] == p["version"]), None)
            if p.get("has_install_script") and p["name"] not in allow_scripts and not (prev and prev.get("has_install_script")):
                out.append({"detector": "D2", "type": "new_install_script", "severity": "high", "hard_signal": True, "component": comp,
                            "file": p.get("source_file"), "line": p.get("lockfile_line"),
                            "summary": "this change brings in a package version that runs code at install time"})
            if prev and prev.get("integrity") and p.get("integrity") and prev["integrity"] != p["integrity"]:
                out.append({"detector": "D7", "type": "lockfile_tamper", "severity": "critical", "hard_signal": True, "component": comp,
                            "file": p.get("source_file"), "line": p.get("lockfile_line"),
                            "summary": "same name and version, but the integrity hash in the lockfile changed: the code was swapped"})
            if prev and prev.get("resolved") and p.get("resolved") and urlparse(prev["resolved"]).netloc != urlparse(p["resolved"]).netloc:
                out.append({"detector": "D3", "type": "lockfile_tamper", "severity": "critical", "hard_signal": True, "component": comp,
                            "file": p.get("source_file"), "line": p.get("lockfile_line"),
                            "summary": f"download host changed from {urlparse(prev['resolved']).netloc} to {urlparse(p['resolved']).netloc}"})
            if olds and not prev and p["version"] and all(o["version"] for o in olds):
                try:
                    from packaging.version import Version
                    if all(Version(p["version"]) < Version(o["version"]) for o in olds):
                        out.append({"detector": "D5", "type": "suspicious_update", "severity": "medium", "hard_signal": False,
                                    "component": comp, "file": p.get("source_file"), "line": p.get("lockfile_line"),
                                    "summary": f"downgraded from {', '.join(o['version'] for o in olds)} (re-opens fixed bugs)"})
                except Exception:
                    pass
            if not olds and p.get("direct") and not p.get("first_party") and base["inventory"]:
                out.append({"detector": "D6", "type": "new_dependency", "severity": "info", "hard_signal": False, "component": comp,
                            "file": p.get("source_file"), "line": p.get("lockfile_line"),
                            "summary": f"new direct dependency added in {p.get('source_file')}"})
    changed = set(files)
    lockfiles = {m["path"] for m in head["manifests"] if m["role"] == "lockfile"}
    for lf in sorted(lockfiles & changed):
        folder = str(Path(lf).parent)
        sibs = {m["path"] for m in head["manifests"] if m["role"] == "manifest" and str(Path(m["path"]).parent) == folder}
        if sibs and not (sibs & changed):
            out.append({"detector": "D7", "type": "modified_lockfile", "severity": "medium", "hard_signal": False, "component": lf,
                        "file": lf, "line": None,
                        "summary": f"{lf} changed but {', '.join(sorted(sibs))} did not: check the lockfile edit was generated, not hand-made"})
    import fnmatch
    for f in sorted(changed):
        for pat in policy.get("sensitive_paths", []):
            if fnmatch.fnmatch(f, pat) or f == pat:
                out.append({"detector": "D4", "type": "sensitive_file_change", "severity": "medium", "hard_signal": False,
                            "component": f, "file": f, "line": None,
                            "summary": f"{f} changed: it controls how code is built, installed or run (policy: sensitive path)"})
                break
    return out


def _label(base: list[dict], head: list[dict], key) -> list[dict]:
    bk, hk = {key(x) for x in base}, {key(x) for x in head}
    return [{**x, "label": "pre_existing" if key(x) in bk else "introduced"} for x in head] + \
           [{**x, "label": "fixed"} for x in base if key(x) not in hk]


def _pkg_diff(b_inv: list[dict], h_inv: list[dict]) -> dict:
    def idx(inv):
        o: dict[str, set] = {}
        for p in inv:
            if not p.get("first_party"):
                o.setdefault(p["name"], set()).add(p["version"] or p.get("declared") or "?")
        return o
    b, h = idx(b_inv), idx(h_inv)
    return {"added": sorted(f"{n}@{v}" for n in h.keys() - b.keys() for v in h[n]),
            "removed": sorted(f"{n}@{v}" for n in b.keys() - h.keys() for v in b[n]),
            "updated": sorted(f"{n} {','.join(sorted(b[n]))} -> {','.join(sorted(h[n]))}" for n in h.keys() & b.keys() if h[n] != b[n])}


def check_any(repo: Path, base: str | None, head: str, out: Path, app: str, log=lambda m: None) -> dict:
    """Full Day 1 report for any git repository. base=None -> full scan of head (nothing is labelled 'introduced')."""
    repo, out = Path(repo).resolve(), Path(out).resolve()  # git -C <repo> would resolve relative output paths inside the repo
    out.mkdir(parents=True, exist_ok=True)
    policy = _policy()
    hc = _commit(repo, head)
    bc = _commit(repo, base) if base else hc
    log(f"Exporting commit {hc[:8]} (git archive: no hooks, no symlinks)")
    export_tree(repo, head, out / "trees" / "head")
    H = scan_tree(out / "trees" / "head", out / f"snap-{hc[:12]}", app, hc, log)
    files: list[str] = []
    if base and bc != hc:
        log(f"Scanning the previous state {bc[:8]} to find what changed")
        export_tree(repo, base, out / "trees" / "base")
        B = scan_tree(out / "trees" / "base", out / f"snap-{bc[:12]}", app, bc, log)
        files = [f for f in subprocess.run(["git", "-C", str(repo), "diff", "--name-only", bc, hc], capture_output=True, text=True).stdout.splitlines() if f]
    else:
        B = H
    vkey = lambda v: v["key"]  # noqa: E731
    vulns = _label(B["vulns"]["vulnerabilities"], H["vulns"]["vulnerabilities"], vkey)
    from guardian.inventory.ci_risk import label_ci
    ci = label_ci(B["ci"]["findings"], H["ci"]["findings"])
    sus = _label(B["suspicious"], H["suspicious"], _key)
    sus = [s for s in sus if s["label"] != "fixed"]
    drift_error = None
    if B is not H:
        sus += [{**s, "label": "introduced"} for s in change_signals(B, H, files, policy)]
        try:  # CI drift hard signals (D11 SHA -> tag, D12 history rewrite): git/JSON only, nothing is executed
            from guardian.detectors.ci_drift import action_sha_to_tag, history_rewrite
            sus += action_sha_to_tag(B["actions"], H["actions"]) + history_rewrite(repo, bc, hc)
        except Exception as e:
            drift_error = f"ci_drift {type(e).__name__}: {e}"[:200]
    # a package that newly runs install code: keep the strong "new_install_script" signal, drop the weak duplicate
    strong = {re.sub(r"@.*$", "", s["component"]) for s in sus if s["type"] == "new_install_script"}
    sus = [s for s in sus if not (s["type"] == "install_script" and re.sub(r"@.*$", "", s["component"]) in strong)]
    pkgs = _pkg_diff(B["inventory"], H["inventory"]) if B is not H else {"added": [], "removed": [], "updated": []}

    def count(items, lab):
        return {lv: sum(1 for x in items if x["label"] == lab and x["severity"] == lv) for lv in LEVELS[::-1]}
    intro_v = [v for v in vulns if v["label"] == "introduced"]
    intro_c = [c for c in ci if c["label"] == "introduced"]
    headline = {
        "base": base or head, "head": head, "app": app, "base_commit": bc[:12], "head_commit": hc[:12], "mode": "universal",
        "repo_path": str(Path(repo).resolve()), "base_sha": bc if base else None, "head_sha": hc,
        "inventory": {**H["summary"], "workflows": H["summary"]["workflows"]},
        "sbom_agreement_pct": H["sbom_agreement"],
        "changes": {"files": files, **{k: len(v) for k, v in pkgs.items()}},
        "vulnerabilities": {"introduced": count(vulns, "introduced"), "pre_existing": count(vulns, "pre_existing"),
                            "fixed": count(vulns, "fixed"), "malicious_introduced": [v["key"] for v in intro_v if v["malicious"]],
                            "scanners": H["vulns"]["counts"], "errors": H["vulns"]["errors"]},
        "ci_image": {"introduced": len(intro_c), "pre_existing": sum(1 for c in ci if c["label"] == "pre_existing"),
                     "fixed": sum(1 for c in ci if c["label"] == "fixed"), "actions": H["ci"]["actions"], "images": H["ci"]["images"],
                     "errors": H["ci"]["errors"]},
        "suspicious_changes": [f"[{x['severity']}] {x['type']}: {x['component']} - {x['summary']}" for x in sus],
        "suspicious_error": drift_error, "syft_error": H["syft_error"],
    }
    report = {"headline": headline, "package_changes": pkgs, "suspicious_changes": sus, "vulnerabilities": vulns, "ci_image": ci,
              "inventory": H["inventory"], "actions": H["actions"], "images": H["images"], "manifests": H["manifests"],
              "sbom": H["sbom"], "runs": {"base": B["dir"], "head": H["dir"]}}
    path = out / f"report-{bc[:8]}-{hc[:8]}.json"
    path.write_text(json.dumps(report, indent=1))
    pointer = {"path": str(path)}
    try:
        from guardian.scoring.contextual_score import score_with_context
        from guardian.scoring.states import stages
        scores = score_with_context(report, out, src=out / "trees" / "head")  # reachability reads the full head tree
        spath = out / f"scores-{bc[:8]}-{hc[:8]}.json"
        spath.write_text(json.dumps(scores, indent=1))
        pointer["scores"] = str(spath)
        report["headline"]["verdict"] = scores["verdict"]
        report["headline"]["verdict_reasons"] = scores["reasons"]
        report["headline"]["complete"] = scores["complete"]
        report["headline"]["incomplete_reasons"] = scores["incomplete_reasons"]
        report["headline"]["blocking"] = scores["verdict"] == "block"
        report["headline"]["stages"] = stages(report["headline"], compared=B is not H, scored=True)
        path.write_text(json.dumps(report, indent=1))
    except Exception as e:
        pointer["scores_error"] = f"{type(e).__name__}: {e}"[:300]
        report["headline"].update(verdict=None, complete=False, blocking=None,
                                  incomplete_reasons=[f"scoring: {pointer['scores_error']}"])
        report["headline"]["stages"] = stages(report["headline"], compared=B is not H, scored=False)
        path.write_text(json.dumps(report, indent=1))
    shutil.rmtree(out / "trees", ignore_errors=True)  # after scoring: reachability needed the full exported head tree
    (out / "latest.json").write_text(json.dumps(pointer))
    return {**report, "path": str(path)}
