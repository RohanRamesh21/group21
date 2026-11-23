"""Static checks of build files for ecosystems without an npm-style lockfile: C/C++, Java, Go (and Python
transport settings). Text parsing only: no build tool, wrapper, conanfile.py or CMake script is ever run.

Components found here (each records the file and line it came from):
  * vcpkg.json dependencies, conanfile.txt requires, CMake FetchContent/ExternalProject sources, meson wraps,
    git submodules, and Gradle dependencies declared in build.gradle(.kts)

Detectors (each finding cites file:line):
  D15 unpinned_source_fetch / unverified_download   C/C++ sources fetched at build time without a commit SHA or hash
  D17 unverified_build_tool                         Gradle/Maven wrapper downloads a build tool without a checksum
  D18 module_replaced / missing_checksums / checksum_bypass   Go module integrity switched off or redirected
  D19 insecure_transport / extra_repository / dynamic_version  plain-HTTP sources, extra package repositories,
                                                    versions that float ('1.+', 'latest.release', version ranges)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$", re.I)
# folders whose contents are not shipped with the application (tests, docs, examples, benchmarks, tooling)
NON_SHIPPED_DIRS = {"test", "tests", "testing", "doc", "docs", "example", "examples", "bench", "benchmark", "benchmarks", "tools"}


def non_shipped(path: str) -> bool:
    return bool({p.lower() for p in Path(path).parts[:-1]} & NON_SHIPPED_DIRS)
DEFAULT_MAVEN_HOSTS = {"repo.maven.apache.org", "repo1.maven.org", "maven.google.com", "dl.google.com",
                       "plugins.gradle.org", "services.gradle.org"}
GRADLE_DEP = re.compile(
    r"""\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt|classpath)"""
    r"""\s*\(?\s*["']([\w.\-]+):([\w.\-]+):([^"'$\s)]+)["']""")
GO_BYPASS = [(re.compile(r"\bGOSUMDB\s*[=:]\s*['\"]?off\b"), "high", "GOSUMDB=off switches off Go's public checksum database"),
             (re.compile(r"\bGONOSUMCHECK\s*[=:]\s*['\"]?1\b"), "high", "GONOSUMCHECK=1 skips checksum verification"),
             (re.compile(r"\bGOFLAGS\s*[=:][^\n]*-insecure\b"), "high", "GOFLAGS -insecure allows plain-HTTP module downloads"),
             (re.compile(r"\bGOINSECURE\s*[=:]\s*\S"), "high", "GOINSECURE allows plain-HTTP module downloads"),
             (re.compile(r"\bGONOSUMDB\s*[=:]\s*\S"), "medium", "GONOSUMDB exempts modules from the checksum database")]


def _read(p: Path, limit: int = 2_000_000) -> str:
    try:
        return "" if p.stat().st_size > limit else p.read_text(errors="replace")
    except OSError:
        return ""


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _finding(det: str, typ: str, sev: str, comp: str, file: str, line: int | None, summary: str, hard: bool = False) -> dict:
    return {"detector": det, "type": typ, "severity": sev, "hard_signal": hard, "component": comp, "file": file,
            "line": line, "summary": summary}


def _component(eco: str, name: str, version: str, purl: str, file: str, line: int | None, how: str, dev: bool = False,
               pinned: bool = True, resolved: str | None = None) -> dict:
    return {"key": f"{eco}:{name}@{version}#{file}", "name": name, "version": version if pinned else "", "declared": version,
            "purl": purl, "ecosystem": eco, "direct": True, "dev": dev or non_shipped(file), "runtime": not (dev or non_shipped(file)),
            "optional": False,
            "resolved": resolved, "integrity": None, "has_install_script": False, "license": None, "alias": None,
            "lockfile_line": line, "source_file": file, "origin": "declared in build file", "pinned": pinned,
            "found_by": f"guardian build-file reader ({how})"}


def _http(url: str) -> bool:
    return url.lower().startswith("http://")


# ------------------------------------------------------------------ C / C++
def vcpkg(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    text = _read(src / rel)
    try:
        doc = json.loads(text)
    except ValueError:
        return [], []
    comps, finds = [], []
    overrides = {o.get("name"): o.get("version") for o in doc.get("overrides", []) if isinstance(o, dict)}
    for d in doc.get("dependencies", []):
        name = d if isinstance(d, str) else d.get("name", "")
        ver = overrides.get(name) or ("" if isinstance(d, str) else d.get("version>=", ""))
        line = _line(text, text.find(f'"{name}"')) if f'"{name}"' in text else None
        comps.append(_component("vcpkg", name, ver, f"pkg:generic/vcpkg/{name}" + (f"@{ver}" if ver else ""), rel, line, "vcpkg.json",
                                pinned=bool(overrides.get(name))))
    has_cfg_baseline = '"baseline"' in _read(src / Path(rel).with_name("vcpkg-configuration.json"))
    if doc.get("dependencies") and not doc.get("builtin-baseline") and not has_cfg_baseline:
        finds.append(_finding("D15", "unpinned_source_fetch", "medium", rel, rel, 1,
                              f"{rel} has no builtin-baseline: dependency versions follow whatever vcpkg checkout builds it"))
    return comps, finds


def conanfile_txt(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    text, comps, finds, section = _read(src / rel), [], [], None
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.split("#", 1)[0].strip()
        if s.startswith("["):
            section = s.strip("[]").strip()
            continue
        if section in ("requires", "tool_requires", "build_requires") and "/" in s:
            name, ver = s.split("@", 1)[0].split("/", 1)
            ranged = ver.startswith("[")
            comps.append(_component("conan", name, ver, f"pkg:conan/{name}@{ver}", rel, i, "conanfile.txt",
                                    dev=section != "requires", pinned=not ranged))
            if ranged:
                finds.append(_finding("D19", "dynamic_version", "low", f"{name}/{ver}", rel, i,
                                      f"{rel}:{i} asks for a version range {ver}: the resolved version can change between builds"))
    if comps and not (src / Path(rel).with_name("conan.lock")).exists():
        finds.append(_finding("D15", "missing_lockfile", "low", rel, rel, None,
                              f"{rel} has no conan.lock next to it: transitive versions and recipe revisions are not pinned"))
    return comps, finds


CMAKE_BLOCK = re.compile(r"\b(FetchContent_Declare|ExternalProject_Add)\s*\(\s*([\w.\-]+)([^)]*)\)", re.I | re.S)


def cmake(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    text, comps, finds = _read(src / rel), [], []
    for m in CMAKE_BLOCK.finditer(text):
        kind, name, body = m.group(1), m.group(2), m.group(3)
        line = _line(text, m.start())
        args = dict(re.findall(r"\b(GIT_REPOSITORY|GIT_TAG|URL|URL_HASH|URL_MD5)\s+\"?([^\s\")]+)", body))
        repo, tag, url = args.get("GIT_REPOSITORY"), args.get("GIT_TAG"), args.get("URL")
        where = f"{rel}:{line}"
        if repo:
            pinned = bool(tag and SHA.match(tag))
            comps.append(_component("cmake", name, tag or "", f"pkg:generic/{name}" + (f"@{tag}" if tag else ""), rel, line,
                                    kind, pinned=pinned, resolved=repo))
            if not pinned and "${" in repo:  # the source is a CMake variable: cannot be resolved statically
                finds.append(_finding("D15", "unpinned_source_fetch", "low", f"{name}@{tag or 'default branch'}", rel, line,
                                      f"{where} {kind} pulls {repo} (a CMake variable, not resolved statically) at "
                                      f"'{tag or 'the default branch'}', not a commit SHA"))
            elif not pinned:
                finds.append(_finding("D15", "unpinned_source_fetch", "medium", f"{name}@{tag or 'default branch'}", rel, line,
                                      f"{where} {kind} pulls {repo} at '{tag or 'the default branch'}', not a commit SHA: "
                                      "whoever controls that repository can change what gets built"))
            if _http(repo):
                finds.append(_finding("D19", "insecure_transport", "high", name, rel, line, f"{where} fetches {repo} over plain HTTP"))
        elif url:
            hashed = bool(args.get("URL_HASH") or args.get("URL_MD5"))
            ver = (re.search(r"(\d+(?:[._]\d+)+)(?:\.tar|\.zip|\.tgz|\.t[bgx]z)", url) or re.search(r"(\d+(?:[._]\d+)+)", url))
            ver = ver.group(1).replace("_", ".") if ver else ""
            # an archive verified by URL_HASH is pinned: the build gets exactly these bytes
            comps.append(_component("cmake", name, ver, f"pkg:generic/{name}" + (f"@{ver}" if ver else ""), rel, line, kind,
                                    pinned=hashed and bool(ver), resolved=url))
            if not hashed:
                finds.append(_finding("D15", "unverified_download", "medium", name, rel, line,
                                      f"{where} downloads {url} without URL_HASH: a changed archive would be built silently"))
            if _http(url):
                finds.append(_finding("D19", "insecure_transport", "high", name, rel, line, f"{where} downloads {url} over plain HTTP"))
    return comps, finds


def meson_wrap(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    text = _read(src / rel)
    kv = dict(re.findall(r"^\s*([\w-]+)\s*=\s*(.+?)\s*$", text, re.M))
    name, comps, finds = Path(rel).stem, [], []
    if "[wrap-git]" in text:
        rev = kv.get("revision", "")
        comps.append(_component("meson", name, rev, f"pkg:generic/{name}", rel, 1, "meson wrap", pinned=bool(SHA.match(rev)),
                                resolved=kv.get("url")))
        if not SHA.match(rev):
            finds.append(_finding("D15", "unpinned_source_fetch", "medium", name, rel, None,
                                  f"{rel} pulls {kv.get('url')} at '{rev or 'HEAD'}', not a commit SHA"))
    elif "[wrap-file]" in text:
        comps.append(_component("meson", name, "", f"pkg:generic/{name}", rel, 1, "meson wrap", pinned=False,
                                resolved=kv.get("source_url")))
        if not kv.get("source_hash"):
            finds.append(_finding("D15", "unverified_download", "medium", name, rel, None,
                                  f"{rel} downloads {kv.get('source_url')} without source_hash"))
    url = kv.get("url") or kv.get("source_url") or ""
    if _http(url):
        finds.append(_finding("D19", "insecure_transport", "high", name, rel, None, f"{rel} fetches {url} over plain HTTP"))
    return comps, finds


def gitmodules(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    """Submodules are pinned by the parent commit (gitlink), so only the transport is checked here."""
    text, comps, finds = _read(src / rel), [], []
    for m in re.finditer(r"\[submodule \"([^\"]+)\"\][^\[]*?url\s*=\s*(\S+)", text):
        name, url = m.group(1), m.group(2)
        line = _line(text, m.start())
        comps.append(_component("git-submodule", name, "", f"pkg:generic/{name}", rel, line, ".gitmodules", pinned=True, resolved=url))
        if _http(url) or url.startswith("git://"):
            finds.append(_finding("D19", "insecure_transport", "high", name, rel, line,
                                  f"{rel}:{line} submodule {name} uses {url.split(':', 1)[0]}:// (no transport security)"))
    return comps, finds


# ------------------------------------------------------------------ Java
def wrapper_properties(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    text = _read(src / rel)
    kv = dict(re.findall(r"^\s*([\w.]+)\s*=\s*(.+?)\s*$", text, re.M))
    url = kv.get("distributionUrl", "").replace("\\:", ":")
    tool = "Gradle" if "gradle" in rel else "Maven"
    finds = []
    line = next((i for i, ln in enumerate(text.splitlines(), 1) if ln.strip().startswith("distributionUrl")), None)
    if url and not kv.get("distributionSha256Sum"):
        finds.append(_finding("D17", "unverified_build_tool", "medium", rel, rel, line,
                              f"{rel} downloads {tool} from {url} without distributionSha256Sum: a swapped build tool runs on every build"))
    if _http(url):
        finds.append(_finding("D19", "insecure_transport", "high", rel, rel, line, f"{rel} downloads {tool} over plain HTTP ({url})"))
    return [], finds


def _repo_findings(rel: str, text: str, urls: list[tuple[str, int]]) -> list[dict]:
    finds = []
    for url, pos in urls:
        line, host = _line(text, pos), re.sub(r"^\w+://([^/:]+).*$", r"\1", url).lower()
        if _http(url):
            finds.append(_finding("D19", "insecure_transport", "high", host, rel, line, f"{rel}:{line} uses package repository {url} over plain HTTP"))
        elif host not in DEFAULT_MAVEN_HOSTS:
            finds.append(_finding("D19", "extra_repository", "medium", host, rel, line,
                                  f"{rel}:{line} adds package repository {url}: a second repository can serve a same-named "
                                  "artifact (dependency confusion)"))
    return finds


def gradle(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    text, comps, finds = _read(src / rel), [], []
    for m in GRADLE_DEP.finditer(text):
        conf, group, art, ver = m.groups()
        line = _line(text, m.start())
        dynamic = "+" in ver or ver.startswith(("latest.", "[", "(")) or ver.endswith("-SNAPSHOT")
        comps.append(_component("maven", f"{group}:{art}", ver, f"pkg:maven/{group}/{art}@{ver}", rel, line, "build.gradle",
                                dev=conf.startswith("test"), pinned=not dynamic))
        if dynamic:
            finds.append(_finding("D19", "dynamic_version", "medium", f"{group}:{art}:{ver}", rel, line,
                                  f"{rel}:{line} uses version '{ver}' for {group}:{art}: it resolves to whatever is newest at build time"))
    urls = [(m.group(1), m.start()) for m in
            re.finditer(r"""(?:\burl\s*(?:=\s*uri\s*\(|=|\()?|\bmaven\s*\()\s*["']([^"']+)["']""", text)]
    return comps, finds + _repo_findings(rel, text, urls)


def pom(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    """Dependencies in pom.xml are listed by Syft; here only repositories and floating versions are checked."""
    text = _read(src / rel)
    # only where dependencies and plugins come FROM; <distributionManagement> is where releases are published TO
    urls = [(u.group(1).strip(), blk.start() + u.start())
            for blk in re.finditer(r"<(repositories|pluginRepositories)>.*?</\1>", text, re.S)
            for u in re.finditer(r"<url>([^<]+)</url>", blk.group(0))]
    finds = _repo_findings(rel, text, urls)
    for m in re.finditer(r"<artifactId>([^<]+)</artifactId>\s*<version>\s*(\[[^<]*|\([^<]*|LATEST|RELEASE)\s*</version>", text):
        line = _line(text, m.start())
        finds.append(_finding("D19", "dynamic_version", "medium", m.group(1), rel, line,
                              f"{rel}:{line} uses version '{m.group(2)}' for {m.group(1)}: it can change between builds"))
    return [], finds


# ------------------------------------------------------------------ Go
def go_mod(src: Path, rel: str) -> tuple[list[dict], list[dict]]:
    text, finds = _read(src / rel), []
    for m in re.finditer(r"^\s*(?:replace\s+)?([\w./\-]+)(?:\s+v[\w.\-+]+)?\s*=>\s*(\S+)(?:\s+(v[\w.\-+]+))?", text, re.M):
        old, new, ver = m.groups()
        line = _line(text, m.start())
        local = new.startswith((".", "/"))
        finds.append(_finding("D18", "module_replaced", "low" if local else "medium", old, rel, line,
                              f"{rel}:{line} replaces {old} with " + (f"the local folder {new}" if local else f"{new} {ver or ''}".strip())
                              + ": the code built is not the module the version suggests"))
    requires = re.search(r"^\s*require\b", text, re.M)
    if requires and not (src / Path(rel).with_name("go.sum")).exists():
        finds.append(_finding("D18", "missing_checksums", "medium", rel, rel, None,
                              f"{rel} requires modules but there is no go.sum next to it: downloads cannot be verified"))
    return [], finds


def go_env(src: Path, rel: str) -> list[dict]:
    text, finds = _read(src / rel, 1_000_000), []
    for rx, sev, why in GO_BYPASS:
        for m in rx.finditer(text):
            line = _line(text, m.start())
            finds.append(_finding("D18", "checksum_bypass", sev, m.group(0).strip()[:60], rel, line, f"{rel}:{line}: {why}"))
    return finds


# ------------------------------------------------------------------ Python transport
def requirements(src: Path, rel: str) -> list[dict]:
    text, finds = _read(src / rel), []
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.strip()
        if s.startswith("--trusted-host") or re.match(r"^trusted-host\s*=", s):
            finds.append(_finding("D19", "insecure_transport", "high", rel, rel, i,
                                  f"{rel}:{i} marks a host as trusted: pip will accept it without valid HTTPS"))
        elif re.search(r"(?:^|\s|=)http://", s):
            finds.append(_finding("D19", "insecure_transport", "high", rel, rel, i, f"{rel}:{i} installs over plain HTTP: {s[:90]}"))
    return finds


# ------------------------------------------------------------------ entry point
def scan(src: Path, manifests: list[dict]) -> tuple[list[dict], list[dict]]:
    """All build-file components and findings for the manifests found by `universal.find_manifests`. Go checksum
    switches are looked for in CI workflows, container files and scripts (Makefiles, *.sh, .envrc)."""
    comps, finds = [], []
    for m in manifests:
        rel, name = m["path"], Path(m["path"]).name
        parser = {"vcpkg.json": vcpkg, "conanfile.txt": conanfile_txt, "CMakeLists.txt": cmake, ".gitmodules": gitmodules,
                  "gradle-wrapper.properties": wrapper_properties, "maven-wrapper.properties": wrapper_properties,
                  "build.gradle": gradle, "build.gradle.kts": gradle, "pom.xml": pom, "go.mod": go_mod}.get(name)
        if parser is None and name.endswith(".cmake"):
            parser = cmake
        if parser is None and name.endswith(".wrap") and "subprojects" in Path(rel).parts:
            parser = meson_wrap
        if parser:
            c, f = parser(src, rel)
            comps += c
            finds += f
        if (m["ecosystem"] == "pypi" and name.lower().startswith("requirements")) or name == "pip.conf":
            finds += requirements(src, rel)
        if m["role"] in ("ci", "container", "script"):
            finds += go_env(src, rel)
    return comps, finds
