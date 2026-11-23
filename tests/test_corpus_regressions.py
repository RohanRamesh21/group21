"""Regressions for false positives found by scanning real apps (testbed/corpus.yaml, docs/TESTING.md).

Each test is a minimal copy of the real pattern, so it runs offline without the corpus.
"""
import json

from guardian import universal as u
from guardian.adapters import build_files as bf
from guardian.inventory.ci_risk import ci_image_scan


def _write(root, files):
    for path, text in files.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_optional_and_type_only_imports_are_not_undeclared(tmp_path):
    """requests/flask: optional imports with a fallback, TYPE_CHECKING imports, py2 fallbacks, extras, examples/docs."""
    _write(tmp_path, {
        "pyproject.toml": '[project]\nname = "app"\ndependencies = ["click>=8"]\n[project.optional-dependencies]\nasync = ["asgiref>=3.2"]\n',
        "src/app/core.py": (
            "import typing as t\nimport click\ntry:\n    import simplejson as json\nexcept ImportError:\n    import json\n"
            "try:\n    from StringIO import StringIO\nexcept (ImportError, AttributeError):\n    from io import StringIO\n"
            "if t.TYPE_CHECKING:\n    import typing_extensions as te\n"
            "def f():\n    from asgiref.sync import async_to_sync\n    import yaml\n"),
        "setup.py": "from setuptools import setup\nsetup()\n",
        "docs/conf.py": "import pallets_sphinx_themes\n",
        "examples/demo/app.py": "import redis\n",
    })
    found = {f["component"] for f in u.undeclared_imports(tmp_path, [], u.find_manifests(tmp_path))}
    assert found == {"pypi:pyyaml"}  # the only real one: a required import nobody declares


def test_requirements_folder_files_are_requirements(tmp_path):
    """flask: requirements/docs.txt, requirements/tests.in."""
    _write(tmp_path, {"requirements/docs.txt": "sphinx==8.1.3\n", "requirements/tests.in": "pytest\n"})
    roles = {m["path"]: (m["ecosystem"], m["role"]) for m in u.find_manifests(tmp_path)}
    assert roles == {"requirements/docs.txt": ("pypi", "lockfile"), "requirements/tests.in": ("pypi", "manifest")}


def test_docs_and_tools_requirements_are_not_runtime():
    """nlohmann/json: docs/mkdocs/requirements.txt was scored as shipped runtime code."""
    doc = {"components": [
        {"bom-ref": "a", "name": "mkdocs", "version": "1.5.3", "purl": "pkg:pypi/mkdocs@1.5.3",
         "properties": [{"name": "syft:location:0:path", "value": "/docs/mkdocs/requirements.txt"}]},
        {"bom-ref": "b", "name": "flask", "version": "3.1.0", "purl": "pkg:pypi/flask@3.1.0",
         "properties": [{"name": "syft:location:0:path", "value": "/requirements.txt"}]}]}
    inv, _ = u._syft_inventory(doc, set())
    assert {p["name"]: p["runtime"] for p in inv} == {"mkdocs": False, "flask": True}


def test_pom_distribution_management_is_not_a_dependency_source(tmp_path):
    """google/gson: <distributionManagement> (where releases are published) was flagged as an extra repository."""
    _write(tmp_path, {"pom.xml": """<project>
  <distributionManagement><repository><url>https://oss.sonatype.org/service/local/staging/deploy/maven2/</url></repository></distributionManagement>
  <pluginRepositories><pluginRepository><url>https://plugins.example.com/maven</url></pluginRepository></pluginRepositories>
  <repositories><repository><url>http://nexus.example.com/repo</url></repository></repositories>
</project>"""})
    _, finds = bf.pom(tmp_path, "pom.xml")
    assert sorted((f["type"], f["component"]) for f in finds) == [("extra_repository", "plugins.example.com"),
                                                                  ("insecure_transport", "nexus.example.com")]


def test_cmake_url_with_hash_is_pinned_and_variable_sources_are_low(tmp_path):
    """libcpr/cpr: URL + URL_HASH downloads counted as unpinned; nlohmann/json: ${VAR} repositories rated medium."""
    _write(tmp_path, {"CMakeLists.txt": """
FetchContent_Declare(curl
    URL https://github.com/curl/curl/releases/download/curl-8_10_1/curl-8.10.1.tar.xz
    URL_HASH SHA256=73a4b0e99596a09fa5924a4fb7e4b995a85fda0d18a2c02ab9cf134bebce04ee # the file hash
    USES_TERMINAL_DOWNLOAD TRUE)
FetchContent_Declare(json GIT_REPOSITORY ${GIT_REPOSITORY_DIRECTORY} GIT_TAG HEAD)
"""})
    comps, finds = bf.cmake(tmp_path, "CMakeLists.txt")
    assert {c["name"]: c["version"] for c in comps} == {"curl": "8.10.1", "json": ""}
    assert [(f["type"], f["severity"]) for f in finds] == [("unpinned_source_fetch", "low")]


def test_unpinned_action_is_reported_once(tmp_path, monkeypatch):
    """Every repo: D10 and zizmor's unpinned-uses reported the same step twice (zizmor at `- name:`, D10 at `uses:`)."""
    from guardian.inventory import ci_risk
    zizmor = [{"detector": "D9", "type": "ci_unpinned_uses", "severity": "high", "component": ".github/workflows/ci.yml",
               "file": ".github/workflows/ci.yml", "line": 6, "summary": "unpinned", "url": None,
               "excerpt": "name: Checkout\n        uses: actions/checkout@v4\n"},  # zizmor points at the step start
              {"detector": "D9", "type": "ci_unpinned_uses", "severity": "high", "component": ".github/workflows/ci.yml",
               "file": ".github/workflows/ci.yml", "line": 12, "summary": "docker image", "excerpt": "", "url": None}]
    monkeypatch.setattr(ci_risk, "zizmor_findings", lambda src: (zizmor, None))
    actions = [{"workflow": ".github/workflows/ci.yml", "uses": "actions/checkout@v4", "pinned_sha": False, "first_party": True, "line": 7}]
    got = ci_image_scan(tmp_path, actions, [])["findings"]
    assert sorted((f["type"], f["line"]) for f in got) == [("action_not_pinned", 7), ("ci_unpinned_uses", 12)]
    assert json.dumps(got)  # still serialisable


def test_fallback_and_flag_guarded_imports_are_optional(tmp_path):
    """psf/requests: fallbacks in the ImportError handler, and `if has_simplejson: from simplejson import ...`."""
    _write(tmp_path, {"setup.py": "from setuptools import setup\nsetup()\n", "src/pkg/compat.py": (
        "has_simplejson = False\ntry:\n    import simplejson as json\n    has_simplejson = True\nexcept ImportError:\n    import json\n"
        "if has_simplejson:\n    from simplejson import JSONDecodeError\n"
        "try:\n    import threading\nexcept ImportError:\n    import dummy_threading as threading\n")})
    assert u.undeclared_imports(tmp_path, [], u.find_manifests(tmp_path)) == []


def test_repeated_action_gets_its_own_line():
    """Every repo: D10 gave each repeated `uses:` the line of its first occurrence, so it never matched zizmor."""
    from guardian.inventory.ci_image import parse_workflow
    wf = ("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n  b:\n    steps:\n      - name: x\n"
          "        uses: actions/checkout@v4 # v4.2\n      - uses: actions/checkout@v4\n")
    assert [(a.line, a.version_comment) for a in parse_workflow("ci.yml", wf)] == [(4, None), (8, "v4.2"), (9, None)]
