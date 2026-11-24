"""Fixtures for the remediation tests: a tiny scored report + a project tree on disk, all offline (no network, no scanners)."""
import json
import subprocess

import pytest

from guardian.remediation.context import RemediationContext
from guardian.remediation.service import Remediator
from guardian.remediation.store import RemediationStore
from guardian.remediation.upgrade_safety import Providers
from guardian.scoring.contextual.pipeline import enrich
from guardian.scoring.score import score_report
from tests.contextual_scoring.conftest import fake_lookup, offline, report  # noqa: F401  (fixtures + helpers reused)

HEAD_PKG = {"name": "demo-app", "version": "1.0.0", "engines": {"node": ">=18"},
            "dependencies": {"foo": "^1.2.0", "axois": "1.0.0"}, "devDependencies": {"devtool": "~0.5.0"}}
BASE_PKG = {"name": "demo-app", "version": "1.0.0", "engines": {"node": ">=18"}, "dependencies": {"foo": "^1.2.0"}, "devDependencies": {"devtool": "~0.5.0"}}

MANIFESTS = {  # (name, version) -> registry manifest used by the upgrade-safety predictor
    ("foo", "1.2.0"): {"name": "foo", "version": "1.2.0", "main": "index.js"},
    ("foo", "1.2.4"): {"name": "foo", "version": "1.2.4", "main": "index.js", "engines": {"node": ">=14"}},
    ("foo", "2.0.0"): {"name": "foo", "version": "2.0.0", "main": "dist/index.js", "type": "module", "engines": {"node": ">=20"},
                       "exports": {".": "./dist/index.js"}, "peerDependencies": {"react": "^18"}},
    ("bar", "3.0.0"): {"name": "bar", "version": "3.0.0"},
    ("bar", "3.0.1"): {"name": "bar", "version": "3.0.1"},
}


def fake_providers(osv=None, manifests=None):
    m = manifests if manifests is not None else MANIFESTS
    return Providers(manifest=lambda n, v: m.get((n, v)), osv=lambda n, v: (osv or {}).get((n, v), []), specs=lambda src: {"foo": {"foo", "foo/lib/util"}})


def write_tree(root, pkg):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")
    (root / "package-lock.json").write_text('{"lockfileVersion": 3}\n')
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "main.js").write_text("const foo = require('foo');\n")
    return root


@pytest.fixture
def trees(tmp_path):
    return write_tree(tmp_path / "head", HEAD_PKG), write_tree(tmp_path / "base", BASE_PKG)


@pytest.fixture
def ctx(report, trees):  # noqa: F811
    head, base = trees
    sc = enrich(score_report(report), report, affected_lookup=fake_lookup, fix_for="all")
    return RemediationContext(sc, report, src=head, base_src=base, affected_lookup=fake_lookup)


@pytest.fixture
def store(tmp_path):
    return RemediationStore("REM-TEST", base=tmp_path / "rem")


@pytest.fixture
def rem(ctx, store):
    return Remediator(ctx, store, fake_providers())


def have_git():
    try:
        return subprocess.run(["git", "--version"], capture_output=True).returncode == 0
    except OSError:
        return False
