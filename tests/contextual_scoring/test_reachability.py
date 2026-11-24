import json
import os

from guardian.scoring.contextual import reachability as r


def _w(p, rel, text):
    f = p / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def test_package_of_normalises_specifiers():
    assert r.package_of("lodash/fp") == "lodash"
    assert r.package_of("@scope/pkg/sub/file") == "@scope/pkg"
    for skip in ("./a", "../b", "/abs", "node:fs", "#internal", "@/alias", "virtual:x"):
        assert r.package_of(skip) is None


def test_import_scan_finds_all_forms_and_ignores_node_modules_and_tests(tmp_path):
    _w(tmp_path, "server/a.js", "const x = require('express');\nimport y from 'axios';\nconst z = await import('chalk');\nimport 'side-effect-pkg';\n")
    _w(tmp_path, "src/b.vue", "<script>\nimport { ref } from 'vue'\n</script>\n")
    _w(tmp_path, "node_modules/evil/index.js", "require('should-not-count')")
    _w(tmp_path, "test/t.js", "require('mocha')")
    _w(tmp_path, "server/dyn.js", "const m = require(name);")
    res = r.scan_imports(tmp_path)
    assert set(res["runtime"]) == {"express", "axios", "chalk", "side-effect-pkg", "vue"}
    assert res["runtime"]["axios"] == ["server/a.js:2"]
    assert "should-not-count" not in res["runtime"] and "mocha" in res["test"] and "mocha" not in res["runtime"]
    assert res["dynamic_requires"] == 1  # reported as a limitation, never resolved or executed


def test_scan_does_not_execute_code(tmp_path):
    marker = tmp_path / "ran.txt"
    _w(tmp_path, "a.js", f"require('fs').writeFileSync({json.dumps(str(marker))}, 'x'); require('real')")
    r.scan_imports(tmp_path)
    assert not marker.exists()


def _inv():
    return [{"key": "node_modules/express", "name": "express", "version": "4.0.0", "runtime": True},
            {"key": "node_modules/qs", "name": "qs", "version": "6.0.0", "runtime": True},
            {"key": "node_modules/lonely", "name": "lonely", "version": "1.0.0", "runtime": True},
            {"key": "node_modules/mocha", "name": "mocha", "version": "9.0.0", "runtime": False},
            {"key": "node_modules/bundled", "name": "bundled", "version": "1.0.0", "runtime": False}]


def test_tiers_transitive_via_import_declared_and_dev_only():
    edges = [{"parent": "", "child": "node_modules/express", "kind": "prod"}, {"parent": "node_modules/express", "child": "node_modules/qs", "kind": "prod"},
             {"parent": "", "child": "node_modules/lonely", "kind": "prod"}, {"parent": "", "child": "node_modules/mocha", "kind": "dev"},
             {"parent": "node_modules/express", "child": "node_modules/mocha", "kind": "dev"}]
    imports = {"runtime": {"express": ["server/a.js:1"], "bundled": ["src/x.js:2"]}, "test": {"lonely": ["test/t.js:1"]}, "files": 2, "dynamic_requires": 0}
    t = r.tiers(_inv(), edges, imports)
    assert t["node_modules/express"]["tier"] == "imported" and t["node_modules/express"]["via"] is None
    assert t["node_modules/qs"]["tier"] == "imported" and t["node_modules/qs"]["via"] == "express"
    assert t["node_modules/lonely"]["tier"] == "declared" and "test code" in t["node_modules/lonely"]["method"]
    assert t["node_modules/mocha"]["tier"] == "dev_only" and not t["node_modules/mocha"].get("possibly_shipped")
    assert t["node_modules/bundled"]["tier"] == "dev_only" and t["node_modules/bundled"]["possibly_shipped"]  # flagged, not discounted further
    assert all(v["estimated"] for v in t.values())


def test_dev_edge_does_not_make_a_package_reachable():
    edges = [{"parent": "", "child": "node_modules/express", "kind": "prod"}, {"parent": "node_modules/express", "child": "node_modules/qs", "kind": "dev"}]
    t = r.tiers(_inv()[:2], edges, {"runtime": {"express": ["a.js:1"]}, "test": {}, "files": 1, "dynamic_requires": 0})
    assert t["node_modules/qs"]["tier"] == "declared"


def test_non_npm_stays_unknown():
    inv = [{"key": "k", "name": "requests", "version": "2", "runtime": True, "ecosystem": "pypi"}]
    assert r.tiers(inv, [], {"runtime": {}, "test": {}, "files": 0, "dynamic_requires": 0})["k"]["tier"] == "unknown"


def test_for_report_without_source_returns_empty_not_a_guess(report):
    assert r.for_report(report) == {}


def test_symlinked_files_are_skipped(tmp_path):
    if not hasattr(os, "symlink"):
        return
    outside = tmp_path / "outside.js"
    outside.write_text("require('secret-pkg')")
    src = tmp_path / "src"
    src.mkdir()
    try:
        os.symlink(outside, src / "link.js")
    except (OSError, NotImplementedError):
        return  # symlinks need privileges on Windows
    assert "secret-pkg" not in r.scan_imports(src)["runtime"]
