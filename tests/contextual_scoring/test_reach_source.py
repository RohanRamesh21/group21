"""Reachability must read real first-party source code. Found live: our scan folder's src/ holds only manifests, so
every runtime package came out 'declared' (no import found) and CVE exposure was lowered for all of them."""
import json

from guardian.scoring import contextual_score as cs


def _report(tmp_path):
    head = tmp_path / "snap"
    (head / "src").mkdir(parents=True)
    (head / "src" / "package.json").write_text("{}")  # manifests only, like our scan folder
    (head / "edges.json").write_text(json.dumps([{"parent": "", "child": "node_modules/foo", "kind": "prod"}]))
    inv = [{"key": "node_modules/foo", "name": "foo", "version": "1.0.0", "direct": True, "runtime": True, "ecosystem": "npm"}]
    vulns = [{"key": "foo@1.0.0#GHSA-1", "component_key": "node_modules/foo", "label": "pre_existing"}]
    return {"inventory": inv, "vulnerabilities": vulns, "runs": {"head": str(head)}}


def test_no_source_files_means_not_computed_not_declared(tmp_path):
    reach, err = cs._reach(_report(tmp_path), None)
    assert reach == {} and "no first-party source files" in err


def test_full_source_tree_finds_the_import(tmp_path):
    tree = tmp_path / "tree"
    (tree / "server").mkdir(parents=True)
    (tree / "server" / "app.js").write_text("const foo = require('foo');\n")
    reach, err = cs._reach(_report(tmp_path), tree)
    assert err is None and reach["foo@1.0.0#GHSA-1"]["tier"] == "imported"


def test_require_resolve_with_a_literal_name_counts_as_an_import(tmp_path):
    """Found live: Uptime Kuma loads jsonata with require.resolve("jsonata") into a vm sandbox. The branch's patterns
    missed it, so a used, vulnerable package was marked 'declared' and its exposure was lowered."""
    from guardian.scoring.contextual.reachability import scan_imports
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "sandbox.js").write_text('const src = fs.readFileSync(require.resolve("jsonata"), "utf8");\n')
    assert "jsonata" in scan_imports(tmp_path)["runtime"]
