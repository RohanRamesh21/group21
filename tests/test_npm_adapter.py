"""Tests for the npm lockfile v3 parser and Node-style dependency resolution."""
import json

from guardian.adapters.npm import parse_lockfile, purl_for

# app depends on express (prod) and jest (dev).
# express depends on qs ^6.10 -> resolves to the NESTED qs 6.11.0 under express.
# body-parser depends on qs ^6.5 -> no nested copy, so it resolves to the TOP-LEVEL qs 6.5.2.
# @scope/util is optional and has an install script.
LOCK = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "app",
            "dependencies": {"express": "^4.0.0", "body-parser": "^1.0.0"},
            "devDependencies": {"jest": "^29.0.0"},
            "optionalDependencies": {"@scope/util": "^1.0.0"},
        },
        "node_modules/express": {
            "version": "4.22.3",
            "resolved": "https://registry.npmjs.org/express/-/express-4.22.3.tgz",
            "integrity": "sha512-AAA",
            "dependencies": {"qs": "^6.10.0"},
        },
        "node_modules/express/node_modules/qs": {
            "version": "6.11.0",
            "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz",
            "integrity": "sha512-BBB",
        },
        "node_modules/body-parser": {
            "version": "1.20.9",
            "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.9.tgz",
            "integrity": "sha512-CCC",
            "dependencies": {"qs": "^6.5.0"},
        },
        "node_modules/qs": {
            "version": "6.5.2",
            "resolved": "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz",
            "integrity": "sha512-DDD",
        },
        "node_modules/jest": {
            "version": "29.7.0",
            "resolved": "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz",
            "integrity": "sha512-EEE",
            "dev": True,
            "dependencies": {"qs": "^6.5.0"},
        },
        "node_modules/@scope/util": {
            "version": "1.2.0",
            "resolved": "https://registry.npmjs.org/@scope/util/-/util-1.2.0.tgz",
            "integrity": "sha512-FFF",
            "optional": True,
            "hasInstallScript": True,
        },
    },
}


def _parsed():
    return parse_lockfile(json.dumps(LOCK))


def test_counts_and_direct_flags():
    pkgs, edges = _parsed()
    assert len(pkgs) == 6
    direct = {p.name for p in pkgs.values() if p.direct}
    assert direct == {"express", "body-parser", "jest", "@scope/util"}


def test_nested_version_resolves_to_closest_copy():
    _, edges = _parsed()
    child_of = {(e.parent, e.name): e.child for e in edges}
    assert child_of[("node_modules/express", "qs")] == "node_modules/express/node_modules/qs"
    assert child_of[("node_modules/body-parser", "qs")] == "node_modules/qs"


def test_runtime_is_computed_from_graph_not_just_flags():
    pkgs, _ = _parsed()
    assert pkgs["node_modules/express"].runtime is True
    assert pkgs["node_modules/express/node_modules/qs"].runtime is True
    assert pkgs["node_modules/qs"].runtime is True  # reached via body-parser (prod)
    assert pkgs["node_modules/jest"].runtime is False  # dev only


def test_edge_kinds():
    _, edges = _parsed()
    kinds = {(e.parent, e.name): e.kind for e in edges}
    assert kinds[("", "jest")] == "dev"
    assert kinds[("", "@scope/util")] == "optional"
    assert kinds[("", "express")] == "prod"


def test_origin_and_install_script_kept():
    pkgs, _ = _parsed()
    util = pkgs["node_modules/@scope/util"]
    assert util.has_install_script and util.optional
    assert util.resolved.startswith("https://registry.npmjs.org/")
    assert util.integrity == "sha512-FFF"


def test_optional_peer_does_not_make_package_runtime():
    lock = json.loads(json.dumps(LOCK))
    lock["packages"]["node_modules/express"]["peerDependencies"] = {"jest": "*"}
    lock["packages"]["node_modules/express"]["peerDependenciesMeta"] = {"jest": {"optional": True}}
    pkgs, edges = parse_lockfile(json.dumps(lock))
    kinds = {(e.parent, e.name): e.kind for e in edges}
    assert kinds[("node_modules/express", "jest")] == "peer_optional"
    assert pkgs["node_modules/jest"].runtime is False


def test_purl_encodes_scope():
    assert purl_for("@scope/util", "1.2.0") == "pkg:npm/%40scope/util@1.2.0"
    assert purl_for("express", "4.22.3") == "pkg:npm/express@4.22.3"
