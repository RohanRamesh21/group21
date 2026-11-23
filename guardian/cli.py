"""Guardian command line.

    guardian scan <repo> [--ref REF] [--out DIR] [--cdxgen] [--no-sbom]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from guardian.adapters.npm import line_of, parse_lockfile
from guardian.graph.builder import build_graph, export_graphml
from guardian.graph.tools import GraphTools
from guardian.inventory.ci_image import parse_dockerfile, parse_workflow
from guardian.inventory.sbom import agreement, run_cdxgen, run_syft, tool_version
from guardian.snapshot.snapshot import fingerprint, open_view, take_snapshot
from guardian.store.evidence import EvidenceStore


def _tool_versions() -> dict[str, str]:
    return {
        "syft": tool_version(["syft", "version"]).replace("Application:", "").strip(),
        "osv-scanner": tool_version(["osv-scanner", "--version"]),
        "zizmor": tool_version(["zizmor", "--version"]),
        "cdxgen": tool_version(["cdxgen", "--version"]),
    }


def scan(repo: Path, ref: str, out: Path, use_cdxgen: bool = False, make_sbom: bool = True, vulns: bool = True) -> dict:
    view = open_view(repo, ref)
    snap = take_snapshot(view, _tool_versions())
    fp = fingerprint(view)
    run_dir = out / snap.id
    run_dir.mkdir(parents=True, exist_ok=True)
    store = EvidenceStore(out)

    if "package-lock.json" not in view.files:
        raise SystemExit("No root package-lock.json at this commit (npm lockfile v2/v3 required).")
    lock_text = view.text("package-lock.json")
    packages, edges = parse_lockfile(lock_text)
    lock_ev = store.add(lock_text, kind="file_excerpt", source="git", path=f"{snap.commit}:package-lock.json")
    pkg_ev = store.add(view.text("package.json") or "", kind="file_excerpt", source="git", path=f"{snap.commit}:package.json")

    actions = [a for wf in fp["workflows"] for a in parse_workflow(wf, view.text(wf))]
    images = [i for df in fp["dockerfiles"] for i in parse_dockerfile(df, view.text(df))]

    g = build_graph(packages, edges, actions, images, app_name=Path(repo).name, commit=snap.commit)
    tools = GraphTools(g)
    summary = tools.summary()

    # Inventory with an evidence locator (lockfile line) for every package.
    inventory = []
    for p in sorted(packages.values(), key=lambda x: (x.name, x.version, x.key)):
        row = p.model_dump()
        row["lockfile_line"] = line_of(lock_text, f'"{p.key}": {{')
        row["evidence_id"] = lock_ev.id
        inventory.append(row)

    sboms: dict[str, str | None] = {}
    if make_sbom:
        src = view.export(run_dir / "src")
        syft_out = run_syft(src, run_dir)
        sboms["syft"] = syft_out["cyclonedx"]
        snap.sbom_paths = syft_out
        if use_cdxgen:
            sboms["cdxgen"] = run_cdxgen(src, run_dir)
            if sboms["cdxgen"]:
                snap.sbom_paths["cdxgen"] = sboms["cdxgen"]
    lock_set = {(p.name, p.version) for p in packages.values()}
    agree = agreement(lock_set, sboms) if sboms else {}

    (run_dir / "snapshot.json").write_text(snap.model_dump_json(indent=2))
    (run_dir / "fingerprint.json").write_text(json.dumps(fp, indent=2))
    (run_dir / "inventory.json").write_text(json.dumps(inventory, indent=2))
    (run_dir / "edges.json").write_text(json.dumps([e.model_dump() for e in edges], indent=2))
    (run_dir / "actions.json").write_text(json.dumps([a.model_dump() for a in actions], indent=2))
    (run_dir / "images.json").write_text(json.dumps([i.model_dump() for i in images], indent=2))
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (run_dir / "sbom_agreement.json").write_text(json.dumps(agree, indent=2))
    export_graphml(g, str(run_dir / "graph.graphml"))

    vuln_counts, ci_counts = None, None
    if vulns:
        from guardian.inventory.ci_risk import ci_image_scan
        from guardian.vuln.scan import scan as vuln_scan
        src = run_dir / "src"
        if not src.exists():
            view.export(src)
        v = vuln_scan(src / "package-lock.json", Path(sboms["syft"]) if sboms.get("syft") else None, inventory)
        (run_dir / "vulns.json").write_text(json.dumps(v, indent=2))
        ci = ci_image_scan(src, [a.model_dump() for a in actions], [i.model_dump() for i in images])
        (run_dir / "ci_risk.json").write_text(json.dumps(ci, indent=2))
        vuln_counts, ci_counts = v["counts"], {"findings": len(ci["findings"]), **{k: ci[k] for k in ("actions", "images")}}

    return {"snapshot": snap.id, "commit": snap.commit, "ref": ref, "run_dir": str(run_dir),
            "summary": summary, "sbom_agreement": agree, "vulnerabilities": vuln_counts, "ci_image": ci_counts,
            "evidence": [lock_ev.id, pkg_ev.id]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="guardian", description="Software Supply Chain Guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Inventory a repository at a commit: lockfile, graph, CI, image, SBOM")
    s.add_argument("repo", type=Path)
    s.add_argument("--ref", default="HEAD", help="commit, tag or branch to scan (no checkout needed)")
    s.add_argument("--out", type=Path, default=Path("guardian-out"))
    s.add_argument("--cdxgen", action="store_true", help="also generate a cdxgen SBOM and compare")
    s.add_argument("--no-sbom", action="store_true", help="skip SBOM generation (fast mode)")
    s.add_argument("--no-vulns", action="store_true", help="skip OSV/Grype/zizmor")
    c = sub.add_parser("check", help="Pre-merge check: compare base and head, label every risk introduced / pre-existing / fixed")
    c.add_argument("repo", type=Path)
    c.add_argument("--base", required=True)
    c.add_argument("--head", required=True)
    c.add_argument("--out", type=Path, default=Path("guardian-out/check"))
    inv = sub.add_parser("investigate", help="Agentic investigation of a PR (base..head)")
    inv.add_argument("--backend", choices=["auto", "replay", "gemini", "openrouter", "claude"], default="auto",
                     help="auto picks from guardian/.env; replay = recorded agent turns (canned world only)")
    inv.add_argument("--world", choices=["canned", "real"], default="canned",
                     help="real = live tools on sandbox/uptime-kuma scenario/base..scenario/s3-s9")
    inv.add_argument("--out", type=Path, default=Path("guardian-out/agents"))
    args = ap.parse_args(argv)

    if args.cmd == "investigate":
        from guardian.agents.run import run, timeline

        args.out.mkdir(parents=True, exist_ok=True)
        board = run(args.out, backend=args.backend, world_kind=args.world)
        print(timeline(board))
        print("\nVERDICT:", json.dumps(board.verdict, indent=1))
        print("CASES:", json.dumps({k: c.model_dump(include={"title", "verdict", "risk", "confidence"}) for k, c in board.cases.items()}, indent=1))
        return 0

    if args.cmd == "check":
        from guardian.check import check
        rep = check(args.repo, args.base, args.head, args.out)
        print(json.dumps(rep["headline"], indent=2))
        print("report:", rep["path"])
        return 0

    if args.cmd == "scan":
        result = scan(args.repo, args.ref, args.out, args.cdxgen, not args.no_sbom, not args.no_vulns)
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
