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
    # T11: devDependencies imported by the shipped frontend are bundled into the browser app
    from guardian.inventory.exposure import frontend_imports, iter_git, mark_shipped
    shipped = mark_shipped(inventory, [e.model_dump() for e in edges], frontend_imports(iter_git(Path(repo), snap.commit)))
    summary["shipped_frontend_inferred"] = len(shipped)

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


EXIT = {"allow": 0, "review": 1, "block": 2}
INCOMPLETE = 3


def exit_code(headline: dict) -> int:
    """CI-friendly result: 0 allow, 1 review, 2 block, 3 incomplete (a block always wins: it is already certain)."""
    v = headline.get("verdict")
    if v == "block":
        return EXIT["block"]
    if v not in EXIT or headline.get("complete") is False:
        return INCOMPLETE
    return EXIT[v]


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
    inv.add_argument("--backend", choices=["auto", "replay", "freemodel", "gemini", "openrouter", "claude"], default="auto",
                     help="auto picks from guardian/.env; replay = recorded agent turns (canned world only)")
    inv.add_argument("--world", choices=["canned", "real"], default="canned",
                     help="real = live tools on sandbox/uptime-kuma scenario/base..scenario/s3-s9")
    inv.add_argument("--out", type=Path, default=None, help="run folder (workflow: default guardian-out/check)")
    inv.add_argument("--deep", action="store_true",
                     help="old open-ended multi-agent loop (many calls; still limited by the token budget)")
    fx = sub.add_parser("fix", help="Propose fixes for a finished run: candidates + one combined patch (nothing is applied)")
    fx.add_argument("--out", type=Path, default=Path("guardian-out/check"), help="run folder (contains latest.json)")
    fx.add_argument("--include", action="append", default=[], help="also fix this pre-existing finding id (repeatable)")
    apv = sub.add_parser("approve", help="Approve (or reject) the current fix plan as a named person, with a reason")
    apv.add_argument("--out", type=Path, default=Path("guardian-out/check"))
    apv.add_argument("--approver", required=True)
    apv.add_argument("--reason", required=True)
    apv.add_argument("--reject", action="store_true")
    apv.add_argument("--hours", type=float, default=24)
    val = sub.add_parser("validate", help="Validate the approved fix in the isolated worker (refuses without a matching approval)")
    val.add_argument("--out", type=Path, default=Path("guardian-out/check"))
    val.add_argument("--profile", default="uptime-kuma")
    rp = sub.add_parser("report", help="Write report.json and report.html for a run")
    rp.add_argument("--out", type=Path, default=Path("guardian-out/check"))
    args = ap.parse_args(argv)

    if args.cmd == "approve":
        from guardian import approval
        from guardian.validation.runner import load_profile
        from guardian.validation.validate import policy_sha256
        plan = json.loads((args.out / "fix-plan.json").read_text())
        rec = approval.decide(args.out, plan, "reject" if args.reject else "approve", approver=args.approver, reason=args.reason,
                              ttl_seconds=int(args.hours * 3600), policy_sha256=policy_sha256(), profile_sha256=load_profile("uptime-kuma")[1])
        print(json.dumps(rec, indent=1))
        return 0
    if args.cmd == "validate":
        from guardian.validation.validate import validate
        res = validate(args.out, args.profile)
        print(json.dumps(res["gate"], indent=1))
        return 0 if res["gate"]["verified"] else 4
    if args.cmd == "report":
        from guardian.report.build import write
        print(json.dumps(write(args.out), indent=1))
        return 0

    if args.cmd == "fix":
        import guardian.remediation.plan as plan_mod
        latest = json.loads((args.out / "latest.json").read_text())
        h = json.loads(Path(latest["path"]).read_text())["headline"]
        plan = plan_mod.propose(Path(h["repo_path"]), h.get("base_sha"), h["head_sha"], args.out, include=args.include)
        for c in plan["candidates"]:
            print(f"[{c['type']}] {c.get('package') or c.get('file') or ''} {c.get('from', '')}->{c.get('to', '')} :: {c['rationale']}")
        print("patch:", plan["patch"]["patch_sha256"], "files:", ", ".join(plan["patch"]["files"]))
        return 0

    if args.cmd == "investigate" and not args.deep:
        from guardian.ai import workflow
        res = workflow.investigate(args.out or Path("guardian-out/check"))
        for c in res["cases"]:
            print(f"  {c['case_id']} {c['component']:<28} {c['status']:<16} {c.get('assessment') or '':<13} "
                  f"claims {len(c['claims'])} kept / {len(c['rejected'])} rejected")
        v = res["verifier"]
        print(f"  verifier: {v['status']} · {len(v['challenges'])} challenges · {len(v['missed_risks'])} missed risks · "
              f"{len(v['rejected'])} rejected")
        u = res["usage"]["run"]
        print(f"\n{res['run_id']}: {res['status']} · rules verdict {res['rules_verdict']['verdict']} (unchanged) · "
              f"{u['calls']} calls + {u['cached_calls']} cached · {u['tokens']} tokens · {res['seconds']} s")
        return 0 if res["status"] == "done" else 3

    if args.cmd == "investigate":
        from guardian.agents.run import run, timeline

        args.out = args.out or Path("guardian-out/agents")
        args.out.mkdir(parents=True, exist_ok=True)
        board = run(args.out, backend=args.backend, world_kind=args.world)
        print(timeline(board))
        print("\nVERDICT:", json.dumps(board.verdict, indent=1))
        print("CASES:", json.dumps({k: c.model_dump(include={"title", "verdict", "risk", "confidence"}) for k, c in board.cases.items()}, indent=1))
        return 0

    if args.cmd == "check":
        from guardian import universal  # M1: one engine for every interface
        rep = universal.check_any(args.repo, args.base, args.head, args.out, Path(args.repo).name)
        print(json.dumps(rep["headline"], indent=2))
        print("report:", rep["path"])
        return exit_code(rep["headline"])

    if args.cmd == "scan":
        result = scan(args.repo, args.ref, args.out, args.cdxgen, not args.no_sbom, not args.no_vulns)
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
