"""Guardian command line.

    guardian scan <repo> [--ref REF] [--out DIR]                 full scan of one commit
    guardian check <repo> --base BASE --head HEAD [--out DIR]    pre-merge check: what this change introduced
    guardian investigate [--backend ...] [--world ...]           agentic investigation
    guardian sandbox setup | status                              pull pinned tool images + Grype DB / show readiness
    guardian watch [--project ID | --all] [--interval MIN]       re-check saved inventories for newly disclosed vulnerabilities
    guardian fix [--project ID] [--validate FIX-... ...]          remediation plan; validate fixes in the sandbox (no branch)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _investigate(out: Path, **kwargs):
    from guardian.agents.run import run, timeline

    board = run(out, **kwargs)
    print(timeline(board))
    print("\nVERDICT:", json.dumps(board.verdict, indent=1))
    print("CASES:", json.dumps({k: c.model_dump(include={"title", "verdict", "risk", "confidence"})
                                 for k, c in board.cases.items()}, indent=1))
    return board


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="guardian", description="Software Supply Chain Guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Full scan of one commit: components, SBOM, graph, vulnerabilities, CI/image, suspicious signals")
    s.add_argument("repo", type=Path)
    s.add_argument("--ref", default="HEAD", help="commit, tag or branch to scan (no checkout needed)")
    s.add_argument("--out", type=Path, default=Path("guardian-out/scan"))
    c = sub.add_parser("check", help="Pre-merge check: compare base and head, label every risk introduced / pre-existing / fixed")
    c.add_argument("repo", type=Path)
    c.add_argument("--base", required=True)
    c.add_argument("--head", required=True)
    c.add_argument("--out", type=Path, default=Path("guardian-out/check"))
    c.add_argument("--fail-on", choices=["block", "review", "never"], default="never",
                   help="exit with code 1 when the verdict is at least this strict (for CI gates)")
    for command in (s, c):
        command.add_argument("--investigate", action="store_true",
                             help="reuse the scan evidence and investigate material findings with the configured LLM")
    w = sub.add_parser("watch", help="Re-check saved inventories for newly disclosed vulnerabilities (no code rescan)")
    w.add_argument("--project", help="a scanned project id (default: the main check in guardian-out/check)")
    w.add_argument("--all", action="store_true", help="the main check and every scanned project")
    w.add_argument("--interval", type=int, default=0, help="repeat every N minutes (0 = once)")
    fx = sub.add_parser("fix", help="Remediation plan for the latest check; --validate applies fixes in the sandbox and rescans")
    fix_source = fx.add_mutually_exclusive_group()
    fix_source.add_argument("--project")
    fix_source.add_argument("--report-dir", type=Path, help="the output directory passed to scan or check")
    fx.add_argument("--validate", nargs="+", metavar="FIX_ID")
    inv = sub.add_parser("investigate", help="Agentic investigation of a PR (base..head)")
    inv.add_argument("--backend", choices=["auto", "replay", "deepseek", "freemodel", "gemini", "openrouter", "claude"], default="auto",
                     help="auto picks from .env; replay uses recorded agent turns")
    inv.add_argument("--world", choices=["canned", "real"],
                     help="real uses committed facts from a repository")
    inv.add_argument("--report-dir", type=Path, help="investigate a saved scan or check with its package evidence across ecosystems")
    inv.add_argument("--repo", type=Path, help="local Git repository for a real investigation")
    inv.add_argument("--base", help="base commit, branch or tag")
    inv.add_argument("--head", help="head commit, branch or tag")
    inv.add_argument("--out", type=Path, default=Path("guardian-out/agents"))
    sb = sub.add_parser("sandbox", help="The podman sandbox every repository-reading tool runs in")
    sb.add_argument("action", choices=["setup", "status"],
                    help="setup = pull the digest-pinned images and import the Grype DB (needs network once); status = readiness")
    args = ap.parse_args(argv)

    if args.cmd == "sandbox":
        from guardian import sandbox
        if args.action == "setup":
            from guardian.sandbox.setup import setup
            result = setup()
            print(json.dumps(result["status"], indent=1))
            return 0 if all(v == "ok" for v in result["images"].values()) and "error" not in result["grype_db"] else 1
        st = sandbox.status()
        print(json.dumps(st, indent=1))
        return 0 if st["podman"] and all(i["present"] for i in st["images"].values()) else 1

    if args.cmd == "investigate":
        refs = (args.repo, args.base, args.head)
        world = args.world or ("real" if args.report_dir else "canned")
        if args.report_dir and (any(x is not None for x in refs) or world != "real"):
            inv.error("--report-dir selects the repository and commits for a real investigation")
        if any(x is not None for x in refs) and (not all(refs) or world != "real"):
            inv.error("--repo, --base and --head must be supplied together with --world real")
        target = dict(zip(("repo", "base", "head"), refs)) if all(refs) else {}
        if args.report_dir:
            try:
                pointer = json.loads((args.report_dir / "latest.json").read_text())
                report = json.loads(Path(pointer["path"]).read_text())
                h = report["headline"]
                target = {"repo": Path(report["repo"]), "base": h["base_commit_full"], "head": h["head_commit_full"],
                          "scan_report": report}
            except (OSError, KeyError, ValueError) as exc:
                inv.error(f"could not load a scan with pinned repository commits: {exc}")
        _investigate(args.out, backend=args.backend, world_kind=world, **target)
        return 0

    if args.cmd == "watch":
        import time

        from guardian import monitor
        while True:
            for name, d in monitor.targets(args.all, args.project):
                e = monitor.recheck(d)
                print(f"{e['at']} {name}: {e['components']} components, {len(e['new_advisories'])} new advisories, "
                      f"{len(e['newly_exploited'])} newly exploited, verdict {e['verdict_before']} -> {e['verdict_after']}"
                      + (f" (error: {e['error']})" if e["error"] else ""))
                for a in e["new_advisories"] + e["newly_exploited"]:
                    print("   ", a)
            if not args.interval:
                return 0
            time.sleep(args.interval * 60)

    if args.cmd == "fix":
        from guardian import projects, remediation
        d = args.report_dir or projects.out_dir(args.project)
        ptr = json.loads((d / "latest.json").read_text())
        rep = json.loads(Path(ptr["path"]).read_text())
        if args.validate:
            v = remediation.validate(rep, args.validate, d, log=lambda m: print("·", m, file=sys.stderr))
            print(json.dumps({k: v[k] for k in ("id", "ok", "fixed", "still_present", "new_problems", "coverage_gaps", "attempts", "verdict_before", "verdict_after",
                                                "diffstat", "patch_file")}, indent=1))
            print("\nApprove in the dashboard (Fix & validate) to create a local branch. Guardian never pushes or merges.")
            return 0 if v["ok"] else 1
        for a in remediation.plan(rep):
            print(f"{a['id']}  {a['kind']:<15} {a['component']:<40} -> {a.get('to') or '-':<12} {'auto' if a['automatable'] else 'manual'}"
                  f"  fixes {len(a['findings'])}  | {a['compatibility']}")
        return 0

    from guardian.universal import check_any

    if args.investigate:
        import uuid

        from guardian import config

        backend = config.provider()
        if backend == "replay":
            (c if args.cmd == "check" else s).error("--investigate requires an LLM provider")
    base, head = (args.base, args.head) if args.cmd == "check" else (None, args.ref)
    rep = check_any(args.repo, base, head, args.out, args.repo.resolve().name, log=lambda m: print("·", m, file=sys.stderr))
    print(json.dumps(rep["headline"], indent=2))
    print("report:", rep["path"])
    verdict = rep["headline"].get("verdict")
    if args.investigate:
        h = rep["headline"]
        board = _investigate(args.out / "investigation", backend=backend, world_kind="real", repo=args.repo,
                             base=h["base_commit_full"], head=h["head_commit_full"], scan_report=rep,
                             run_id=f"RUN-{uuid.uuid4().hex[:16].upper()}")
        if (board.verdict or {}).get("decision") == "block":
            verdict = "block"
        elif verdict != "block" and (board.verdict or {}).get("decision") == "inconclusive":
            verdict = "review"
    order = ["allow", "review", "block"]
    if getattr(args, "fail_on", "never") != "never" and verdict in order and order.index(verdict) >= order.index(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
