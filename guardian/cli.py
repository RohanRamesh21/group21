"""Guardian command line.

    guardian scan <repo> [--ref REF] [--out DIR]                 full scan of one commit
    guardian check <repo> --base BASE --head HEAD [--out DIR]    pre-merge check: what this change introduced
    guardian investigate [--backend ...] [--world ...]           agentic investigation
    guardian sandbox setup | status                              pull pinned tool images + Grype DB / show readiness
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


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
    inv = sub.add_parser("investigate", help="Agentic investigation of a PR (base..head)")
    inv.add_argument("--backend", choices=["auto", "replay", "gemini", "openrouter", "claude"], default="auto",
                     help="auto picks from guardian/.env; replay = recorded agent turns (canned world only)")
    inv.add_argument("--world", choices=["canned", "real"], default="canned",
                     help="real = live tools on sandbox/uptime-kuma scenario/base..scenario/s3-s9")
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
        from guardian.agents.run import run, timeline

        args.out.mkdir(parents=True, exist_ok=True)
        board = run(args.out, backend=args.backend, world_kind=args.world)
        print(timeline(board))
        print("\nVERDICT:", json.dumps(board.verdict, indent=1))
        print("CASES:", json.dumps({k: c.model_dump(include={"title", "verdict", "risk", "confidence"}) for k, c in board.cases.items()}, indent=1))
        return 0

    from guardian.universal import check_any

    base, head = (args.base, args.head) if args.cmd == "check" else (None, args.ref)
    rep = check_any(args.repo, base, head, args.out, args.repo.resolve().name, log=lambda m: print("·", m, file=sys.stderr))
    print(json.dumps(rep["headline"], indent=2))
    print("report:", rep["path"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
