# Handoff: Software Supply Chain Guardian (Bosch BGSW hackathon)

Last updated **24 Nov 2026** on branch `sandbox` (latest commit `27a8504` "Protect Guardian investigations from untrusted
evidence", plus the uncommitted work described below). Read this first, then `docs/FINAL_PLAN.md` (v3) and
`docs/AGENTIC_CORE.md` (v4, agent design). The problem statement is `docs/Amrita_BD Hackathon_Problem_Statement (1).pdf`.

**Not committed yet:** everything in "24 Nov (night)" below is in the working tree only. Commit and push when the user asks.

## 1. Context
- **Event:** Bosch BGSW hiring hackathon. Day 1 = build + continuous evaluation, Day 2 = production stages, Day 3 = tech + HR interview. Goal: win.
- **Problem statement:** "Software Supply Chain Guardian: know what you build, trust what you ship." An agentic AI that discovers, detects, analyses, remediates and validates supply-chain risks.
  - **Day 1 checkpoint:** "Show us what is in the application, what changed, and what appears risky."
  - **Day 2:** prioritise, investigate a non-CVE risk, recommend a fix, validate it in a sandbox, verify and report, with human approval.
  - **Stretch goals (slide 6):** reachability, automated remediation, provenance verification, advanced package risk, policy-as-code, continuous monitoring.
- **Our framing:** a pre-merge PR check. Every risk is labelled *introduced* (by this PR), *pre-existing* or *fixed*.
- **Sample app:** Uptime Kuma release **2.5.12** (commit `5aa5dec4…`), forked locally at `sandbox/uptime-kuma`, with attack scenarios on branches `scenario/control`, `scenario/s1` … `scenario/s8` (all branch from 2.5.12).

## 2. How the user wants to work
- Simple, clear English. Discuss in chat first; write files once a plan is agreed.
- Be honest: say what is verified and what is not. Never present replay or canned data as live.
- Commit or push only when asked. Keep local scenario branches local.
- Never execute analysed package code. Never publish to public registries.
- Never print or log API keys.
- Codex also works on this branch (agent self-protection, `docs/GUARDIAN_SELF_PROTECTION.md`); check `git status` and `git log` before editing.

## 3. How to run (verified 24 Nov on this machine)
```bash
.venv/bin/guardian sandbox setup      # once per machine: digest-pinned images (node, syft, grype, osv-scanner, zizmor, conftest) + Grype DB
.venv/bin/guardian sandbox status     # exit 0 = every sandboxed tool can run
.venv/bin/guardian check sandbox/uptime-kuma --base 5aa5dec425f8a955b54e150636979a6927745ec5 --head scenario/s3 --fail-on block
                                      # Day 1 + stretch goals on the malware PR; writes guardian-out/check (the dashboard's main report)
.venv/bin/guardian scan <repo> --ref <ref>             # full scan of one commit
.venv/bin/guardian fix                                  # remediation plan for the latest check; --validate FIX-… applies + rescans
.venv/bin/guardian watch [--all] [--interval 60]        # continuous monitoring: newly disclosed vulns / newly exploited CVEs
.venv/bin/uvicorn guardian.server:app --port 8765       # dashboard (GUARDIAN_MONITOR_INTERVAL=<min> for automatic monitoring)
.venv/bin/python testbed/corpus.py fetch && .venv/bin/python testbed/corpus.py scan    # 20 real open-source apps (8 flagship apps per language)
.venv/bin/python -m pytest -q                           # 94 passed, 4 skipped (need scenario/s3-s9 or Verdaccio)
cd guardian/dashboard && npx tsc --noEmit && npx vite build                            # rebuild the UI after edits
```
- Dashboard scans (Git URL, ZIP, local folder) are stored under `guardian-out/projects/<id>/`; the latest CLI `guardian check`
  (`guardian-out/check/latest.json`) is listed among them as "main". **Restart uvicorn after pulling backend changes** (the
  redesigned UI needs `/api/projects/path`, `/api/sources` and the new `/api/runs`).
- **Investigate page** runs live agents on any finished scan (its repo copy, base and head commits). It no longer depends on
  `scenario/base` / `scenario/s3-s9`. The CLI `guardian investigate` still defaults to those branches (`agents/run.py`).

## 4. What is done (verified on real data, 24 Nov)

**Finding reviews:** Risk scores now records Confirm, Challenge, and Defer decisions with an evidence-bound timeline and JSON download. See [Human feedback](docs/HUMAN_FEEDBACK.md) for the review and reopening demo.

### Day 1 (all five steps of the brief)
Main demo report = 2.5.12 (`5aa5dec4`) → `scenario/s3` (`8c505a38`):
| Step | Result |
|---|---|
| 1 Discover | 1,368 components (1,228 unique name@version): npm 1,311 + GitHub Actions 57; 217 direct; 690 runtime; 17 install scripts |
| 2 Supply-chain view | Syft CycloneDX + SPDX + Guardian CycloneDX; 2,598 dependency links; SBOM agrees with the lockfile 100%; 21 workflows / 79 actions (all SHA-pinned); 16 base images (none digest-pinned) |
| 3 Vulnerabilities | OSV.dev 120 + Grype 120 → 121 merged (119 confirmed by both) on 30 packages; CVSS v3 score shown; reachability: 67 imported by shipped code, 11 via an imported dependency, 3 not imported (all `axois`, which nothing imports), 40 dev-only |
| 4 Suspicious changes | `axois@1.7.9`: malware MAL-2025-15245, attacker host `10.0.0.5:4873` (critical), typosquat of axios, new install script |
| 5 Evidence | every finding: component, dependency path, file:line, advisory/detector proof, level; new-in-this-change first |
| Verdict | **block** (risk score block, policy block: GP-001, GP-002, GP-003) |

All 10 scenario branches (2.5.12 → branch), run 24 Nov:
| Scenario | Injected | Verdict |
|---|---|---|
| control | safe bump | allow, 0 alerts |
| s1 | direct dep downgraded to vulnerable axios 0.21.1 | review (24 advisories; axios imported at `server/check-version.js:2`) |
| s2 | transitive override to vulnerable qs 6.5.2 | review (path traced through express > body-parser) |
| s3 | typosquat + attacker registry + install script + malware | block |
| s4 | dayjs "update" adds an install script | **block**: `dayjs@1.11.99` does not exist on registry.npmjs.org (forged lockfile entry) |
| s5 | integrity changed / host changed | block |
| s6 | base image → `ghcr.io/unknown-org/…:latest` | review (untrusted image + `:latest`) |
| s7 | action SHA → tag (comment still says v6.0.1) | review (hard signal `action_pin_removed`) |
| s8 | AI issue-triage workflow | review (template injection + unpinned third-party action) |
| s9 | `.npmrc` registry redirect ("fix typo" commit) | block (hard signal + GP-002) |

### Stretch goals (all six, no LLM involved)
| Goal | Where | What it does |
|---|---|---|
| 1 Reachability | `guardian/reachability.py` | import-level: is the vulnerable package imported by shipped code (npm/PyPI/Go; Go is package-precise via OSV). `not_imported` lowers a CVE's priority; attacks are never discounted |
| 2 Automated remediation | `guardian/remediation.py`, UI "Fix & validate" | one fix per package (lowest release that fixes all its advisories; override for transitive; remove a newly added bad package; restore a tampered file; pip pin edit) → validate in the sandbox (npm registry-only) and rescan before vs after → retry if the chosen version has its own advisories (axios 0.33.0 → 0.34.0) → human approves → local branch `guardian/fix-…`. Never pushed or merged; build/tests not run (policy) |
| 3 Provenance | `guardian/registry_intel.py` | npm registry signatures verified (ECDSA), lockfile integrity vs registry, SLSA provenance attestation (source repo, workflow, digest match), provenance dropped, version missing from registry |
| 4 Advanced package risk | `guardian/registry_intel.py` | publisher / maintainer change, brand-new or dormant-revived releases, release bursts, young packages, install-script behaviour read from the tarball (secrets, network, process spawning, obfuscation), internal-scope dependency confusion |
| 5 Policy-as-code | `policies/guardian.rego`, `guardian/policy.py` | Conftest/OPA in the sandbox; deny = block, warn = review; final verdict = stricter of score and policy; `guardian check --fail-on block` for CI |
| 6 Continuous monitoring | `guardian/monitor.py`, `guardian watch`, Risk scores tab | re-queries OSV for the saved inventory, refreshes KEV/EPSS, re-scores, keeps a history; on demand, `--interval`, or `GUARDIAN_MONITOR_INTERVAL` in the server |

### Flagship apps per language (24 Nov)
Like uptime-kuma for npm, each checked previous release → latest release (`testbed/corpus.yaml`, results in `docs/TESTING.md` §6):
paperless-ngx (Python), miniflux (Go), Stirling-PDF (Java), vaultwarden (Rust), firefly-iii (PHP), mastodon (Ruby), jellyfin (.NET),
netdata (C/C++). They found 5 more false-positive/coverage bugs (fixed, incl. .NET packages being invisible).
All eight also pass end to end in the dashboard. **Step-by-step UI test guide: `docs/TESTING.md` §7.** Pinned commits and facts:
`docs/SAMPLE_APP.md`.

### Earlier work (still valid)
- **Sandbox** (`guardian/sandbox/`; podman = a Docker-like container tool, rootless, installed per machine): every tool that reads a scanned repo (npm, Syft, Grype, OSV-Scanner, zizmor, Conftest) runs in rootless
  podman: `--network=none`, read-only, digest-pinned images, limits. npm reaches only `registry.npmjs.org` through an in-process allow-list
  proxy. Only resolution-only settings from a repo's `.npmrc` (e.g. `legacy-peer-deps`) are passed; registry/git/script settings never.
- **Languages:** npm, Python, Go, Java (Maven/Gradle), C/C++ (CMake, vcpkg, conan, meson, submodules), Rust and the rest of Syft's list.
- **Corpus:** 20 real apps (`testbed/corpus.yaml`: 12 small apps/libraries + 8 flagship apps) and synthetic sample apps (`testbed/apps/`), see `docs/TESTING.md`.
- **Agents (v4, `guardian/agents/`)**: Lead, Dependency Hunter, Change Forensics, Skeptic on LangGraph; constitution C1–C9 in code; replay
  backend works offline. Codex added mandatory checks independent of model decisions (`docs/GUARDIAN_SELF_PROTECTION.md`).

### Dashboard (redesigned 24 Nov, late morning; user asked for it)
Two pages. **Scan** (home): source form (Git URL · ZIP · Local path, optional base → head) → live eight-stage pipeline →
results with **Overview · Dependency graph · Risk scores · Fix & validate**; recent scans below the form; hash links
`#/scan/<id>/<view>`. **Investigate**: pick a finished scan or bring a new source (scanned first, then the agents start);
live agents on that scan; a labelled "recorded example" replay. The Day 1 report view and the header project picker were
removed (`/api/day1` and `guardian/day1.py` remain). Code: `guardian/dashboard/src/` (`App.tsx`, `route.ts`, `api.ts`,
`components/Home`, `SourceInput`, `ScanPage`, `ScanProgress`, `ProjectResults`, `ResultsOverview`, `RecentScans`, `Investigate`).
UI tested end to end in Chromium (Playwright): `docs/TESTING.md` §5. Another agent added finding reviews in Risk scores at the
same time (`FindingReview.tsx`, `guardian/reviews.py`).

## 5. Not done yet
1. **Agentic workflow** (user: not now). LLM key: the OpenRouter key in `.env` returned 401 earlier; test with
   `curl -s -o /dev/null -w "%{http_code}" https://openrouter.ai/api/v1/key -H "Authorization: Bearer $OPENROUTER_API_KEY"`.
   The Investigate page runs live agents on any scan but needs a working key; `.env` now sets `GUARDIAN_LLM_PROVIDER=freemodel`,
   which `agents/run.py` does not implement (the page shows "unknown backend freemodel"). A Fixer agent can wrap `guardian/remediation.py`.
2. **Build and test in validation:** not done on purpose (Guardian never runs analysed code). If wanted for the sample app only, it needs a
   decision (CLAUDE.md §3.2) and a no-network container profile.
3. **Gaps** (`docs/KNOWN_LIMITATIONS.md`): function-level reachability, Sigstore certificate-chain verification, registry checks for
   non-npm ecosystems, tag-moved detection for actions, Gradle version catalogs, an allow-list for approved extra Maven repositories.
4. **Docs still missing** (CLAUDE.md §7): `AGENTS.md`, `EVIDENCE_AND_REPORT.md`, `CHAOS_SCENARIOS.md`, `RESPONSIBLE_AI.md` (also a
   hackathon deliverable: "Responsible AI & Security Note"); a human-readable report export. (`SAMPLE_APP.md` and `CHANGELOG.md` exist since 24 Nov.)
5. **CLAUDE.md:** §4 (layout) and §5 (commands) were updated on 24 Nov to match the code. §2 still describes an Investigator/Judge
   design while the code has Lead / Hunter / Forensics / Skeptic; that is a design decision for the team.
6. **Housekeeping:** commit/push when asked; ask the user to delete the old OpenRouter key (it was pasted in chat).

## 6. Key files
| Path | What |
|---|---|
| `guardian/cli.py` | `scan`, `check` (+ `--fail-on`), `fix`, `watch`, `sandbox`, `investigate` |
| `guardian/universal.py` | The pipeline for any repo: discovery, SBOM, graph, vulns, detectors, labels, report; calls the modules below |
| `guardian/reachability.py`, `registry_intel.py`, `policy.py`, `remediation.py`, `monitor.py` | Stretch goals 1–6 |
| `policies/guardian.rego` | Sample policies (GP-001 … GP-105) |
| `guardian/scoring/score.py` | Floors, SSVC, AHP score, verdict (introduced high/critical → at least review) |
| `guardian/sandbox/` | podman runner, egress proxy, bridge, setup |
| `guardian/adapters/` | npm lockfile parser; C/C++/Java/Go/pip build-file readers |
| `guardian/inventory/ci_risk.py` | D8 images (untrusted, floating, not digest-pinned), D9 zizmor, D10 actions |
| `guardian/day1.py` | Day 1 view (5 steps) |
| `guardian/server.py` | FastAPI: day1, depgraph, scores, policy, provenance, remediation (+ jobs, approve), monitor, projects, runs |
| `guardian/dashboard/src/components/` | `Home`, `SourceInput`, `ScanPage`/`ScanProgress`, `ProjectResults`/`ResultsOverview`, `DepGraph`, `RiskScores`, `Guard` (policy + monitoring), `Remediation`, `Investigate` + agent views |
| `guardian/agents/` | Agent team, constitution, boundary (Codex), tools, replay |
| `guardian.yaml` | Policy data: hosts, trusted images, install-script allow-list, licence deny-list, sandbox images and limits |
| `testbed/` | `apps/` (synthetic, ground truth), `corpus.yaml` + `corpus.py` (real apps), `injector/` (attack scenarios) |
| `tools.lock`, `requirements.lock.txt` | Pinned tool versions, image digests, checksums |

## 7. Demo script (no LLM key needed)
1. **Terminal:** `guardian check sandbox/uptime-kuma --base 5aa5dec4… --head scenario/s3 --fail-on block` → exit 1. Say: "1,368
   components; this PR adds a look-alike of axios from an attacker registry, with an install script and a known malware ID: block."
2. **Dashboard home:** Local path `…/sandbox/uptime-kuma`, Compare: base `5aa5dec4…`, head `scenario/s3` → Run scan. Narrate the
   live pipeline (≈1 min). Or open the "main" card under Recent scans (the CLI report) to skip the wait.
3. **Overview:** block, the three attack signals on `axois` (lockfile tamper, new install script, typosquat), vulnerabilities by severity.
4. **Dependency graph:** Risk paths, then This PR → click `axois`.
5. **Risk scores:** policy panel (GP-001 malware, GP-002 attack signal) + score card; press **Re-check now** (monitoring).
6. **Fix & validate:** select "Remove axois" → Validate → verdict block → allow, 3 fixed, 0 new problems → (approve creates a local
   branch in the project's copy under `guardian-out/projects/`, never in the fork).
7. **Another source:** ZIP (e.g. a Java or C++ app) or `https://github.com/gin-gonic/gin` with base `v1.9.1` head `v1.10.0`.
8. **Investigate with agents:** live if a key works; otherwise "Play the recorded example run" and say it is a replay.

**Ready answers for judges:**
- **Is the LLM needed for detection?** No. Detection, scoring, policy, remediation and monitoring are deterministic; agents add investigation.
- **Is anything from the app executed?** No. Tools run in a no-network podman sandbox; npm only resolves metadata; tarballs are read in memory.
- **Are the vulnerabilities real?** Yes: OSV.dev + Grype agree on 119 of 121, and every finding carries an advisory ID.
- **What blocks a merge?** A critical or attack-signal finding introduced by the PR, or a `deny` policy rule. High-severity introduced findings need a human.
