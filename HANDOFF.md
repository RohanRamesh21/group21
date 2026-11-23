# Handoff: Software Supply Chain Guardian (Bosch BGSW hackathon)

Written 23 Nov 2026 to continue in a new session. Read this first, then `docs/FINAL_PLAN.md` (v3) and `docs/AGENTIC_CORE.md` (v4, agent design).

## 1. Context
- **Event:** Bosch BGSW hiring hackathon. Day 1 = build + continuous evaluation, Day 2 = production stages, Day 3 = tech + HR interview. Goal: win.
- **Problem statement:** "Software Supply Chain Guardian: know what you build, trust what you ship." An agentic AI that discovers, detects, analyses, remediates and validates supply-chain risks.
  - **Day 1 checkpoint:** "Show us what is in the application, what changed, and what appears risky." Must have: discover components; supply-chain view (SBOM + graph + image/CI); detect vulnerabilities; detect suspicious changes; present evidence.
  - **Day 2:** prioritise risks, investigate one non-CVE risk, recommend a fix, validate it in a sandbox, verify and report, with human approval.
- **Our framing:** a pre-merge PR check. Every risk is labelled *introduced* (by this PR), *pre-existing* or *fixed*.
- **Sample app:** Uptime Kuma pinned to release **2.5.12** (commit `5aa5dec4…`), forked locally at `sandbox/uptime-kuma`.

## 2. How the user wants to work
- Simple, clear English. Discuss in chat first; write files once a plan is agreed.
- Be honest: say what is verified and what is not. Never present replay or canned data as live.
- Commit or push only when asked. **Nothing is committed yet.** Never push scenario branches.
- Never execute analysed package code (always `--ignore-scripts`). Local registry only; never publish to public registries.
- Never print or log API keys. Cognee is the preferred long-term memory.
- The user interrupts long tool calls. Keep steps short, and say what an interrupted step may have changed.

## 3. How to run (all verified)
```bash
cd /Users/kirankishorev/Documents/BOSCH/guardian
.venv/bin/uvicorn guardian.server:app --port 8765          # dashboard at http://localhost:8765
.venv/bin/guardian check sandbox/uptime-kuma --base scenario/base --head scenario/s3-s9   # no-AI Day 1 check (~30 s)
.venv/bin/guardian scan sandbox/uptime-kuma --ref scenario/s3-s9 --out guardian-out/day1  # one commit
.venv/bin/guardian investigate --backend replay --out guardian-out/agents                # recorded agent run (CLI)
.venv/bin/python -m pytest -q                                                            # 22 tests pass
cd guardian/dashboard && npx vite build                                                  # rebuild UI after edits
```
- **"Address already in use" on 8765** means a server is already running (possibly the Claude browser-pane preview). Open the page, stop that server, or use `--port 8766`.
- The dashboard reads `guardian-out/check/latest.json`. Re-run `guardian check` after changing the scenario.
- **Local registry (Verdaccio)** must be running for the suspicious-change detectors and the "real" agent world: `curl http://localhost:4873/-/ping`. It serves two hostnames: `localhost:4873` plays the approved public registry (allow-listed in `guardian.yaml`); `127.0.0.1:4873` plays the attacker's registry.
- **Rebuild the attack scenario:** `.venv/bin/python testbed/injector/build_s3_s9.py`. It creates `scenario/base` and `scenario/s3-s9` (commit "fix typo") in the sandbox fork. Lockfile only, scripts ignored, nothing pushed. A canary file in the temp folder proves the install script never ran.

## 4. What is done (verified on real data)

| Day 1 need | Status | Evidence |
|---|---|---|
| Discover components | ✅ | 1,312 lockfile entries (1,203 unique name@version), 161 direct, 654 runtime, 17 install scripts. Syft CycloneDX + SPDX SBOMs match the lockfile 100%. |
| Dependency graph | ✅ | 2,542 links = 2,346 unique, **exactly equal to `npm ls --all`** (0 missing, 0 extra; test covers both 2.5.12 and the PR head). 45 packages are installed in more than one folder, which explains the gap. |
| CI and images | ✅ | 20 workflows, 79 actions (all SHA-pinned), 12 base images (none digest-pinned). zizmor finds 9 workflow issues (3 high `dangerous-triggers`). 21 CI/image findings, all pre-existing. |
| Vulnerabilities | ✅ | OSV (offline copy, 212 MB in `.cache/osv`) + Grype (DB built 23 Nov 2026) on every package: 30 vulnerable packages, 121 advisories, 119 confirmed by both. Matches live api.osv.dev exactly (jsonata 3/3, protobufjs 11/11, tar 12/12, axois 2/2). |
| Suspicious changes | ✅ | `axois@1.0.0`: look-alike of axios (high), resolved from a host not on the allow-list (critical), new postinstall script (high), malware `MAL-2025-15245` (critical). `.npmrc` registry redirect (critical). The kuma-helper bump stays info. |
| Introduced vs pre-existing | ✅ | `guardian check`: 3 critical introduced (all axois), 118 pre-existing, 0 fixed, decision = block. |
| Evidence | ✅ | Content-addressed evidence store with IDs (`E-…`), lockfile line numbers, untrusted text wrapped as data. |

**Agents (v4, `guardian/agents/`)**
- Lead, Dependency Hunter, Change Forensics and Skeptic on LangGraph.
- Constitution C1–C9 is enforced in code: claims need evidence, hard-signal floors, coverage before verdict, untrusted-data wrapping, tool allow-lists, humans own irreversible decisions, budgets, only the Skeptic clears.
- Two worlds: `canned` (Stage A fixed facts, used by the replay) and `real` (`realworld.py`: git, lockfile, registry, OSV, policy).
- Backends: `ScriptedBackend` (replay), `OpenRouterBackend`, `ClaudeBackend` (direct Anthropic; currently fixed to Opus 5.5).

**Dashboard (`guardian/server.py` + `guardian/dashboard/`, Vite/React/Tailwind/Motion/React Flow)**
- **Investigation tab:**
  - agent lanes and a live timeline
  - rule rejections and risk-floor alerts
  - supply-chain mini graph, Skeptic review, case board
  - human approval dialog (waits 120 s, then falls back to policy) and evidence drawer
  - verdict animation
- **Dependency graph tab:** real data, no AI.
  - summary cards
  - three views: Risk paths / This PR / Direct runtime deps
  - search, plus a click panel showing path to the app, source host, lockfile line, signals and advisories with fix versions
  - long columns wrap
- **Header** shows the model ("claude-sonnet-5.5 | low effort").

## 5. Not done yet
1. **Working LLM key (blocked on user).** The OpenRouter key in `.env` returns **401 "User not found"**; it is the same key the user pasted, so the key itself is dead. Config is ready: `GUARDIAN_LLM_PROVIDER=openrouter`, `GUARDIAN_MODEL=anthropic/claude-sonnet-5.5`, `GUARDIAN_EFFORT=low` (`GUARDIAN_EFFORT` overrides every agent's effort). Test a key with `curl -s -o /dev/null -w "%{http_code}" https://openrouter.ai/api/v1/key -H "Authorization: Bearer $OPENROUTER_API_KEY"` (200 = good). Alternative: an Anthropic key. In that case make `ClaudeBackend` use `GUARDIAN_MODEL` / `claude-sonnet-5-5` (about 5 minutes).
2. **Investigation tab is replay only.** The replay uses canned details (commit `a1b2c3d`, host `10.0.0.5`). Once a key works: run live on the real world (`mode=live, world=real`), then record it as the new replay.
3. **"Real data, no AI" mode in the Investigation tab.** Planned: detectors + vulns + CI findings → board findings, cases per component, rule-based verdict through `check_verdict`. Today only the terminal `guardian check` and the graph tab show real findings.
4. **Dashboard views for the vulnerability list and the CI/image risks.** The data is already in `/api/depgraph` (`nodes[].vulns`, `ci`, `ci_stats`). The user said to leave the *vulnerability graph* out for now; confirm before building.
5. **More attack scenarios.** Only S3 (registry hijack) + S9 (typosquat with install script) are built. Others planned in FINAL_PLAN §4 (S1–S9), e.g. CI action tag drift and image change.
6. **Day 2, not started:** prioritisation (EPSS/KEV planned), deep non-CVE investigation, Fixer agent, sandbox validation, verify + report, human approval of the fix.
7. **Housekeeping:**
   - commit when the user asks
   - the published architecture page (`https://claude.ai/artifact/Qt8VSW5P5drXaXrtZStaz6`) is outdated: Juice Shop, 12 agents
   - ask the user to delete the old OpenRouter key (it was pasted in chat)

## 6. Key files
| Path | What |
|---|---|
| `guardian/cli.py` | `scan`, `check`, `investigate` commands |
| `guardian/check.py` | Pre-merge check: scan base + head, label, suspicious detectors (D1/D2/D3/D4/D7), report |
| `guardian/vuln/scan.py` | OSV (offline) + Grype, merged per package version by ID/alias overlap |
| `guardian/inventory/ci_risk.py` | D8 image not digest-pinned, D9 zizmor (offline), D10 action not SHA-pinned |
| `guardian/adapters/npm.py` | Lockfile v3 parser, aliases, optional peers, runtime set |
| `guardian/graph/` | Graph build + tools (paths to root, blast radius) |
| `guardian/agents/` | protocol, board (+ ordered `feed`), constitution, tools, llm backends, agents, orchestrator, run, realworld, fakeworld |
| `guardian/server.py` | FastAPI: `/api/meta`, `/api/runs` (+ SSE events, human answer, evidence), `/api/depgraph` |
| `guardian/dashboard/src/` | `App.tsx`, `components/` (TopBar, Overview, AgentLanes, GraphView, Debate, CaseBoard, HumanModal, EvidenceDrawer, DepGraph) |
| `guardian.yaml` | Policy: allowed/fetch hosts, typosquat distance, install-script allow-list, sensitive paths |
| `testbed/injector/build_s3_s9.py` | Builds the attack scenario safely |
| `testbed/replays/s3_s9_agents.json` | Recorded agent turns for the replay |
| `tools.lock`, `requirements.lock.txt` | Pinned tool versions and checksums |
| `.env` (mode 600, git-ignored) | Keys and model settings. Never print it. |

## 7. Demo script (works now, no key needed)
1. **Terminal:** run `guardian check`. Say: "1,312 packages; 3 critical problems introduced by this PR, including malware; 118 older ones reported separately; decision: block."
2. **Dependency graph tab:**
   - Risk paths: "red = critical; lines show how it gets in."
   - This PR, then click `axois`: look-alike, attacker registry, install script, malware.
   - `kuma-helper` beside it: routine, not flagged.
3. **Investigation tab, Replay:** press Run check, answer **No** to the human question, end on "Block this merge". Be honest that this tab is a recorded agent run.

**Ready answers for judges:**
- **Why Uptime Kuma?** A real, popular app with all three surfaces (npm, CI, Docker). Real baseline findings. Pinned and reproducible. MIT licence. Juice Shop was rejected because it is vulnerable on purpose.
- **Is the LLM needed for Day 1?** No. Detection uses fixed rules; agents add investigation and explanation.
- **Are the vulnerabilities real?** Yes: two offline databases, matched live OSV exactly, and every finding carries an advisory ID anyone can look up.
- **Why 2,542 vs 2,346 links?** The same version installed in several folders. The unique count equals npm exactly.
- **What does red mean?** Critical: CVSS 9 or more, or malware, or a hard signal. Only `axois` is new in this PR; jsonata, protobufjs and tar were already there.
