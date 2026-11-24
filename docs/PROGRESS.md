# Build Progress Log

*Plan: `docs/GUARDIAN_FINAL_PLAN.md`. Branch: `m0-trust-gate` (uncommitted; nothing pushed). Every ✅ below has a test or a recorded run.*

## M0: Trust-and-correctness gate ✅ (24 Nov 2026)

Method: for each item, a test reproducing the defect was written first and seen failing, then the fix, then the full suite.

| ID | Defect | Fix | Test (in `tests/`) |
|---|---|---|---|
| T1 | URL could read files outside the dashboard build (`/..%2F..%2F..%2Fpyproject.toml` returned the file) | `server.py` resolves the path and requires it inside `dist/` | `test_m0_trust.py::test_t1_*` |
| T2 | Unsafe action added to a *different* workflow was labelled pre-existing | CI finding key now includes the file (`inventory/ci_risk.py`) | `test_t2_*` |
| T3 | Vulnerability ↔ component join ignored ecosystem; merge could join npm and PyPI records | Records carry ecosystem (OSV API, Grype purl, offline OSV = npm); merge and join are ecosystem-aware; ambiguous joins skipped | `test_t3_*` (2) |
| T4 | AI sentences labelled "verified" when their numbers appeared in the evidence | Always `inferred`, plus `cites_checked`; dashboard badge "🤖 AI · cites checked" | `test_scoring_projects.py` (2) |
| T5 | A scanner failure could look like a clean result | `scoring/verdict.py::incomplete_reasons`; every report has `complete` + `incomplete_reasons`; a scoring crash marks the run incomplete | `test_t5_*` (2) |
| T6 | `guardian check` exited 0 even on BLOCK | Exit codes 0 allow · 1 review · 2 block · 3 incomplete | `test_t6_*` (5 cases) |
| T7 | Agent verdict accepted invented case/evidence IDs | `constitution.check_citations`: case must exist; evidence must exist in this run, match its SHA-256, and belong to a cited case | `test_t7_*` (6 cases) |
| T8 | Introduced High (by severity) could end as ALLOW after SSVC lowered its level | Shared verdict: introduced High/Critical severity, CVE or not, including CI, gives at least REVIEW | `test_t8_*` (3) |
| T9 | Three different verdict rules (scoring, headline `blocking`, agents) | One function `scoring/verdict.py::decide` used by scoring; headline `blocking` now derived from it. *Agent constitution rule to be aligned in M3 when agents are rewired.* | `test_t9_*`, `test_verdict_*` |
| T10 | npm pipeline: same version moved to another download host was labelled pre-existing, or not flagged at all between two allowed hosts | `agents/realworld.py` D3 compares per-version host with base | `test_t10_*` (3) |
| T11 | Frontend libraries listed as devDependencies treated as dev-only | `inventory/exposure.py`: packages imported by frontend code (`src/**`, `.vue`, …) and their non-dev dependency closure marked `shipped_frontend_inferred`, in both pipelines; the scoring text says "inferred" | `test_t11_*` (2) |

**Real-data verification** (Uptime Kuma scenario `scenario/base → scenario/s3-s9`, 28 s):
- `guardian check` → **exit 2 (BLOCK)**, `complete: true`, 5 blocking reasons (malware record, lockfile tamper, `.npmrc` redirect, look-alike + install script ×2).
- T11 marked **85** dev-listed packages as shipped frontend. Real effect: `vue-i18n` / `@intlify/*` 11.2.8 advisory **GHSA-83rm-6c8r-g728 (high)**, previously discounted as dev-only, is now scored as shipped to users.

**Suite:** 73 passed (was 45). Dashboard `tsc --noEmit` passes. No Python linter is configured in the project (ruff not installed), so a compile check was used instead.

**Files changed:** `guardian/server.py`, `guardian/cli.py`, `guardian/check.py`, `guardian/universal.py`, `guardian/scoring/score.py`, `guardian/scoring/explain.py`, `guardian/scoring/verdict.py` (new), `guardian/inventory/ci_risk.py`, `guardian/inventory/exposure.py` (new), `guardian/vuln/scan.py`, `guardian/agents/constitution.py`, `guardian/agents/tools.py`, `guardian/agents/realworld.py`, `guardian/dashboard/src/components/RiskScores.tsx`, `tests/test_m0_trust.py` (new), `tests/test_scoring_projects.py`.

**Known follow-ups (not hidden):**
- The agent constitution still has its own "introduced High → block" rule (stricter than the shared verdict). Align in M3.
- The graph view (`build_graph`) doesn't yet reflect T11's shipped marking; only inventory, vulnerabilities and scoring do.

## M1: One engine ✅ (24 Nov 2026)

`guardian.universal.check_any` is now the only analysis engine. `guardian check` (CLI), the dashboard's local-sandbox runs, Git URL and ZIP scans all call it; `guardian/check.py` is a thin wrapper kept for older callers.

| Change | Why | Test |
|---|---|---|
| npm package downloaded from an **http(s) host outside the allow-list** → `untrusted_source`, severity critical, hard signal, new scoring floor (critical/Act) | Parity with the old npm pipeline (it floored this as `lockfile_tamper` critical); the universal engine had it at medium/low | `test_m1_engine.py::test_package_from_unapproved_http_host_*`, `test_untrusted_source_has_a_scoring_floor` |
| `git+` / `file:` sources → `non_registry_source` (medium, not hard) | Visible and common choice, not a hijack | `test_git_source_is_non_registry_source_*` |
| CLI `check` and `_run_local` call `check_any` | One engine for every interface | `test_cli_check_runs_the_universal_engine` |

**Acceptance runs (real data):**

| Repository | Result |
|---|---|
| Uptime Kuma scenario (`scenario/base → scenario/s3-s9`) via CLI | exit 2, **BLOCK**, complete; introduced: MAL-2025-15245 (critical), typosquat (critical, combo), new install script (critical), untrusted source 127.0.0.1:4873 (critical), `.npmrc` source change (critical), plus lower ones. Routine `kuma-helper` bump no longer flagged (correct benign behaviour). 153 findings total. |
| Flask (`github.com/pallets/flask`, single scan) | complete; 118 components (100 PyPI, 17 Actions, 1 npm); 57 advisories (55 confirmed by both OSV and Grype) |
| ARKABROAD (`github.com/kirankishoreV-07/ARKABROAD`, single scan) | complete; 1 browser-extension component; no third-party packages |

**Suite:** 77 passed.

**Note:** the old npm-only detectors in `agents/realworld.py` remain as agent *tools* (M3 will rewire agents to the engine's findings).

## M2: Run states + confidence ✅ (24 Nov 2026)

| Change | Where | Test |
|---|---|---|
| Per-stage states (snapshot, discover, vulnerabilities, detectors, CI/images, compare, scoring) with status complete / partial / failed / not_applicable / skipped and a reason | `scoring/states.py`; `headline.stages` in every engine report | `test_m2_states_confidence.py::test_stage_*`, `test_compare_stage_*` |
| Confidence per finding: 5 dimensions (collection, applicability, freshness, contradictions, evidence), each ok / weak / missing / not_applicable with a reason; band high / medium / low by simple rule (no weights) | `scoring/confidence.py`, attached in `score_report` | 9 tests |
| Evidence requirements differ by finding type (a registry redirect needs no advisory) | `confidence._evidence` | `test_registry_redirect_needs_no_advisory`, `test_ci_finding_requires_file_and_line` |
| Each scanner's own severity kept (`severity_by_source`) so disagreements are visible | `vuln/scan.py::merge` | `test_severity_disagreement_is_a_contradiction` |
| Introduced High/Critical (by level or severity) with low confidence → verdict reason "needs human check: …" | `score_report` | `test_score_report_attaches_confidence_*` |

**Real run (scenario):** all 7 stages `complete`; 153 findings, all confidence `high`. Checked, not assumed: all 121 advisories have an exact version and a lockfile location, 119 are confirmed by both scanners, 0 severity disagreements. Lower bands appear under outages or missing data, as the tests show.

**Suite:** 89 passed.

## M4: Fix recommendation (deterministic part) ✅ · agent part ⏳ waiting for API key (24 Nov 2026)

**Built (no AI involved):**

| Piece | What it does | Tests |
|---|---|---|
| `remediation/versions.py` | npm-style semver ordering; OSV affected-range evaluation (introduced / fixed / last_affected / explicit versions); `smallest_safe` = smallest published version outside **every** affected range, same major first, no pre-releases or deprecated releases | 11 |
| `remediation/candidates.py` | Groups findings (per package / config file / CI item) → one candidate each: `remove_package`, `revert_change`, `upgrade_to_fixed`, `override_transitive`, or `escalate` (with the honest reason). Real data from registry.npmjs.org (cached a day) and OSV records; each source recorded with URL + SHA-256. Ordered by rules: resolves target → smaller semver jump → fewer lockfile changes → easier rollback | 8 |
| `remediation/patch.py` | Applies candidates to a **private export** of the PR head, config reverts first; npm with `--package-lock-only --ignore-scripts` + explicit public registry; output = one git diff + SHA-256; preserves the file's indentation; reports the lockfile footprint (added / removed / changed entries) | 6 |
| `remediation/plan.py` | Fix plan for a finished run, bound to full base/head SHAs; refuses a stale run; saves `fix-plan.json` | 2 |
| CLI `guardian fix --out <run> [--include <finding id>]`; API `POST/GET /api/fix-plan` | Same code path | 3 |
| Engine report now records `repo_path`, full `base_sha` / `head_sha` | Needed to bind fixes and approvals | 1 |

**Real run (scenario + the pre-existing jsonata advisories):**
- `upgrade_to_fixed` jsonata 2.2.0 → **2.2.1** (computed: smallest version outside all three advisories' ranges; patch jump)
- `remove_package` axois (malware record + hard signals; added by this change)
- `revert_change` `.npmrc` (restore base content)
- One patch, 77 lines, files `.npmrc`, `package.json`, `package-lock.json`; lockfile footprint: removed `node_modules/axois`, changed `node_modules/jsonata` (new integrity hash taken from the registry). SHA-256 `83603548…`, identical across two runs (reproducible).

**Bugs found by real data and fixed (test-first):** (1) writing `package.json` with a different indentation made npm rewrite the whole lockfile (34,658-line diff), now fixed by preserving the original formatting; (2) the lockfile-change counter read an empty diff, now it compares the two lockfiles.

**Reasoning:** fixes are computed, not generated, so no model can introduce a non-existent or still-vulnerable version. A human-reviewable patch (tens of lines, not thousands) is a precondition for meaningful approval in M5.

**Pending (API key):** Fixer agent's plain-language explanation and the Verifier's challenge of the candidates.

**Suite:** 119 passed.

## M5: Approval contract + validation worker 🟡 (code + tests done; live run on Uptime Kuma pending the Node image download)

| Piece | What it does | Tests |
|---|---|---|
| `guardian/approval.py` | Approval bound to base SHA + head SHA + patch SHA-256 + policy SHA-256 + profile SHA-256 + approver + expiry; any change, expiry or rejection → `ApprovalInvalid`. Risk acceptance with owner, scope, reason, expiry. Append-only, hash-chained `audit.jsonl` + `audit.head`, so editing any entry (including the last) is detected | 12 |
| `validation/profiles/uptime-kuma/` | Declared profile (hashed, incl. the integration script): `npm ci --ignore-scripts` → only the `@louislam/sqlite3@15.1.6` hook with its exact lockfile integrity → `npm run build` → security target test `test-jsonata-sandbox.js` → unit tests (SQLite-only cases selected by name) → integration. Exclusions listed with reasons | — |
| `integration.cjs` | Real app operations over the app's own socket.io API: start server on a disposable data dir → `setup` admin → `login` → `add` HTTP monitor → wait for a stored heartbeat (status up) → cleanup | (live run) |
| `validation/runner.py` | Disposable container: `--cap-drop ALL`, `no-new-privileges`, unprivileged user, CPU/memory/pids limits, tmpfs, no secrets, no host home, no Docker socket, internal network where only Verdaccio is reachable. Hook exceptions run only on exact name+version+integrity match. Deterministic gate: verified only if approval matches, evidence chain intact, every required stage passed, security test passes on the candidate (baseline failure is no excuse), no regression vs baseline, rescans complete, same advisory snapshot, target findings gone, no new High+; reports target / validation / decision separately | 18 |
| `validation/validate.py` | Order: approval check first (no match → nothing executes) → baseline run → candidate run (patch applied only if its bytes match the approved hash) → artifact SBOMs (Syft on the built tree) → source rescan with the same engine (PR head vs candidate) → gate → `validation.json` + audit entry | 2 (refusal paths) |
| CLI `guardian approve / validate`; API `POST /api/approval`, `POST /api/risk-acceptance`, `POST /api/validate` (background), `GET /api/validation` | | 6 |

**Reasoning:** the approval is checked before anything runs, so a stale or rejected approval can't trigger code execution. Pass/fail is decided by code from exit codes and scan diffs; the Verifier agent (pending the key) will only explain these results.

**Not done yet (honest):** the live end-to-end validation on Uptime Kuma. It needs the `node:20-bookworm` image (a slow download; a retry is in progress). The Docker image build of the app (plan §13.2) isn't in the profile yet; the "resulting artifact" is currently the installed dependency tree + build output, scanned with Syft.

## M6: Guardian report ✅ (24 Nov 2026)

`guardian/report/build.py` → `report.json` + `report.html` from one run folder, sections: run (identity, decision, completeness, stages, capability level L1–L4, pinned tool versions), components & SBOMs (with SHA-256), ranked findings with confidence and evidence, investigation (**"pending: needs the AI model"** until the key is set), recommended & approved action (candidates, patch hash, approval record), validation, before/after, remaining & accepted risk, overall confidence, audit trail (chain verified). HTML escapes everything (test injects `<script>`). CLI `guardian report`, API `GET /api/report?fmt=json|html`. Tests: 5.

**Suite:** 160 passed.

## M8: PR trigger ✅ code + tests · live GitHub run ⏳ needs a GitHub token, fork and runner setup (24 Nov 2026)

| Piece | What it does | Tests |
|---|---|---|
| `ci/github/guardian.yml` | Workflow for our fork: `pull_request` events, `concurrency` + `cancel-in-progress`, self-hosted runner `guardian-demo`, **no checkout**, event data only via env vars, fixed script `/opt/guardian/bin/guardian-submit` | 1 (lock-down rules checked) |
| `trigger/submit.py` (`guardian-submit`) | Strict input validation (repo name, PR number, action, 40-hex SHAs); sends to the local server; exit code = scan decision (0/1/2/3; 64 bad input; 70 server unreachable) | 2 |
| `trigger/queue.py` | Analysis identity = repo + PR + base + head + policy hash + profile hash + intelligence snapshot; duplicate deliveries reuse; new head supersedes; drafts ignored; closed → not current; explicit rerun; a late result of a superseded run never becomes current | 4 |
| `trigger/events.py` | Persisted, numbered events; `since(seq)` resume (survives restart) | 1 |
| `trigger/github.py` | Statuses limited to GitHub's states (REVIEW → failure "needs human review"; incomplete → error; success says "scan policy passed", never "verified"); one comment updated in place (marker); markdown/HTML escaped; paginated listing; token held privately, never printed | 5 |
| `trigger/service.py` | event → queue → fetch `pull/<N>/head` into a hook-free mirror and **verify the SHA** (stop if the branch moved) → engine → events → statuses/comment only for the current run and only if `GUARDIAN_GITHUB_TOKEN` is set (otherwise "not posted: no GitHub token configured") | 3 |
| `trigger/watcher.py` | Polling backup: new PR, new commits, draft → ready, base change, closed | 1 |
| Server: `POST /api/github/event` (validated), `GET /api/trigger/current` (snapshot), `/api/trigger/events?since=`, `/api/trigger/stream` (SSE with ids, `Last-Event-ID` resume) | | 1 |

**Reasoning:** GitHub Actions gives the native trigger and check; the job only forwards four validated values, so a malicious PR can't run code on our machine through the workflow. Everything after "event received" is one code path shared with the polling backup.

**Pending (needs you):** create the fork, a fine-grained token (`GUARDIAN_GITHUB_TOKEN` in `.env`), and register the self-hosted runner. Then one benign PR proves the live path.

**Suite:** 181 passed.

## M7: Dashboard v2 (Run page) ✅ first version (24 Nov 2026)

**Diagnosis (why the old UI felt hard-coded):** the default tab replayed a recorded agent run with made-up details. **Fix:** a new default **Run** page that renders only `/api/run`, built by the same code as the Guardian report (one source of truth). The replay stays, renamed **"Recorded investigation"** with a RECORDED banner.

Run page (`dashboard/src/components/RunPage.tsx`):
- **Header:** run selector (main scenario or any finished project scan), repo and commits, decision badge (animated flip on change, "incomplete" tag), capability level, overall confidence, audit-chain status, SHA-256 of the scan report it was built from, link to the HTML report.
- **Stepper:** the 7 real scan stages from `headline.stages` + Investigate / Recommend / Approve / Validate derived from real state (pending / complete / failed), with reasons.
- **Findings:** introduced first, older ones collapsed; each shows level + confidence; click → **proof drawer** (🔒 recorded evidence fields, the 5 confidence dimensions with reasons, how the priority was computed). Esc closes.
- **Recommended fix:** "Propose fixes" (calls `/api/fix-plan`), candidate cards (action, rationale, forecast risk reduction, compatibility, rollback), **patch diff viewer**, patch hash; **Approve / Reject** requires a name and a reason (👤 recorded in the audit chain).
- **Validation:** enabled only after approval; runs in the background, polls, shows target / validation / verified separately and baseline vs candidate stage results.
- **Investigation:** shows "pending: needs the AI model" (🤖) until the key is set.
- **Pull-request events:** live SSE stream from the trigger with connected/offline status.
- Empty, loading and error states; keyboard focus rings; motion only on real events; respects reduced motion.

**Verified over HTTP against the real main run:** `/api/run` → BLOCK, complete, L2, 7/7 stages complete, 153 findings (9 introduced); `/api/fix-plan` from the UI's call → remove `axois`, revert `.npmrc`, one patch (`25b64757…`), lockfile footprint 1 entry; HTML report 200. `tsc` and `vite build` pass. **A browser screenshot check couldn't be done in this session** (the Playwright tools weren't available), so a visual pass is still to do.

**Deliberately not done:** I did not approve the plan myself. Approval is a human decision; the attempt was correctly blocked. It's waiting for you on the Run page.

**Bug found and fixed (test-first):** a relative output path (the CLI default) made `git archive` fail inside the engine; paths are now resolved first. (The earlier checks had all used absolute paths.)

**Suite:** 183 passed.

## M9: Docs ✅ (24 Nov 2026)
`README.md` (what works, commands, two-minute demo), `docs/SETUP.md` (tools with pinned versions, install, local registry, secrets, PR trigger setup), `docs/ARCHITECTURE.md` (deliverable diagram: agents, tools, data sources, AI interactions, approval point, evidence storage, trust boundaries, code map, sample policies), `docs/RESPONSIBLE_AI.md`, `docs/KNOWN_LIMITATIONS.md`. Prompts live in code: agent roles `guardian/agents/agents.py`, explanation prompt `guardian/scoring/explain.py` (the empty `agents/prompts/` folder was removed).

---

## Status after the night of 24 Nov 2026

| Milestone | State |
|---|---|
| M0 trust gate | ✅ |
| M1 one engine | ✅ |
| M2 states + confidence | ✅ |
| M3 live investigation | ⏳ API key |
| M4 fix recommendation | ✅ deterministic · ⏳ agent explanations (API key) |
| M5 approval + validation | ✅ approval · 🟡 validation code/tests done, live run pending image download |
| M6 report | ✅ |
| M7 dashboard Run page | ✅ first version (visual check pending) |
| M8 PR trigger | ✅ code/tests · ⏳ fork + token + runner |
| M9 docs | ✅ |

Tests: **183 passed**. Nothing committed or pushed (branch `m0-trust-gate`).

---

## M3 (redone): token-budgeted AI workflow ✅ (24 Nov 2026)

**Why it was redone.** The first live run used the open-ended agent loop: all 24 tool schemas were sent on every call, the whole conversation was re-sent at every step, and there were no limits. FreeModel's dashboard showed **598K of the 1M monthly tokens spent in 73 calls** (about 8.2K per call), and the run never finished. Per-call usage was only kept in memory, so it was lost when the run was stopped.

**What research suggested** (used as design direction, not as claims about our numbers):
- ReWOO (Xu et al. 2023): gather evidence without the model, reason once.
- LLMCompiler (ICML 2024): run independent calls in parallel.
- Agentless (FSE 2025): a fixed pipeline beat agent loops at lower cost.
- Anthropic, "Building effective agents": use workflows for well-defined tasks.

**What was built (test-first, 220 tests; no test can reach a real model, see `tests/conftest.py`):**

| Part | File | What it does |
|---|---|---|
| Ledger + budget guard | `guardian/llm_budget.py` | Every call is written to `.cache/llm_usage.jsonl` (tokens, purpose, run, finish_reason; never the key or the prompt). Before sending, the worst case (input + output cap + reasoning allowance) must fit **25K per run** and **300K per 30 days**; otherwise nothing is sent. |
| Response cache | same | Identical requests are answered from `.cache/llm/` with 0 tokens and labelled `cached`. |
| Evidence packet | `guardian/ai/packet.py` | Code (no AI) builds one case per component, using introduced findings only. Each case holds the engine findings, its lockfile entry (base vs head), the manifest diff, the file diff, and from the downloaded tarball the lifecycle scripts plus the file they run (`setup.js`), read in memory and never executed. Third-party text is marked `<untrusted-data>`. Each item is stored with an ID and SHA-256. |
| Single-shot agents | `guardian/ai/workflow.py` | 1 Investigator call per case (in parallel), then 1 Verifier call. No tool calling. Code rejects any claim that cites no evidence or unknown evidence, or that mentions a version or ID missing from the cited evidence. The rules verdict is copied, never changed. A budget stop or failure is shown as `partial`. |
| Explanations | `guardian/scoring/explain.py` | On request; low reasoning effort (`GUARDIAN_EXPLAIN_EFFORT`). Opening the scores page no longer spends tokens (`GUARDIAN_AUTO_EXPLAIN=1` turns that back on). |
| Deep mode | `guardian investigate --deep` | The old loop, kept behind a flag and under the same budget. |
| API + UI | `/api/investigate`, `/api/investigation`, `/api/ai/usage`; `Investigation.tsx`, AI review in the fix panel | Progress events, 🤖 claims with evidence chips (SHA-256 on hover), Verifier challenges, a monthly token meter, and calls/tokens per run. |

**Measured live runs (Uptime Kuma scenario, DeepSeek V4 Flash, medium), from the ledger:**

| Run | Calls | Tokens | Time | Result |
|---|---|---|---|---|
| 1 | 3 | 15,669 | 31 s | Investigators good (9 claims kept, 0 rejected). Verifier returned empty: all output went to hidden reasoning. |
| 2 | 0 + 2 cached | 0 | 0.1 s | The budget guard refused the Verifier *before sending*. This exposed that the run cap was keyed to the packet and summed across retries; it's now per run. |
| 3 | 1 + 2 cached | 9,481 | 30 s | Complete: 6 challenges, 3 missed risks. Some disputes came from my 250-character trimming. |
| 4 (after the fixes) | 2 + 1 cached | 16,023 | 43 s | Complete. The Investigator read `setup.js` and called it a canary, "consistent with a deliberately planted test fixture". The Verifier caught a real overstatement: GHSA-ch9v is Grype-only and rated Track/low. |
| 5 (same evidence) | 0 + 3 cached | **0** | 0.1 s | Identical result from the cache. |

Other live calls:
- **Fix-plan review:** 1 call, 5,542 tokens, 15 s; 2 explanations and 5 concerns, 0 rejected.
- **One explanation (low effort):** 4,286 tokens, 13 s; 5 sentences, all citations checked.
- **A 9-card explanation batch at medium effort failed:** 13,192 tokens, `finish_reason=length`, empty reply. That is why explanations now use low effort and are no longer generated automatically.

**Before → after:**
- About 600K tokens, 73+ calls, unfinished → **about 16K tokens, 3 calls, 43 s, complete**.
- Re-running the same PR costs 0.
- Total spent on building and testing this: **64,193 tokens** (ledger).

**Changes found by measuring, not planned:**
- `max_tokens` does not cap hidden reasoning at medium effort, so the estimate now adds a 3,000-token reasoning allowance (`GUARDIAN_REASONING_ALLOWANCE`).
- Empty replies are errors and are never cached.
- The Verifier gets the full text of the evidence the claims cite.
- The Verifier may link cases using any evidence from the same run.

## M7 (redone): dashboard by journey ✅ (24 Nov 2026)

**Why.** The Run page had grown into one crowded screen, and the 4 agents weren't visible as agents.

**New structure.** Seven sections, following the product's own steps; each status comes from `/api/run`. Deep links use `#summary`, `#investigate` and so on.

| Section | Contents |
|---|---|
| Summary | The decision (rules), its reasons, run identity and hashes, key numbers, the journey with the next step highlighted |
| 1 Discover | Dependency graph (risk paths, this PR, direct runtime deps), package path, SBOMs |
| 2 Detect | Scan stages; findings table with introduced / already there / all filters, search, priority bars; proof drawer |
| 3 Investigate | The **4 agents as a live pipeline**: Lead (rules) → Investigator ×cases (parallel) → Verifier → Fixer → Gatekeeper (rules) → You. Animated connectors flow toward the working agent; clicking an agent shows exactly what it produced. One click runs them all (`POST /api/investigate {fix_review: true}`); progress comes from `/api/investigation/events`. |
| 4 Fix & approve | Computed patch → the AI review (named by package) → your decision, bound to the patch hash |
| 5 Validate | Baseline vs candidate in the isolated worker |
| 6 Report | The report's sections and their status, integrity hashes, PR events |

"Scan a project" and the clearly labelled "Recorded demo" sit in the header.

**Code structure.**
- New views live in `guardian/dashboard/src/run/`.
- Removed: `RunPage.tsx`, `Investigation.tsx`, `runShared.tsx` and `TopBar.tsx`.

**Checks.**
- Type-check and build pass; 222 tests pass.
- Screenshots via headless Chrome for Summary, Discover, Detect, Investigate and Fix.
- A live one-click run over HTTP produced the full Lead → Investigators → Verifier → Gatekeeper → Fixer → human event stream, for 0 tokens (all cached).
