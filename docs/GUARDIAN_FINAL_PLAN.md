# Software Supply Chain Guardian: Final Plan (v2.0)

> **"Know what you build. Trust what you ship."**
> Bosch BGSW Hackathon · Problem statement: *Software Supply Chain Guardian*

| | |
|---|---|
| **Version / date** | 2.0 · 25 Nov 2026. Replaces v1.2 (24 Nov), whose status was "implementation starts with M0". v1.2 is in git history. |
| **Status** | Core M0–M9 built and demonstrated live on GitHub pull requests. Main branch: `final`. |
| **Rechecked against** | The code on branch `final` (commit `c94691c`), the 489-test suite (all passing), and real PR runs on `kirankishoreV-07/uptime-kuma` (24 Nov). |
| **Legend** | ✅ built and tested · 🟡 partly built · ⬜ not built |

---

## Contents
1. [Summary](#1-summary)
2. [The problem](#2-the-problem)
3. [What is novel](#3-what-is-novel)
4. [Brief compliance](#4-brief-compliance)
5. [Design principles](#5-design-principles)
6. [End-to-end flow](#6-end-to-end-flow)
7. [Detection: scanners and detectors](#7-detection)
8. [Scoring and the verdict](#8-scoring-and-the-verdict)
9. [AI agents](#9-ai-agents)
10. [Fix, approval and repair](#10-fix-approval-and-repair)
11. [Validation sandbox](#11-validation-sandbox)
12. [Prompt-injection guardrails](#12-prompt-injection-guardrails)
13. [GitHub integration](#13-github-integration)
14. [Interfaces: dashboard, Buddy, report](#14-interfaces)
15. [Budgets and limits](#15-budgets-and-limits)
16. [Evidence of it working](#16-evidence-of-it-working)
17. [Status: built vs not built](#17-status)
18. [Demo plan](#18-demo-plan)
19. [Operations runbook](#19-operations-runbook)
20. [Risks and known limitations](#20-risks-and-known-limitations)
21. [Next steps](#21-next-steps)
22. [Decisions](#22-decisions)
23. [Glossary](#23-glossary)

---

## 1. Summary

**Guardian watches every pull request for supply-chain risk.** For each one it:
1. finds the risks the PR **adds**;
2. has AI agents investigate them **with evidence**;
3. proposes an **exact fix**;
4. waits for a **human to approve** that patch;
5. **proves** the fix in a locked sandbox: two copies of the app built, tested and rescanned side by side;
6. reports the **before/after** result on the PR.

Rules make every decision. AI only investigates and explains, and code checks everything the AI writes.

**Proven live on 24 Nov 2026:** PR #11 (`follow-redirects`) went from REVIEW to ALLOW, verified in the sandbox. PR #12 (`lodash`) went from REVIEW to ALLOW. Both ran from opening the PR on GitHub to the final report.

## 2. The problem

Teams still can't answer four questions quickly:
1. What is in my application, and what did this change add?
2. Which of these risks actually matter here?
3. Is this change suspicious even though no CVE exists (look-alike package, registry redirect, tampered lockfile)?
4. How do I fix it safely, and how do I know the fix worked?

Bosch asks for an agentic AI solution that answers all four, keeps a human in control and proves its results.

## 3. What is novel

**AI investigates, rules decide, and the sandbox proves the fix.** Scanners only find problems. Guardian closes the loop.

| # | Feature | Why it matters |
|---|---|---|
| 1 | **Judges only what the PR adds**, comparing against the merge base as GitHub does | No developer is blocked for someone else's old debt |
| 2 | **AI explains, rules decide.** 4 agents; every claim must cite stored evidence or it is rejected | Reproducible; prompt injection can't flip a verdict |
| 3 | **Proves the fix.** Base branch and PR plus patch are built and tested in parallel in locked Docker sandboxes, then rescanned | "Fixed" means shown to work, not predicted |
| 4 | **The human approves the exact patch hash.** Change one byte and the approval is void; the audit trail is hash-chained | Accountable, tamper-evident |
| 5 | **Learns from failure.** A failed validation is remembered and blamed on a package; the next fix avoids that version; replacement versions must have 0 known advisories | Bounded self-repair, never self-approving |
| 6 | **AI-written tests** when the project's own tests don't reach an upgraded package | Covers the dependency-test gap |
| 7 | **Detects attacks with no CVE**: look-alikes, registry redirects, lockfile tampering, new install scripts, dangerous CI triggers | Catches what databases don't know yet |

## 4. Brief compliance

| Brief item | Where | Status |
|---|---|---|
| Discover components (direct/transitive, runtime/dev) | `inventory/`, `adapters/` | ✅ |
| Supply-chain view: SBOM (CycloneDX + SPDX), dependency graph, CI workflows, images | `inventory/`, `graph/` | ✅ |
| Detect known vulnerabilities | OSV + Grype (`vuln/`) | ✅ |
| Detect suspicious changes | 17 detector types (§7) | ✅ |
| Compare a change with its base | merge-base comparison (`trigger/service.py`) | ✅ |
| Prioritise with reasons | floors, then SSVC, then AHP priority (`scoring/`) | ✅ |
| Agentic investigation | Lead, Investigators, Verifier, Fixer (`ai/workflow.py`) | ✅ |
| Recommend an exact fix | deterministic candidates and patch (`remediation/`) | ✅ |
| Human in control | patch-hash approval (`approval.py`) | ✅ |
| Validate the fix | Docker sandbox, baseline vs candidate, rescan, SBOM diff (`validation/`) | ✅ |
| Report | HTML + JSON evidence pack (`report/`) | ✅ |
| Continuous (PR trigger) | GitHub Actions on a self-hosted runner, with statuses and comment | ✅ |

## 5. Design principles
1. **Rules decide; AI advises.** The verdict, scores, fix versions and the "verified" gate are code.
2. **Evidence or it didn't happen.** Every claim cites stored evidence; unknown facts stay "unknown".
3. **Blame the PR only for what it adds.**
4. **The human approves the exact bytes** (patch SHA-256).
5. **Never claim more than was checked.** An incomplete scan or validation is shown as incomplete, never as clean.
6. **Fail safe.** No model, no budget or an outage means rules-only results, never a silent pass.
7. **All third-party text is data, never instructions** (§12).

## 6. End-to-end flow

```
PR opened on GitHub
  → guardian.yml on our self-hosted runner → Guardian server queue
  → ① Snapshot (git objects, nothing executed) of base and head; comparison base = merge-base
  → ② Discover: components, SBOMs, graph, CI, images
  → ③ Detect: OSV + Grype + 17 detector types → introduced / already there / fixed
  → ④ Score: floors → SSVC → priority → verdict BLOCK / REVIEW / ALLOW
  → GitHub status guardian/scan + PR comment; Buddy pops up
  → ⑤ Investigate (AI): Lead groups into cases → Investigators (parallel) → Verifier
  → ⑥ Fix: rules compute candidates + patch → Fixer explains → readiness pre-check
  → ⑦ Approve (human, exact patch hash)
  → ⑧ Validate: baseline ‖ candidate ‖ rescan in parallel → SBOMs → AI tests → gate
      └─ failed → Repair: remember → blame → recompute (needs new approval, max 3)
  → status guardian/validation ("Fix verified: REVIEW → ALLOW …")
  → ⑨ Report: HTML + JSON, hash-chained audit
```

The dashboard follows the same seven steps: Summary → Discover → Detect → Investigate → Fix & approve → Validate → Report.

## 7. Detection

**Scanners:** OSV and Grype (vulnerabilities, `MAL-` malware records), Syft (SBOM), zizmor (workflow weaknesses). EPSS and CISA KEV are cached daily.

**Detector types** (deterministic, with file/line evidence; each has a positive and a benign test):

| Group | Types |
|---|---|
| Package identity | `typosquat`, `unresolvable_dependency` (dependency confusion), `undeclared_dependency`, `new_dependency`, `suspicious_update` |
| Install-time code | `install_script`, `new_install_script` |
| Source and integrity | `untrusted_source`, `source_change`, `non_registry_source`, `extra_index_url`, `lockfile_tamper`, `modified_lockfile` |
| Config and CI | `sensitive_file_change` (`.npmrc`, workflows, hooks …), dangerous CI triggers, unpinned actions and images |
| Web | `remote_script_no_sri`, `unpinned_remote_script` |

**Benign controls:** routine patch bumps and allow-listed install scripts (`esbuild`, `core-js` …) are not flagged.

## 8. Scoring and the verdict

| Layer | What it does |
|---|---|
| ① Hard floors | Malware, registry redirect, tampered integrity, or look-alike plus install script → **Critical**, which nothing can lower |
| ② SSVC | Exploitation (KEV/EPSS), automatable, exposure, impact → Act / Attend / Track* / Track |
| ③ Priority 0–100 | AHP-weighted factors; orders findings that share a decision |
| ④ Explanation | Points per factor, decision path, "what would change it" |

**One verdict function** (`scoring/verdict.py`), counting **introduced findings only**:
- **BLOCK**: a Critical or an "Act" decision is introduced.
- **REVIEW**: a High is introduced.
- **ALLOW**: nothing High or Critical is introduced.
- **Incomplete**: a required scanner failed. This is never shown as clean.

## 9. AI agents

| Agent | Kind | Job |
|---|---|---|
| **Lead** | rules | Groups introduced findings into cases by package or file; plans by risk (lower of level and severity) |
| **Investigator** ×N | AI, parallel | Examines one case with its evidence; must cite evidence IDs |
| **Verifier** | AI | Challenges claims and looks for missed risks (sees up to 12 cases) |
| **Fixer** | AI | Explains each computed fix and its trade-offs (batches of 12, up to 48) |
| **Gatekeeper** | rules | Checks every AI sentence against stored evidence; rejects invented IDs, numbers, links or directives |

**Planning:** the 6 highest-risk cases are investigated in depth. Other High/Critical cases go to a batched triage (5 per call, up to 30). The rest are rules-only. A failed call is split and retried, never silently dropped.

**Providers:** DeepSeek first, then FreeModel, then Gemini as fallbacks. Identical evidence is answered from cache at 0 tokens.

## 10. Fix, approval and repair

- **Candidates (rules):**
  - `upgrade_to_fixed`
  - `override_transitive`
  - `remove_package`
  - `restore_lock_entry` (tampered existing package)
  - `revert_change`
  - CI and image pins are escalated to a person.
- **Clean-target rule:** a version is chosen only if OSV lists **0 advisories** for it. Skipped versions are listed in the rationale.
- **Patch:** one combined patch with a SHA-256 hash, files changed and lock entries changed.
- **Readiness pre-check:** before validating, a static check verifies the plan, merge base, profile, required packages, approval, sandbox image and registry. A run that can't pass is refused unless forced ("run anyway").
- **Approval:** bound to `{base, head, patch_sha256, profile hash}`. It expires after 24 h and is recorded in the hash-chained audit.
- **Repair loop** (`remediation/repair.py`):
  1. A failed validation is written to `repair-memory.json`.
  2. Blame: rules read the obvious cases (new advisory, target still present, AI-test regression). For a failed build or test with several upgrades, the Fixer picks suspects, but **only from the plan's own packages**.
  3. The fix is recomputed with the failed versions excluded.
  4. The new patch has a new hash, so it **needs a new approval**.
  5. After **3** failed repairs, a person decides.

## 11. Validation sandbox

**Isolation:**
- all Linux capabilities dropped;
- non-root user;
- no secrets and no Docker socket;
- no internet except the local Verdaccio registry;
- 2 CPU / 4 GB per sandbox;
- containers removed after the run, and orphans cleaned at server start.

**Flow** (`validation/validate.py`):
1. Prepare two copies of the code: the **baseline** (base branch) and the **candidate** (PR plus approved patch).
2. Run **in parallel**: baseline sandbox ‖ candidate sandbox ‖ rescan of the candidate.
3. Generate Syft SBOMs of what was really installed.
4. Run AI behaviour tests for upgraded packages that no project test imports (up to 6 packages). Guardian writes the test header; code checks the test body. A test must pass on the PR's version first, otherwise it is discarded as unreliable.
5. **Gate:** verified only if every required stage passed on the candidate, the targets are corrected, no new High is introduced, and no AI-test regression.

**Uptime Kuma profile (v5) stages:**

| Stage | Command |
|---|---|
| install | `npm ci`, scripts off |
| hooks | 1 allow-listed install script, cached by name, version, integrity, image digest and command |
| build | `npm run build` |
| target_test | jsonata sandbox security test |
| unit | SQLite suite |
| integration | start, log in, add a monitor |

- Test stages are retried once and labelled `flaky`.
- A failed test stage doesn't stop the later stages.
- Repositories with no profile get the **generic-npm** profile (install / build / `npm test`, where present).

**Time:**
- about 1.5–2 minutes when Docker has free memory;
- about 5 minutes when other containers compete for Docker's memory (seen 24 Nov).

## 12. Prompt-injection guardrails

`ai/guard.py` is applied on every model path:
- packet, workflow, review, explanations, advisor, agent tools, constitution;
- GitHub comments;
- dashboard links.

**Input:**
- `clean()` removes invisible characters, control bytes and fake fence tags, and caps the length.
- `fence()` wraps untrusted text in a boundary derived from the content, so the text can't forge it.
- `scan()` names injection attempts; a hit is evidence for the human, never a decision.

**Output:**
- `check_output()` rejects role or fence tokens, images or HTML, links not found in the evidence, and "approve / merge" directives.
- Rejected text is recorded along with the reason.

**Structural:** the verdict, fix versions, approval and gate are code, so persuading the model changes nothing.

## 13. GitHub integration

- **Trigger:** `.github/workflows/guardian.yml` on a self-hosted runner. It submits the PR to the local server's queue.
- **Two statuses:**
  - `guardian/scan` (BLOCK / REVIEW → failure, ALLOW → success, incomplete → error);
  - `guardian/validation` (e.g. "Fix verified: REVIEW → ALLOW. Fixed PR adds 0 vulnerabilities, 0 malware …").
- **Branch protection:** `guardian-demo` requires `guardian/scan`, and admins are included. A risky PR **cannot merge** until the fix is committed to it and the rescan is ALLOW.
- **PR comment:** a single comment, updated in place. It is sanitised: one line per item, only Guardian's own link, markdown escaped.
- **Nightly:** `guardian-nightly.yml` rescans the whole repository and keeps **one** open issue updated, so newly published advisories in "already there" packages are tracked.
- **Tokens:** a per-repository fine-grained token, never logged, kept in `guardian/.env` (mode 600, git-ignored).

## 14. Interfaces

- **Dashboard** (React / TypeScript / Tailwind, served at `127.0.0.1:8765`):
  - the 7 steps;
  - live PR events (server-sent events), with an option to follow new PRs;
  - live validation lanes with an animated progress rail;
  - readiness card, AI-tests card and repair memory;
  - the token budget meter.
- **Guardian Buddy** (Electron shield pet): pops up on PR events and opens Guardian pages in its own window. It only displays; it has no approval buttons.
- **Report:** HTML and JSON built from the same run. It covers:
  - run and decision;
  - inventory and SBOMs;
  - findings;
  - investigation;
  - the approved action;
  - validation;
  - before/after;
  - remaining risk;
  - confidence;
  - audit chain.

## 15. Budgets and limits

| Item | Value |
|---|---|
| Monthly AI token cap | 1,000,000 (`GUARDIAN_MONTH_TOKEN_BUDGET`) |
| Per-run AI budget | 60,000 tokens |
| Deep-investigated cases per run | 6 (the rest are triaged or rules-only) |
| Triage | batches of 5, up to 30 cases |
| Verifier | up to 12 cases |
| Fixer review | batches of 12, up to 48 candidates |
| AI tests | up to 6 packages, 5 tests each, 40 lines |
| Repair attempts | 3, then a person decides |
| Approval lifetime | 24 h |

## 16. Evidence of it working
- **Tests:** 489 pass (`pytest`), covering every detector, the verdict, guardrails, merge base, readiness, AI tests, clean target, repair, fix-review batching and investigation planning.
- **Live PRs on `kirankishoreV-07/uptime-kuma` (24 Nov):**
  - **#5** verified;
  - **#11** REVIEW → ALLOW verified after one repair (follow-redirects 1.16.0 had its own advisories, so the repair moved to 1.16.2);
  - **#12** REVIEW → ALLOW verified;
  - **#4** "fix typo" is correctly **BLOCKed** (a hidden supply-chain attack);
  - **#3** (docs) is ALLOWed and mergeable.
- **Agents:** investigation completed on small and large PRs. The Fixer reviewed 48 of 48 candidates.

## 17. Status

| Area | Status | Note |
|---|---|---|
| M0 trust fixes (T1–T11) | ✅ | Regression tests included |
| M1 one engine | ✅ | `universal.py` |
| M2 run states, confidence, one verdict | ✅ | |
| M3 live investigation | ✅ | Risk-ordered planning and triage |
| M4 fix generator and Fixer | ✅ | Clean-target rule |
| M5 approval and validation | ✅ | Parallel lanes, readiness, AI tests, repair |
| M6 report | ✅ | HTML + JSON |
| M7 dashboard | ✅ | 7-step journey |
| M8 PR trigger | ✅ | Actions and a self-hosted runner; two statuses; comment; branch protection |
| M9 docs | ✅ | `docs/README.md` index; older plans in `docs/archive/` |
| Prompt-injection guardrails | ✅ | §12 |
| Guardian Buddy | ✅ | macOS-tested |
| S1 reachability | 🟡 | Level 1 (imported by app code) only; no function-level call graph |
| S2 automatic fix PR | ⬜ | The patch exists, but Guardian doesn't push it to the PR; a person commits it |
| S3 provenance (`npm audit signatures`, cosign) | ⬜ | |
| S4 advanced package risk | 🟡 | Dependency confusion ✅; maintainer change, release age and bursts ⬜ |
| S5 policy-as-code (Rego) | ⬜ | Python policy only |
| S6 continuous monitoring | 🟡 | Nightly workflow and one updated issue ✅; EPSS/KEV re-ranking of stored inventories not separately tested |
| MCP server | ⬜ | Optional |

## 18. Demo plan

**About 6 minutes. Demo branches are prepared but have no PRs yet:** `demo/10`, `demo/11` and `demo/12-pin-lodash`. Each is an identical copy of PR #1: lodash is pinned to 4.17.20, and the fix moves it to 4.18.1, which has 0 advisories.

| # | Scene | Shows |
|---|---|---|
| 1 | Open `compare/guardian-demo...demo/11-pin-lodash` (**check base = `guardian-demo`**) and create the PR | Trigger |
| 2 | Status 🔴 REVIEW, PR comment, Buddy pops up | Continuous checking |
| 3 | Detect: "introduced 6 vs already there 144" | Only the PR is blamed |
| 4 | Investigate: Lead → cases → Investigators → Verifier → Gatekeeper | Agentic AI with evidence |
| 5 | Fix & approve: patch, folders, budget → **you approve** | Human in control |
| 6 | Validate: parallel lanes → ✅ **REVIEW → ALLOW** | The proof |
| 7 | Report, plus PR #4 BLOCK and PR #3 ALLOW | Evidence and contrast |
| 8 | *(Optional)* commit the fix → scan 🟢 → Merge unlocks | The loop closes |

**Backup:** `demo/12-pin-lodash`. If the judges should see the agents run live rather than answer from cache, use a PR whose evidence hasn't been seen before.

**Say:** *"Other tools say 'you have a problem'. Guardian says 'here's the problem, here's the fix, and here's proof the fix works', and a human stays in control."*

## 19. Operations runbook

| Task | Command or action |
|---|---|
| Start Docker | Open Docker Desktop |
| Free memory for faster validation | `docker stop $(docker ps -q --filter name=supabase_)` |
| Start the runners | `cd ~/actions-runner-guardian-kuma && ./svc.sh start` (and `~/actions-runner-guardian`) |
| Stop the runners | `./svc.sh stop` in the same folders |
| Start the server | `cd guardian && .venv/bin/uvicorn guardian.server:app --host 127.0.0.1 --port 8765` |
| Health check | dashboard opens; Verdaccio `curl 127.0.0.1:4873/-/ping`; `grype db status` is valid; runner shows online in repo settings |
| **Never** | restart the server during a validation; click "Compare & pull request" on `louislam/uptime-kuma`; open a PR against `master` |

## 20. Risks and known limitations

**Risks**

| Risk | Mitigation |
|---|---|
| Slow validation under Docker memory pressure | Stop other containers; the UI shows live progress and the elapsed time |
| PR opened against the wrong base (`master`) | Use the compare links; the merge-base comparison limits the damage; change the base in PR settings |
| AI quota or outage | Fallback chain; cache; rules-only results; the budget meter |
| Server restarted mid-validation | Marked "interrupted", orphans cleaned; run it again |

**Limitations**
- The full fix-and-validate loop targets **npm**. Other ecosystems get scan and compare only.
- Reachability is a static import estimate.
- Passing tests prove only the named tests. MariaDB, network-dependent and Playwright e2e suites are reported as "not run".
- EPSS is a probability; KEV shows exploitation, not our exposure.
- Confidence measures the quality of the evidence, not whether a finding is correct.
- Counts depend on the commit, tool versions and the advisory database date.
- Dashboard links in PR comments point to `127.0.0.1` and open only on the demo machine.
- The attack scenario is planted by us and harmless.

## 21. Next steps

After the hackathon, cheapest first:
1. **S2:** push the approved patch to the PR branch automatically (only with a valid approval).
2. **S5:** Rego backend with a parity test.
3. **S3:** `npm audit signatures` provenance per changed package.
4. **S4:** maintainer change, release age (under 7 days) and release bursts.
5. **S1 level 2:** a call graph to the vulnerable function.
6. Host the dashboard so PR-comment links work for everyone.
7. **Housekeeping:** update the AI token row in `KNOWN_LIMITATIONS.md` to the current caps (60K per run, 1M per month), and rotate every key and token used during the demo.

## 22. Decisions

| Decision | Reason |
|---|---|
| Uptime Kuma 2.5.12 as the sample app (fork, `guardian-demo` branch) | Real npm tree, tests, MIT licence |
| One rule engine; AI never decides | Reproducible, explainable, injection-resistant |
| Merge-base comparison | Matches what GitHub shows; no wrong-base noise |
| Four AI roles plus rule-based Lead and Gatekeeper | Separation of duties; parallel cases |
| Parallel baseline, candidate and rescan | About 2× faster validation |
| Clean-target rule and repair loop | A "fix" must not bring its own advisories |
| AI tests only with a code-written header and a code-checked body | Extra coverage without unsafe code |
| GitHub Actions and a self-hosted runner; branch protection on `guardian/scan` | A native PR check that actually blocks merges |
| Never PR to upstream `louislam/uptime-kuma` | Out of scope and unsafe |

## 23. Glossary

| Term | Meaning |
|---|---|
| SBOM | List of every component and version (CycloneDX / SPDX formats) |
| Lockfile | Exact installed versions, sources and hashes (`package-lock.json`) |
| Merge base | The commit where a PR branch split from its target |
| CVE / GHSA / MAL- | Vulnerability IDs / GitHub advisory / OSV malware record |
| Typosquat | Look-alike package name (`axois` for `axios`) |
| EPSS / KEV | Exploit probability / CISA list of exploited vulnerabilities |
| SSVC | CISA decision method: Act / Attend / Track |
| AHP | Method for deriving weights from pairwise comparisons |
| Verdaccio | Local npm registry used by the sandbox |
| Prompt injection | Text that tries to give instructions to an AI |

*Older plans (`PRODUCT_PLAN`, `PR_TRIGGER_PLAN`, `AGENTIC_CORE`, v1 `FINAL_PLAN`) are kept in `docs/archive/` for history.*
