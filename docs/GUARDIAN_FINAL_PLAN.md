# Software Supply Chain Guardian: Final Comprehensive Plan

> **"Know what you build. Trust what you ship."**
> Bosch BGSW Hackathon · Problem statement: *Software Supply Chain Guardian*

| | |
|---|---|
| **Document** | Final comprehensive plan (consolidates `PRODUCT_PLAN.md` v2.2, `day2-scoring/PLAN.md`, `PR_TRIGGER_PLAN.md`) |
| **Version / date** | 1.2 · 24 Nov 2026 (trigger: GitHub Actions primary; review corrections applied) |
| **Status** | Architecture frozen. Implementation starts with M0. |
| **Checked against** | `brief/Problem_Statement.pdf`, all 6 slides, point by point (§3) |
| **Status legend** | ✅ built and tested · 🟡 partly built · ⬜ planned · ❌ built but has a known defect (fix planned in M0) |
| **Data note** | All counts come from Uptime Kuma 2.5.12 (`5aa5dec4`) and the scenario PR `da93835 → 576752d`, with tool and database versions as of 23 Nov 2026. Other commits or databases give different numbers. |

---

## Contents

1. [Executive summary](#1-executive-summary)
2. [The problem in our words](#2-the-problem-in-our-words)
3. [Slide-by-slide compliance (all 6 slides)](#3-slide-by-slide-compliance)
4. [How we got here](#4-how-we-got-here)
5. [Design principles](#5-design-principles)
6. [Architecture](#6-architecture)
7. [The pipeline, stage by stage](#7-the-pipeline-stage-by-stage)
8. [Tools: what each does and why we chose it](#8-tools)
9. [Detectors](#9-detectors)
10. [Scoring and prioritisation](#10-scoring-and-prioritisation)
11. [AI agents](#11-ai-agents)
12. [Run contracts: identity, states, approval, verification](#12-run-contracts)
13. [Validation sandbox](#13-validation-sandbox)
14. [Evidence and proof model](#14-evidence-and-proof-model)
15. [Triggers and GitHub integration](#15-triggers-and-github-integration)
16. [User interfaces: dashboard and Guardian Buddy](#16-user-interfaces)
17. [Stretch goals](#17-stretch-goals)
18. [Security and Responsible AI](#18-security-and-responsible-ai)
19. [Testing strategy](#19-testing-strategy)
20. [Milestones, effort and team plan](#20-milestones-effort-and-team-plan)
21. [Demonstration script](#21-demonstration-script)
22. [Risks and known limitations](#22-risks-and-known-limitations)
23. [Decisions](#23-decisions)
24. [Glossary](#24-glossary)
25. [Sources](#25-sources)

---

## 1. Executive summary

**Guardian analyses supported supply-chain changes in an application, explains which risks matter with evidence, recommends an exact fix, waits for a human to approve it, and then validates the fix by building, testing and rescanning. It reports what it checked and what it could not check.**

**What exists today:** a working scan engine. It discovers components in supported formats (coverage reported per run; deepest for npm), builds CycloneDX and SPDX SBOMs and a dependency graph, finds known vulnerabilities (OSV + Grype) and malware records, runs 14 supply-chain detectors, compares a PR against its base, scores every finding with explainable rules, and shows results with evidence in a web dashboard. Tests: 45 pass on a machine with the sandbox, registry and network; without them, 42 pass and 3 are skipped.

**What remains:** the Day 2 loop: live AI investigation, fix recommendation, human approval, validation in a sandbox, the final report, the PR trigger, and the stretch goals. Before that, M0 fixes 9 confirmed defects and adds 2 regression requirements (T9, T10, whose defects are not yet confirmed).

**Our honest difference:** Dependabot and OSV-Scanner already propose upgrades for known CVEs. Guardian adds:
1. detection of **suspicious changes that have no CVE** (look-alike packages, registry redirects, tampered lockfiles, new install scripts);
2. **evidence-backed investigation** that also considers innocent explanations;
3. an **exact, human-approved patch**;
4. **independent validation** with a before/after comparison;
5. every statement labelled as 🔒 verified fact, 🤖 AI inference, or 👤 human decision.

---

## 2. The problem in our words

Modern applications are assembled from open-source packages, their dependencies, container images and CI/CD components, and all of these change constantly. Scanners can list known vulnerabilities, but teams still struggle to answer four questions:

1. **What is actually in my application, and what changed?**
2. **Which of these risks really matter here?** (exploited? reachable? shipped?)
3. **Is this change suspicious even though no CVE exists?** (e.g. a look-alike package)
4. **How do I fix it safely, and how do I know the fix worked?**

Bosch asks for an **agentic AI solution** that answers all four, keeps a human in control, and proves its results with evidence.

---

## 3. Slide-by-slide compliance

### Slide 1: Title and pillars

| Pillar | How Guardian addresses it |
|---|---|
| Secure dependencies | Vulnerability + malware detection, exact fixes, validation (§7, §13) |
| Detect risks | 14 detectors + OSV + Grype + CI/image checks (§9) |
| Enable developers | PR status + comment, dashboard, Buddy, plain-language explanations (§15, §16) |
| Improve resilience | Before/after validation, continuous monitoring (§13, §17 S6) |
| Stronger together | Human approval, audit trail, shareable reports (§12, §14) |

### Slide 2: Problem statement and five capabilities

| Requirement | Guardian | Status |
|---|---|---|
| Agentic AI solution | Four tool-using agents in a fixed flow with human approval (§11) | 🟡 agents run on recorded data; live tools, Fixer and Verifier ⬜ |
| Continuously analyses the supply chain | PR trigger on every change (§15) + nightly monitoring (§17 S6) | ⬜ |
| Identify dependency risks, vulnerabilities, suspicious changes | Rule engine (§7, §9) | ✅ |
| Before they impact applications | Base→head comparison; BLOCK fails the PR status and the CLI exit code | 🟡 comparison ✅ · exit code ❌ T6 |
| Understand which risks matter, reachable or exploitable | SSVC + KEV + EPSS + exposure + reachability (§10) | 🟡 reachability ⬜ |
| What changed in the supply chain | introduced / pre-existing / fixed labels | 🟡 labelling defects T2, T3 |
| How to remediate safely | Fix → approve → validate (§11–§13) | ⬜ |
| Connect evidence with application context | Dependency paths, runtime vs dev, shipped frontend, introduced-by-PR | ✅ (T11 fix for frontend) |
| **① Discover** | §7 stages ③–④ | ✅ |
| **② Detect** | §7 stage ⑤ | ✅ |
| **③ Analyse & prioritise with AI** | §10 (rules) + §11 (agents explain and investigate) | 🟡 |
| **④ Recommend safe remediation** | §11 Fixer + §10.6 fix generator | ⬜ |
| **⑤ Validate & report** | §13 + §14 | ⬜ |

### Slide 3: Guidelines

**Examples of supply-chain risks.** These are examples, not a requirement that every run triggers all of them.

| Risk | Detection | Demonstrated on | Status |
|---|---|---|---|
| Vulnerable direct dependency | OSV + Grype | `jsonata@2.2.0` (direct) | ✅ |
| Vulnerable transitive dependency | OSV + Grype + path to root | Uptime Kuma baseline | ✅ |
| Typosquatted or malicious package | D1 look-alike + OSV `MAL-` | `axois` (look-alike of `axios`) | ✅ |
| Suspicious package update or install script | D2, D5 | `axois` postinstall | ✅ |
| Untrusted container image or artifact | D8, D3 | 12 unpinned images (**pre-existing** in the app) | ✅ |
| Unexpected lockfile or dependency change | D6, D7, D3 | Scenario lockfile tamper | ✅ |
| Unpinned or unsafe CI/CD component | D10 + zizmor | Flask / Uptime Kuma workflows | 🟡 T2 |

**Sample application guidelines**

| Guideline | Our choice | Status |
|---|---|---|
| Free open-source app from a public repository | **Uptime Kuma 2.5.12** (MIT licence), pinned commit `5aa5dec4` | ✅ |
| Realistic dependency tree | 161 direct, 1,312 total packages | ✅ |
| Containerised, runnable locally | `docker/dockerfile`; health check recorded | ⬜ |
| Build, test and scan locally | Validation profile (§13) | 🟡 scan ✅ |
| Document repo, setup, dependencies, tools | README, SETUP, `tools.lock` (pinned versions + SHA-256) | 🟡 |

**Out of scope: how we comply**

| Rule | Compliance |
|---|---|
| No scanning or attacking production systems | Scans read files only; code runs only inside the isolated worker and restricted builder |
| No repositories/registries outside the authorised sandbox | Mentors confirmed (24 Nov) that **read-only scans of public Git URLs are allowed**. The attack scenario uses only our local sandbox and local Verdaccio. |
| No publishing malicious or modified packages | The test package exists only in local Verdaccio; scenario branches are never pushed |
| No real credentials or secrets | Tokens in `.env` (git-ignored, mode 600), never logged or sent to the model; the worker receives none |
| No auto-merge, deploy or release without approval | Approval contract (§12.3); Guardian never merges |
| Nothing affecting other teams | Everything runs locally |

### Slide 4: Day 1 "Build the Guardian's Eyes"

| Box | Requirement | How | Status |
|---|---|---|---|
| 1 Discover | Manifests and lockfiles; direct and transitive; names and versions | Own npm lockfile parser + Syft for other ecosystems | ✅ |
| 2 Supply-chain view | Generate or consume an SBOM (CycloneDX or SPDX) | Both formats, from Syft, plus our own CycloneDX | ✅ |
| | Build the dependency graph | NetworkX graph from the lockfile, cross-checked with `npm ls` | ✅ |
| | Where each component originates | Resolved URL and registry host per package | ✅ |
| | At least one container image or CI/CD workflow | 12 images, 20 workflows, 79 actions | ✅ |
| 3 Detect vulnerabilities | Correlate with known vulnerabilities | OSV (offline + API) + Grype | ✅ (T3 join fix) |
| | CVE, severity, available fixes | Advisory ID, CVSS, fixed versions | ✅ |
| | Trace transitive vulnerabilities to their source | Path, e.g. app → parent → vulnerable package | ✅ |
| 4 Suspicious changes | At least one anomaly | Scenario: look-alike, install script, registry redirect, untrusted source, malware record, each with its own evidence | ✅ |
| 5 Present evidence | What, which component, path, evidence, initial risk | Dashboard finding cards + proof drawer | ✅ |
| **Checkpoint** | "What is in the application, what changed, what appears risky" | `guardian check` base→head | ✅ |

### Slide 5: Day 2 "Build the Guardian's Brain & Shield"

| Box | Requirement | Plan | Status |
|---|---|---|---|
| 1 Prioritise | Severity × exploitability × reachability × exposure | §10 | 🟡 reachability ⬜ |
| | Is the dependency used in production? | Runtime vs dev **plus** shipped-frontend rule (T11) | 🟡 |
| | Urgent vs lower priority | SSVC Act / Attend / Track | ✅ |
| | Explainable risk score **and confidence level** | §10.3–10.4 | 🟡 confidence ⬜ |
| 2 Investigate | At least one non-CVE risk | Live investigation of the `axois` + `.npmrc` case (§11) | ⬜ |
| | Compare versions, manifests, lockfiles | Base→head diff | ✅ |
| | Suspicious scripts, provenance gaps, integrity changes | D2, D7 ✅ · provenance S3 ⬜ | 🟡 |
| | **Separate verified evidence from AI inference** | Three badges; checker fix T4 | ❌ T4 |
| 3 Recommend | Upgrade / replace or remove / pin / update base image / block / escalate | Deterministic fix generator (§10.6) | ⬜ |
| | Expected risk reduction, compatibility impact, rollback | On every fix card | ⬜ |
| 4 Validate | Apply in a controlled branch or sandbox | Isolated worker (§13) | ⬜ |
| | Build; unit and integration tests | Exact test manifest (§13.3) | ⬜ |
| | Rescan the resulting artifact | Source **and** image rescan | ⬜ |
| | Compare before/after SBOM; detect new vulnerabilities or dependencies | SBOM diff + finding diff | ⬜ |
| 5 Verify & report | Original finding + evidence; approved action; build/test results; before/after risk; remaining or accepted risk; final confidence and audit trail | §14.4 report | 🟡 |
| **Final demo** | "Detection → verified remediation" | §21 | ⬜ |

### Slide 6: Stretch goals and deliverables

**Stretch goals** (detail in §17)

| # | Goal | Status |
|---|---|---|
| S1 | Reachability analysis | ⬜ (import tier = partial; function tier = complete) |
| S2 | Automated remediation PR | ⬜ |
| S3 | Provenance verification (Cosign / Sigstore / in-toto / SLSA) | ⬜ |
| S4 | Advanced package risk (dependency confusion, maintainer change, unusual releases, suspicious behaviour) | 🟡 dependency confusion ✅ |
| S5 | Policy-as-code (OPA / Conftest) | ⬜ |
| S6 | Continuous monitoring | ⬜ |

**Deliverables**

| Deliverable | What we hand in | Section | Status |
|---|---|---|---|
| Working prototype | Full npm loop on Uptime Kuma | §7–§13 | 🟡 |
| Architecture overview | Diagram: agents, tools, data sources, AI interactions, approval points, evidence storage, trust boundaries | §6 | 🟡 |
| Source code & setup | Code, configuration, setup steps, **sample policies**, **prompts**, validation profile, **known limitations** | §20, §22 | 🟡 |
| Live demonstration | Discovery → detection → prioritisation → remediation → approval → validation | §21 | ⬜ |
| Guardian report | Human-readable HTML + machine-readable JSON from the same run | §14.4 | 🟡 |
| Responsible AI & security note | Where AI is used, hallucination control, approvals, protection of code and secrets | §18 | 🟡 |

**Summary:** every point on all six slides has a defined place in this plan. Day 1 functionality is substantially implemented, with known correctness defects (M0) and scenario validation still to finish; Day 2, the stretch goals and the deliverables are planned with acceptance tests.

---

## 4. How we got here

| Phase | What we did | Outcome |
|---|---|---|
| **1. Day 1 engine (npm)** | Lockfile parser, SBOMs, dependency graph, OSV + Grype, detectors D1–D10, base→head comparison | Uptime Kuma: 1,312 components; 121 advisories, 119 confirmed by both scanners |
| **2. Attack scenario** | Built a safe, local attack PR "fix typo": adds the look-alike `axois` (its postinstall only writes a marker file), redirects `.npmrc` to a local registry, tampers with the lockfile | Guardian blocks it, catching it several independent ways |
| **3. Explainable scoring** | Hard floors → SSVC (with CISA KEV and EPSS) → AHP-weighted 0–100 priority; explanations checked against evidence | Every score shows its parts |
| **4. Any repository** | `universal.py`: Syft for all ecosystems, CDN/vendored scripts, browser extensions, undeclared imports, registry config, CI, OSV.dev API | Flask (Python), ARKABROAD (extension), portfolio sites all complete |
| **5. Dashboard** | FastAPI + React: project scans (Git URL, ZIP, local sandbox), scores, graph, Day 1 report | Usable end to end |
| **6. Selection** | Selected for the next stage | Shift from Day 1 to the full product |
| **7. Plan reviews** | Five independent reviews; every claim checked against code | 9 confirmed defects + 2 regression requirements (§20 M0); architecture frozen |

**Lessons that shaped this plan**
- Some earlier claims were too strong. Statuses are now **test-backed**, not percentages.
- More agents or models don't mean a better product. We keep **4 agents**, **simple rules**, and a **fixed flow**.
- A green signal must mean exactly one thing. We now keep **two separate statuses** and an "incomplete" state.

---

## 5. Design principles

1. **Rules decide, AI explains, humans approve.** Detection, floors, policy, pass/fail and the verdict are deterministic. AI investigates, proposes and explains. Humans approve every change.
2. **Evidence or it didn't happen.** Every claim cites stored evidence with a SHA-256 fingerprint.
3. **Unknown stays unknown.** Missing data is never treated as safe; incomplete runs are labelled.
4. **Same input, same answer.** Pinned tools (`tools.lock`), recorded database snapshots.
5. **Nothing runs that we didn't choose to run.** Scans read files only; candidate code executes only inside the two declared isolated environments (validation worker and restricted builder) under a declared profile.
6. **Honest scope.** Capability levels L1–L4 are shown on every run; unsupported checks are reported, not hidden.
7. **Simple beats clever.** One engine, one policy, one verdict function, ordered rules.

**Capability levels**

| Level | Meaning | Supported |
|---|---|---|
| L1 Scan | Inventory, SBOM, vulnerabilities, malware, CI, images, risky sources | ✅ npm, Python, GitHub Actions, Dockerfiles, browser extensions, CDN scripts · ⬜ Java/Go/Rust via Syft (untested) |
| L2 Compare | Introduced / pre-existing / fixed | 🟡 the formats above, with Git history |
| L3 Fix + rescan | Exact patch applied and rescanned | ⬜ npm |
| L4 Build + test | Baseline and candidate built and tested | ⬜ Uptime Kuma |

---

## 6. Architecture

```
 DATA SOURCES: Git repository · npm registry · OSV.dev · Grype DB · CISA KEV · FIRST EPSS · GitHub API
        │
 ┌──────▼──────────────── RULE ENGINE (deterministic, no AI) ────────────────────┐
 │ snapshot · inventory · SBOM · graph · 14 detectors · OSV + Grype             │
 │ floors → SSVC → priority · confidence · run states · ONE policy (Rego/OPA)   │──┐
 └──────┬────────────────────────────────────────────────────────────────────────┘  │
 ┌──────▼──────────────── AGENTS (fixed LangGraph flow · Gemini) ───────────────┐   │
 │ Investigator ×N (read-only) → Lead (groups cases) → Fixer ×N → combiner      │   │
 │ → Verifier (challenges, explains results) · Gatekeeper checks every citation │───┤
 └──────┬────────────────────────────────────────────────────────────────────────┘   │   EVIDENCE STORE
        │                                                                            ├─▶ + AUDIT LOG
   👤 APPROVAL POINT: run + base + head + patch hash + policy + profile + expiry ────┤   (SQLite, run-scoped,
        │                                                                            │    SHA-256 per item)
 ┌──────▼──────── VALIDATION WORKER (disposable · no secrets · no Docker socket) ┐   │
 │ baseline + candidate: install (hook allowlist) → build → unit → integration   │   │
 │ restricted builder → image → source + image rescan → SBOM diff → gates        │───┘
 └──────┬────────────────────────────────────────────────────────────────────────┘
        │
 OUTPUTS: dashboard · Guardian Buddy · GitHub statuses + comment · HTML/JSON report
          · SBOMs · fix PR (S2) · monitoring alerts (S6)

 TRIGGERS: GitHub Actions (self-hosted runner) · polling backup · Git URL · ZIP · local sandbox · nightly
```

**Trust boundaries**
1. **Repository content** is untrusted: read as files, never executed during scanning.
2. **Package text** (READMEs, changelogs, scripts) is untrusted: marked as such for agents, and checked for prompt injection.
3. **The validation worker** is where untrusted code runs, isolated from secrets, the host and the network.
4. **The model** receives minimal, redacted data and cannot change decisions.
5. **The human** is the only one who can authorise a change.

---

## 7. The pipeline, stage by stage

Running example throughout: the scenario PR **"fix typo"** on Uptime Kuma.

### ① Intake
- **Purpose:** decide exactly what to analyse.
- **How:** a GitHub PR event, Git URL, ZIP upload or local sandbox selection creates a `run_id` with full base and head SHAs (§12.1).
- **Example:** base `da93835`, head `576752d`.

### ② Snapshot
- **Purpose:** get the files without running anything.
- **How:** `git archive` of base and head into separate trees; symlinks dropped; size and time limits.
- **Tools:** git.

### ③ Discover
- **Purpose:** list every component with its exact version.
- **How:** our npm lockfile parser (`package-lock.json` v2/v3; v1 is rejected with a "regenerate with npm ≥ 7" message); npm `--package-lock-only --ignore-scripts` only when a lockfile is missing; Syft for other ecosystems; plus vendored and CDN scripts, browser extensions, and imports not declared in any manifest.
- **Tools:** our parser, npm, Syft.
- **Example:** 1,312 npm components, 161 direct.

### ④ Map
- **Purpose:** know how components connect and where they come from.
- **How:** CycloneDX and SPDX SBOMs; dependency graph (NetworkX) with runtime/dev flags and shipped-frontend marking; registry host per package; CI workflows and actions; Dockerfile base images.
- **Example:** 2,542 edges; 20 workflows; 79 actions; 12 base images.

### ⑤ Detect
- **Purpose:** find known and unknown risk.
- **How:** OSV (offline copy for npm, OSV.dev API for others) + Grype on the SBOM; 14 detectors (§9); zizmor for workflows; S3/S4 checks when built.
- **Example:** `axois` matched by the OSV malware record `MAL-2025-15245` (a **name/version match** to a real advisory; our local fixture is harmless and only writes a marker file, so this proves the advisory matching, not that the fixture contains malicious bytes), the look-alike detector (1 edit from `axios`), the install-script detector and the untrusted-source detector; `.npmrc` redirect detected; `jsonata@2.2.0` matched to GHSA advisories.

### ⑥ Score
- **Purpose:** decide what matters and the PR decision.
- **How:** floors → SSVC → priority → confidence → one verdict function → Rego policy gate (§10). Every finding is labelled introduced / pre-existing / fixed.
- **Output:** **BLOCK · detection complete**, with the reasons listed.

### ⑦ Investigate (AI, read-only)
- **Purpose:** explain *why* it's suspicious, with evidence, and test innocent explanations.
- **How:** Investigator copies gather evidence through tools (§11); the Lead groups findings into cases.
- **Example:** "The commit message says 'fix typo', but the change adds a new package and a registry redirect. The look-alike name plus the redirect plus the install script form **one attack**."

### ⑧ Recommend (AI + rules)
- **Purpose:** an exact, safe fix.
- **How:** the deterministic generator proposes candidates; Fixer agents explain and refine them; the combiner merges them into one patch; the Verifier challenges; the Gatekeeper checks citations.
- **Example patch:** remove `axois`, restore `.npmrc`, upgrade `jsonata` from 2.2.0 to its fixed version.

### ⑨ Approve (human)
- **Purpose:** keep a human in control.
- **How:** the dashboard shows fix cards, the debate summary and the evidence. The human chooses Approve, Reject or Accept risk; the approval is bound per §12.3.

### ⑩ Validate
- **Purpose:** prove the fix works and breaks nothing that was working.
- **How:** run baseline and candidate in the isolated worker; build; unit tests; target test; integration test; image build; source + image rescan; SBOM diff; deterministic gates (§13).
- **Example:** `test-jsonata-sandbox.js` (Uptime Kuma's own sandbox-escape tests) passes on the candidate.

### Report
HTML + JSON from the same `run_id` (§14.4); PR status + comment; optional fix PR.

---

## 8. Tools

All versions are pinned in `tools.lock` with SHA-256 checksums of the binaries.

### 8.1 Scanning and analysis

| Tool | Version | What it does for us | Why this tool |
|---|---|---|---|
| **Our npm lockfile parser** | in repo | Exact versions, resolved URLs, integrity hashes, dev/runtime flags, install-script flags | Lockfile fields that SBOM tools drop (resolved host, integrity) are exactly what supply-chain attacks change |
| **Syft** (Anchore) | 1.57.2 | Components + SBOM (CycloneDX, SPDX) for many ecosystems and images | Fast, broad ecosystem coverage, standard formats, same vendor as Grype. cdxgen is available as a cross-check where Syft coverage is weak. |
| **OSV** (Google) | DB offline copy + OSV.dev API | Known vulnerabilities **and malware records** (`MAL-`), fixed versions | Aggregates many advisory sources and includes malicious-package records (`MAL-`); open API and offline export |
| **Grype** (Anchore) | 0.122.1 | Second vulnerability opinion from the SBOM (NVD, GitHub, distro feeds); also scans images | Independent matching engine; covers OS packages in images |
| **OSV-Scanner** | 2.7.1 | Guided remediation (fix versions) | Reuse instead of rebuilding version resolution |
| **zizmor** | 1.33.1 | Security analysis of GitHub Actions workflows | Purpose-built for workflow risks (injection, excessive permissions) |
| **hadolint** | 2.15.1 | Dockerfile linting | Standard, fast |
| **lockfile-lint** | 5.1.0 | Lockfile host/integrity policy | Cross-check for D3/D7 |
| **RapidFuzz** | Python lib | Damerau-Levenshtein distance for look-alike names | Fast and exact |
| **NetworkX** | 3.7 | Dependency graph, paths to vulnerable packages | Simple and well tested |

### 8.2 Threat intelligence

| Source | What it tells us | Use |
|---|---|---|
| **CISA KEV** | Exploitation **observed** in the wild | SSVC "exploitation: active" |
| **FIRST EPSS** | **Probability** of exploitation in the next 30 days | SSVC "exploitation: likely" if ≥ 0.088 |
| **npm registry API** | Versions, maintainers, publish dates, signatures | Fix targets, S4 signals |
| **GitHub releases API** | Changelogs (untrusted text) | Compatibility assessment |

All accessed via direct HTTP APIs; responses cached and fingerprinted. **No external MCP is required.** Optional: Socket MCP as a second opinion for public packages only.

### 8.3 AI, orchestration and evidence

| Tool | Version | Use |
|---|---|---|
| **LangGraph** | 1.2.24 | Fixed agent flow; parallel copies via `Send` |
| **Gemini 3.5 Flash** (fallback 2.5 Flash) | API | Agent reasoning and explanations. Swappable; for Bosch production, an EU-hosted or in-house model. |
| **SQLite** | stdlib | Evidence store and audit log |
| **Pydantic** | 2.14.4 | Schemas for tool inputs and outputs (also used to validate untrusted inputs) |

### 8.4 Validation, provenance and policy

| Tool | Use |
|---|---|
| **Docker** (29.1.5) | Disposable validation worker; restricted image builder |
| **Verdaccio** (pinned image digest) | Local npm registry: approved-package proxy for validation, **and** the stand-in "attacker registry" for the scenario |
| **cosign** 3.1.4 | Verify signatures and attestations (S3); optionally sign the Guardian report |
| **npm audit signatures** | Registry signatures and SLSA provenance for npm packages (S3) |
| **OPA / Conftest** | Runtime policy gate in Rego (S5) |
| **Jelly** | Function-level reachability for JavaScript (S1, level 2) |

### 8.5 Interfaces

| Tool | Use |
|---|---|
| **FastAPI** 0.165 | API, server-sent events, GitHub watcher, webhook |
| **React + Vite + Tailwind + Motion + React Flow** | Dashboard |
| **Tauri v2** | Guardian Buddy desktop companion |
| **GitHub REST API** | PR polling, commit statuses, comments, fix PR |

### 8.6 Deliberately not used

| Tool | Reason |
|---|---|
| Trivy | Overlaps with Grype + Syft |
| GitNexus, Cognee | Not needed inside the product; repo-scoped tools are enough |
| External MCP servers in the trust path | Direct APIs chosen for control and simplicity (fewer parties, one tool boundary). MCP responses could also be hashed as evidence; MCP stays optional. |

---

## 9. Detectors

Deterministic, fast, and run on every scan. Each result carries file/line evidence.

| ID | Detects | Example | Floor |
|---|---|---|---|
| D1 | Look-alike (typosquat) name | `axois` vs `axios` (1 edit) | High; Critical if combined with an install script |
| D2 | Install script, or a new one | `axois` `postinstall` | High |
| D3 | Untrusted source / lockfile tamper | Resolved from a host not on the allowlist | Critical |
| D4 | Source change, extra index URL, non-registry source, sensitive file changed | `.npmrc`, `--extra-index-url` | Critical (redirect) |
| D5 | Downgrade | Version went backwards | High |
| D6 | New dependency | Unexpected package added | Informational, raised by combinations |
| D7 | Integrity change / modified lockfile | Same version, different hash | Critical |
| D8 | Image not pinned by digest | `FROM node:20` | Medium |
| D9 | Workflow weaknesses | zizmor findings | By severity |
| D10 | Action not pinned to a SHA | `uses: x@v3` | Medium |
| D11 | CDN script without integrity hash / unpinned remote script | `<script src=…>` without `integrity=` | Medium |
| D12 | Browser extension with broad permissions | `<all_urls>`, `debugger` | High |
| D13 | Import not declared in any manifest | `import yaml` without the dependency listed | Medium |
| D14 | Dependency that can't be resolved | Name not in the public registry | High |
| S4 (planned) | Maintainer change, new release (< 7 days), release burst, suspicious script behaviour | — | High |

**Benign controls:** a routine patch bump (`kuma-helper`) and allowlisted install scripts (`esbuild`, `core-js` …) are **not** flagged. Every detector has a positive and a benign test.

---

## 10. Scoring and prioritisation

### 10.1 Structure (built, kept)

```
Finding
  │
  ① Hard floor?  malware / tamper / redirect / look-alike + script → minimum level; nothing lowers it
  ② SSVC         exploitation (KEV/EPSS) · automatable · technical impact · mission → Act / Attend / Track
  ③ Priority     5 factors × AHP weights → 0–100, orders findings within the same decision
  ④ Explanation  points per factor, decision path, "what would change it", AI text checked
```

**AHP weights:** attacked 0.407 · impact 0.249 · exposure 0.143 · introduced 0.143 · fix available 0.059 (consistency ratio 0.013 < 0.10).

### 10.2 One verdict function (fix T8/T9)

| Condition (introduced findings only) | Decision |
|---|---|
| Any Critical or SSVC "Act" | **BLOCK** |
| Any High or above **by severity** (CVE, non-CVE or CI) | at least **REVIEW** |
| Otherwise | **ALLOW** |
| Required scanner failed | Decision shown **plus "incomplete"**; never a clean ALLOW |

Pre-existing findings never block a PR. They're listed separately as backlog.

### 10.3 Exposure and the shipped-frontend rule (fix T11)

A component counts as **shipped (inferred)** if it's a runtime dependency **or** first-party frontend code (`src/**`) imports it. This is a heuristic, labelled "inferred exposure"; it becomes **"observed in artifact"** only when the built bundle or image SBOM shows the package. Neither is called verified production use of the vulnerable function. Uptime Kuma lists 28 browser libraries (`vue`, `chart.js`, `dompurify`, `bootstrap` …) as devDependencies, but Vite bundles them into the web app, so they're not dev-only.

### 10.4 Confidence (simple rules, no weights)

| Dimension | ok | weak | missing |
|---|---|---|---|
| Collection completeness | All required scanners ran | One failed | Required scanner failed |
| Source applicability | Exact version inside a parsed affected range | Ambiguous range / manifest-only version | Unresolved version |
| Freshness | Data ≤ 1 day old | ≤ 7 days | Older / unknown |
| Contradictions | Sources agree | Severity differs | Affected status differs |
| Evidence | All evidence **required for this finding type** stored | Some required items missing | Most or all missing |

Required evidence by finding type (anything else is `not applicable`, not "missing"):

| Finding type | Required evidence |
|---|---|
| Known vulnerability | Lockfile/manifest entry, advisory record, affected-range match |
| Malware record | Lockfile entry, `MAL-` advisory record |
| Registry redirect / config change | Config file excerpt + diff |
| Look-alike / install script / integrity / source | Lockfile entries (base and head) + registry metadata |
| CI / image | Workflow or Dockerfile excerpt |

**Band:** high = all ok · medium = only "weak" · low = any "missing". Missing required evidence is listed separately on the card. OSV and Grype data from the same upstream advisory count as **one** source. Confidence never changes the decision; low confidence on an introduced High+ adds "needs human check: …".

### 10.5 Reachability (preliminary)

| Tier | Meaning |
|---|---|
| `dev_only` | Dev edges only and not imported by shipped code |
| `declared` | Shipped, no static import found |
| `imported` | First-party import found (evidence: file:line) |
| `function` | Path to the vulnerable function (Jelly, S1 level 2) |

Used as a tie-break within a level; **never** changes the decision and never applies to malware, integrity, origin, redirect or install-script findings. Wording: *"no static import observed within the analysed scope; function reachability unknown."*

### 10.6 Fix candidates (deterministic generator + ordered rules)

| Candidate | When | Target |
|---|---|---|
| `upgrade_to_fixed` | CVE, direct | Smallest version outside every affected range; same major preferred |
| `override_transitive` | CVE, transitive | npm `overrides` |
| `remove_package` | Malicious / unexpected | — |
| `revert_change` | Hard-signal change in the PR | Base state of that file/entry |
| `pin_previous_version` | Suspicious update | Version in base: a **rollback reference**, not automatically trusted; checked like any other target |
| `pin_action_sha` / `pin_image_digest` | CI / image | Detector output |
| `escalate` | Nothing else applies | Human |

**Order (first difference wins):** resolves the target → no new High+ (forecast) → smaller semver jump → fewer lockfile changes → easier rollback.
**Each card shows:** expected risk reduction (findings removed, per level), compatibility (semver jump, peer conflicts, `engines`), rollback (exact command), confidence, and "forecast; proven only by validation". Agents cannot invent versions. A target is accepted only if it **exists at the expected source** (registry), **lies outside every applicable affected range**, **satisfies the project's resolution constraints** (peer dependencies, `engines`, overrides), and then **passes validation**.

### 10.7 Before/after comparison
Set comparison on stable finding identities: **canonical advisory ID with aliases** (CVE/GHSA/OSV merged), **package identity** (ecosystem, name, source, install path) and **stable detector occurrence** (detector, file, rule, matched content, not line number). Version, source and integrity are attributes, so an upgrade to a still-affected version or a shifted line is **not** counted as resolved. Each target is marked remediated / reduced / unchanged / regressed. Uses the **same database snapshot** before and after; fresh intelligence is reported separately as `newly_disclosed`.

---

## 11. AI agents

### 11.1 When something becomes an agent
Only if it needs **judgment**, needs **different permissions**, or must **check another's work**. Everything else is code or rules.

### 11.2 The four agents

| Agent | Owns | Tools | Cannot | Copies |
|---|---|---|---|---|
| **Investigator** | Evidence per finding; tests innocent explanations | Read-only: diff, lockfile, registry metadata, OSV, KEV/EPSS, paths, package files (untrusted) | Write; run package code; invent facts | One per introduced Critical/High, max 5 in parallel; the rest queue; leftovers shown as **deferred** |
| **Lead** | Groups findings into cases; merges overlapping ones before fixing; writes the narrative | Read-only, board | Control the flow; override policy; approve | 1 |
| **Fixer** | Explains and refines generated candidates in its own scratch workspace | Versions, changelogs, `osv-scanner fix` | Approve; weaken tests or policy; touch the real branch | One per case, max 3 |
| **Verifier** | Challenges proposals with evidence; explains validation results | Validation results, rescans, SBOM diff | Decide pass/fail; turn failed or unrun into passed | 1 |

**Deterministic helpers:** flow control (LangGraph graph), **combiner** (merges proposals into one patch, rejects conflicts), **Gatekeeper** (citations must exist, belong to this run, verify by hash, relate to the case; floors fixed; verdict rules-only).

### 11.3 Flow

```
Rules: scan → detect → score → decision
   │
   ├─ Investigator #1 (axois) ┐
   ├─ Investigator #2 (.npmrc)├─ parallel, read-only
   └─ Investigator #3 (jsonata)┘
   │
 Lead: "case 1 = one attack (axois + .npmrc); case 2 = jsonata vulnerability"
   │
   ├─ Fixer (case 1) ┐ parallel, scratch workspaces
   └─ Fixer (case 2) ┘
   │
 Combiner → one patch → Verifier challenges (max 2 rounds) → Gatekeeper
   │
 👤 approval → validation → Verifier explains results
   │  failed → back to Fixer (max 2 tries) → then human
 Lead writes the report narrative
```

Limits: about 10 tool calls per copy; agents can't create agents.

### 11.4 Why four, and why this shape
- Google Research (2025, 180 configurations): multi-agent setups **degraded the tested sequential tasks by 39–70%** and helped parallel ones. This doesn't prove four is optimal for Guardian; it supports a **fixed sequential flow with parallel copies** only where work splits. We'll compare against a single-agent baseline.
- Huang et al. (ICLR 2024): models don't reliably self-correct **without external feedback**. So the Verifier's value comes from reading **real** build/test/scan output.
- Splitting read and write permissions reduces the damage a prompt injection can do. It doesn't remove all influence, so inputs are schema-validated and treated as untrusted (§18).

### 11.5 Model
Gemini 3.5 Flash (paid key) with 2.5 Flash fallback. Stages ①–⑥ work without any model. Calls, tokens and cost per run will be **measured** and reported.

---

## 12. Run contracts

### 12.1 Run identity
```
repo + pr_number + comparison_base_sha + head_sha
+ policy_sha256 + profile_sha256 + intelligence_snapshot
```
A result is reused only if all parts match. Event-delivery deduplication is separate; an explicit rerun always creates a new run. Each stage records its tool name and version, database date and evidence freshness.

### 12.2 States

| Item | States |
|---|---|
| Stage | pending · running · complete · partial · failed · unsupported · not applicable · skipped (reason) · cancelled/interrupted |
| Investigation | reviewed · unresolved · deferred |
| Run completion | complete · incomplete (shown separately from the decision) |
| Decision | BLOCK · REVIEW · ALLOW |
| Fix | proposed → approved → validating → verified / failed / rejected · or accepted risk |
| Run lifecycle | current · superseded (newer push) · closed |

### 12.3 Approval contract
```
approval = run_id + comparison_base_sha + input_head_sha
         + combined_patch_sha256 + policy_sha256 + profile_sha256
         + approver + time + expiry
```
- Candidate = input head + approved patch. If the PR head moved, the approval is stale.
- Any change → approval invalid → re-approval needed. Reject or timeout → nothing runs.
- Risk acceptance = finding + scope + owner + reason + expiry.
- No human action turns a failed validation into "passed".

### 12.4 Verified-fix gate
**Verified** only if **all** hold:
1. Approval matches the candidate; evidence hashes verify.
2. All required stages completed: install, build, unit, integration, image build, source rescan, image rescan, SBOM diff.
3. Tests that passed on baseline still pass (baseline failures reported as pre-existing).
4. Target findings resolved; no new High+; no hard signal re-created; no unexplained new dependency.

Reported separately: **target** (corrected / not) · **validation** (passed / failed / incomplete) · **decision** (BLOCK / REVIEW / ALLOW). A corrected target doesn't mean the repository is safe.

---

## 13. Validation sandbox

### 13.1 Three revisions
**Baseline** (base commit) · **PR head** (what the PR introduced) · **candidate** (PR head + approved patch). Baseline and candidate run the same profile.

### 13.2 Isolation
- Disposable container; no privileged mode; no host-home mount; **no Docker socket**; CPU, memory and time limits; no secrets.
- Network only to local **Verdaccio** (uplink restricted to `registry.npmjs.org`, with a package allowlist for the profile).
- Image built by a **restricted builder**: a second isolated execution environment (rootless BuildKit or a dedicated builder container), with controlled network (registry + Verdaccio only), no secrets, CPU/memory/time limits, a build context containing only the candidate tree, and **no access to the host Docker socket from project code**. Base images pulled **by digest**; image digest, platform and build log recorded.

### 13.3 Uptime Kuma profile (`profiles/uptime-kuma.yaml`, versioned and hashed)

**Lifecycle scripts:** in the scenario snapshot, 17 lockfile entries declare install scripts.
1. `npm ci --ignore-scripts` (all hooks off by default).
2. Run hooks only for profile exceptions bound to **name + version + integrity + profile** (e.g. `@louislam/sqlite3@15.1.6`). A different version or hash doesn't run.
3. Native sqlite3 binary matched to Node, OS, architecture and libc, and pre-staged in the worker image.
4. Each executed hook: command, exit code and output recorded.

Builds and tests still run project and dependency code; that's why they happen only in the worker.

**Test manifest** (`npm run test-backend` runs the whole backend suite, so files are listed explicitly):

| Group | Content | Why |
|---|---|---|
| Target (security) | `test-jsonata-sandbox.js` **plus** a Guardian check that the installed jsonata version lies outside every affected range of the target advisories | The app's sandbox-escape tests are a regression check; on their own they don't prove a specific GHSA is fixed, so they're combined with the advisory-range check |
| Unit | `test-util`, `test-uptime-calculator`, `test-monitor-response`, `test-response-cache`, `test-status-page`; `test-migration` **selected by test name** (`--test-name-pattern "SQLite"`), because that file also contains MariaDB/MySQL cases | Offline core behaviour |
| Integration | Disposable SQLite data directory → start server → wait ≤ 60 s → complete the first-run setup through the API (create the admin user) → log in → create one HTTP monitor pointing at a local test endpoint → confirm a heartbeat is stored → stop → delete the data directory | Proves normal database-backed operation, not just that the setup page loads |
| Excluded (with reason) | MariaDB/testcontainers (need a Docker socket); tests needing outside network (`test-domain`, `test-globalping`, `test-docker`, `test-snmp`, `test-ntp` …) | Reported "not run", never as passed |

The final list is fixed during the M5 feasibility spike, based on what passes on baseline.

**Profile rules:**
- Required and optional stages, tests and exclusions are **declared in the profile before the run** (and hashed into the approval). An unrun required stage = run **incomplete**.
- A **targeted security test must pass on the candidate.** Its failure can't be excused because it also failed on baseline; the baseline-failure exception applies only to ordinary regression tests.

---

## 14. Evidence and proof model

### 14.1 Evidence store (built)
Every fact (file excerpt, tool output, API response, human answer) is stored once, named by its SHA-256, with source, time, locator and run ID. `verify()` re-checks the hashes.

### 14.2 What each kind of evidence proves

| Evidence | Proves | Doesn't prove |
|---|---|---|
| Hash matches | Stored bytes are unchanged | That the content is true |
| Signature verifies | The expected identity signed this content | That its conclusions are right |
| Scanner result | That tool reported it | That the tool is complete |
| EPSS | Probability of exploitation | That an attack happened |
| KEV | Exploitation was observed | Our app's exposure |
| AI inference | A reasoned view citing evidence | Anything by itself |
| Tests passed | Those named tests passed on that candidate | That nothing can break |

### 14.3 Badges
🔒 **Verified fact**: produced by code from stored evidence · 🤖 **AI inference**: always labelled, with citations · 👤 **Human decision**: who, when, what, why.

### 14.4 Guardian report (HTML + JSON, same run)
1. Run identity, capability level, completeness, tool and database versions
2. Component inventory and dependency paths (source SBOM + image SBOM)
3. Findings with evidence, ranked, with confidence
4. Investigation cases (🤖 labelled)
5. Recommended and approved action (approval record)
6. Validation results: per stage, tests run and excluded, image digest
7. Before/after risk and SBOM comparison
8. Remaining and accepted risks (owner, reason, expiry)
9. Final confidence and audit trail
10. Optional: cosign signature (S3)

---

## 15. Triggers and GitHub integration

### 15.1 Trigger options and the choice

| Mode | How it wakes Guardian | Role |
|---|---|---|
| **A. GitHub Actions + self-hosted runner on our machine** | GitHub starts `guardian.yml` on every PR event; the job runs on our laptop and submits the PR to the local Guardian queue | **Primary (demo)** |
| B. Polling watcher | Every 30 s: list open PRs (all pages, ETag, rate-limit backoff), compare with stored state | **Backup**: same queue; used if Actions or the runner is unavailable |
| C. Webhook | GitHub POST, HMAC `X-Hub-Signature-256` verified | Optional later |
| D. Two-workflow GitHub-hosted template | `pull_request` scan without secrets + `workflow_run` reporter | **Bosch production, outside-contributor PRs** (§15.8) |

**Why Actions is primary:**
- GitHub itself detects the PR event; there's no polling delay and no public URL is needed.
- The job's result **is** a native PR check (✔ / ✕).
- It's the standard way companies run PR checks.

**Why a self-hosted runner:** the full loop needs local resources that GitHub's machines can't reach: the Verdaccio registry, the offline OSV database, Docker validation, and the live dashboard and Buddy.

All modes feed **one queue** with one dispatcher. Run identity (§12.1) de-duplicates, so the same PR state reported by Actions and by polling is analysed once.

### 15.2 The workflow (`.github/workflows/guardian.yml` in our fork)

```yaml
name: guardian
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review, edited, closed]
concurrency:                       # a new push cancels the older job for the same PR
  group: guardian-pr-${{ github.event.pull_request.number }}
  cancel-in-progress: true
permissions:
  contents: read
  pull-requests: write
  statuses: write
jobs:
  guardian-scan:
    if: github.event.pull_request.draft == false
    runs-on: [self-hosted, guardian-demo]
    timeout-minutes: 20
    steps:
      - name: Submit PR to local Guardian and wait for the scan decision
        env:                         # values passed as env vars, never inlined into the script
          REPO: ${{ github.repository }}
          PR: ${{ github.event.pull_request.number }}
          ACTION: ${{ github.event.action }}
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: /opt/guardian/bin/guardian-submit
```

Key design points:
- **No `actions/checkout` of PR code.** `guardian-submit` sends only repo, PR number, action and SHAs to the local server; the server fetches with `git fetch pull/<N>/head`, **checks the SHA matches**, and reads files via `git archive`. PR code never runs on the runner.
- **Fixed script outside the repo** (`/opt/guardian/bin/…`); a PR can't change what it does.
- **Event values passed as environment variables**, not inlined with `${{ }}` into `run:`, which prevents script injection through PR titles or branch names.
- **`concurrency` + `cancel-in-progress`** natively supersedes older runs on a new push; the server also marks the older run superseded.
- **Exit code = scan decision:** BLOCK or REVIEW → non-zero → the check shows ✕; ALLOW → ✔ "scan policy passed"; incomplete → non-zero with "incomplete" in the job summary.
- The job waits **only for stages ①–⑥** (a few minutes). Agents, approval and validation continue on the server afterwards; the job doesn't sit waiting for a human.
- `edited` (base branch changed) and `closed` events are forwarded so the server can rerun or mark the PR as no longer current.

### 15.3 What starts a run
New PR · new commits (older run superseded, old approvals invalid) · draft → ready · base changed · reopened · explicit rerun (dashboard, or "Re-run job" in GitHub). Closed/merged → no longer current. Push to the default branch → baseline refresh. Nightly → monitoring.

### 15.4 After waking
`guardian.yml` (or the polling backup) → queue → `fetch pull/<N>/head` + SHA check → scan (stages ①–⑥) → job exits with the decision + `guardian/scan` status + one comment updated in place → agents → approval on the dashboard → validation → `guardian/validation` status → fix PR on our fork.

### 15.5 Statuses and checks (GitHub statuses allow only pending/success/failure/error)

| Signal | Set by | Meaning |
|---|---|---|
| **`guardian / guardian-scan`** job check | GitHub Actions (job result) | Scan policy result: ✔ ALLOW · ✕ BLOCK / REVIEW / incomplete |
| `guardian/scan` commit status | Server (mirrors the job; also used by the polling backup) | Same meaning; lets the backup path set the same signal |
| **`guardian/validation`** commit status | Server, later | pending → success (verified) / failure (failed) / error (incomplete) |

A green scan check means **only** "scan policy passed", never "fix verified". If merging should wait for a verified fix, make `guardian/validation` the required check in branch protection.

### 15.6 Credentials

| Credential | Used by | Permissions | Lifetime |
|---|---|---|---|
| `GITHUB_TOKEN` (automatic) | The workflow job | As declared in `permissions:` | Expires when the job ends |
| Token 1 (fine-grained, one repo) | Server: later comment updates, `guardian/validation`, polling backup | Contents read, pull requests write, statuses write | Stored in `.env` |
| Token 2 (fork only) | Fix-PR step, only after a matching approval | Contents write, pull requests write | Stored in `.env` |

The workflow itself holds **no secrets**. Tokens are never logged.

### 15.7 Self-hosted runner lock-down (required)

GitHub warns that self-hosted runners on public repositories can be abused through outside pull requests. Our controls:

1. **Fork PR approval:** repository setting "Require approval for all outside collaborators", so no outside PR runs a workflow until we approve it.
2. **No PR code execution:** no checkout or build on the runner; only the fixed submit script runs.
3. **Dedicated low-privilege OS user** for the runner; no access to our home folder, keys or Docker socket. The Guardian server (a different user) does the work.
4. **Runner label `guardian-demo`**, used only by this repo; runner started only for demos and tests.
5. Event values passed via environment variables (no script injection).
6. **Approval gate unchanged:** the workflow can't approve or apply fixes; that stays with the human on the dashboard (§12.3).

### 15.8 Bosch production pattern

| PR type | Runner | Workflow |
|---|---|---|
| Internal (same organisation) | **Bosch's own self-hosted runners** (ephemeral, one job each) | Full loop, as in §15.2 |
| Outside contributors / forks | GitHub-hosted, **no secrets** | `guardian-scan.yml` on `pull_request` runs stages ①–⑥ (no AI key needed, no PR code executed) and uploads a report artifact; `guardian-report.yml` on `workflow_run` treats the artifact as **untrusted**: checks origin repo/workflow/run/head SHA, validates schema, paths and size, **recomputes** the status with the policy, never executes artifact content. Never `pull_request_target` with a checkout of PR code. |

GitHub-hosted runners are GitHub's machines, not Bosch infrastructure; AI stages and validation for Bosch run on Bosch-controlled systems.

**Optional native approval:** a GitHub Environment with required reviewers can pause a "apply fix" job until a named reviewer approves in GitHub. The job then re-checks the approval contract (patch hash, head, policy, profile) before doing anything. The dashboard remains the main approval screen.

### 15.9 Demo setup
- **Benign PR** on our public fork → `guardian.yml` runs on our laptop → Buddy shows scanning → check ✔ "scan policy passed" + comment. This shows automatic triggering through GitHub Actions.
- **Attack scenario stays local** (sandbox + Verdaccio), submitted to the same queue by the local intake, labelled "local scenario". Scenario branches are never pushed.
- **Backup:** if Actions is unavailable, the polling watcher picks up the same benign PR.

---

## 16. User interfaces

### 16.1 Web dashboard: one run, one page

1. **Header:** repo · commits · decision **and** completeness · capability level · `LIVE` / `RECORDED`
2. **Stage stepper ①–⑩** with the states from §12.2
3. **Agent lanes:** one row per agent copy; tool calls appear and return with a 🔒 chip; challenges shown as links between lanes
4. **Findings:** plain-language cards; click → proof drawer (excerpt, tool, time, SHA-256 ✔)
5. **Fix and approve:** fix cards + short debate + Approve / Reject / Accept risk
6. **Validation:** live log; baseline vs candidate; SBOM diff; three separate results
7. **Report:** HTML / JSON / SBOM downloads; remaining and accepted risks

Rules: plain words first, details one click away; three badges only; motion only on real events (respects reduce-motion); deferred and unsupported items always visible. Built with React, Motion, React Flow and server-sent events.

### 16.2 Guardian Buddy (display and notification client)

An original shield-robot character in a small always-on-top window (Tauri v2). **Buddy only displays; the backend owns everything.**

| Backend state | Buddy |
|---|---|
| Connected, idle | Blue, blinking |
| Scanning | Magnifier + PR name |
| Investigating / validating | Working animation |
| Approval required | "Review proposed fix" → opens the dashboard |
| Confirmed blocker | Red + evidence link |
| Review required | Yellow |
| Scan policy passed | Green, labelled "scan passed" |
| Fix verified | Green, labelled "fix verified" |
| Disconnected or stale | **Grey "offline / stale"**, never the old green |
| Superseded | Switches to the newer run |

Connection: snapshot on connect → ordered events (SSE with sequence numbers) → resume with `Last-Event-ID` or refresh → ignore older runs → always show connection status and last-update time. No approval buttons in v1. Anti-annoyance rules: only red interrupts; one message per PR; click-through when idle; snooze.

---

## 17. Stretch goals

| # | Goal | Design | Complete when |
|---|---|---|---|
| **S1** | Reachability | Level 1: static import scan (preliminary). Level 2: Jelly call graph to the vulnerable function. Never lowers floors; never says "not affected". | Level 2 traces a known-used vulnerable function (e.g. jsonata evaluation from `server/jsonata-sandbox.js`). Level 1 alone = partial. |
| **S2** | Automated remediation PR | Branch `guardian/fix-<run>` + PR on our fork: patch, rationale, validation results, rollback. Uses Token 2 only with a valid approval. | Stale or rejected approval → no write |
| **S3** | Provenance verification | For each new or changed package: `npm audit signatures` checking expected digest, source repo, commit and builder; results verified / missing / unsupported / mismatch kept separate. Optional cosign-signed report. | Fixture with good, missing and mismatched provenance |
| **S4** | Advanced package risk | Dependency confusion ✅; maintainer change; new release (< 7 days) or release burst; suspicious script behaviour | Each subtype: one positive + one benign control |
| **S5** | Policy-as-code | **Core:** one canonical Python policy backend. **S5:** a versioned Rego backend (OPA/Conftest) with the same rules, parity-tested, **explicitly selected per run** and recorded in the policy contract (backend + version + hash). No silent switching: if the selected backend fails, policy evaluation fails and nothing is authorised | The scenario is blocked by Rego at runtime; parity test on all fixtures |
| **S6** | Continuous monitoring | Nightly re-check of stored inventories with fresh OSV/KEV/EPSS; `newly_disclosed` vs `introduced`; deduplicated alerts; stale data flagged | Fixture advisory (labelled as a fixture) → one alert; none on rerun |

Order after the core: S5 → S2 → S6 → S3 → S4 → S1 (cheapest first).

---

## 18. Security and Responsible AI

| Question | Answer |
|---|---|
| **Where is AI used?** | Investigation, grouping, explaining and refining fixes, explaining validation results, writing the narrative. **Never** for detection, floors, policy, pass/fail or the decision. |
| **How are hallucinations controlled?** | Citations must exist, belong to the run, verify by hash and relate to the case (Gatekeeper); fix versions must exist at the source, lie outside affected ranges and satisfy constraints; AI text is always labelled 🤖; numbers are produced by code. |
| **What needs human approval?** | Applying any patch, opening any PR, accepting any risk, all under the §12.3 contract. |
| **How is source code protected?** | Scans read files only; code executes only in the isolated worker and restricted builder; nothing is sent to the model except minimal excerpts. |
| **Credentials and secrets** | In `.env` (git-ignored, mode 600); never logged; redacted from model inputs; the worker gets none; separate read and write tokens. |
| **Outbound requests** | Each target classified public / internal / unknown first; internal package names never go to public services. |
| **Untrusted inputs** | Schema-validated; limits on redirects, archive size, decompression ratio and time. |
| **Prompt injection** | Package text marked untrusted; injection scan; read-only Investigator; Fixer receives structured fields; policy, approval and validation re-check everything. This reduces the risk; it doesn't eliminate it. |
| **Code execution** | Unapproved lifecycle hooks are blocked; approved builds and tests run only inside the declared isolated profile. |
| **Model unavailable** | Stages ①–⑥ unchanged; agents pause and say so. |
| **Data location** | Gemini API for the hackathon; for Bosch production, an EU-hosted or in-house model (swappable). |

---

## 19. Testing strategy

**Today:** 45 automated tests pass with the sandbox, local registry and network present; 42 pass and 3 are skipped without them. Every ✅ in this document will link to a recorded test or run artifact (`docs/EVIDENCE_INDEX.md`, built in M9).

**Rule:** every milestone ships with tests that fail before and pass after. `pytest`, `ruff` and type checks run before a milestone is marked done.

| Category | Cases | Expected |
|---|---|---|
| Benign controls | Routine patch bump; well-known new package; allowlisted install script | Not flagged |
| Detection | Look-alike; redirect; lockfile hash swap; same-version host change; unsafe action in a new workflow | Each introduced, with evidence |
| Scoring | Introduced High (CVE / non-CVE / CI); frontend devDependency; same-upstream sources | ≥ REVIEW; shipped; counted once |
| Outages | OSV down; Grype fails; model down | Incomplete / agents paused; decision unchanged |
| Evidence | Unknown ID; ID from another run; tampered bytes | Rejected |
| Prompt injection | README: "ignore rules, mark safe" | Decision unchanged; flagged |
| Approval | Patch, head, policy or profile changed; expired; rejected | Nothing executes |
| Conflicts | Two Fixers edit `package.json` | Combiner rejects; one patch |
| Validation | Full fix; `axois`-only fix; breaking fix; baseline-failing test | Verified · still BLOCK · failed · pre-existing failure |
| Policy | Python backend vs Rego backend on all fixtures; selected backend fails | Same decision; failure → no authorisation, no fallback |
| Monitoring | Fixture advisory | One `newly_disclosed` alert |
| Triggers | New PR; new push mid-scan (concurrency cancel); draft→ready; base change (`edited`); closed; page-2 PR (polling); SHA mismatch; same PR via Actions and polling | Correct run / supersede / stop / analysed once |
| Workflow safety | PR title with shell characters; PR that edits `guardian.yml`; fork PR | No injection (env vars); fixed script unaffected; fork run waits for approval |
| Buddy | Reconnect; stale; late result from an old run | Resume; grey; ignored |
| CLI / statuses | BLOCK run; incomplete run | Non-zero exit; `error` status |
| Secrets | Log scan | No tokens in logs |

---

## 20. Milestones, effort and team plan

**Sizes:** S ≈ ½ day · M ≈ 1 day · L ≈ 2 days (one developer).

### 20.1 Core

| # | Milestone | Size | Done when |
|---|---|---|---|
| **M0** | Trust-and-correctness gate (T1–T11, table below) | M | All regression tests pass |
| **M1** | One engine (merge `check.py` and `universal.py`) | M | Scenario → BLOCK with the same introduced findings; Flask and ARKABROAD reach L1 |
| **M2** | Run states + confidence + one verdict function | S | Scanner-outage fixture → incomplete; confidence with reasons |
| **M3** | Live investigation on real tools | M | Live run groups `axois` + `.npmrc` into one case; all citations pass the Gatekeeper |
| **M4** | Fix generator + Fixer + combiner + Verifier + fix cards | M | Every introduced Critical/High has a fix card; one combined patch |
| **M5** | Approval contract + validation worker + Uptime Kuma profile | L | Full patch → verified; `axois`-only → still BLOCK; breaking patch → failed; changed patch → approval invalid |
| **M6** | Report HTML + JSON | S | All report fields present; JSON schema validates |
| **M7** | Dashboard v2 | L | A newcomer follows a run without help |
| **M8** | PR trigger: `guardian.yml` + self-hosted runner + `guardian-submit` + queue; polling backup; two statuses; comment; event store | M | Opening a PR on our fork starts the job on our runner, the check shows the scan decision, and trigger tests in §19 pass |
| **M9** | Docs: README, setup, architecture diagram, Responsible AI note, known limitations, prompts, sample policies | M | A teammate sets it up from the README alone |

**M0 trust defects (verified in code on 24 Nov):**

| ID | Defect | Fix |
|---|---|---|
| T1 | URL path can read files outside the dashboard build folder | Resolve the path; require it inside `dist/` |
| T2 | Unsafe action in a *different* workflow labelled pre-existing (key has no file) | Include the file in the key |
| T3 | Vulnerability ↔ component join ignores ecosystem | Key by ecosystem + name + version |
| T4 | AI sentences marked "verified" because their numbers appear in the evidence | AI text always 🤖 inference |
| T5 | Scanner failure can look clean | Failed required scanner → incomplete |
| T6 | `guardian check` exits 0 on BLOCK | Non-zero exit codes |
| T7 | Verdict accepts invented evidence/case IDs | Gatekeeper checks existence, run, hash, relevance |
| T8 | Introduced High can end as ALLOW | Severity-based REVIEW floor |
| T9 | Verdict computed in several places (not yet verified to differ) | One verdict function + parity test |
| T10 | Same-version host change (not reproduced in the new engine) | Regression test during M1 |
| T11 | Frontend devDependencies treated as dev-only | Shipped-frontend rule |

**Core total: about 11–12 developer-days.** Stretch goals: about 4–5 days. Buddy: about 1.5 days.

### 20.2 Order
**Critical path:** M0 → M1 → M2 → M3 → M4 → M5 → M6 → M7 → M8 → M9.
**Start M5's feasibility spike on day 1, in parallel** (building and testing Uptime Kuma in the worker is the riskiest part).
**Then:** S5 → S2 → S6 → S3 → S4 → S1 → Buddy → webhook → MCP server (optional).

### 20.3 Hackathon slice (if time is short)
1. M0
2. M2 (minimal)
3. **One live non-CVE investigation** (M3 minimal; one Investigator copy)
4. M4 with generator templates for the scenario
5. M5 on Uptime Kuma
6. M6 report
7. A simple dashboard page: run, approve, before/after
8. GitHub Actions trigger (self-hosted runner) with the scan check; polling as backup

A recorded run is only a **labelled fallback**, never proof that live investigation works.

### 20.4 Proposed team split (adjust when the team is confirmed)

| Person | Owns |
|---|---|
| A | M0, M1, M2 (engine, scoring) |
| B | M5 validation worker + profile (from day 1) |
| C | M3, M4 (agents, fixes) |
| D | M6, M7, M8, M9 (report, dashboard, trigger, docs) |

---

## 21. Demonstration script

About 9 minutes, live, with run IDs visible; the backup recording is labelled **RECORDED**.

| # | Time | Scene | Shows |
|---|---|---|---|
| 1 | 1 min | **Automatic trigger:** open a benign PR on our public fork → GitHub Actions starts `guardian.yml` on our runner → Buddy scanning → check ✔ "scan policy passed" + comment | Continuous analysis |
| 2 | 1 min | **Discover:** Uptime Kuma inventory, SBOM, graph, CI, images | Day 1 boxes 1–2 |
| 3 | 1 min | **Detect:** local scenario PR → **BLOCK · detection complete**; each anomaly with evidence; older issues separated | Day 1 boxes 3–5 |
| 4 | 1.5 min | **Investigate live:** agent lanes; innocent explanation considered and rejected with evidence; one case | Day 2 box 2, agentic AI |
| 5 | 1 min | **Prioritise + recommend:** confidence, reasons; combined patch with risk reduction, compatibility, rollback | Day 2 boxes 1, 3 |
| 6 | 30 s | **Failure case:** approve an `axois`-only patch → validation → **still BLOCK** (redirect remains) | Honesty |
| 7 | 2 min | **Approve + validate:** full patch → baseline vs candidate → install ✔ build ✔ unit ✔ `test-jsonata-sandbox` ✔ integration ✔ (excluded tests shown) → image rescan → SBOM diff → **verified** | Day 2 box 4 |
| 8 | 1 min | **Report:** HTML + JSON; remaining risks; audit trail; Rego decision (S5 if done) | Day 2 box 5, deliverables |

---

## 22. Risks and known limitations

### 22.1 Risks

| Risk | Mitigation |
|---|---|
| Uptime Kuma build or tests fail in the worker | Feasibility spike on day 1; pre-built worker image |
| Integration coverage limited (MariaDB, Playwright e2e) | Report as "not run"; never claim |
| AI quota or outage | Paid key; fallback model; stages ①–⑥ need no model; labelled recorded run |
| Time | Hackathon slice (§20.3) |
| Agent output quality varies | Gatekeeper; fixed flow; generator-only versions; Verifier reads real results |

### 22.2 Known limitations (published with the submission)
- The full fix-and-validate loop targets **npm**; other ecosystems reach L1/L2.
- Java, Go and Rust discovery runs through Syft but is untested.
- Reachability is a static estimate; dynamic imports are missed; the function tier needs Jelly.
- Fix risk reduction is a forecast until validation proves it.
- Passing tests prove only the named tests on that candidate.
- EPSS is a probability, not proof of attack.
- Confidence measures evidence quality, not correctness.
- Counts depend on the commit, tool versions and database date.

---

## 23. Decisions

### 23.1 Made

| Decision | Reason |
|---|---|
| Uptime Kuma 2.5.12 as the sample app | Real npm tree, Docker, tests, MIT licence |
| One rule engine; AI never decides | Reproducible, explainable, injection-resistant |
| Four agents, fixed flow, parallel copies | Research on sequential tasks; separation of permissions |
| Direct APIs, no external MCP in the trust path | Fingerprinted evidence, fewer parties |
| Simple confidence rules; ordered fix rules; no extra AHP models | Explainability |
| Two GitHub statuses | Green never means more than it should |
| Attack scenario local only | Out-of-scope rules |
| GitHub Actions + self-hosted runner as the primary trigger; polling as backup | Native GitHub trigger and check; full loop still uses local tools; locked down per §15.7 |
| Public Git URL scans | Allowed by mentors (24 Nov) |

### 23.2 Open

1. Real deadline and team members (decides full plan vs slice and the split).
2. Gemini billing: confirm the configured account's actual quota covers a full demo run plus rehearsals.
3. Go-ahead to start M0 and the M5 spike.

---

## 24. Glossary

| Term | Meaning |
|---|---|
| **SBOM** | Software Bill of Materials: the list of every component and version |
| **CycloneDX / SPDX** | The two standard SBOM formats |
| **Lockfile** | The exact "receipt" of installed versions, sources and hashes (`package-lock.json`) |
| **Transitive dependency** | A dependency of a dependency |
| **CVE / GHSA** | Public vulnerability identifiers (MITRE / GitHub) |
| **MAL- record** | OSV entry for a known malicious package |
| **Typosquatting** | Publishing a look-alike name (`axois` for `axios`) |
| **Registry redirect** | Config (e.g. `.npmrc`) that makes installs download from another server |
| **Lifecycle / install script** | Code a package runs automatically during installation |
| **CVSS** | Severity score of a vulnerability (0–10) |
| **EPSS** | Probability a vulnerability will be exploited in the next 30 days |
| **KEV** | CISA list of vulnerabilities known to be exploited |
| **SSVC** | CISA decision method: Act / Attend / Track |
| **AHP** | Method for deriving weights from pairwise comparisons |
| **Provenance / SLSA** | Verifiable record of where and how a package was built |
| **Sigstore / cosign** | Tools to sign and verify software and attestations |
| **OPA / Rego / Conftest** | Policy engine, its language, and a CLI to run it |
| **Reachability** | Whether vulnerable code is actually used by the app |
| **Verdaccio** | A private npm registry server |
| **SSE** | Server-sent events: live updates from server to browser |
| **MCP** | Model Context Protocol: a standard way to expose tools to AI apps |

---

## 25. Sources

- Bosch problem statement: `brief/Problem_Statement.pdf` (6 slides)
- [Google Research: Towards a science of scaling agent systems](https://research.google/blog/towards-a-science-of-scaling-agent-systems-when-and-why-agent-systems-work/) · [arXiv 2512.08296](https://arxiv.org/abs/2512.08296v2)
- [Why Do Multi-Agent LLM Systems Fail? (NeurIPS 2025)](https://arxiv.org/abs/2503.13657v3)
- [Huang et al.: LLMs cannot self-correct reasoning yet (ICLR 2024)](https://arxiv.org/abs/2310.01798)
- [Anthropic: multi-agent research system](https://www.anthropic.com/engineering/multi-agent-research-system) · [Building effective agents](https://www.anthropic.com/engineering/building-effective-agents)
- [OSV API](https://google.github.io/osv.dev/api/) · [OSV-Scanner guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- [Dependabot security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates)
- [GitHub commit statuses](https://docs.github.com/en/rest/commits/statuses) · [REST API best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api) · [`workflow_run` event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run) · [Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [npm provenance](https://docs.npmjs.com/generating-provenance-statements/) · [cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [FIRST EPSS](https://www.first.org/epss/) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Jelly](https://github.com/cs-au-dk/jelly) · [Conftest](https://www.conftest.dev/) · [GuardDog](https://github.com/DataDog/guarddog)
- Incidents that motivate the non-CVE detectors: [CISA: tj-actions compromise](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066) · [Securelist: Shai-Hulud](https://securelist.com/shai-hulud-worm-infects-500-npm-packages-in-a-supply-chain-attack/117547/) · [StepSecurity: chalk/debug compromise](https://www.stepsecurity.io/blog/20-popular-npm-packages-compromised-chalk-debug-strip-ansi-color-convert-wrap-ansi)
