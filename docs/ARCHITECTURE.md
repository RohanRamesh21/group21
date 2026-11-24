# Architecture

Deliverable diagram: agents, deterministic tools, data sources, AI interactions, approval points, evidence storage and trust boundaries. Status marks match `PROGRESS.md`.

```
 TRIGGERS ─────────────────────────────────────────────────────────────────────────────────────────────
  GitHub PR ─▶ GitHub Actions (self-hosted runner, no checkout) ─▶ guardian-submit ─┐   (polling backup ─┐)
  CLI `guardian check` · Dashboard (Git URL / ZIP / local sandbox) ─────────────────┼────────────────────┤
                                                                                    ▼                    ▼
 ┌──────────────────────────── RULE ENGINE  guardian/universal.py (no AI) ──────────────────────────────┐
 │ ① snapshot (git archive, nothing runs) ② inventory (lockfile parser, Syft) ③ SBOM + graph            │
 │ ④ OSV (offline + API) + Grype · 14 detectors · zizmor · shipped-frontend exposure                    │
 │ ⑤ scoring: floors → SSVC (KEV, EPSS) → priority · confidence (5 dimensions) · ONE verdict function    │
 │    + run states per stage, complete/incomplete                                         ✅             │
 └──────────────┬────────────────────────────────────────────────────────────────────────────────────────┘
                │ findings (+ evidence locators)
 ┌──────────────▼─────────── AI WORKFLOW  guardian/ai (DeepSeek V4 Flash via FreeModel) ──────── ✅ ─────┐
 │ evidence packet per case (code) → Investigator ×cases (1 call each, parallel) → Verifier (1 call)     │
 │ every call: budget check → ledger → cache · claims checked against stored evidence · deep mode: --deep│
 │ Gatekeeper rules (constitution.py): citations must exist, belong to the run, match SHA-256, relate    │
 └──────────────┬────────────────────────────────────────────────────────────────────────────────────────┘
 ┌──────────────▼─────────── REMEDIATION  guardian/remediation (no AI) ───────────────────────── ✅ ─────┐
 │ candidates (OSV ranges + npm registry) → ordered rules → ONE combined patch (lockfile-only, scripts    │
 │ off, private export) → patch SHA-256                                                                  │
 └──────────────┬────────────────────────────────────────────────────────────────────────────────────────┘
        👤 APPROVAL POINT  guardian/approval.py ✅
        approval = base_sha + head_sha + patch_sha256 + policy_sha256 + profile_sha256 + approver + expiry
 ┌──────────────▼─────────── VALIDATION  guardian/validation ──────────────── 🟡 live run pending ───────┐
 │ approval check FIRST → baseline + candidate in disposable containers (cap-drop ALL, no-new-privileges,│
 │ non-root, limits, no secrets, no host home, no Docker socket, internal network: only Verdaccio)       │
 │ install (scripts off) → profile-approved hooks only → build → security test → unit → integration     │
 │ → artifact SBOM (Syft) + source rescan (same engine) → deterministic gate                            │
 └──────────────┬────────────────────────────────────────────────────────────────────────────────────────┘
                ▼
 OUTPUTS: dashboard Run page · report.json + report.html · SBOMs · GitHub status guardian/scan (+ validation) + comment

 EVIDENCE & AUDIT (every stage writes here):
   store/evidence.py: content-addressed evidence (SHA-256, verify())
   audit.jsonl + audit.head: hash-chained approvals, risk acceptances, validations
   trigger/events.jsonl: numbered run events (dashboard/Buddy resume)
```

## Data sources
Git repository · npm registry (`registry.npmjs.org`) · OSV.dev API + offline OSV export · Grype DB · CISA KEV · FIRST EPSS · GitHub REST API (statuses, comments, PR list). All accessed directly over HTTPS; responses cached and fingerprinted. No external MCP servers in the trust path.

## Trust boundaries
1. **Repository content**: untrusted; read as files only during scanning.
2. **Package text** (READMEs, changelogs): untrusted; marked as such for agents.
3. **Validation worker + image builder**: the only places candidate code runs.
4. **The model**: receives minimal data; cannot change detection, floors, verdicts or pass/fail.
5. **The human**: the only one who can authorise a change or accept a risk.

## Code map
| Area | Path |
|---|---|
| Engine | `guardian/universal.py`, `guardian/inventory/`, `guardian/vuln/`, `guardian/graph/` |
| Scoring | `guardian/scoring/` (`score.py`, `verdict.py`, `confidence.py`, `states.py`, `intel.py`, `explain.py`) |
| Agents | `guardian/agents/` (roles and prompts in `agents.py`, Gatekeeper in `constitution.py`, tools in `tools.py`) |
| Remediation | `guardian/remediation/` |
| Approval / audit | `guardian/approval.py` |
| Validation | `guardian/validation/` (profiles in `profiles/<name>/`) |
| Report | `guardian/report/build.py` |
| Trigger | `guardian/trigger/`, workflow `ci/github/guardian.yml` |
| API + dashboard | `guardian/server.py`, `guardian/dashboard/` |
| Sample policies | `guardian.yaml` (registries, typosquat, install-script allowlist, sensitive paths), `guardian/validation/profiles/uptime-kuma/profile.yaml` |
