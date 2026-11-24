# Responsible AI & Security Note

## Where AI is used
| Used for | Not used for |
|---|---|
| Investigating findings with tools, grouping them into cases, explaining computed fixes, challenging proposals, explaining validation results, writing the narrative | Detection, hard floors, policy, the BLOCK/REVIEW/ALLOW decision, fix versions, validation pass/fail |

Without a model, scanning, scoring, fix computation, approval, validation and reporting all still work. Agent parts show "pending".

## How hallucinations are controlled
- **Facts come from code.** Numbers, versions and decisions are computed deterministically; fix targets must exist in the registry and lie outside every affected advisory range.
- **Citations are checked** (`agents/constitution.py::check_citations`): every cited case and evidence ID must exist, belong to this run, still match its SHA-256, and be linked to the cited case.
- **AI text is labelled** 🤖 "inference" (with "cites checked" when citations are valid), never 🔒 "verified".
- **Floors can't be argued down**; the verdict comes from one rule function.
- **Investigation claims are checked** (`guardian/ai/workflow.py`): each claim must cite evidence IDs from this run's packet, and every version or advisory ID it mentions must appear in that evidence; otherwise it is rejected and shown as rejected.

## What needs human approval
Applying any patch (validation), opening any fix PR, accepting any risk. Approval needs a name and a reason, and is bound to base commit, head commit, patch SHA-256, policy SHA-256 and validation-profile SHA-256, with an expiry. Any change invalidates it. Rejection or expiry executes nothing. No human action can turn a failed validation into "passed". Guardian never merges, deploys or releases.

## How source code is protected
- Scans read files from git objects (`git archive`); nothing from the repository runs during scanning.
- Lockfile edits use `npm --package-lock-only --ignore-scripts` with an explicit public registry.
- Builds and tests (which do run project and dependency code) happen only in a disposable container: all capabilities dropped, no-new-privileges, non-root user, CPU/memory/pids limits, tmpfs, no secrets, no host-home mount, no Docker socket, internal network where only the local registry proxy is reachable. Lifecycle hooks run only for profile exceptions matching name + version + lockfile integrity.
- The GitHub workflow never checks out PR code; event data is passed via environment variables and validated strictly.

## Credentials and secrets
Stored in `.env` (git-ignored, mode 600). Never logged or printed (tested: the GitHub client hides its token from `repr`; log scan). Not passed to the validation worker or the model. Separate read and write tokens for GitHub; the write token is used only after a matching approval.

## Prompt injection
Package text is marked untrusted; the reading agent (Investigator) has no write tools; the Fixer gets structured fields, not raw package files; policy, approval and validation re-check every proposal. This reduces the risk; it doesn't eliminate it.

## Model and data location
DeepSeek V4 Flash (`deepseek-v4-flash-0731`, reasoning effort medium; explanations low) through FreeModel's OpenAI-compatible API for the hackathon (model swappable). Every call is budget-checked before it is sent and recorded in a local ledger (tokens only, never prompts or keys). For Bosch production: an EU-hosted or in-house model; minimal payloads (package names, versions, evidence excerpts); internal package names never go to public services.

## Audit
Approvals, risk acceptances and validations go to a hash-chained `audit.jsonl` with `audit.head`; editing any entry is detected (`approval.verify_audit`). The report shows the chain status.
