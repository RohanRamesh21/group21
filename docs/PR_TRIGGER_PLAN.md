# How Guardian Wakes Up on a Pull Request (v2)

> **Update (v3, 24 Nov):** the primary trigger is now **GitHub Actions with a self-hosted runner** on our machine; polling (below) is the **backup**. The workflow, lock-down rules and production pattern are in `GUARDIAN_FINAL_PLAN.md` §15. Everything after "event received" in this document (queue, run identity, statuses, Buddy) is unchanged.

*Plan, nothing built yet. Applies to PRODUCT_PLAN v2.2 (M7 GitHub integration, Buddy, dashboard).*
*v2 changes: two separate statuses, wider run identity, SHA re-check, more watched PR changes, Buddy states + reconnect, permissions split, attack scenario stays local, wording fixes.*

## 1. The idea in one line

**GitHub tells Guardian "a PR changed", Guardian analyses that exact commit, stores every step as events, and the dashboard and Buddy display those events. The backend owns scanning, credentials, approvals and results; Buddy only displays and notifies.**

```
GitHub ──poll / webhook──▶ watcher ──▶ ONE queue ──▶ Guardian engine
                                                        │
                                               stored run events (ordered, numbered)
                                                        │
                                       dashboard  +  Buddy (read-only)  +  GitHub statuses
```

## 2. Three ways to be notified

| Way | How | Use |
|---|---|---|
| **A. Polling** | Every 30 s, ask the GitHub API for open PRs and compare with what we stored | **Hackathon demo** (no public URL) |
| **B. Webhook** | GitHub POSTs on every PR change; signature checked | Upgrade; GitHub recommends webhooks for ongoing integrations |
| **C. GitHub Action** | Workflow in the repo | Production template |

A and B feed the **same queue**; everything after that is shared. Only **one** watcher/dispatcher runs, even if the server has several workers (a lock file / single background task).

Limits: Guardian must be running and the laptop awake; polling can't wake a sleeping computer. On start, the watcher catches up by comparing stored state with GitHub.

## 3. What the watcher detects

| Change | Detected by | Guardian does |
|---|---|---|
| New PR | PR not seen before | New run |
| New commits | `head.sha` changed | New run; older run marked **superseded**; old approvals invalid |
| Draft → ready | `draft` true → false | New run (drafts are skipped) |
| Base changed | `base.ref` or `base.sha` changed | New run |
| Reopened | `state` closed → open | New run |
| Closed / merged | `state` / `merged_at` | Stop showing as current; cancel queued work |
| Rerun requested | Dashboard button (later: a PR comment command) | New run even if nothing changed |
| Push to default branch | Branch SHA changed | Refresh baseline SBOM |
| Nightly | Schedule | Monitoring re-check (`newly_disclosed`) |

Polling details: authenticated requests, **all pages** followed (`Link: rel="next"`), conditional requests with ETag (`304 Not Modified` costs no rate limit), back off on `X-RateLimit-Remaining`/`Retry-After`.

## 4. Run identity

Two separate ideas:

- **Delivery dedup:** the same webhook delivery ID or poll observation is processed once.
- **Analysis identity:** a result can be reused only if **all** of these match:

```
repo + pr_number + comparison_base_sha + head_sha
+ policy_sha256 + profile_sha256 + intelligence_snapshot (advisory DB date)
```

If any part changes (e.g. new advisory DB, new policy) the same head is analysed again. An explicit rerun always creates a new run.

## 5. Steps after waking

```
1. RECEIVE   webhook: verify X-Hub-Signature-256 (HMAC-SHA256); poll: compare stored state
2. QUEUE     run_id; supersede older run for this PR
3. PENDING   status guardian/scan = pending "scanning…"; events → dashboard + Buddy
4. FETCH     git fetch origin pull/<N>/head  → check it resolves to the EXPECTED head_sha.
             If the branch moved meanwhile: stop, the newer event will start a new run.
             Files only (git archive); nothing runs.
5. SCAN      stages ①–⑥ (rules) → decision + completeness
6. STATUS    guardian/scan (see §6) + one PR comment, updated in place
7. AGENTS    investigation + fix proposal (background); comment updated
8. APPROVE   on the dashboard only (v1). Bound to run + base + head + patch + policy + profile.
9. VALIDATE  validation worker → guardian/validation status
10. FIX PR   on our fork, using the separate write capability (§8). Never merged by Guardian.
```

A late event from a superseded run is stored for the audit trail but **never** changes what is shown as current.

## 6. Two GitHub statuses, never mixed

GitHub commit statuses support only `pending`, `success`, `failure`, `error` (no `neutral`).

| Context | Meaning | Mapping |
|---|---|---|
| **`guardian/scan`** | "Scan policy result for this commit" | BLOCK → `failure` · REVIEW → `failure` ("needs human review") · ALLOW → `success` ("scan policy passed") · incomplete/scanner down → `error` |
| **`guardian/validation`** | "The approved fix was validated" | not started / running → `pending` · verified → `success` · failed → `failure` · incomplete → `error` |

`success` on `guardian/scan` means **only** "scan policy passed", never "fix verified". If a team requires the full workflow before merging, they make `guardian/validation` the required check; it stays pending until validation finishes.

## 7. Buddy (display and notification client)

### States

| Backend state | Buddy shows |
|---|---|
| Connected, no active run | Idle (blue) |
| Run queued / scanning | Scanning + PR name and number |
| Investigation running | Investigating |
| Approval required | "Review proposed fix" → click opens the dashboard run page |
| Validation running | Validating |
| Confirmed blocker | Red + link to evidence |
| Review required | Yellow |
| Scan policy passed | Green, labelled **"scan passed"** |
| Fix verified | Green, labelled **"fix verified"** |
| Backend disconnected or result stale (no update > N min) | **Grey "offline / stale"**, never the previous green |
| Run superseded | Drops it; shows the newer run |

### Connection rules

1. On connect: fetch a **snapshot** of current runs (`GET /api/runs/current`).
2. Subscribe to events (SSE) with **sequence numbers**.
3. On reconnect: send `Last-Event-ID` to resume; if the server can't resume, refresh the snapshot.
4. Ignore any event whose run is older than the current run for that PR.
5. Always show connection status and last-update time.

**v1: no approval buttons on Buddy.** Approval stays on the dashboard. Buddy buttons later need authenticated requests bound to the exact patch, not just a desktop click.

## 8. Credentials and permissions (split)

| Capability | Token | Permissions | Used by |
|---|---|---|---|
| Scan + report | Token 1 (one repo) | Contents **read**, Pull requests read/write (comment), Commit statuses read/write | Watcher, engine, reporter |
| Fix branch + fix PR | Token 2 (our fork only), used **only after a matching approval** | Contents **write**, Pull requests write | Fix-PR step (stretch S2) |

Both in `.env`, never logged; the log-scan test checks this. Richer check runs (with buttons) need a GitHub App, which comes later.

## 9. Demo setup (attack stays local)

| What | Where | Shows |
|---|---|---|
| **Benign PR** (e.g. a small dependency bump or README change) on **our public fork** | GitHub | Automatic trigger: PR opened → Buddy scanning → status + comment appear |
| **Attack scenario** (`axois` + `.npmrc` + tampered lockfile) | **Local only** (sandbox repo + local Verdaccio), labelled "local scenario" | BLOCK, investigation, fix, approval, validation |

Both enter the **same queue and pipeline** (the local scenario is submitted as a local intake event). Scenario branches are never pushed; nothing malicious appears in a public repo, even pointing at localhost.

## 10. Production template (mode C)

1. `guardian-scan.yml` on `pull_request`: stages ①–⑥, **read-only token, no secrets**, no PR code executed → uploads report artifact.
2. `guardian-report.yml` on `workflow_run`: treats the artifact as **untrusted input**:
   - check the originating repository, workflow name, run ID and head SHA;
   - validate the JSON against the schema; check paths and size limits;
   - never execute anything from the artifact;
   - **recompute** the status from the findings with the policy; never trust a status the artifact asks for.
3. Never use `pull_request_target` to check out PR code with secrets.
4. **GitHub-hosted runners are GitHub's machines, not Bosch infrastructure.** For Bosch, AI stages and validation run on Bosch-controlled systems; self-hosted runners only for trusted (non-fork) PRs.

Notes: a `smee.io` relay is a third-party service that sees webhook payloads; fine for public demo repos, not for private code. A local Gitea would need its own adapter (its API isn't identical to GitHub's); not planned.

## 11. Failure handling

| Situation | Behaviour |
|---|---|
| New push while scanning | Old run superseded; new run starts |
| Fetched SHA ≠ expected | Stop; wait for the newer event |
| Scanner / API down | `guardian/scan = error`, "incomplete"; Buddy yellow/grey, never green |
| Guardian was offline | Catch up on start |
| Bad webhook signature | 401, logged |
| Rate limit | Back off; status stays pending |
| Buddy loses connection | Grey "offline"; snapshot on reconnect |

## 12. Tests (before any animation work)

- New PR → one run; same state polled again → no run.
- New push → old run superseded; its late result doesn't change the current state; approval invalidated.
- Draft → ready (no new commit) → run. Base change → run. Close → not current.
- Pagination: PR on page 2 detected.
- Fetched SHA mismatch → run stops.
- Same head, new advisory DB → new analysis; explicit rerun → new run.
- Status mapping: REVIEW → `failure`; incomplete → `error`; `guardian/scan` success never sets `guardian/validation`.
- Buddy: reconnect with `Last-Event-ID`; stale timeout → grey; superseded update ignored.
- `workflow_run` reporter rejects an artifact from the wrong repo/run or with a mismatched SHA.
- Tokens never appear in logs.

## 13. Effort

| Work | Effort |
|---|---|
| Watcher (all changes, pagination, ETag, single instance) + queue + run identity + supersede | 1 day |
| Two statuses + one updated comment | ½ day |
| Event store with sequence numbers + snapshot endpoint + resume | ½ day |
| Buddy read-only client (states, reconnect, stale) | 1–1½ days |
| Webhook endpoint + HMAC | ½ day |
| Fix PR with separate token (S2) | ½ day |
| Action templates with safe `workflow_run` reporter | ½ day |
