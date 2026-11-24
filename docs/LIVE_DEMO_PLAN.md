# Live Demo Plan: Guardian on a real GitHub repository

**Goal:** a real pull request on `github.com/kirankishoreV-07/PIPELINE_CHECK`. GitHub Actions wakes Guardian on our machine. The **Buddy** pet reacts. Enlarging Buddy opens the dashboard on that PR's run. The 4 agents investigate, a person approves, the fix is validated, and GitHub shows the result. Nightly scheduled jobs keep watching `main`.

Status of the repo today: **public, empty** (checked 24 Nov 2026). `gh` is logged in as the owner on this machine.

---

## 1. What the audience will see (3 PRs, about 6 minutes)

| # | PR opened on GitHub | What happens | Result on GitHub |
|---|---|---|---|
| A | `feat: show pipeline duration chart` (adds a clean, current package) | Buddy: magnifier → green. Dashboard: ALLOW. | ✔ `guardian/scan` "scan policy passed" + one comment |
| B | `feat: alert rules with JSONata` (adds `jsonata@2.2.0`, which has real public advisories) | Buddy: yellow/red. Enlarge Buddy → dashboard → **Run the 4 agents** → fix (upgrade to the first safe version) → **you approve** → validation in the isolated container → verified | ✘ `guardian/scan` blocks the merge (branch protection); `guardian/validation` ✔ after the fix |
| C | `chore: fix typo` (hides a look-alike package from a local registry, an `.npmrc` redirect and a tampered lockfile) | Buddy turns **red** and sends a macOS notification. Dashboard: BLOCK with proof; the Investigator reads the install script (a harmless canary). | ✘ blocked, with an evidence comment |

Optional finale (stretch S2): after approval, Guardian opens a fix PR (`guardian/fix-<run>`) itself. **It never merges.**

---

## 2. Key design decision, backed by research

### 2.1 Use `pull_request_target`, not `pull_request`
- With `pull_request`, a fork's PR runs **the workflow file from the PR itself**. On a self-hosted runner, a stranger could edit the workflow to run commands on our laptop ([GitHub docs](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target); [GitHub community](https://github.community/t/self-hosted-runner-security-with-public-repositories/17860)).
- `pull_request_target` always uses the workflow from `main`. Its known danger ("pwn request") only applies when the job **checks out and runs** the PR's code. **Our job never does:** it only passes the commit SHAs to the local server. The server fetches the code as git objects with hooks disabled and never executes it (`trigger/service.py`).
- So `pull_request_target` + no checkout is the safe pattern for our design.
- We add two more layers:
  - "Require approval for all external contributors" for fork workflows ([GitHub docs](https://docs.github.com/en/enterprise-server@3.12/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/approving-workflow-runs-from-public-forks));
  - the runner runs as a separate low-privilege macOS user.

### 2.2 Keep the repository public
Required status checks (branch protection) are free only on **public** repositories for personal accounts; private repos need GitHub Pro ([GitHub docs](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches); [community discussion](https://github.com/orgs/community/discussions/174419)). Branch protection is what makes Guardian's ✘ really stop the merge, so public + the protections above is the right setup.

### 2.3 Self-hosted runner as the primary trigger (outbound only)
- The runner connects out to GitHub, so no port on the laptop is opened.
- A webhook through a tunnel (ngrok/cloudflared are installed) would expose the server to the internet. We keep it only as a documented alternative.
- If the runner is offline, the existing **polling backup** (`trigger/watcher.py`) picks the PR up on a schedule (see §5).

---

## 3. The demo application (`PIPELINE_CHECK`)

**Our full fix-and-validate loop targets npm**, so the app is a small but real Node project.

| Part | Content |
|---|---|
| App | **"ShipLog"**: a pipeline-status board. Express API (`/health`, `/api/pipelines`, `/api/pipelines/:id/runs`), a small static frontend, JSON data file |
| Dependencies | A handful of real, current packages (e.g. `express`, `helmet`, `pino`, `zod`), all exact versions, with a committed `package-lock.json` (v3) |
| Tests | `node --test` unit tests + an HTTP test (`supertest`) |
| Container | `Dockerfile` (Node 20). The image tag is deliberately not pinned to a digest, so Guardian shows a real pre-existing finding |
| CI | `.github/workflows/ci.yml` on GitHub-hosted runners (install + test), separate from Guardian |
| Guardian | `.github/workflows/guardian.yml` (`pull_request_target`, self-hosted, no checkout) + `guardian-nightly.yml` (schedule) |
| Docs | README explaining the app and that the repo is a Guardian demo; `SECURITY.md` note that scenario packages are harmless fixtures |

A validation profile `guardian/validation/profiles/shiplog/` does the following: install (scripts off) → unit tests → start the server inside the container → integration checks (`/health`, `/api/pipelines`) → artifact SBOM.

---

## 4. Product changes needed (what I will build)

| Phase | Work | Done when |
|---|---|---|
| **P0 Safety** | Switch the workflow template to `pull_request_target` with a lint test that fails if a checkout step is ever added; pass the PR title through env (treated as untrusted: length-limited, shown escaped) | Tests pass; template reviewed |
| **P1 Demo repo** | Write ShipLog (app, tests, Dockerfile, CI, README), push to `main`; Guardian scans `main` once as the baseline | CI green on GitHub; baseline scan ALLOW with a few honest pre-existing findings |
| **P2 Live trigger** | Register the runner (label `guardian-demo`); install `guardian-submit`; statuses + one comment per PR; branch protection requires `guardian/scan` | A real PR shows pending → result on GitHub within about 1 minute |
| **P3 Dashboard live mode** | PR runs appear in the run selector ("PIPELINE_CHECK #2 · title"); a live banner "PR #3 opened, scanning"; auto-follow the newest PR; deep link from the PR comment; agents, fix, approval and validation work on PR runs | Opening a PR moves the dashboard to that run without a reload |
| **P4 Buddy (the pet)** | A small always-on-top desktop window with an **original** shield-robot drawn in SVG (not the existing mascot). States: idle (blue, blinking), scanning (magnifier + PR title), agents working, needs approval, red blocker, yellow review, green passed / fix verified, **grey when offline or stale**. Drag to move. **Click to enlarge:** the window grows into the full dashboard on that PR's run; collapse back to the pet. A macOS notification only for red. Snooze. | Buddy follows a real PR from opened → verdict → approval → validation, and goes grey when the server stops |
| **P5 Demo PRs** | Prepare branches A, B and C (C uses the local Verdaccio registry); the validation profile for ShipLog; agents run on B and C | All three PRs behave as in §1 in a dry run |
| **P6 Scheduled jobs** | See §5 | Each job ran once and left a record |
| **P7 Rehearsal + failure drills** | A step-by-step demo script; drills: server down (job exits 70 → status `error`, Buddy grey), runner offline (polling backup posts the result), PR pushed again mid-scan (old run superseded) | Each drill shows the documented behaviour |

### Buddy technology
| Option | For | Against |
|---|---|---|
| **Electron (recommended)** | Uses Node, already installed; transparent, frameless, always-on-top windows are well documented ([Electron docs](https://electronjs.org/docs/latest/api/base-window); [frameless windows](https://electronjs.org/de/docs/latest/api/frameless-window)); fastest to build | Larger app (~100 MB). On macOS a window can't be placed over the menu bar ([issue](https://www.github.com/electron/electron/issues/42104)); transparency can fail with some GPU settings, so we'll test on this Mac |
| Tauri v2 (in the original plan) | Small binary | Rust isn't installed here (install + first build takes extra time) |

---

## 5. Scheduled jobs ("cron")

| Job | Where | When | What it does |
|---|---|---|---|
| **Nightly re-check of `main`** (stretch S6) | GitHub Actions `schedule` on our runner (`guardian-nightly.yml`) | 02:30 IST daily (`0 21 * * *` UTC) | Re-scans `main` with fresh advisory data. **Newly disclosed** problems in unchanged code are reported separately from PR-introduced ones, in one GitHub issue that is updated, not duplicated |
| **Advisory data refresh** | macOS `launchd` on this machine | 02:00 IST daily | `grype db update`, OSV offline export, CISA KEV, FIRST EPSS, so the nightly scan uses fresh data even if GitHub delays the schedule |
| **Missed-PR watchdog** | `launchd` | every 10 min | Runs the polling backup: finds open PRs whose head has no Guardian status (runner was offline) and scans them |

Limits we design around:
- GitHub's `schedule` runs only from the default branch.
- It can be delayed under load and its minimum interval is 5 minutes.
- Public repos can have schedules disabled after long inactivity.

That's why the local `launchd` jobs exist ([GitHub Actions limits](https://docs.github.com/en/actions/reference/actions-limits); [community report](https://github.com/orgs/community/discussions/185355); [guide](https://cronuru.com/guides/github-actions-scheduled-workflows)). These come from community sources and are checked against the official page during P6.

---

## 6. Token use (AI)

- One full agent run costs **about 16K tokens**. Re-running on the same evidence costs **0** (cache).
- About 338K remain this cycle, so roughly 20 fresh PR investigations.
- **Agents start automatically only for BLOCK/REVIEW PRs**, never for ALLOW. Each run stays under the 25K cap, and the monthly cap still applies.

---

## 7. What I need from you

| # | Item | Why | How |
|---|---|---|---|
| 1 | **Fine-grained token** for `PIPELINE_CHECK` only: Commit statuses **read/write**, Pull requests **read/write**, Issues **read/write** (nightly issue), Contents **read**, Metadata read | Server posts statuses, the PR comment, the nightly issue | GitHub → Settings → Developer settings → Fine-grained tokens → paste into `guardian/.env` as `GUARDIAN_GITHUB_TOKEN` yourself (don't paste it in chat) |
| 2 | (Only for the S2 finale) a second token: Contents **read/write** + Pull requests **read/write** | Guardian opens the fix PR after your approval | Same place; `GUARDIAN_GITHUB_WRITE_TOKEN` |
| 3 | **OK to push** the demo app to `main` and create the demo branches using your logged-in `gh` | These are public, outward-facing actions | Say yes, or push yourself |
| 4 | **OK to register a self-hosted runner** on this Mac. Best practice: a separate macOS user `guardian-runner` (creating it needs your admin password, so you do that step) | Runs the 1-step workflow | I'll give the exact commands |
| 5 | **Repo settings** (I can do them via `gh api` if you allow): fork-PR approval for all external contributors; branch protection on `main` requiring `guardian/scan` | Safety + a real merge block | Say yes, or click them |
| 6 | **Decision: PR C on a public repo.** Earlier we agreed the attack scenario stays local. On GitHub it would be a branch whose lockfile points to `127.0.0.1` and whose package exists only in our local registry (harmless canary). I'd use a look-alike name I've confirmed is **not registered on npm**, so nobody can install a real package by that name | It's the most convincing part of the demo | Yes / no / keep C local-only |
| 7 | **Docker internet access** for validation (`docker pull node:20-bookworm` failed earlier with no DNS) | Validation needs the base image once | Check Docker Desktop network/proxy settings |
| 8 | Preferences: Buddy on **Electron** (recommended) or Tauri; nightly time (02:30 IST suggested) | | |

## 8. Non-negotiables kept
- No checkout or execution of PR code on the runner.
- Package code runs only in the isolated validation container.
- Approval only by a person, bound to the patch hash.
- Guardian never merges, deploys or releases.
- Tokens stay in `.env` and are never logged.
- Nothing is pushed or created on GitHub without your OK.
- Recorded data is never shown as live.
