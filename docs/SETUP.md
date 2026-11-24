# Setup

## Requirements
| Tool | Version used | Why |
|---|---|---|
| Python | 3.12 | engine, API |
| Node.js / npm | 20+ (tested with 26.7 for lockfile edits) | lockfile-only edits, dashboard build |
| Git | any recent | snapshots (`git archive`), diffs |
| Docker | 29.x | validation worker, Verdaccio |
| Syft 1.57.2 · Grype 0.122.1 · OSV-Scanner 2.7.1 · zizmor 1.33.1 · cosign 3.1.4 · hadolint 2.15.1 | see `tools.lock` (with SHA-256) | scanners |

macOS: `brew install syft grype osv-scanner zizmor cosign hadolint`.

## Install
```bash
cd guardian
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.lock.txt && .venv/bin/pip install -e .
(cd guardian/dashboard && npm ci --ignore-scripts && npm run build)
grype db update            # once; the validation gate compares the DB before and after
docker pull node:20-bookworm
```

## Local registry (attack scenario + validation proxy)
```bash
docker run -d --name verdaccio -p 4873:4873 verdaccio/verdaccio:6   # pinned digest in tools.lock
python testbed/injector/build_s3_s9.py                               # builds the local-only scenario branches
```
The validation worker joins the internal Docker network `guardian-validate` (created automatically); only Verdaccio is attached to it, and its uplink is `registry.npmjs.org`.

## Secrets (`.env`, mode 600, git-ignored)
```
FM_API_KEY=...                # FreeModel key: AI investigation, fix review, explanations (optional: rules work without it)
GUARDIAN_LLM_PROVIDER=freemodel
GUARDIAN_MODEL=deepseek-v4-flash-0731
GUARDIAN_EFFORT=medium          # agents; explanations use GUARDIAN_EXPLAIN_EFFORT (default low)
GUARDIAN_RUN_TOKEN_BUDGET=25000  # per investigation run (default)
GUARDIAN_MONTH_TOKEN_BUDGET=300000  # rolling 30 days (default)
GUARDIAN_GITHUB_TOKEN=...     # fine-grained, demo repo only: Commit statuses RW, Pull requests RW, Issues RW, Contents R
```
Never commit `.env`. Tokens are never logged.

## PR trigger (GitHub Actions on your machine)
1. Fork the sample app on GitHub; copy `ci/github/guardian.yml` to `.github/workflows/`.
2. Repository settings → Actions → "Require approval for all outside collaborators".
3. Register a self-hosted runner with label `guardian-demo`, running as a separate low-privilege user.
4. Install the submit script outside the repository: `~/.guardian/bin/guardian-submit` (this file with the venv's Python on its shebang; the workflow calls `$HOME/.guardian/bin/guardian-submit`).
5. Start the server (`uvicorn guardian.server:app --port 8765`) and open a PR.

## Always-on services and scheduled jobs (macOS)
```bash
scripts/install-services.sh     # server, Buddy, 02:00 advisory refresh, 10-min missed-PR watchdog (LaunchAgents, no sudo)
scripts/uninstall-services.sh
```
Logs go to `~/Library/Logs/guardian/`. Buddy can also be started by hand: `cd buddy && npm start`.

## Run the tests
```bash
.venv/bin/python -m pytest
```
