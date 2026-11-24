# Software Supply Chain Guardian

**Know what you build. Trust what you ship.** Bosch BGSW hackathon · Software Supply Chain Guardian.

Guardian analyses the supply-chain changes in a pull request, explains which risks matter with evidence, computes an exact fix, waits for a named person to approve it, then validates the fix by building, testing and rescanning in an isolated container. It reports what it checked and what it could not check.

- **All docs, by question:** [`docs/README.md`](docs/README.md)
- **Plan:** [`docs/GUARDIAN_FINAL_PLAN.md`](docs/GUARDIAN_FINAL_PLAN.md) · **Build log with evidence:** [`docs/PROGRESS.md`](docs/PROGRESS.md)
- **Architecture:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · **Responsible AI & security:** [`docs/RESPONSIBLE_AI.md`](docs/RESPONSIBLE_AI.md) · **Known limitations:** [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) · **Setup:** [`docs/SETUP.md`](docs/SETUP.md)

## What works today

| Step | Command | Status |
|---|---|---|
| Discover + detect + score a change (any supported repo) | `guardian check <repo> --base <ref> --head <ref>` | ✅ exit code 0 allow · 1 review · 2 block · 3 incomplete |
| Propose fixes: deterministic candidates + one combined patch | `guardian fix --out <run>` | ✅ |
| Approve / reject as a named person (bound to commits, patch, policy, profile) | `guardian approve --out <run> --approver <name> --reason "<why>"` | ✅ |
| Validate in an isolated container (baseline vs candidate, rescans, gate) | `guardian validate --out <run>` | 🟡 code + tests done; live Uptime Kuma run pending |
| Guardian report (HTML + JSON) | `guardian report --out <run>` | ✅ |
| Web dashboard (Run page, proof drawer, fix + approval, validation, live PR events) | `uvicorn guardian.server:app --port 8765` | ✅ |
| PR trigger (GitHub Actions on a self-hosted runner; polling backup) | `ci/github/guardian.yml` + `guardian-submit` | 🟡 code + tests done; needs a fork, token and runner |
| AI investigation (1 call per case + 1 Verifier, checked claims, token-budgeted, cached) | `guardian investigate --out <run>` or the Run page | ✅ live: about 16K tokens, 3 calls, 43 s on the scenario; repeat = 0 tokens |

## Two-minute demo (local, no AI needed)

```bash
cd guardian
.venv/bin/guardian check sandbox/uptime-kuma --base scenario/base --head scenario/s3-s9   # → BLOCK (exit 2)
.venv/bin/guardian fix                                                                     # → remove axois, revert .npmrc: one patch
.venv/bin/uvicorn guardian.server:app --port 8765                                          # open http://127.0.0.1:8765 → Run
```
Then review the patch on the Run page and approve it yourself (name + reason), and start validation.

## How it decides (short)
1. **Rules find and decide** (no AI): Syft / lockfile parser → SBOM and graph; OSV + Grype; 14 supply-chain detectors; floors → SSVC (KEV, EPSS) → priority; one verdict function.
2. **Fixes are computed** from advisory ranges and the npm registry; agents may explain them, never invent versions.
3. **A person approves** an exact patch hash; any change invalidates the approval.
4. **Validation decides by exit codes and scan diffs**; "verified" only when every required stage passed.

## Sample application
Uptime Kuma 2.5.12 (MIT), pinned commit `5aa5dec4`, in `sandbox/uptime-kuma`. The attack scenario (`scenario/s3-s9`: look-alike `axois`, `.npmrc` redirect, tampered lockfile) exists **only locally**; its package is harmless (writes a marker file) and lives only in the local Verdaccio registry.

## Tests
`.venv/bin/python -m pytest` → 220 passed (24 Nov 2026). Each milestone's tests are listed in `docs/PROGRESS.md`.
