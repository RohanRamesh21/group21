# Software Supply Chain Guardian

*Know what you build. Trust what you ship.* A pre-merge check for the software supply chain (Bosch BGSW hackathon).
Given a repository and a base/head pair, it lists what the application is built from and finds vulnerabilities and
suspicious changes. Each risk is labelled as introduced by the change, pre-existing, or fixed, and backed by
evidence.

- **Any repository:** npm, Python, Go, Java (Maven/Gradle), C/C++ (vcpkg, conan, CMake, meson) and the other
  ecosystems Syft knows, plus CI workflows and container images.
- **Beyond detection (no LLM needed):** reachability (is the vulnerable package used?), npm signature and build-provenance checks,
  package-history and install-script analysis, policy-as-code (Conftest/OPA), fixes that are validated by a rescan and turned into a branch
  only after a human approves, and continuous monitoring for newly disclosed vulnerabilities.
- **Handling untrusted code:** Guardian reads committed Git objects. Package managers and third-party scanners
  run in pinned Podman containers with read-only inputs and restricted network access (`docs/SETUP.md`).
- **Review findings:** confirm, challenge, or defer a finding in **Risk scores**. Guardian keeps the review history and reopens a
  finding when its evidence changes or the deferral expires.

## Quick start

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.lock.txt && uv pip install --python .venv/bin/python -e .
.venv/bin/guardian sandbox setup                       # once: pinned tool images + vulnerability DB (needs podman)
.venv/bin/guardian check <repo> --base <ref> --head <ref>   # what this change introduced
.venv/bin/guardian scan <repo> --ref <ref>             # full scan of one commit
.venv/bin/guardian fix                                 # remediation plan (validate + approve in the dashboard)
.venv/bin/guardian watch --all                         # re-check scanned apps for newly disclosed vulnerabilities
.venv/bin/uvicorn guardian.server:app --port 8765      # dashboard
.venv/bin/python -m pytest -q
```

## Dashboard

Open `http://127.0.0.1:8765` (build the UI first: `cd guardian/dashboard && npx vite build`). Two pages:

- **Scan** (home): give it a public Git URL, a ZIP, or a folder on this machine, optionally with a base and head to compare.
  The pipeline runs live (fetch → inventory → SBOM and graph → CI and images → vulnerabilities → compare → provenance → verdict),
  then the results open in four views: **Overview**, **Dependency graph**, **Risk scores** and **Fix & validate**. Recent scans,
  including the latest `guardian check` from the command line, are listed underneath. Every scan has its own link (`#/scan/<id>`).
- **Investigate**: pick a finished scan, or bring a new source (it is scanned first), and run the agents on it. Live agents need an
  LLM key in `.env`. Without one, the deterministic checks still run, and a clearly labelled recorded example shows a full agent debate.

A local folder must be inside your home directory (or `GUARDIAN_PATH_ROOTS`). A Git repository is cloned and never modified;
its committed code is scanned. Any other folder is copied with the same limits as a ZIP.

## Documentation

| | |
|---|---|
| `HANDOFF.md` | Current state, demo script, what is not done |
| `docs/SETUP.md` | Setup, the sandbox and its guardrails, troubleshooting |
| `docs/ARCHITECTURE.md` | Scan pipeline, trust boundaries, ecosystem coverage |
| `docs/DETECTORS.md` | Detector reference (D15-D19, T0) |
| `docs/TESTING.md` | Test layers, real-app results (20 apps incl. one flagship app per language), how to test them in the UI (§7) |
| `docs/SAMPLE_APP.md` | The pinned sample app (uptime-kuma) and the flagship apps per language |
| `CHANGELOG.md` | What changed, by date |
| `docs/SCORING.md` | How risk is scored |
| [Human feedback](docs/HUMAN_FEEDBACK.md) | Finding reviews, reopening, and the downloadable review report |
| `docs/AGENTIC_CORE.md` | The agent team and its constitution |
| [Guardian self-protection](docs/GUARDIAN_SELF_PROTECTION.md) | Rohan's proposal for defending the review workflow |
| `docs/DECISIONS.md` · `docs/KNOWN_LIMITATIONS.md` | Why things are the way they are; what does not work |
| `testbed/apps/README.md` | Synthetic sample apps per ecosystem (simulated risks) |
