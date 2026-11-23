# Software Supply Chain Guardian

*Know what you build. Trust what you ship.* A pre-merge check for the software supply chain (Bosch BGSW hackathon).
Given a repository and a base/head pair, it lists what the application is built from and finds vulnerabilities and
suspicious changes. Each risk is labelled as introduced by the change, pre-existing, or fixed, and backed by
evidence.

- **Any repository:** npm, Python, Go, Java (Maven/Gradle), C/C++ (vcpkg, conan, CMake, meson) and the other
  ecosystems Syft knows, plus CI workflows and container images.
- **Safe on untrusted code:** nothing from the scanned repository is installed or run. Every tool that reads it runs
  in a locked-down podman sandbox: no network, read-only, pinned images (`docs/SETUP.md`).

## Quick start

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.lock.txt && uv pip install --python .venv/bin/python -e .
.venv/bin/guardian sandbox setup                       # once: pinned tool images + vulnerability DB (needs podman)
.venv/bin/guardian check <repo> --base <ref> --head <ref>   # what this change introduced
.venv/bin/guardian scan <repo> --ref <ref>             # full scan of one commit
.venv/bin/uvicorn guardian.server:app --port 8765      # dashboard
.venv/bin/python -m pytest -q
```

## Documentation

| | |
|---|---|
| `HANDOFF.md` | Current state, demo script, what is not done |
| `docs/SETUP.md` | Setup, the sandbox and its guardrails, troubleshooting |
| `docs/ARCHITECTURE.md` | Scan pipeline, trust boundaries, ecosystem coverage |
| `docs/DETECTORS.md` | Detector reference (D15-D19, T0) |
| `docs/TESTING.md` | Test layers, real-app corpus results (12 open-source apps, 7 ecosystems) |
| `docs/SCORING.md` | How risk is scored |
| `docs/AGENTIC_CORE.md` | The agent team and its constitution |
| `docs/DECISIONS.md` · `docs/KNOWN_LIMITATIONS.md` | Why things are the way they are; what does not work |
| `testbed/apps/README.md` | Synthetic sample apps per ecosystem (simulated risks) |
