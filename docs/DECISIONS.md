# Decision log

Append-only. One entry per decision: date, decision, alternatives, why.

## 2026-11-23 — Run every repository-reading tool in a rootless podman sandbox
- **Decision:** npm lockfile resolution, Syft, Grype, OSV-Scanner and zizmor run in fresh rootless podman containers:
  digest-pinned images, `--network=none`, read-only inputs and root filesystem, no host environment, non-root,
  all capabilities dropped, memory/CPU/pids/time limits. If the sandbox is unavailable the step is not run on the
  host and is reported as `tool_error`.
- **Alternatives:** bubblewrap (fast, no images, but reuses host toolchains, so every machine would need go/maven/
  syft/grype installed); running on the host (status quo).
- **Why:** a scanned repository is attacker-controlled input. We reproduced that a repository `.npmrc` (`git=<program>`)
  made host npm run a repository-supplied program despite `--ignore-scripts` (now a regression test). Podman images also
  bring the tools, so the host needs only podman.

## 2026-11-23 — Egress through an in-process allow-list proxy on a Unix socket
- **Decision:** containers never get a network interface. A step that needs a registry gets a Unix socket to an
  allow-list proxy running in Guardian's process, bridged to `127.0.0.1:3128` inside the container (`bridge.js`).
  HTTPS `CONNECT` to allow-listed hosts on port 443 only; refusals become finding D16.
- **Alternatives:** an internal podman network plus a proxy container (needs `pasta` and `aardvark-dns`, which are not
  installed on the dev machine and need root to install); full network for the resolution container.
- **Why:** no extra system packages, and no way around the proxy: there is no route other than the socket.

## 2026-11-23 — New dependencies: podman (system) and five container images
- **Decision:** podman 5.x (rootless). Images: `docker.io/library/node:24-alpine`, `docker.io/anchore/syft:v1.57.2`,
  `docker.io/anchore/grype:v0.122.1`, `ghcr.io/google/osv-scanner:v2.7.1`, `ghcr.io/zizmorcore/zizmor:1.33.1`, pinned
  by digest in `guardian.yaml` and `tools.lock`.
- **Publisher check:** official images of each project (Docker official `library/node`; Anchore for Syft/Grype; Google
  for OSV-Scanner; the zizmor project's own `zizmorcore` organisation). Versions match the CLI versions already pinned
  in `tools.lock`.
- **Grype DB:** downloaded by Guardian on the host, sha256 checked against the official listing, imported offline.

## 2026-11-23 — No dependency resolution for Python, Go, Java or C/C++
- **Decision:** these ecosystems are read statically (Syft + `guardian/adapters/build_files.py`). Only npm lockfiles
  are resolved, as before, now inside the sandbox.
- **Alternatives:** `uv pip compile`, `go mod download`, `mvn dependency:tree`, `conan graph`.
- **Why:** Maven/Gradle plugins, `conanfile.py`, `setup.py` and CMake scripts are code, so resolving runs analysed code
  (CLAUDE.md §3.2). Python resolution would also add a new public registry (pypi.org) to the scanner's network
  access (CLAUDE.md §3.1). Cost: transitive dependencies of these ecosystems are visible only when a lockfile is
  committed (`docs/KNOWN_LIMITATIONS.md`).

## 2026-11-23 — Synthetic sample apps instead of cloning third-party repositories
- **Decision:** `testbed/apps/` holds small synthetic projects per ecosystem with planted risks, two clean controls
  and a ground-truth file. They are never built.
- **Alternatives:** a corpus of pinned real open-source repositories cloned from GitHub.
- **Why:** CLAUDE.md §3.1 forbids accessing repositories outside our sandbox, and synthetic apps give an exact ground
  truth (including false-positive controls). Real repositories can still be scanned on demand through "Scan a project".

## 2026-11-23 — Unpinned components carry no version in the SBOM
- **Decision:** components without an exact version are written to `sbom.guardian.cdx.json` without a version (range
  kept in `guardian:declared`), and Grype matches on version-less components are dropped.
- **Why:** Grype matched `guava` declared as `31.+` against advisories for every version (4 false advisories in the
  `java-gradle` sample app). The floating version is itself reported (D19 `dynamic_version`).

## 2026-11-24 — Real open-source apps are allowed as a test corpus (supersedes the synthetic-only entry above)
- **Decision:** the user changed CLAUDE.md §3.1. Public repositories listed in `testbed/corpus.yaml` may be fetched for
  testing: pinned to a full commit SHA, fetched bare and read-only into `sandbox/corpus/` (depth 1, hardened git from
  `guardian/projects.py`, the fetched commit checked against the pin), and scanned only through the sandbox. They are
  never built, run, modified or pushed to. The synthetic apps in `testbed/apps/` stay, as exact ground truth and
  false-positive controls.
- **Corpus choice:** popular, permissively licensed projects that cover the readers we have: npm with and without a
  lockfile (axios, express), Python (flask, requests), Go (cobra, gin + a release diff), Java Maven/Gradle (gson,
  spring-petclinic), C++ CMake/FetchContent/meson (spdlog, cpr, nlohmann-json) and Rust (ripgrep).
- **Why:** synthetic apps only prove the rules fire as designed. The first real run found 211 duplicate or false-positive
  findings and a line-number bug in D10 (`docs/TESTING.md` §3).

## 2026-11-24 — Treat the Guardian review as a security boundary

- **Decision:** credit Rohan Ramesh's proposal to defend the reviewer itself. Run mandatory checks outside model
  control, validate actions server-side, and preserve unsafe or incomplete outcomes across model failures.
- **Why:** the agent team reads content controlled by a change author or package publisher. Prompt framing and
  reviewer-directed text detection help with triage. The action checks still hold if a model follows that text.
- **Details:** [How Guardian protects its own review](GUARDIAN_SELF_PROTECTION.md).

## 2026-11-24 — Day 1 verdict: introduced high/critical severity needs a human
- **Decision:** the verdict is at least `review` when a change introduces any finding whose own severity is high or critical, even if SSVC
  ranks it Track (no exploitation seen). SHA→tag for a CI action is a hard signal (floor High).
- **Why:** scenarios s1/s2/s8 (new high CVEs, new template injection) were `allow`, and CLAUDE.md §3.2 lists SHA→tag as a hard signal.

## 2026-11-24 — Trusted base images are a policy list
- **Decision:** `guardian.yaml` `images.trusted` (globs over `registry/repository`); anything else is `untrusted_image` (high for an unknown
  registry, medium for an unknown publisher on a known registry). Dockerfiles are discovered case-insensitively (`docker/dockerfile`).
- **Why:** scenario s6 (`ghcr.io/unknown-org/…:latest`) was not detected at all.

## 2026-11-24 — npm registry checks run on the host, against fetch hosts only
- **Decision:** signatures, provenance, publishers, release history and install-script reading (`guardian/registry_intel.py`) run in
  Guardian's process with the existing `fetch_hosts` allow-list; tarballs are read in memory and never extracted or run.
- **Alternatives:** run in the sandbox (needs a Python image + egress bridge); use `npm audit signatures` (needs node_modules installed).
- **Why:** this is Guardian's own code parsing data, like the OSV lookups; `cryptography` (already a dependency) verifies ECDSA signatures.
  The Sigstore certificate chain of attestations is not verified (limitation).

## 2026-11-24 — Policy-as-code with Conftest/OPA in the sandbox
- **Decision:** `policies/guardian.rego` evaluated by `openpolicyagent/conftest:v0.62.0` (pinned by digest) in the sandbox; the final
  verdict is the stricter of score and policy. New dependency: the Conftest image (official Open Policy Agent project image).
- **Why:** the brief names OPA/Conftest; rules are reviewable code with IDs (GP-xxx) shown in the UI.

## 2026-11-24 — Deterministic remediation; humans approve; no build or tests
- **Decision:** `guardian/remediation.py` plans fixes, applies them to a copy inside the sandbox (npm registry-only), rescans, retries up
  to twice when a chosen version has its own advisories, and creates a local branch only after a named human approves in the UI.
- **Alternatives:** an LLM Fixer agent (later: it can wrap this module); running `npm ci && npm test` (rejected: executes analysed code,
  CLAUDE.md §3.2).
- **Why:** validation must be reproducible and honest; "build and tests: not run" is stated in every validation and PR text.

## 2026-11-24 — Safe `.npmrc` pass-through
- **Decision:** a repository's `.npmrc` is still never copied into the sandbox; only resolution-only keys (`legacy-peer-deps`,
  `min-release-age`, `engine-strict`, …) with plain values are passed as `npm_config_*` variables.
- **Why:** uptime-kuma needs `legacy-peer-deps=true`; without it every npm fix failed with ERESOLVE. Registry, git, script and auth keys stay out.

## 2026-11-24 — UI end-to-end tests with Playwright are test tooling only
- **Decision:** the dashboard was tested in the system Chromium with Playwright installed in a throw-away virtualenv; Playwright is not a
  project dependency. Results in `docs/TESTING.md` §4.

## 2026-11-24 — One flagship app per language, and a .NET reader
- **Decision:** add eight popular, containerised applications with committed lockfiles and CI to `testbed/corpus.yaml` (paperless-ngx,
  miniflux, Stirling-PDF, vaultwarden, firefly-iii, mastodon, jellyfin, netdata), each checked previous release → latest release, the way
  uptime-kuma is used for npm. Guardian now reads `Directory.Packages.props` / .NET project files itself.
- **Why:** libraries and small apps did not exercise real application layouts; jellyfin showed that centrally managed .NET apps had no
  visible packages at all (Syft reads only `packages.lock.json` / `deps.json`).

## 2026-11-24 — CLAUDE.md §4 and §5 now describe the real repository
- **Decision:** the layout and command sections were rewritten to match the code; paths in §2/§3.2 were corrected
  (`guardian/agents/llm.py`, `guardian/scoring/score.py`). The design rules in §2 (agent roles) were not changed.
- **Why:** both sections described a planned layout (`pipeline/`, `referee/`, Streamlit UI, `guardian chaos`) that was never built.

## 2026-11-24 — Finding review history follows the evidence

- **Decision:** persist reviewer actions in local SQLite. Use a stable finding key for history, a digest for the evidence being reviewed, and the exact scan revision for a submission. Compare against the latest review in the write transaction.
- **Why:** the same evidence can be reviewed once across several scans. New evidence or an expired deferral returns the finding to the queue, and earlier actions stay available in the timeline. The [human feedback guide](HUMAN_FEEDBACK.md) documents the API and the report.

## 2026-11-24 — Dashboard: input-first home page, Day 1 view removed, agents on any scan
- **Decision:** the dashboard has two pages. **Scan** (home) takes a Git URL, a ZIP or a local folder, shows the pipeline live
  and then the results (Overview, Dependency graph, Risk scores, Fix & validate). **Investigate** takes its own input (a
  finished scan, or a new source scanned first) and runs the live agents on that scan's repository and commits. The
  "Day 1 report" view and the header project picker were removed (the `/api/day1` endpoint and `guardian/day1.py` remain for
  the CLI and tests); the Overview tab now carries the verdict, headline numbers, attack signals and SBOM downloads.
  `/api/meta` no longer reports numbers from the uptime-kuma demo branches. The recorded agent run stays available only as an
  explicitly labelled "recorded example".
- **Alternatives:** keep the six tabs and add a source field to "Scan a project" (rejected: the user found the tabs confusing
  and the agent page tied to one sample app); drop the recorded run (rejected: without an LLM key it is the only full debate
  to show, so it stays, labelled).
- **Why:** user feedback (24 Nov): the home page should take the source and run everything, animations should play properly,
  and nothing should be hardcoded to uptime-kuma.

## 2026-11-24 — Local-folder sources are cloned or copied, never scanned in place
- **Decision:** `POST /api/projects/path` accepts a folder inside `GUARDIAN_PATH_ROOTS` (default: the home directory, which
  itself is refused). A Git repository is cloned with `--no-checkout --no-hardlinks --no-recurse-submodules` (the "file"
  protocol is allowed for this one clone and branch fetch only) and its branches are copied as local branches, so `base`/`head`
  can name them. Other folders are copied with the ZIP limits.
- **Alternatives:** scan the folder in place (rejected: remediation approval creates a branch in the scanned repository, and
  `check_any` must not touch the user's working tree); accept any path (rejected: the dashboard should not read arbitrary
  system folders).
- **Why:** the CLI already takes local paths; the dashboard needed the same, with the same "never modify what we analyse" rule.
