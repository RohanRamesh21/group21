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
