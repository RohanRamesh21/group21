# Known limitations

An honest list of what does not work, or is simulated. Update it whenever a limitation is found or removed.

## Sandbox
- **Needs podman.** Without it, sandboxed steps are skipped and reported as `tool_error` (not checked). They are not run
  unsafely. `GUARDIAN_SANDBOX=host` runs them without isolation (developers only; reported in every scan).
- **Containers are not VMs.** Rootless podman isolates with Linux namespaces, seccomp and cgroups; a kernel exploit could
  escape. Mitigated by least privilege (non-root, no capabilities, no network, read-only), not eliminated.
- **The egress allow-list is by host name.** HTTPS is not inspected, so an allow-listed registry is trusted for whatever
  it serves. Only npm resolution has egress at all.
- **git runs on the host.** It only reads objects (`archive`, `show`, `diff`, hooks disabled, our own config). A git
  parser bug is outside the sandbox.

## Ecosystem coverage
- **Transitive dependencies are visible only through lockfiles** for Python, Go, Java and C/C++. Guardian does not
  resolve these ecosystems (resolving runs build code; see `docs/DECISIONS.md`). Without `poetry.lock`/`uv.lock`/
  `go.sum`/`gradle.lockfile`/`conan.lock`, only declared direct dependencies are listed.
- **C/C++ build files are read with patterns,** not evaluated: CMake variables (`${VERSION}`), `conanfile.py` and
  nested `include()`s are not followed. vcpkg and CMake-fetched sources are not in OSV, so they get no CVE matches.
- **`build.gradle` parsing covers the common string notation** (`'group:name:version'`), not version catalogs
  (`libs.versions.toml`), `platform()` BOMs or map notation.
- **D19 `extra_repository` has no allow-list yet:** an approved company Nexus is reported like any other extra
  repository.
- **Dependency graphs are flat** for components found by Guardian's build-file readers (all direct).
- **Maven:** versions inherited from a parent BOM (e.g. Spring Boot) are not resolved, so those components have no version
  and get no advisories (spring-petclinic: 26 of 30 Maven components). Scopes and module packaging are not read either, so
  test or benchmark modules count as runtime (gson `metrics`, `proto`).
- **Vendored C/C++ code is not recognised** (e.g. spdlog's bundled `fmt`). Vendored *JavaScript* is.
- **Undeclared-import check (D13):** modules that exist only inside a host program (`gdb` in GDB's Python) are reported.
  Imports are judged per file, and examples, docs and benchmarks are skipped.

## Test data
- The real-app corpus (`testbed/corpus.yaml`, 20 apps) is scanned at pinned commits. Its results in `docs/TESTING.md` were
  reviewed by hand for false positives; they are not a measured recall/precision figure.
- `testbed/apps/` are **synthetic** projects (simulated risks, `example.com` hosts). Detection rates on them say the
  rules fire as designed. They do not measure performance on real-world projects.
- The npm attack scenarios (`sandbox/uptime-kuma`, branches `scenario/*`) are **simulated** in a local fork.

## Agent investigation security

The live investigation has mandatory npm checks. Changed workflows and Dockerfiles prevent a safe recommendation
until their deterministic checks are integrated. The local reviewer token is a run-scoped capability. Shared
deployment requires reviewer authentication and per-project authorization. Marker detection and secret redaction
are heuristic. See [Guardian self-protection](GUARDIAN_SELF_PROTECTION.md) for the remaining integration limits.

## Dashboard sources and investigations (24 Nov 2026)
- **Agents read only the root `package-lock.json`.** On any scan the agents' package tools (registry, OSV, install hooks,
  typosquat) see npm packages from the repository root lockfile only. Other ecosystems, nested npm projects and lockfiles that
  the scan resolved in the sandbox are not visible to them; they still examine commits, changed files and sensitive paths, and
  the run says so. The scan results cover every ecosystem.
- **Single-commit investigations review the saved scan.** Agents can read deterministic findings across ecosystems. The
  commit-comparison tools have no changed files in this mode.
- **Local Git repositories: committed code only.** Uncommitted changes in a local repository are not scanned (the clone has no
  working tree). Copy the folder without `.git`, or commit, to include them.
- **Live agents need a working LLM key** for the provider named in `.env`. FreeModel uses `FM_API_KEY`. Provider and model
  failures are surfaced in the run, and the deterministic checks still run. The recorded example replays a fixed scenario.
- **Local-folder scans run as the dashboard's user.** Anyone who can reach the dashboard can scan folders inside
  `GUARDIAN_PATH_ROOTS`. The server binds to 127.0.0.1 by default; a shared deployment needs authentication first.

## Stretch goals (24 Nov 2026)
- **Reachability is import-level.** "Imported" means shipped code imports the package, not that the vulnerable function is called. Go is
  package-precise (OSV lists vulnerable packages); npm/PyPI are package-level; other ecosystems are `unknown`. Packages loaded by name at
  runtime (plugins, CLIs) can show as `not_imported`; they are only de-prioritised, never hidden.
- **Provenance:** npm registry signatures are verified cryptographically; SLSA attestations are checked for presence, source repo and
  digest match, but their Sigstore certificate chain is **not** verified. Containers are not cosign-verified. Registry checks cover npm only.
- **Package history checks** are heuristics with real false positives (publisher change on maintainer rotation, new releases of busy projects).
  They are medium/low and only warn.
- **Remediation** applies fixes automatically for npm (upgrade / override / remove / revert) and pip `==` pins; Go, Maven, Gradle, Cargo and
  others get a manual command (running their tooling would execute build code). **Build and tests are not run** during validation; the
  rescan proves the risk is gone and nothing new was introduced, not that the app still works.
- **Monitoring** re-queries OSV and KEV/EPSS for the saved inventory; it does not notice a changed repository (rescan for that). Automatic
  runs need `guardian watch --interval` or `GUARDIAN_MONITOR_INTERVAL` on the server; there are no e-mail or chat alerts.
- **Policy-as-code** ships sample rules; organisations must tune `policies/*.rego` and the lists in `guardian.yaml`.
- **Action tags that moved** (same tag, new commit) are not detected; only SHA→tag changes are (needs GitHub API access).

## Flagship apps (24 Nov 2026)
- **Trusted-image list is a sample.** Real apps use many legitimate third-party images (paperless-ngx: 29 `untrusted_image` findings
  for gotenberg, tika, redis forks …). They are medium and pre-existing; extend `images.trusted` per organisation.
- **.NET:** versions come from `Directory.Packages.props` / project files; transitive NuGet packages are only visible with a committed
  `packages.lock.json`. Test-only projects are not yet told apart from runtime ones.
- **Undeclared-import check (D13)** still reports imports in helper scripts and tests that a project installs by hand (7 on Stirling-PDF).

## Finding reviews

Reviewer names are self-reported on the local dashboard. Review status is evaluated against the saved scan and UTC due date when loaded. Advisory and exploitation changes from monitoring need a fresh scan to appear in Risk scores. [Human feedback guide](HUMAN_FEEDBACK.md)
