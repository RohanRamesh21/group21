# Detectors

> Status: this file documents the detectors added with the multi-ecosystem sandbox work (D15-D19, T0). The older
> detectors (D1-D14) are documented in their docstrings in `guardian/universal.py` and `guardian/inventory/ci_risk.py`,
> and in `docs/FINAL_PLAN.md` §9. Moving them here is still open.

Every finding cites a file and, where one exists, a line. None of these detectors is a hard signal: an agent may
argue them up, and the scoring floors in `docs/SCORING.md` are unchanged. All are static text checks: no build
tool, wrapper or script from the repository is run. Ground truth: `testbed/apps/expected.json`
(`tests/test_sample_apps.py`).

| ID | Type | Severity | Signal | Why it matters / incident modelled | Known false positives |
|---|---|---|---|---|---|
| D15 | `unpinned_source_fetch` | medium | CMake `FetchContent_Declare`/`ExternalProject_Add` with `GIT_TAG` that is not a 40-hex commit (or missing); meson `[wrap-git]` revision not a SHA; `vcpkg.json` with dependencies but no `builtin-baseline` (and no baseline in `vcpkg-configuration.json`) | Whoever controls the upstream branch or tag decides what gets built. Moved tags were the mechanism in the tj-actions (2025) compromise | Tags that are protected upstream; internal repositories you control |
| D15 | `unverified_download` | medium | CMake `URL` without `URL_HASH`/`URL_MD5`; meson `[wrap-file]` without `source_hash` | A swapped archive is built silently (xz-utils 2024 shipped its backdoor in release tarballs only) | Archives also verified some other way, e.g. a signature checked in a later CMake step |
| D15 | `missing_lockfile` | low | `conanfile.txt` with requires but no `conan.lock` next to it | Transitive versions and recipe revisions float | Lockfile kept elsewhere or generated in CI |
| D16 | `sandbox_egress_blocked` | high | While resolving an npm lockfile in the sandbox, something tried to reach a host outside `sandbox.npm_registry_hosts` (a dependency given as a URL or git repository, or a redirect); the proxy refused it | Dependencies fetched from arbitrary hosts bypass the registry's controls (malware takedowns, the policy allow-list) and can change at any time | Legitimate tarball or git dependencies on an internal host. Add the host to the allow-list if approved |
| D17 | `unverified_build_tool` | medium | `gradle-wrapper.properties` / `maven-wrapper.properties` `distributionUrl` without `distributionSha256Sum` | The wrapper downloads and runs a build tool on every developer machine and CI run; without a checksum a swapped distribution runs unnoticed | Wrapper JAR validated by a separate CI action |
| D18 | `module_replaced` | medium (low for a local path) | `go.mod` `replace` pointing at another module or a local folder | The code compiled is not the module and version the `require` line suggests (fork or vendored edit) | Intentional forks with an upstream fix; monorepo local replaces |
| D18 | `missing_checksums` | medium | `go.mod` with `require` but no `go.sum` beside it | Module downloads cannot be verified against recorded hashes | Modules with only standard-library imports (no require: not flagged) |
| D18 | `checksum_bypass` | high (medium for `GONOSUMDB`) | `GOSUMDB=off`, `GONOSUMCHECK=1`, `GOFLAGS=… -insecure`, `GOINSECURE=…`, `GONOSUMDB=…` in CI workflows, Dockerfiles, Makefiles, `*.mk`, `*.sh`, `.envrc` | Switches off Go's checksum database or allows plain-HTTP module downloads | `GONOSUMDB` for genuinely private modules (hence medium) |
| D19 | `insecure_transport` | high | Plain `http://` (or `git://`) for a CMake/meson/submodule source, a Maven/Gradle repository, a wrapper distribution, or a pip install line; pip `--trusted-host` | Content can be read and changed in transit | Air-gapped mirrors on trusted networks |
| D19 | `extra_repository` | medium | A Maven/Gradle repository other than Maven Central, Google or the Gradle plugin portal (e.g. jitpack, a company Nexus) | A second repository can serve a same-named artifact: dependency confusion (Birsan 2021) | Approved internal repositories. An allow-list in `guardian.yaml` is a planned follow-up |
| D19 | `dynamic_version` | medium (low for conan ranges) | Gradle `1.+`, `latest.release`, `[..)` ranges, `-SNAPSHOT`; Maven ranges, `LATEST`, `RELEASE`; conan `[>=…]` ranges | The resolved version changes between builds without any code change | Ranges pinned by a lockfile (gradle.lockfile is read by Syft; not cross-checked yet) |
| T0 | `tool_error` | info, label `not_checked` | A sandboxed tool (or a vulnerability source) did not complete | CLAUDE.md §6 "no silent failures": the report must say what was not checked. Never scored; shown in the Day 1 view | n/a |

## Changes to older detectors found by the real-app corpus (2026-11-24, `docs/TESTING.md` §3)
- **D10 `action_not_pinned` / D9 zizmor `ci_unpinned_uses`:** one finding per workflow step (D10 is kept). D10 now gives
  each repeated `uses:` its own line; it used to repeat the line of the first occurrence.
- **D13 `undeclared_dependency`:** only imports the code cannot run without count. Not counted: imports in
  `try/except ImportError` (including the fallback branch), later imports of the same module in that file,
  `if TYPE_CHECKING:` imports, `setuptools`/`pkg_resources`/`distutils`/`pip`/`wheel`, and code under
  `examples/`, `docs/`, `benchmarks/`. Requirement strings anywhere in pyproject/setup files count as declared.
- **Exposure:** components declared in manifests under `docs/`, `tests/`, `examples/`, `benchmarks/` or `tools/`
  are dev-only.

Components found by the same readers: vcpkg dependencies, conan requires, CMake fetches, meson wraps, git
submodules and Gradle dependencies. Each records its file and line, and has a version only when it is exactly
pinned. Unpinned components are written to the SBOM without a version, so scanners cannot match a range like `31.+`
as if it were a release. The declared range stays in the `guardian:declared` property.
