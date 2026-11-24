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

## Added 2026-11-24: Day 1 gaps and stretch goals

Found by running all nine attack scenarios (`docs/TESTING.md` §1) and built for the stretch goals. Ground truth: `tests/test_day1_gaps.py`,
`tests/test_stretch_goals.py`.

| ID | Type | Severity | Hard | Signal | Why it matters | Known false positives |
|---|---|---|---|---|---|---|
| D8 | `untrusted_image` | high (unknown registry) / medium (unknown publisher on a known registry) | no | Base image whose `registry/repository` matches no glob in `guardian.yaml` `images.trusted` | Whoever publishes the image controls what the build runs (scenario s6) | Internal images not yet on the list |
| D8 | `image_not_pinned` | high for `:latest` or no tag, else medium | no | Image referenced by tag, not `@sha256` digest | A tag can be repointed; `latest` moves on every release | Images rebuilt on purpose |
| D10 | `action_pin_removed` | high | **yes** | An action pinned to a commit SHA on base is referenced by a tag on head (same workflow) | Tag-moving attacks (tj-actions/changed-files 2025) only work against tags; scenario s7 even kept the old `# v6.0.1` comment | Deliberate move to a trusted first-party tag (still needs review) |
| D20 | `publisher_change` | medium | no | npm version published by a different account than the previous release | Account takeover publishes from a new account or token | Maintainer rotation, move to trusted publishing |
| D20 | `maintainer_change` | low | no | Maintainer list changed since the previous release | Takeovers often add a maintainer first | Normal team changes |
| D21 | `unusual_release` | medium | no | Published < 72 h ago; or after > 1 year of silence; or ≥ 5 versions within a day | Malicious releases are usually removed within days; dormant packages are takeover targets | Fast-moving projects |
| D21 | `young_package` | medium | no | Package created < 30 days ago | Most typosquats are brand new | New legitimate packages |
| D22 | `suspicious_install_behavior` | high | no | Install script (`preinstall`/`install`/`postinstall` + the JS file it runs, read from the tarball in memory) reads secrets, makes network requests, starts programs, runs obfuscated code or contacts raw IPs / data-drop services | Install-time code runs on every developer machine and CI runner | Native-binary installers (esbuild, sharp): skipped when on the policy's install-script allow-list |
| D23 | `dependency_confusion` | critical | **yes** | Name in `guardian.yaml` `internal_scopes` resolved from the public registry | A public package replaced an internal one (Birsan 2021) | none when the scope list is right |
| D24 | `signature_invalid` | critical | **yes** | npm registry ECDSA signature over `name@version:integrity` does not verify | The tarball is not what npm signed | none |
| D24 | `lockfile_integrity_mismatch` | critical | **yes** | Lockfile integrity ≠ the registry's for the same version | The lockfile points at a different tarball | none |
| D24 | `registry_version_missing` | critical | **yes** | Lockfile says registry.npmjs.org, but the registry has no such version (scenario s4: `dayjs@1.11.99`) | Forged lockfile entry, or a version npm removed (often malware) | Versions unpublished for other reasons |
| D24 | `provenance_mismatch` | critical | **yes** | SLSA provenance subject digest ≠ lockfile integrity | Provenance is for another build | none |
| D24 | `provenance_dropped` | high | no | Previous release had build provenance, this one has none | Hand-published release, e.g. with a stolen token | Project stopped using provenance |
| T0 | `tool_error` for `npm registry checks` | info, `not_checked` | no | Registry checks could not run (offline, host not in `fetch_hosts`) | Coverage gap is reported, never hidden | n/a |

Registry checks (D20–D24) cover npm packages new in the change (PR mode) or the direct dependencies (full scan, max 80). They use only hosts
in `registries.fetch_hosts`, cache for a day, and never run package code.

### Policy rules (`policies/guardian.rego`, Conftest/OPA in the sandbox)
| Rule | Effect | Fires when |
|---|---|---|
| GP-001 | deny | a known malicious package is anywhere in the application |
| GP-002 | deny | the change introduces any hard signal |
| GP-003 | deny | the change introduces a critical vulnerability in shipped (runtime) code |
| GP-004 | deny | the change introduces a base image from an untrusted registry |
| GP-005 | deny | the change introduces a component whose licence is on `policy.license_denylist` |
| GP-101 | warn | the change introduces a high-severity vulnerability |
| GP-102 | warn | the change introduces an unpinned or untrusted image or action |
| GP-103 | warn | the change weakens a dependency source (extra repository/index, insecure transport, checksum bypass, blocked egress) |
| GP-104 | warn | the change brings package behaviour or history that needs review (D20–D22, provenance dropped) |
| GP-105 | warn | a check did not run (coverage incomplete) |

### Reachability (not a detector: it changes priority)
Each vulnerability gets `imported` / `via_import` / `not_imported` / `dev_only` / `unknown` from an import-level analysis of shipped code
(`guardian/reachability.py`). Only CVE findings marked `not_imported` get a lower exposure (×0.5) and the SSVC mission "support";
malicious packages, tampering and other hard signals are never discounted.

### .NET (added 24 Nov, found on jellyfin)
`Directory.Packages.props` (`<PackageVersion Include Version>`) and `.csproj/.fsproj/.vbproj` files with an explicit `Version` become
NuGet components (OSV ecosystem NuGet). D19 `dynamic_version` for `*` and version ranges; D19 `insecure_transport` / `extra_repository`
for `nuget.config` package sources that use HTTP or are not nuget.org / Azure Artifacts.
