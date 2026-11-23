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
- The real-app corpus (`testbed/corpus.yaml`, 12 apps) is scanned at pinned commits. Its results in `docs/TESTING.md` were
  reviewed by hand for false positives; they are not a measured recall/precision figure.
- `testbed/apps/` are **synthetic** projects (simulated risks, `example.com` hosts). Detection rates on them say the
  rules fire as designed. They do not measure performance on real-world projects.
- The npm attack scenarios (`sandbox/uptime-kuma`, branches `scenario/*`) are **simulated** in a local fork.
