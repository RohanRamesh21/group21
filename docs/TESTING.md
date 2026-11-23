# Testing

## 1. Test layers

| Layer | What it proves | Where |
|---|---|---|
| Unit and regression tests (offline) | Parsers, detectors, labels, scoring, the agent constitution, the sandbox command line and egress proxy | `tests/` (`.venv/bin/python -m pytest -q`) |
| Sandbox integration | Real containers: no network, no host secrets, read-only inputs, non-root, time and memory limits; a repository `.npmrc` cannot run code | `tests/test_sandbox.py` (skipped without podman) |
| npm graph ground truth | Guardian's dependency edges equal `npm ls --all` exactly | `tests/test_graph_vs_npm.py` (needs `sandbox/uptime-kuma`) |
| Synthetic sample apps (simulated) | Each planted risk is found in JS, Python, Go, Java and C/C++; clean controls give 0 findings | `testbed/apps/`, `tests/test_sample_apps.py` |
| **Real apps (corpus)** | Guardian works end to end on real projects in 7 ecosystems, and its false positives are found and fixed | `testbed/corpus.yaml`, `testbed/corpus.py` |
| Attack scenarios (simulated) | Introduced / pre-existing / fixed labels and the verdict on a real app with injected attacks | `sandbox/uptime-kuma` branches `scenario/*` |

Latest full run (2026-11-24, this machine): **64 passed, 4 skipped.** The 4 skipped tests need `scenario/s3-s9` or
Verdaccio, which this checkout does not have.

## 2. Real-app corpus

Twelve public open-source projects, each pinned to a full commit SHA. They are fetched read-only as bare
repositories and scanned through the sandbox. None is built, installed or run. Fetching them is allowed by the
test-corpus exception in CLAUDE.md §3.1.

```bash
.venv/bin/python testbed/corpus.py fetch     # once: bare, depth-1 fetch of each pinned commit, verified against the pin
.venv/bin/python testbed/corpus.py scan      # writes guardian-out/corpus/summary.json and one report per app
```

### Results (2026-11-24, Guardian working tree of that day, Grype DB built 2026-11-23T06:28:32Z)

All counts come from `guardian-out/corpus/summary.json` for the commits listed. Each app is a full scan of one commit,
so nothing is "introduced" and the verdict is `allow`, except gin, which is compared against its previous release.
"Findings" means detector and CI/image findings, not advisories. "Before → after" is the first corpus run versus the
run after the fixes in §3.

| App | Pinned commit | Components (ecosystems) | Advisories crit/high/med/low | Findings before → after fixes | Verdict | Time |
|---|---|---|---|---|---|---|
| express | `v5.1.0` `cd7d4397c398` | 407 (npm 390, github 17) | 3/5/9/3 | 7 → 5 | allow | 36.8 s |
| axios | `v1.7.9` `b2cb45d5a533` | 2146 (npm 2118, github 28) | 50/133/90/22 | 92 → 61 | allow | 10.6 s |
| flask | `3.1.0` `ab8149664182` | 36 (github 14, pypi 21, npm 1) | 1/5/12/0 | 23 → 14 | allow | 2.3 s |
| requests | `v2.32.3` `0e322af87745` | 14 (github 12, pypi 2) | 0/0/0/0 | 17 → 6 | allow | 2.2 s |
| cobra | `v1.8.1` `e94f6d0dd9a5` | 11 (github 7, golang 4) | 0/0/0/0 | 27 → 16 | allow | 2.1 s |
| gin | `v1.10.0` `75ccf94d605a` (base v1.9.1) | 40 (github 11, golang 29) | 9/17/19/0 | 68 → 42 | review | 4.4 s |
| gson | `gson-parent-2.11.0` `828a97be0f8d` | 32 (github 15, maven 17) | 0/7/7/0 | 14 → 11 | allow | 2.3 s |
| spring-petclinic | `main (2026-11-24)` `500158f73241` | 37 (github 7, maven 30) | 0/0/0/0 | 25 → 18 | allow | 2.3 s |
| spdlog | `v1.15.0` `8e5613379f51` | 5 (github 3, cmake 2) | 0/0/0/0 | 17 → 12 | allow | 2.0 s |
| cpr | `1.11.1` `dec9422db3af` | 20 (github 16, cmake 4) | 0/0/0/0 | 133 → 90 | allow | 2.3 s |
| nlohmann-json | `v3.11.3` `9cca280a4d0c` | 76 (github 22, pypi 51, cmake 3) | 8/88/55/6 | 139 → 89 | allow | 3.1 s |
| ripgrep | `14.1.1` `4649aa970061` | 55 (github 4, cargo 51) | 0/0/4/0 | 41 → 28 | allow | 2.2 s |

- **Totals:** 2,879 components. 603 → 392 findings (−35%), all removed findings being duplicates or false
  positives, see §3. 0 tools failed. Every tool ran isolated, and the egress proxy refused nothing.
- **express** has no lockfile. Its lockfile was resolved in the sandbox, reaching only `registry.npmjs.org`.
- **gin v1.9.1 → v1.10.0**, a real release diff: 45 advisories introduced and 51 fixed. All are Go `golang.org/x/*`
  modules, updated to versions that are newer but still affected. 3 new dependencies were found
  (`bytedance/sonic/loader`, `cloudwego/base64x`, `cloudwego/iasm`), and 3 changed workflows (sensitive paths).
  The verdict is `review`.
- **What the advisories look like:**
  - axios: the criticals are almost all dev tooling. 1 is runtime (`form-data@4.0.0`), and OSV and Grype agree on it.
  - nlohmann-json: every advisory is in `docs/mkdocs/requirements.txt`, so all are scored dev-only (low).
  - express: `handlebars@4.7.7`, pinned exactly by the dev dependency `hbs`; both scanners agree.

## 3. Problems the corpus found (and fixed)

Each fix has an offline regression test that copies the real pattern (`tests/test_corpus_regressions.py`).

| Found on | Problem | Fix |
|---|---|---|
| every app with workflows | Each unpinned action was reported twice: by D10 and by zizmor `unpinned-uses` (cobra 11 + 11) | One finding per step (D10 kept, since it knows first-party owners). zizmor points at the step start and D10 at the `uses:` line, so they are paired by file + action reference |
| every app with repeated actions | **D10 line numbers were wrong.** Every repeat of the same `uses:` (e.g. `actions/checkout@v4` in each job) got the line of its first occurrence | n-th occurrence → n-th line |
| requests, flask | 19 "undeclared dependency" false positives: optional imports (`try … except ImportError`, including the fallback branch), flag-guarded imports (`if has_simplejson:`), `if TYPE_CHECKING:` imports, `[project.optional-dependencies]`, `setuptools` in `setup.py`, and docs/examples code | Imports are only counted when the code cannot run without them; requirement strings are read anywhere in pyproject/setup files; examples, docs and benchmarks are skipped (19 → 0) |
| flask | `requirements/docs.txt` and other files in a `requirements/` folder were not recognised | Recognised as pip requirements |
| nlohmann-json | 157 advisories in docs tooling (`docs/mkdocs/requirements.txt`) were scored as shipped runtime code | Manifests under `docs/`, `tests/`, `examples/`, `benchmarks/` and `tools/` are dev-only |
| gson | `<distributionManagement>` (where releases are *published*) was flagged as an extra dependency repository | Only `<repositories>` / `<pluginRepositories>` are checked |
| cpr | CMake downloads verified by `URL_HASH` were counted as unpinned | Hash-verified archives are pinned; the version is read from the URL |
| nlohmann-json | `GIT_REPOSITORY ${VARIABLE}` (a local test fixture) was rated medium | Rated low and labelled "not resolved statically" |
| java-gradle sample app | Floating versions (`31.+`) produced Grype advisories for versions that do not exist | Unpinned components carry no version in the SBOM; Grype matches without a version are dropped |

### Known remaining false positives / gaps (see `docs/KNOWN_LIMITATIONS.md`)
- nlohmann-json: `tools/gdb_pretty_printer` imports `gdb`, which exists only inside GDB. It is reported as undeclared (low).
- spring-petclinic: versions come from the Spring Boot parent BOM, so 26 Maven components have no version and get no
  advisories.
- gson: Maven sub-modules that are not shipped (`metrics`, `proto`) count as runtime, because Maven scopes and
  module packaging are not read.
- spdlog: its bundled `fmt` copy (`include/spdlog/fmt/bundled`) is not detected as a component.

## Guardian self-protection

Run `.venv/bin/python -m pytest -q tests/test_guardian_boundary.py tests/test_agent_loop.py tests/test_constitution.py`.
The boundary tests use inert strings, fake model turns, local Git and mocked HTTP. They assert the peer and tool
channels cannot override mandatory checks and that untrusted model input is bounded and kept away from privileged
actions. See [the defense design](GUARDIAN_SELF_PROTECTION.md).
