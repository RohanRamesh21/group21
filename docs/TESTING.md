# Testing

## 1. Test layers

| Layer | What it proves | Where |
|---|---|---|
| Unit and regression tests (offline) | Parsers, detectors, labels, scoring, the agent constitution, the sandbox command line and egress proxy | `tests/` (`.venv/bin/python -m pytest -q`) |
| Sandbox integration | Real containers: no network, no host secrets, read-only inputs, non-root, time and memory limits; a repository `.npmrc` cannot run code | `tests/test_sandbox.py` (skipped without podman) |
| npm graph ground truth | Guardian's dependency edges equal `npm ls --all` exactly | `tests/test_graph_vs_npm.py` (needs `sandbox/uptime-kuma`) |
| Synthetic sample apps (simulated) | Each planted risk is found in JS, Python, Go, Java and C/C++; clean controls give 0 findings | `testbed/apps/`, `tests/test_sample_apps.py` |
| **Real apps (corpus)** | Guardian works end to end on 20 real projects (12 small apps/libraries + 8 flagship apps, one per language), and its false positives are found and fixed | `testbed/corpus.yaml`, `testbed/corpus.py` (§2, §6) |
| **Dashboard end to end** | Every view works in a real browser for the CLI report, ZIP uploads, Git URLs and local folders; source intake and agent runs on any scan | Playwright run (§5); `tests/test_dashboard_sources.py`; manual guide (§7) |
| Attack scenarios (simulated) | Introduced / pre-existing / fixed labels and the verdict on a real app with injected attacks | `sandbox/uptime-kuma` branches `scenario/*` |

Latest full run (2026-11-24 late morning, this machine): **110 passed, 4 skipped.** The 4 skipped tests need `scenario/s3-s9` or
Verdaccio, which this checkout does not have. Newest: `tests/test_dashboard_sources.py` (local-folder intake: path rules,
safe copy, a local Git repository cloned with its branches and left untouched; pipeline stages; `/api/meta` names no sample app;
live runs need a key and a scan with a repository, and investigate that scan's commits; agents on a repository without a lockfile). New since the morning: `tests/test_day1_gaps.py` (Day 1 gaps found by the
attack scenarios) and `tests/test_stretch_goals.py` (provenance, package risk, reachability, policy-as-code in the sandbox,
remediation validate + approve in the sandbox, monitoring).

## 2. Real-app corpus

Twelve public open-source projects (the first corpus; the eight flagship apps are in §6), each pinned to a full commit SHA. They are fetched read-only as bare
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

## Finding reviews

Run `.venv/bin/python -m pytest -q tests/test_finding_reviews.py` for the saved-report and API regressions. The [human feedback guide](HUMAN_FEEDBACK.md) has a dashboard walkthrough for carrying a review across scans and reopening it after an evidence change.


## 4. Attack scenarios: Day 1 checkpoint (24 Nov)

`guardian check sandbox/uptime-kuma --base 5aa5dec4 --head scenario/<x>` (2.5.12 → each branch). "Before" is the committed `sandbox`
branch at `610dde5` (24 Nov morning); "after" is the working tree with the Day 1 fixes and stretch goals.

| Scenario | Injected | Before | After | What changed |
|---|---|---|---|---|
| control | safe bump | allow, 0 alerts | allow, 0 alerts | - |
| s1 | direct dep downgraded to axios 0.21.1 | allow | **review** | introduced high severity needs a human; reachability: axios imported at `server/check-version.js:2` |
| s2 | transitive override to qs 6.5.2 | allow | **review** | same rule; path traced through express > body-parser |
| s3 | typosquat `axois` from `10.0.0.5:4873` + install script + malware | block | block | policy GP-001/002/003 also deny |
| s4 | dayjs update adds an install script | review | **block** | `dayjs@1.11.99` does not exist on registry.npmjs.org (`registry_version_missing`) |
| s5 | integrity / host changed | block | block | - |
| s6 | base image → `ghcr.io/unknown-org/…:latest` | allow, **not detected** | **review** | lowercase `docker/dockerfile` is discovered; `untrusted_image` + `:latest` |
| s7 | action SHA → tag (comment still `v6.0.1`) | allow | **review** | hard signal `action_pin_removed` |
| s8 | AI issue-triage workflow | allow | **review** | introduced high-severity template injection + unpinned third-party action |
| s9 | `.npmrc` registry redirect in a "fix typo" commit | (not run) | block | source change (hard signal) + policy GP-002 |

Remediation on the same reports (validated in the sandbox, rescan before vs after):
- s3: remove `axois` → verdict block → allow, 3 findings fixed, 0 new problems; diff only `package.json` + `package-lock.json`.
- Reachability on the s3 report: 67 advisories on packages imported by shipped code, 11 via an imported dependency, 3 not imported
  (all on `axois`, which nothing imports), 40 dev-only. A review of the screenshots found a false "not imported" on jsonata:
  uptime-kuma loads it with `require.resolve("jsonata")` into a vm sandbox (`server/jsonata-sandbox.js:19`); `require.resolve` and
  `import.meta.resolve` are now recognised (regression test in `tests/test_stretch_goals.py`).
- s1: upgrade axios 0.21.1 → 0.33.0 fixed all 24 advisories, but the rescan found 2 advisories **in 0.33.0 itself**; the retry moved to
  0.34.0 → 24 fixed, 0 new problems, verdict review → allow. (Before the `.npmrc` pass-through fix, every npm fix failed with
  ERESOLVE because uptime-kuma needs `legacy-peer-deps=true`.)

## 5. Dashboard end to end in a real browser (24 Nov)

**Redesigned UI (24 Nov, late morning).** Playwright + system Chromium against the Vite dev server and the production build
served by `uvicorn`: home → Local path `testbed/apps/js-web` → live pipeline (8 stages; screenshots every 0.45 s show the
rail filling, the active stage spinning, done stages checked, "Compare: not needed" for a full scan) → Overview → Dependency
graph (nodes revealed column by column after the first fit) → Risk scores → Fix & validate → Investigate with agents.
Also: Local path `sandbox/uptime-kuma` as a Git repository with base `5aa5dec4` and head `scenario/s3` (block, 1,368 components,
lockfile tamper + new install script + typosquat introduced: same result as `guardian check`), a ZIP through the file picker,
a refused Git URL (inline error), the Investigate picker, a live run (shows the provider error and the deterministic checks),
the recorded example (labelled) and the home page at 390 px (no horizontal scroll). Production build: **0 console errors.**
Bugs found and fixed on the way: the graph never appeared because `useNodesInitialized` does not update for a controlled
graph in @xyflow/react 13 (now driven by node "dimensions" changes); the stage rail showed through the circles; recent-scan
cards overflowed on phones; the local-repo branch fetch was blocked by the clone's own `protocol.file.allow=never`.

The table below is the earlier run on the previous UI (Day 1 report tab, since removed).

Playwright (test tooling in a throw-away virtualenv) driving the system Chromium against `uvicorn guardian.server:app`. Every view of every
project is opened: Day 1 report (5 steps), Risk scores (policy panel, monitoring "Re-check now" must record a new entry), Dependency
graph, Fix & validate. Browser console errors and HTTP 5xx responses are collected; the run fails on any.

Final run (24 Nov, final code, fresh project list): **0 console errors, 0 HTTP 5xx, every view rendered for every project.**

| Input | Kind | Verdict | Policy rules fired | Fix plan (automatic) | Extra steps exercised |
|---|---|---|---|---|---|
| uptime-kuma 2.5.12 → scenario/s3 | main report | block | GP-001, GP-002 | 28 (27) | validate "remove axois": block → allow, 3 fixed, 0 new |
| axios v1.7.9 | ZIP (npm, lockfile) | allow | - | 78 (69) | |
| cobra v1.8.1 | ZIP (Go) | allow | - | 0 | |
| gson 2.11.0 | ZIP (Maven) | allow | - | 3 (0, manual) | |
| nlohmann/json v3.11.3 | ZIP (C++ + docs Python) | allow | - | 15 (15, pip pins) | |
| requests v2.32.3 | ZIP (Python) | allow | - | 0 | |
| ripgrep 14.1.1 | ZIP (Rust) | allow | - | 4 (0, manual cargo) | |
| testbed sample-cpp-native | ZIP (CMake, vcpkg, conan, meson) | allow | - | 0 | |
| testbed sample-java-gradle | ZIP (Gradle) | allow | - | 1 (0, manual) | |
| testbed sample-js-web | ZIP (npm + CDN) | **block** | GP-001 (`lodahs` is real malware, MAL-2025-25502) | 3 (1) | validate "remove lodahs": block → allow, 2 fixed, 0 new |
| testbed sample-python-api | ZIP (pip) | allow | - | 2 (2) | validate pin flask 2.0.0 → 2.2.5 + **approve**: local branch `guardian/fix-…` |
| evil-traversal.zip | hostile ZIP | rejected | | | "unsafe path in archive: ../../escape.txt" |
| not-a-zip.zip | not a ZIP | rejected | | | "BadZipFile" |
| github.com/gin-gonic/gin v1.9.1 → v1.10.0 | Git, PR compare | **block** | GP-003 (critical x/crypto advisory introduced) | 5 (0, manual go) | score says review, policy says block |
| github.com/pallets/flask 3.1.0 | Git | allow | - | 5 (3) | |
| github.com/libcpr/cpr 1.11.1 | Git (C++) | allow | - | 0 | |
| github.com/spring-projects/spring-petclinic `500158f` | Git (Java) | allow | - | 0 | |
| github.com/expressjs/express v5.1.0 | Git (npm, **no lockfile**: resolved in the sandbox) | allow | - | 6 (5) | |

Bugs this browser testing found and fixed: an error banner for the agent replay shown on every tab; React Flow drawing NaN-sized SVG
in a hidden tab; the Day 1 header and Risk scores banner showing the score verdict instead of the final (score + policy) verdict; the
monitor ignoring policy (block → "allow"); a malicious package that was already present had no removal fix; reasons not led by the side
that decided the verdict; a false "not imported" for jsonata (`require.resolve`).

## 6. Flagship apps per language (24 Nov)

Used the way uptime-kuma is used for npm: a popular, containerised application with a committed lockfile and CI, checked as a pull
request from its previous release to its latest release (`testbed/corpus.yaml`, pinned by commit; `testbed/corpus.py scan <name>`).
Advisories are for the latest release; "+ / −" are advisories the release introduced / fixed.

| App | Language | Release diff | Components | Advisories crit/high/med/low | + / − | Verdict | Top reason |
|---|---|---|---|---|---|---|---|
| paperless-ngx | Python (Django) + Angular | v3.5.0 → v3.5.1 | 1,196 (npm 851, PyPI 272, Actions 73) | 1/23/28/3 | +0 / −0 | allow | nothing high or critical introduced |
| miniflux | Go | v2.3.4 → v2.3.5 | 62 (Go 34, Actions 28) | 0/0/1/0 | +0 / −6 | allow | nothing high or critical introduced |
| Stirling-PDF | Java (Gradle) + TS + Rust + Python | v3.4.0 → v3.5.0 | 2,616 (npm 1,528, Cargo 702, Actions 247, PyPI 103, Maven 36) | 9/31/60/3 | +0 / −1 | review | GP-103: a new extra Maven repository (`maven.stirlingpdf.com`) |
| vaultwarden | Rust | 1.37.4 → 1.37.5 | 902 (Cargo 654, npm 226, Actions 22) | 1/26/68/13 | +1 / −31 | review | GP-102: base image `rust:1.99.1-slim-trixie` by tag |
| firefly-iii | PHP (Laravel) | v6.7.8 → v6.7.9 | 448 (npm 264, Composer 170, Actions 14) | 0/1/1/3 | +0 / −0 | allow | nothing high or critical introduced |
| mastodon | Ruby on Rails + JS | v4.7.5 → v4.7.6 | 1,769 (npm 1,381, RubyGems 344, Actions 44) | 5/33/35/7 | +0 / −23 | review | GP-102: base image `ruby:4.0.10-slim-trixie` by tag |
| jellyfin | C# (.NET) | v12.3 → v12.4 | 122 (NuGet 82, Actions 40) | 0/0/0/0 | +0 / −0 | allow | nothing high or critical introduced |
| netdata | C/C++ (+ Go, Rust, Python) | v2.12.3 → v2.13.0 | 1,220 (Cargo 684, Go 234, Actions 125, npm 111, PyPI 45, CMake 18, …) | 0/3/14/0 | +3 / −69 | review | `web-features@3.40.1` published without the build provenance its previous release had |

All tools ran in the sandbox; nothing failed and the egress proxy refused nothing. Problems these apps found (fixed, with offline
regression tests in `tests/test_corpus_regressions.py`):

| Found on | Problem | Fix |
|---|---|---|
| jellyfin | **0 NuGet packages**: .NET apps with central package management (`Directory.Packages.props`, versionless `<PackageReference>`) were invisible; Syft only reads `packages.lock.json`/`deps.json` | Guardian reads `Directory.Packages.props` and project files (82 packages), flags floating versions and extra/HTTP feeds in `nuget.config` |
| Stirling-PDF | 101 "undeclared" npm packages were TypeScript `paths` aliases (`@editor-core/*`) | aliases from `tsconfig*/jsconfig*` are local code (101 → 17) |
| Stirling-PDF | 10 more came from a validator function named `require` (`require("adminUsername")`) | a file that defines its own `require` is not treated as importing modules (17 → 7; the 7 left are real undeclared imports in helper scripts) |
| miniflux | 65 "CDN script without SRI" findings were HTML test fixtures (`internal/reader/sanitizer/testdata`) | test data, fixtures and spec folders are not shipped code (65 → 0) |
| netdata | "9 versions of @playwright/test within a day" were nightly pre-releases | release bursts count stable versions only (24 → 18 release-timing flags) |

The same eight apps were also scanned through the dashboard (Scan a project → Git URL with base = previous release, head = latest)
in Chromium: every view opened (Day 1, Risk scores incl. policy and monitoring re-check, Dependency graph, Fix & validate),
**0 console errors, 0 HTTP 5xx**, verdicts identical to the CLI runs above (allow: paperless-ngx, miniflux, firefly-iii, jellyfin;
review: Stirling-PDF, vaultwarden, mastodon, netdata).


## 7. How to test the flagship apps in the dashboard (manual guide)

**Once per machine:** podman installed; `.venv/bin/guardian sandbox setup` (pulls the 6 pinned tool images and the Grype DB);
`.venv/bin/guardian sandbox status` must exit 0. Network access is needed (GitHub clone, OSV.dev, npm registry).

1. Build the UI if `guardian/dashboard/dist` is missing or the UI changed: `cd guardian/dashboard && npm ci && npx vite build`.
2. Start the server: `.venv/bin/uvicorn guardian.server:app --port 8765` and open http://localhost:8765.
3. On the home page (**Scan**) choose **Git URL**, paste the URL, open **Compare two versions** and enter base and head from the
   table, press **Run scan**. (Or **Local path** for a folder on this machine, or **ZIP upload**.)
4. The live pipeline opens: eight stages fill from left to right with the scanner log underneath (15 s – 4 min; Stirling-PDF and
   netdata are the slowest). A failed scan stops on a red stage with the reason.
5. When it finishes, the results open (every scan has its own link, and is listed under **Recent scans** on the home page). Check
   each view:
   - **Overview**: the verdict card and its reasons must match the table; attack signals introduced; vulnerabilities by severity
     (new vs already present); what changed; SBOM downloads; top risks.
   - **Risk scores**: Policy-as-code panel (which GP rules fired), verdict box and reasons, a score card; press **Re-check now** in
     Continuous monitoring and confirm a new entry appears.
   - **Dependency graph**: Risk paths, This PR, click a package for its path, source and advisories.
   - **Investigate with agents** (button in the header card): runs the live agents on this scan (needs a working LLM key; without one
     the required checks still run and the reason is shown). "Play the recorded example run" is a labelled replay of a fixed scenario.
   - **Fix & validate**: the plan (automatic vs manual fixes). Optional: tick an automatic fix → **Validate selected** → wait for the
     card (fixed / new problems / verdict before → after). **Approve** creates a local branch only in that project's copy
     (`guardian-out/projects/<id>/src`); nothing is pushed.

| App (language) | Git URL | Base | Head | Expected verdict | Expected top reason |
|---|---|---|---|---|---|
| paperless-ngx (Python) | https://github.com/paperless-ngx/paperless-ngx | v3.5.0 | v3.5.1 | allow | nothing high or critical introduced |
| miniflux (Go) | https://github.com/miniflux/v2 | v2.3.4 | v2.3.5 | allow | release fixed 6 advisories |
| Stirling-PDF (Java) | https://github.com/Stirling-Tools/Stirling-PDF | v3.4.0 | v3.5.0 | review | GP-103: new extra Maven repository |
| vaultwarden (Rust) | https://github.com/dani-garcia/vaultwarden | 1.37.4 | 1.37.5 | review | GP-102: base image by tag |
| firefly-iii (PHP) | https://github.com/firefly-iii/firefly-iii | v6.7.8 | v6.7.9 | allow | nothing high or critical introduced |
| mastodon (Ruby) | https://github.com/mastodon/mastodon | v4.7.5 | v4.7.6 | review | GP-102: base image by tag |
| jellyfin (.NET) | https://github.com/jellyfin/jellyfin | v12.3 | v12.4 | allow | 82 NuGet packages, nothing introduced |
| netdata (C/C++) | https://github.com/netdata/netdata | v2.12.3 | v2.13.0 | review | web-features published without its usual provenance |

Advisory counts can grow over time (new advisories get published); verdicts only change if a release-introduced advisory appears.

**As ZIP uploads instead** (no GitHub access from the dashboard): `.venv/bin/python testbed/corpus.py fetch <name>` then
`git -C sandbox/corpus/<name>.git archive --format=zip --prefix=<name>/ -o /tmp/<name>.zip <head commit from testbed/corpus.yaml>`
and drop it on **ZIP upload** on the home page. A ZIP is one snapshot, so it is a full scan (no base/head, no "introduced").

**Reset:** stop the server, delete `guardian-out/projects/`, start again.
