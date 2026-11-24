# Sample apps

Which applications Guardian is demonstrated and tested on, pinned to exact commits, with facts **recomputed from those commits**
(CLAUDE.md §1). All are open source and analysed read-only: never built, installed or run.

## Main sample app: Uptime Kuma (npm)

| | |
|---|---|
| Repository | `louislam/uptime-kuma` (MIT), local fork at `sandbox/uptime-kuma` |
| Pinned release | **2.5.12**, commit `5aa5dec425f8a955b54e150636979a6927745ec5` |
| Why | real, popular self-hosted app with all three surfaces (npm, CI workflows, Docker), committed lockfile, real baseline findings |

Facts recomputed on 2026-11-24 with `guardian check … --base 5aa5dec4 --head scenario/s3` (base snapshot = 2.5.12,
`guardian-out/check/snap-5aa5dec425f8/`):

| Fact | 2.5.12 |
|---|---|
| Components | 1,367 (npm 1,310 + GitHub Actions 57); 1,227 unique name@version |
| Direct / runtime / install scripts | 216 / 689 / 16 |
| CI and images | 21 workflows, 79 actions (all SHA-pinned), 16 base images (none digest-pinned) |
| Vulnerabilities | 118 advisories on 29 packages (critical 4, high 43, medium 61, low 10), all 118 confirmed by both OSV.dev and Grype |
| Example versions | axios 0.32.0, express 4.22.3, socket.io 4.8.4, jsonata 2.2.0 |

### Attack scenarios (local branches, never pushed; all branch from 2.5.12)
| Branch | Commit message | Injected (simulated) | Guardian verdict |
|---|---|---|---|
| `scenario/control` | safe bump | nothing risky | allow, 0 alerts |
| `scenario/s1` | chore(deps): pin axios to 0.21.1 for compatibility | direct dependency downgraded to a vulnerable version | review |
| `scenario/s2` | build: add overrides for body-parser | transitive dependency forced to vulnerable qs 6.5.2 | review |
| `scenario/s3` | feat: add HTTP helper | look-alike `axois` from `10.0.0.5:4873`, install script, known malware ID | block |
| `scenario/s4` | chore(deps): update dayjs | dayjs "update" to a version that does not exist on npm, with an install script | block |
| `scenario/s5` | chore: refresh lockfile | same version, changed integrity and download host | block |
| `scenario/s6` | build: use faster base image | base image `ghcr.io/unknown-org/…:latest` | review |
| `scenario/s7` | ci: simplify checkout | `actions/checkout` SHA → tag (comment still says v6.0.1) | review |
| `scenario/s8` | ci: add AI issue triage | workflow feeding issue text to an unpinned third-party AI action | review |
| `scenario/s9` | fix typo | `.npmrc` redirects the npm registry | block |

The agent Investigation tab still expects older branches `scenario/base` and `scenario/s3-s9` (see HANDOFF).

## Flagship apps per language

Used like Uptime Kuma: a popular, containerised application with committed lockfiles and CI, checked **previous release → latest
release** (`testbed/corpus.yaml`). Facts and results: `docs/TESTING.md` §6; UI test guide: §7.

| App | Language | Base (commit) | Head (commit) |
|---|---|---|---|
| paperless-ngx/paperless-ngx | Python (Django) + Angular | v3.5.0 `bfd0d7fe3671` | v3.5.1 `35b0439195bb` |
| miniflux/v2 | Go | v2.3.4 `238c5614e584` | v2.3.5 `faecfa2fac61` |
| Stirling-Tools/Stirling-PDF | Java (Gradle) + TS + Rust + Python | v3.4.0 `c544e2c3457f` | v3.5.0 `588b7992061b` |
| dani-garcia/vaultwarden | Rust | 1.37.4 `7c188967e7a4` | 1.37.5 `6ed6921cc2b0` |
| firefly-iii/firefly-iii | PHP (Laravel) | v6.7.8 `c7d1adf35185` | v6.7.9 `ba2676861984` |
| mastodon/mastodon | Ruby on Rails + JS | v4.7.5 `24cd1c875a1a` | v4.7.6 `a593c9420d2f` |
| jellyfin/jellyfin | C# (.NET) | v12.3 `06de749d435e` | v12.4 `83d0d0e7f76e` |
| netdata/netdata | C/C++ (+ Go, Rust, Python) | v2.12.3 `0549a74d8493` | v2.13.0 `1f88c0da6429` |

Twelve smaller projects (express, axios, flask, requests, cobra, gin, gson, spring-petclinic, spdlog, cpr, nlohmann/json, ripgrep) and
synthetic sample apps (`testbed/apps/`, simulated risks) complete the test set.
