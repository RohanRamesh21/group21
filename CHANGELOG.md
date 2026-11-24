# Changelog

User-visible changes, newest first.

## 2026-11-24 (redesigned dashboard)
- **Home page takes the source:** Git URL, ZIP upload or a **local folder** (new; a Git repository is cloned and never modified,
  base/head can name its branches). The scan runs with a live, animated eight-stage pipeline, then opens the results:
  Overview, Dependency graph, Risk scores, Fix & validate. Recent scans (including the latest CLI `guardian check`) are listed
  on the home page, and every scan has its own link.
- **Day 1 report view removed.** Its essentials (verdict, numbers, attack signals, vulnerabilities by severity, what changed,
  SBOM downloads, top risks) are on the new Overview. The header project picker is gone.
- **Investigate takes its own input:** pick a finished scan or bring a new source (scanned first, then investigated). Live agents
  now run on any scan's repository and commits; nothing is tied to uptime-kuma. The recorded agent run remains as a labelled
  "recorded example". Model failures (e.g. a rejected key) are shown with the reason; the deterministic checks still run.
- **Animations:** page and tab transitions, count-up numbers, staggered lists, the dependency graph revealed after it is fitted
  (it was previously left invisible or jumped while zooming), dark zoom controls.
- New endpoints `POST /api/projects/path` and `GET /api/sources`; `/api/context` carries the overview numbers; `/api/meta` no
  longer reports demo-branch numbers; `POST /api/runs` takes `project`.

## 2026-11-24 (later)
- **Finding reviews:** confirm, challenge, or defer in Risk scores. History follows the finding and shows why it reopened. Download the current finding and review timeline as JSON.
- **Dashboard navigation:** a project picker in the header drives the Day 1, Dependency graph, Risk scores and Fix & validate tabs
  (main report or any scanned project); a finished scan is selected automatically and can be opened in those tabs; live scan progress
  shows at the top of "Scan a project"; agent controls and the agent-demo label appear only on the Investigation tab (no more
  hard-coded "uptime-kuma" header elsewhere). New endpoint `/api/context`.

## 2026-11-24
- **Flagship apps per language:** paperless-ngx, miniflux, Stirling-PDF, vaultwarden, firefly-iii, mastodon, jellyfin, netdata, checked
  release → release from the CLI and the dashboard. .NET packages from `Directory.Packages.props` are now inventoried; false positives
  from TypeScript path aliases, local `require` functions, test fixtures and nightly releases are fixed.
- **Stretch goals:** reachability (is the vulnerable package imported?), npm signature and build-provenance checks, package history and
  install-script analysis, policy-as-code (Conftest/OPA, `policies/guardian.rego`, `--fail-on`), remediation with sandbox validation,
  retry and human-approved local branches ("Fix & validate" tab, `guardian fix`), continuous monitoring (`guardian watch`, "Re-check now").
- **Day 1 gaps:** lowercase `dockerfile` discovered; untrusted / `:latest` base images; SHA→tag action changes are a hard signal; any
  introduced high/critical finding needs review; CVSS scores shown; the shown verdict includes policy.
- **Dashboard:** new panels and tab; project-neutral dependency graph; Investigation-only banner; no hidden-graph rendering errors.
- Agent self-protection (Codex, commit `27a8504`): mandatory checks independent of model decisions.

## 2026-11-23
- **Sandbox:** every repository-reading tool runs in rootless podman (no network, read-only, pinned images, limits); npm reaches only the
  registry through an allow-list proxy; fixes a code-execution path through a repository `.npmrc`.
- C/C++, Java and Go build-file checks (D15–D19); synthetic sample apps; first real-app corpus (12 apps).
- One pipeline for every repository (`guardian scan` / `check` both use `universal.check_any`); dead code removed.
