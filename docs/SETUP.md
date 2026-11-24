# Setup

How to get Guardian running on a new machine. Exact tool versions and checksums are in `tools.lock`.

## 1. Python and the CLI

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.lock.txt
uv pip install --python .venv/bin/python -e .
.venv/bin/python -m pytest -q
```

## 2. The sandbox (required for scanning)

**What podman is:** a program for running containers (like Docker). A container is a sealed, throw-away box for one program: it sees
only the files you share with it, can be cut off from the network and given memory/time limits, and starts in about a second. Podman
runs "rootless" (as your normal user, no root service). It is installed on the machine, not as a Python/npm dependency:
Linux `sudo apt install podman` (or your distro's package), macOS/Windows: Podman Desktop or `podman machine init && podman machine start`.

Every tool that reads a scanned repository (npm lockfile resolution, Syft, Grype, OSV-Scanner, zizmor) runs in a
rootless **podman** container. Nothing else needs to be installed on the host: the containers bring the tools.
Guardian refuses to run these tools on the host. A step whose container cannot start is reported as a
`tool_error` ("not checked"), and the rest of the scan continues.

| Need | Version used | Notes |
|---|---|---|
| podman, rootless | 5.8.6 | Linux: distro package. macOS/Windows: `podman machine init && podman machine start` |
| Network helpers (`pasta`, `aardvark-dns`) | not needed | Containers run with `--network=none`; see "How network access works" |

One-time setup. It needs internet access once, and is the only step that downloads tools:

```bash
.venv/bin/guardian sandbox setup    # pulls the 6 digest-pinned images (incl. Conftest), downloads + verifies + imports the Grype DB
.venv/bin/guardian sandbox status   # exit code 0 when everything is ready
```

* Images are pinned by digest in `guardian.yaml` (`sandbox.images`) and recorded in `tools.lock`. A scan never
  pulls an image (`--pull=never`). Image refs without a `@sha256:` digest are refused.
* The Grype DB is downloaded from `https://grype.anchore.io/databases/v6/latest.json`. Its sha256 is checked
  against that listing, and Grype imports it in a container with no network into `.cache/grype/db`. The DB build
  date is recorded in every report (`headline.sandbox.grype_db`). Re-run `guardian sandbox setup` to refresh it.
* The offline OSV database (`.cache/osv`) is optional. It is only the fallback when `api.osv.dev` cannot be reached.

### Guardrails applied to every sandboxed run

| Guardrail | How |
|---|---|
| No network | `--network=none`. A step that needs a registry gets the egress proxy, which then is its only way out |
| Only approved registries | Egress proxy allow-list: `sandbox.npm_registry_hosts` in `guardian.yaml` (HTTPS `CONNECT` to port 443 only) |
| Repository cannot be changed | Inputs mounted read-only; read-only root file system; one writable output folder; 512 MB `/tmp` |
| No secrets | No host environment variables, home folder, SSH keys or tokens are passed in (`HOME=/tmp`) |
| Least privilege | Non-root inside (`--userns=keep-id`), `--cap-drop=all`, `no-new-privileges` |
| Resource limits | 2 GB memory (no extra swap), 2 CPUs, 512 processes, 900 s wall clock (killed on timeout); `sandbox.limits` |
| Known tools only | Images pinned by digest; never pulled during a scan |

### How network access works

Rootless containers with `--network=none` have only a loopback interface. When npm has to resolve a lockfile,
Guardian starts an allow-list proxy *in its own process* on a Unix socket. It mounts that socket into the
container, where `guardian/sandbox/bridge.js` exposes it as `127.0.0.1:3128` and points npm at it. The container
has no other route out. Refused connections are listed in the report and raised as finding D16
(`sandbox_egress_blocked`).

### Developer escape hatch

`GUARDIAN_SANDBOX=host` runs the same tools on the host **without isolation**, for example on a machine without
podman. Those tools must then be installed locally, at the versions in `tools.lock`. Every report made this way
says so (`headline.sandbox.mode = "host"`, and a warning in the Day 1 view). Never use it on untrusted
repositories.

## 3. Real-app test corpus (optional)

```bash
.venv/bin/python testbed/corpus.py fetch            # 20 pinned public repos, bare and read-only, into sandbox/corpus/ (~230 MB, ~7 min)
.venv/bin/python testbed/corpus.py scan [name ...]  # ~2 min for the 12 small apps, ~5 min for the 8 flagship apps; guardian-out/corpus/summary.json
```

The list, and why each app is in it, is in `testbed/corpus.yaml`. Results are in `docs/TESTING.md`; how to run the flagship apps
through the dashboard is `docs/TESTING.md` §7.

## 4. Policy, remediation and monitoring
- Policies: `policies/*.rego` (Conftest/OPA, run in the sandbox); lists in `guardian.yaml` (`images.trusted`, `policy.license_denylist`,
  `install_scripts.allowlist`, `internal_scopes`). CI gate: `guardian check … --fail-on block` (exit 1).
- Remediation: `guardian fix` (plan), `guardian fix --validate FIX-…` (apply in the sandbox + rescan), approval in the dashboard.
- Monitoring: `guardian watch [--all] [--interval MIN]`, or start the server with `GUARDIAN_MONITOR_INTERVAL=<minutes>`.
- npm registry checks need `registry.npmjs.org` in `registries.fetch_hosts` (default) and network access; offline they are reported as
  "not checked".

## 5. Dashboard

```bash
.venv/bin/uvicorn guardian.server:app --port 8765          # http://localhost:8765 (restart it after backend changes)
cd guardian/dashboard && npm ci && npx vite build           # rebuild the UI after edits (.npmrc sets ignore-scripts)
cd guardian/dashboard && npx vite                           # dev server on :5173, proxies /api to GUARDIAN_API (default http://127.0.0.1:8765)
```

| Variable | Default | Effect |
|---|---|---|
| `GUARDIAN_PATH_ROOTS` | your home directory | Folders the **Local path** source may read (`:`-separated). The home directory itself is always refused. |
| `GUARDIAN_MONITOR_INTERVAL` | off | Minutes between automatic monitoring re-checks |
| `GUARDIAN_LLM_PROVIDER`, `OPENROUTER_API_KEY`, `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY` | none | Live agents on the Investigate page; without a key only the recorded example runs |
| `GUARDIAN_API` (Vite dev server only) | `http://127.0.0.1:8765` | Backend the dev server proxies to |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `tool_error: sandbox image for syft is not pulled` | `guardian sandbox setup` |
| `tool_error: podman is not installed` | Install podman (above). Scans continue but skip those tools |
| `grype DB missing` | `guardian sandbox setup` |
| `Error: setting up Pasta` | You ran a container with networking by hand. Guardian itself never needs it |
| `killed by the sandbox memory limit` | Raise `sandbox.limits.memory` in `guardian.yaml` for very large repositories |
