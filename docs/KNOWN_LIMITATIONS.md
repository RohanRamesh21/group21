# Known Limitations (24 Nov 2026)

Stated plainly, so nothing is claimed beyond what the tests and recorded runs show.

## Not finished yet
| Area | State | What's needed |
|---|---|---|
| AI investigation | Live and measured (about 16K tokens, 3 calls, 43 s on the scenario). One Investigator call per case plus one Verifier call; no follow-up tool round, so an Investigator's "open questions" are left for the human. Cases are capped at 6 per run (the rest are shown as "not investigated"). | — |
| AI token use | FreeModel free tier: 1M tokens/month, shared with anything else using the key. Guardian's own caps: 25K/run, 300K/30 days (ledger in `.cache/llm_usage.jsonl`). The ledger only counts calls made after it was added (the earlier 598K isn't in it). | — |
| Live validation | Docker works; the ShipLog profile passed an isolated infrastructure run. A full approved-fix validation (baseline vs candidate) runs after a person approves on the dashboard | Your approval |
| Docker image build of the app + image SBOM | Not in the profile yet; the "resulting artifact" is the installed dependency tree + build output scanned with Syft | Restricted builder stage |
| GitHub PR trigger live | Live on `kirankishoreV-07/PIPELINE_CHECK`: runner online, real PR scanned. Statuses/comments wait for the token's "Commit statuses: write" permission. Dashboard links in PR comments point to `127.0.0.1`, so they open only on the demo machine | Token permission |
| Dashboard visual check | Type-check and build pass; API verified over HTTP | Browser review |
| Stretch goals S1–S6 | S4 dependency confusion and S2-style patch generation exist; others not built | Time after the core |
| Deep mode (old agent loop) | Kept behind `--deep`. Its constitution verdict rule is still its own (stricter than the shared verdict); the default workflow copies the shared rules verdict. | Align or retire |
| Guardian Buddy | Built (Electron, macOS-tested); click-through on transparent areas isn't implemented | — |
| MCP server | Not built | After the core |

## Scope limits
- The full fix-and-validate loop targets **npm**. Python, GitHub Actions, Dockerfiles, browser extensions and CDN scripts reach scan + compare (L1/L2). Java/Go/Rust discovery goes through Syft but is untested.
- CI/image findings are escalated, not auto-pinned (resolving the reviewed SHA/digest isn't automated).
- Reachability: only "imported by frontend code" is used (for exposure). Function-level reachability isn't implemented. Imports are a static, inferred signal.
- Fix risk reduction is a **forecast** until validation proves it.
- Passing tests prove only the named tests on that candidate. Excluded tests (MariaDB/testcontainers, network-dependent suites, Playwright e2e) are reported as "not run".
- EPSS is a probability, not proof of attack; KEV shows observed exploitation, not our exposure.
- Confidence measures evidence completeness and consistency, not whether a finding is correct.
- Counts depend on the commit, tool versions and advisory database date.
- The attack scenario is planted by us and harmless; `MAL-2025-15245` matches the real advisory by name, not by the fixture's bytes.
