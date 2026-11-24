# Day 2 Scoring: Revised Plan (simplified)

*Reviewed version of the "Day 2 Scoring: Plan and Specification" draft. Status: plan, nothing built yet.*
*Aligned with `docs/PRODUCT_PLAN.md` v2.2 (§5.4 verified gate, §5.7 confidence, §2 S1 reachability).*

## 0. Decision in one line

**Keep Day 1 scoring as it is (built, tested, documented). Add only what Bosch asks for, using simple rules, not more AHP matrices or simulations.**

The draft adds three more weighted models (rank-stability simulation, a confidence AHP, a fix-ranking AHP). Our problem is that scoring is already hard to explain; adding three more models makes it harder. Each Day 2 feature below uses **plain, ordered rules** that one sentence can explain.

## 1. Draft features: keep, simplify or drop

| Draft feature | Bosch asks for it? | Decision | Why |
|---|---|---|---|
| A. Rank stability (1,000 weight draws) | No | **Drop** (optional extra later) | Only reorders findings *within* a level; level and verdict never change. Hard to explain, no demo value. |
| B. Confidence (6 signals, AHP-weighted) | **Yes** ("score and confidence level") | **Keep, simplified** | Use rule bands, not AHP. Fix: OSV + Grype from the same advisory are **one** source, not two. |
| C. Reachability tiers | **Yes** ("reachability") | **Keep, narrowed** | Import tier only, labelled *preliminary*; it does not change the decision. |
| D. Fix-candidate scoring (AHP) | **Yes** ("risk reduction, compatibility, rollback") | **Keep generator, replace AHP with ordered rules** | A sort order a reviewer can read beats a 0–100 fix score. |
| E. Before/after delta | **Yes** ("before-and-after", "newly introduced") | **Keep, align gate** | Add the missing conditions from PRODUCT_PLAN §5.4. |
| Phase 0 floors (SHA→tag, history rewrite) | Indirectly | **Keep** + add the trust fixes T8/T11 | |

## 2. Bug found while reviewing (add to M0 as T11)

**Frontend libraries are wrongly treated as dev-only.** In Uptime Kuma (`5aa5dec4`), 28 libraries such as `vue`, `chart.js`, `dompurify`, `bootstrap` and `vue-router` are `devDependencies`, but Vite bundles them into the shipped web UI. Today they get exposure 0.2 ("dev only"), so a `dompurify` XSS advisory would be under-ranked.

**Fix:** a component counts as **shipped** if it is a runtime dependency **or** it is reachable from the frontend entry (`src/` imports) that the build bundles. Until bundle analysis exists, devDependencies imported by `src/**` are treated as shipped (exposure 1.0, label "shipped in browser bundle"). Recorded in `docs/SAMPLE_APP.md`.

## 3. Confidence (simple rules)

Five dimensions, matching PRODUCT_PLAN §5.7. Each is `ok`, `weak` or `missing`, with a reason.

| Dimension | ok | weak | missing |
|---|---|---|---|
| Collection completeness | All required scanners ran | One scanner failed | Required scanner failed |
| Source applicability | Exact version inside a parsed affected range | Range ambiguous / version from manifest only | Version unresolved |
| Freshness | Advisory DB and EPSS/KEV ≤ 1 day old | ≤ 7 days | Older / unknown |
| Contradictions | Sources agree | Severity disagrees | Affected/not-affected disagrees |
| Evidence | Lockfile line + source file + advisory record stored | Two of three | One or none |

**Band (no weights):** `high` = no weak/missing · `medium` = only weak · `low` = any missing.
Detector findings (typosquat, tamper, redirect, install script) use the stored file/line evidence; a `MAL-` record plus a detector hit counts as two independent sources.

**Rules:** confidence never changes level, decision or verdict. Introduced + High or above + low confidence → verdict reason "needs human check: <missing items>". AI text never raises confidence.

## 4. Reachability (preliminary tier only)

| Tier | Meaning |
|---|---|
| `dev_only` | Only via dev edges **and** not imported by shipped code (frontend or backend) |
| `declared` | In the shipped graph; no static import found |
| `imported` | First-party code imports it (`require('x')`, `import … from 'x'`, `import('x')` literal); evidence = file:line |
| `function` | *Stretch S1, level 2 only* (Jelly): path to the vulnerable function |

- Text scan only, nothing executed; `node_modules` ignored; dynamic `require(var)` reported as a limitation.
- **Effect:** shown on the card and used as a **tie-break** inside the same level. It **does not** change the SSVC decision or verdict (import-level evidence is too weak for that). Never applied to malware, integrity, origin, redirect or install-script findings.
- S1 is claimed complete only with the `function` tier (PRODUCT_PLAN §2 S1).

## 5. Fix candidates: generator + ordered rules

**Generator (deterministic; agents can't add candidates or versions):**

| Type | When | Target |
|---|---|---|
| `upgrade_to_fixed` | CVE, direct dependency | Smallest version outside every affected range (OSV), same major preferred |
| `override_transitive` | CVE, transitive | `overrides` entry with that version |
| `remove_package` | Malicious / unexpected package | — |
| `revert_change` | Hard-signal change in the PR (e.g. `.npmrc` redirect, lockfile tamper) | Base state of that file/entry |
| `pin_trusted_version` | Suspicious update | Last version in base |
| `pin_action_sha` / `pin_image_digest` | CI / image | Detector output |
| `escalate` | Nothing above applies | Human review |

Every target version must exist in the registry metadata and in the advisory's fixed versions (referee check).

**Ranking: ordered rules, read left to right (first difference wins):**
1. Resolves the target finding (forecast) → first.
2. Creates no new High+ finding (forecast) → first.
3. Smaller semver jump (patch < minor < major) → first.
4. Fewer lockfile entries changed → first.
5. Easier rollback (lockfile-only < manifest + lockfile < multi-file) → first.

Each candidate card shows: **expected risk reduction** (findings removed by level, as a count, e.g. "1 critical, 0 high"), **compatibility** (semver jump, peer-dependency conflicts, `engines` match), **rollback** (exact command), and "forecast; proven only by validation".

For the scenario, the generator produces one combined patch: remove `axois` + revert `.npmrc` line + `jsonata` 2.2.0 → smallest fixed version, validated by `test-jsonata-sandbox.js`.

## 6. Before/after delta

Set operations on finding keys (`package@version#advisory`, `detector:file:line:type`, **including ecosystem**): `resolved`, `remaining`, `new_in_after`; per target: `remediated` / `reduced` / `unchanged` / `regressed`.

**`verified` only if all hold** (PRODUCT_PLAN §5.4):
1. Approval matches the candidate; evidence hashes verify.
2. All required validation stages completed (install, build, unit, integration, image build, source + image rescan, SBOM diff).
3. Tests that passed on baseline still pass.
4. Target resolved; no new High+; no hard signal re-created.
5. Same advisory-DB snapshot before and after.

Output shows three results separately: **target** (corrected / not) · **validation** (passed / failed / incomplete) · **decision** (BLOCK / REVIEW / ALLOW).

"Risk Index" from the draft is dropped: counts per level before/after are clearer and can't be misread as an absolute measure.

## 7. Code layout

```
guardian/scoring/day2/
  confidence.py     # confidence(finding, run) -> {band, dimensions, missing}
  reachability.py   # scan_imports(root); tier(component, graph, imports)
  fixes.py          # candidates(finding, report); order(candidates)
  delta.py          # before_after(before, after, validation) -> {...}
  enrich.py         # adds fields; never edits level/decision/floor/verdict
tests/day2_scoring/
```

No new dependencies.

## 8. Tests

| Test | Proves |
|---|---|
| `test_enrich_never_changes_decision` | Enrichment adds fields only |
| `test_frontend_devdeps_are_shipped` | T11: `dompurify` imported by `src/` is not dev-only |
| `test_confidence_bands` / `test_same_upstream_counts_once` | Rules behave; OSV+Grype same advisory = one source |
| `test_reachability_never_touches_hard_signals` | Malware/tamper/redirect/scripts unaffected |
| `test_import_scan_*` | require/import/dynamic literal found; nothing executed; dynamic var reported |
| `test_fix_targets_exist` | Invented versions rejected |
| `test_fix_order` | Patch beats major at equal effect; resolving beats non-resolving |
| `test_delta_not_verified_*` | New High, re-created hard signal, failed/unrun stage, stale approval → not verified |
| `test_prompt_injection_does_not_move_verdict` | Injected text can't change the decision |

## 9. Order and effort

| # | Work | Effort |
|---|---|---|
| 1 | T11 shipped-frontend fix + Phase 0 floors | ½ day |
| 2 | Confidence | ½ day |
| 3 | Fix generator + ordering | 1 day |
| 4 | Before/after delta | ½ day |
| 5 | Reachability import tier | ½ day |
| — | Rank stability | optional, only if everything else is done |

## 10. Notes on the draft

- It cites `CLAUDE.md §3.2`, but the Guardian repo has no `CLAUDE.md` (only Uptime Kuma's own). Either add one with those rules or cite `PRODUCT_PLAN.md`.
- "Sandbox runs use `--ignore-scripts`" conflicts with the validation profile (allowlisted hooks bound to version + integrity). Use the profile rule.
- Its effort estimates (1–3 h per feature) are optimistic; the table above includes tests.
