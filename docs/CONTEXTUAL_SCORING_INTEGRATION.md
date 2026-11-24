# Contextual scoring in the Guardian dashboard

Source: `RohanRamesh21/group21`, branch `contextual-scoring`, commit
`dd8d8ca17e32e5abead1aa88835995c9a3a5f987` (fetched 24 November 2026).

## Integration approach

The branch diverged before Guardian's current approval, validation and journey dashboard.
Its scoring modules and tests were ported into those existing flows rather than replacing
the application with the branch's older server and remediation implementation.

The integration covers:

1. Read the full exported head tree for static reachability before the tree is removed.
2. Score findings with hard floors, the SSVC decision table and AHP priority weights.
3. Add contextual confidence, rank stability, ranked fix options and human-check notes.
4. Expose those fields through the existing run/report builder and `/api/scores`.
5. Put the branch's scoring UI inside the main dashboard's Detect step; show the delta in Validate.
6. Keep AHP proposals inactive until a named reviewer approves; allow a return to baseline.

## Exact priority calculation

The row/column order of the priority matrix is exploitation, impact, exposure, introduced,
actionable:

```text
       exploitation impact exposure introduced actionable
exploitation   1       2       3        3          5
impact        1/2      1       2        2          4
exposure      1/3     1/2      1        1          3
introduced    1/3     1/2      1        1          3
actionable    1/5     1/4     1/3      1/3         1
```

`guardian/scoring/score.py::ahp` uses power iteration (at most 200 iterations;
convergence tolerance `1e-12`), normalizes the principal eigenvector and rounds
weights to four decimal places. The baseline weights are:

| Factor | Weight |
|---|---:|
| Exploitation | 0.4065 |
| Impact | 0.2490 |
| Exposure | 0.1428 |
| Introduced by the PR | 0.1428 |
| Fix available | 0.0589 |

For each factor, `_contrib` computes `round(100 * weight * value, 1)`.
The displayed priority is `round(sum(factor_points), 1)`. It is a ranking score,
not a probability that an application will be compromised.

For advisory findings, the inputs are:

- Exploitation: 1 for malware or KEV; otherwise the available EPSS percentile,
  or a neutral 0.3 when unavailable.
- Impact: critical 1, high 0.8, medium 0.5, low 0.2, informational 0.05.
- Exposure: direct runtime 1, indirect runtime 0.7, dev-only 0.2.
- Introduced: 1 for an introduced finding, otherwise 0.3.
- Actionable: 1 when a fixed version is reported or the package is malicious;
  otherwise 0.4.

SSVC separately uses KEV/active exploitation, the EPSS threshold `0.088`,
CVSS-derived automatability and impact, and runtime importance. Its decisions map
to Act → critical, Attend → high, Track* → medium, Track → low. Hard floors
take precedence. Priority weights do not determine those levels or the merge verdict.

## Contextual calculations from the source branch

| Calculation | Algorithm |
|---|---|
| Confidence | Six evidence signals, AHP weighted; non-applicable signals are omitted and weights renormalized. High ≥ 0.80, medium ≥ 0.50, otherwise low. |
| Reachability | Static imports/requires plus dependency graph paths. No import found is an estimate, never proof of unused code. For non-malware advisory findings, a declared direct runtime dependency drops from essential to support before SSVC. |
| Rank stability | 1,000 draws; multiply each priority weight by a uniform factor in `[0.8, 1.2]`, renormalize, rerank within levels. Seed 1337; report rank percentiles 5/95 and top-five share. |
| Fix ranking | `round(100 * Σ(weight * value), 1)` over risk reduction, compatibility, footprint, rollback and evidence. Baseline weights: 0.4030, 0.2444, 0.0791, 0.1367, 0.1367. |
| Before/after | Match finding identities across versions; report remediated/reduced/unchanged/regressed, level counts and sum of high/critical priority scores. This contextual summary does not replace the validation gate. |

Fix-ranking candidates are forecasts. Their peer-dependency and engine checks are
explicitly reported as not run. Ranked CI/image pinning suggestions do not mean
the patch builder can automatically resolve and apply a reviewed SHA or digest.

The confidence matrix has consistency ratio 0.0059, the fix-ranking matrix 0.0074,
and the baseline priority matrix 0.0127. The full matrices are emitted in scoring metadata.

## Human-approved AHP weights

The advisor proposes the ten upper-triangle cells of the 5×5 priority matrix.
Code fills reciprocal entries and checks the Saaty scale, consistency ratio below
0.10, and a maximum absolute weight drift of 0.10 (ten percentage points) from baseline.
A proposal does not activate itself. Approval records the reviewer and freezes the
matrix/profile identity. A scripted replay is explicitly labelled as making no AI call.

`with_active_matrix` applies approved weights when reading existing runs. Returning
to baseline also recomputes runs that were saved under custom weights. Neither action
changes finding levels, hard floors, SSVC decisions or the verdict.

## Reconciliation with the current application

- Contextual modules retain the source branch's calculations. `reachability.py` additionally
  recognizes literal `require.resolve("package")`, used by the Uptime Kuma sandbox loader.
- Missing source code is reported as not computed; a manifest-only snapshot is not
  treated as evidence that packages have no imports.
- The contextual confidence band is shown alongside Guardian's existing data-quality dimensions.
- The main application's shared `scoring/verdict.py` is retained. Unlike the older
  branch gate, introduced high/critical advisory severity still requires review when
  SSVC assigns a lower priority level. Scan completeness also remains explicit.
- Patch construction, named approval and isolated validation use the main application's
  existing implementation. Contextual delta is informational.

## Dashboard location and validation

Open `http://127.0.0.1:8765/#detect`:

- **Findings & priority**: level, priority, rank range, reachability and confidence.
  Select a finding for evidence, contributions, SSVC, contextual signals and ranked fixes.
- **How it's scored**: hard floors, SSVC, exact priority formula, active matrix,
  consistency ratio, contextual method and missing checks.
- **AHP weights · AI-advised**: repository context, baseline/approved weights,
  proposed rankings, named decisions and history.
- **Validate**: before/after contextual delta when validation has produced one.

Run `.venv/bin/python -m pytest -q` from the repository root and `npm run typecheck`
plus `npm run build` from `guardian/dashboard` for automated checks. A live browser
review is a separate check and must not be inferred from a passing build.
