# Evaluation Report — GhostTrace October 2026 (October 25 rescue revision)

## Protocol

Only participant-facing `dataset/` files were used to generate predictions. The 32 labeled public samples were evaluated separately and were **not used as 518-case answers**. The emergency generator emits a structurally valid fallback `INCOMPLETE` with `[]` if the strict auditor cannot establish a conclusion. Such fallback rows are **unverified**, not verified findings.

## Measured results

| Metric | Result |
|---|---:|
| Automated unit tests | **41/41 passed** |
| Full dataset size | 518 |
| Strict provisional determinations | **263** |
| Strict unresolved | **255** |
| Structural CSV validation | PASS, 518 rows |
| Public sample fallback status accuracy | **21/32 = 65.625%** |
| Public sample exact step-array accuracy | **0/32** |
| Public sample strict predictions | **11/32** |
| Public sample strict status accuracy among predicted | **7/11 = 63.64%** |
| Public sample strict status accuracy of all cases | **7/32 = 21.875%** |
| Public sample strict exact step arrays | **0/11** |
| Public sample strict operation-sequence accuracy | **0/11** |
| Field-level precision | Not measured; no defensible alignment of predicted vs reference steps |

Sample status accuracy is from the same pipeline using a fallback for unresolved public sample requests, without copying their labels into inference. Detailed step accuracy is poor; this is an emergency structural output, not a validated compliance audit.

## Code improvements

1. Extract independently corroborated state from timestamped correlated log readbacks; do not treat a successful workflow operation as state proof.
2. Extract service-export JSON readbacks with explicit status-code 404/200, `hits.total`, connector enabled and restore access flags. No ownership assigned by resource ID alone.
3. Treat active data flows and allowed restores as incomplete risks requiring disable/block operations, while preserving exact evidence IDs and timestamps.
4. Add five regression tests for explicit service readback semantics. Expanded request-intent tests remain enabled.

## Three additional participant-authored evaluation cases

1. A 404 account readback with a null profile may justify `ABSENT` for **that specific resource**; a 200 response with null profile is not proof of `PRESENT`.
2. A connector `enabled=true` with an exact subject identifier must be treated as an active re-creation risk with `DISABLE_DATA_FLOW` remediation.
3. A backup with `restore_allowed=true` must trigger a restore risk, but an unknown restore flag must not be inferred as `BLOCKED`.

These behaviors have automated regression tests in `code/tests/test_service_readbacks.py` and are not hidden golden labels.

## Known limitations

- **255/518 fallback rows have no verified status or steps**, so this file is not a proven full audit.
- PDFs/PNGs (15 files) have not been reliably converted into attributable structured observations. Some service exports lack subject ownership. Missing evidence does not imply deletion success or failure.
- Correctness on challenge-private cases cannot be estimated from the 32 public samples; neither award outcome nor score is guaranteed.
- Further improvements should focus on document evidence, full resource-graph coverage, cross-replica state, exact policy conditions and complete step sets, with sample-based iteration.
