# Evaluation report — pending execution against the real challenge dataset

## Local code tests

28/28 unit tests passed during creation of the consolidated package (synthetic inputs and module-level contracts). This does not establish challenge accuracy.

## Last previously shared real-dataset diagnosis (before consolidation)

- 518 deletion requests, 32 separate labeled sample requests.
- 51/518 had timely attributable structured resource snapshots.
- 7 possible data-resurrection signals requiring verification.
- 0/32 public sample cases had a grounded prediction; sample status accuracy **not measurable**.

## Custom scenario tests

1. Deletion negation cannot authorize erasure.
2. Same-resource sync/update after a deletion claim is flagged only as possible resurrection; an event claim is not a proven state.
3. A record observation after `audit_at` cannot establish the audited state.
4. An LLM policy response inventing `deletion_status` or evidence references is rejected.
5. Exact identity reference matching prevents substring false positives.

## Next required measured results

Run `python code/ghosttrace.py all` and capture actual coverage, status accuracy (if evaluable), exact step-array accuracy, sequence accuracy, field accuracy, failures and improvements. Do not report 0 evaluated cases as an accuracy percentage. Test the final file using `python code/ghosttrace.py validate --file output.csv` once it exists.
