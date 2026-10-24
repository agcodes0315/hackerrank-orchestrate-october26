# Evaluation report — in progress

Run `python code/main.py --audit` and `python code/evaluate.py` on the local participant dataset, then insert the actual figures from `ghosttrace_evaluation.json` here. Coverage is not accuracy. Never substitute guessed values.

## Custom test cases

1. **Negated deletion:** `Please do not delete my account` must never authorize deletion.
2. **Tombstone:** an account tombstone with `user_id` and still-present email requires redaction, not deleting the stable subject reference.
3. **Ordering:** findings must precede remediation and verification, ordered according to allowed operation ranks.

Additional tests: ambiguous requests require review; UTC-equivalent time zones compare equal; explicit erasure request authorizes deletion.

## Known failures to resolve

- Unsupported scanned evidence and non-JSON logs are not treated as proofs.
- Sync/restore controls have not yet been modeled as full temporal state machines.
- Complete vs incomplete verdicts may be wrong when evidence is missing, even when extraction appears confident.

## Required measured metrics

Record: evaluated sample count, case status accuracy, step/field accuracy, sequence accuracy, failure cases, fixes and rerun results.
