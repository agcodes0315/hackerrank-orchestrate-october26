# GhostTrace — reproducible emergency submission

This project reconstructs subject-specific deletion state using participant-facing snapshots and readback logs. The optional MongoDB Atlas + Gemma workflow is a separate advisory proof of concept.

## Run (Python 3.12+)

```powershell
python -m unittest discover -s code/tests -v
python code/emergency_submit.py
python code/validate_output.py
python code/evaluate.py
```

The strict `python code/main.py --audit` refuses to certify unresolved cases. The emergency writer produces a *structurally valid but partially unverified* 518-row output.csv. Read evaluation/evaluation_report.md for real accuracy and limitations.

MongoDB and Ollama are **not required** for the deterministic submission run. Optional packages: `pymongo`, `dnspython` for Atlas and local `gemma3:4b` via Ollama for advisory policy interpretation. Do not commit credentials.

See `SUBMISSION_STEPS.txt`, `AGENTS.md`, and `problem_statement.md`.
