GhostTrace targeted intent-parser update

In your existing repository, BACK UP code/engine.py first.
Replace code/engine.py with this patched file and copy code/tests/test_intent_expanded.py into code/tests/.

This patch ONLY expands explicit deletion-intent recognition, including verified high-confidence multilingual phrases. It deliberately does not infer missing evidence, invent verdicts, or bypass review. It does not solve the 337 evidence-gap cases.

Run:
  python -m unittest discover -s code/tests -v
  python code/ghosttrace.py all
  python code/main.py --audit

Compare coverage with your baseline (30/518, 488 review). The audit STOP remains normal until all cases can be supported.
Review changes before commit: git diff -- code/engine.py.
