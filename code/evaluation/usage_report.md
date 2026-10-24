# Model usage report — pending full dataset execution

## Provider and model

- Deterministic core uses Python, CSV, SQLite, and JSON: no model calls.
- Optional policy advisor: local Ollama, model selectable (example `gemma3:4b`).
- **Model calls performed in package development/test environment: 0**. Validation/unit tests do not constitute model inference.
- **Input tokens observed: none**; **output tokens observed: none**; **actual runtime or compute costs: not measured**.

When you invoke the real model, `ghosttrace_model_usage.jsonl` records returned `prompt_eval_count` and `eval_count` for each successful validated call. Transfer verified totals, average tokens per actual call, specific model IDs, hardware/compute details and cost methodology to this report before submission. Never invent usage estimates as actual figures.
