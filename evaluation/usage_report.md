# Token Usage & Cost Report — final 518-row emergency CSV

## Final CSV generation

The final emergency full-dataset CSV was produced using **deterministic local Python only**, with no inference service called by the submission generator.

| Model/provider | Calls | Input tokens | Output tokens | API cost |
|---|---:|---:|---:|---:|
| None — deterministic Python for final CSV | 0 | 0 | 0 | $0.00 |
| **Total for final CSV** | **0** | **0** | **0** | **$0.00** |

- Total requests processed: **518**
- Total tokens, final generation: **0**
- Mean input tokens per request: **0**
- Mean output tokens per request: **0**
- API cost per request: **$0.00**
- Infrastructure/electricity cost: not measured.

## Separate optional local Gemma proof of concept (not part of the final CSV run)

Previous locally observed policy-advice demonstration used Ollama `gemma3:4b`: 1 call, 209 prompt tokens and 77 completion tokens, $0 provider API charge. Its policy advice had `audit_impact: NONE` and was not used to synthesize output rows. MongoDB Atlas vector search and `nomic-embed-text` were used for separate policy-retrieval testing, **not** for the emergency final CSV; cumulative embedding usage was not measured and is not included in the final-run model total.

Local inference hardware costs are not included in $0 provider API cost.
