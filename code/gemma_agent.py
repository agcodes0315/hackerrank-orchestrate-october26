
"""Optional local Gemma policy interpretation using the Ollama HTTP API.

Requires:
    - Ollama running locally
    - An installed Gemma model (e.g. gemma3:4b or gemma3:1b)

All model responses are validated using policy_agent.validate_advice.
The AI is advisory only and cannot change deletion verdicts or output.csv.
"""

import json
import os
import urllib.request
import urllib.error

from datetime import datetime, timezone
from pathlib import Path

from policy_agent import build_policy_request, validate_advice


# Record actual model usage without logging raw user data.
LOG = Path(__file__).resolve().parents[1] / "ghosttrace_model_usage.jsonl"

ALLOWED_ENUMS = {
    "YES",
    "NO",
    "UNKNOWN",
    "ACTIVE",
    "INACTIVE",
}


def interpret(rule, facts, model="gemma3:4b", host=None):
    """Interpret policy conditions using a local Gemma model.

    Args:
        rule: Policy-rule dictionary.
        facts: Non-sensitive, structured facts.
        model: Installed Ollama model name.
        host: Optional Ollama server URL.

    Returns:
        Validated advisory interpretation and actual model usage.

    Raises:
        ValueError: Invalid input facts.
        RuntimeError: Ollama connection, model, or response error.
    """

    # --------------------------------------------------
    # 1. Validate input facts
    # --------------------------------------------------

    if not isinstance(facts, dict):
        raise ValueError("facts must be a dictionary")

    for key, value in facts.items():

        if not isinstance(key, str):
            raise ValueError("Fact keys must be strings")

        if isinstance(value, (bool, int, float)):
            continue

        if isinstance(value, str) and value in ALLOWED_ENUMS:
            continue

        raise ValueError(
            f"Invalid fact '{key}'. "
            "Use only non-sensitive booleans, numbers, "
            "or approved enum values."
        )

    # --------------------------------------------------
    # 2. Build constrained policy prompts
    # --------------------------------------------------

    prompts = build_policy_request(rule, facts)

    # --------------------------------------------------
    # 3. Configure Ollama
    # --------------------------------------------------

    base_url = (
        host
        or os.environ.get(
            "OLLAMA_HOST",
            "http://127.0.0.1:11434"
        )
    ).rstrip("/")

    url = f"{base_url}/api/chat"

    body = {
        "model": model,
        "stream": False,
        "format": "json",
        "messages": [
            {
                "role": "system",
                "content": prompts["system"],
            },
            {
                "role": "user",
                "content": prompts["user"],
            },
        ],
        "options": {
            "temperature": 0,
        },
    }

    request_data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        url=url,
        data=request_data,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    # --------------------------------------------------
    # 4. Execute Ollama request
    # --------------------------------------------------

    try:
        with urllib.request.urlopen(
            req,
            timeout=180
        ) as response:

            response_text = response.read().decode(
                "utf-8"
            )

            result = json.loads(response_text)

    except urllib.error.HTTPError as exc:

        detail = exc.read().decode(
            "utf-8",
            errors="replace"
        )

        raise RuntimeError(
            f"Ollama returned HTTP {exc.code}: {detail}"
        ) from exc

    except urllib.error.URLError as exc:

        raise RuntimeError(
            "Cannot connect to Ollama. "
            "Check that the Ollama application is running. "
            f"Details: {exc.reason}"
        ) from exc

    except TimeoutError as exc:

        raise RuntimeError(
            "Ollama request timed out while running "
            f"the model '{model}'."
        ) from exc

    except json.JSONDecodeError as exc:

        raise RuntimeError(
            "Ollama returned invalid JSON at the HTTP "
            "response level."
        ) from exc

    # --------------------------------------------------
    # 5. Extract model response
    # --------------------------------------------------

    try:
        reply = result["message"]["content"]

    except (KeyError, TypeError) as exc:

        raise RuntimeError(
            "Unexpected Ollama response: "
            "missing message.content"
        ) from exc

    if not isinstance(reply, str) or not reply.strip():
        raise RuntimeError(
            "Ollama returned an empty model response."
        )

    # --------------------------------------------------
    # 6. Validate policy advice
    # --------------------------------------------------

    try:
        advice = validate_advice(
            reply,
            rule,
            facts
        )

    except (ValueError, TypeError, KeyError) as exc:

        raise RuntimeError(
            "Gemma returned policy advice that failed "
            f"the validation contract: {exc}"
        ) from exc

    # --------------------------------------------------
    # 7. Collect actual usage statistics
    # --------------------------------------------------

    usage = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "provider": "ollama_local",

        "model": model,

        "prompt_eval_count": result.get(
            "prompt_eval_count"
        ),

        "eval_count": result.get(
            "eval_count"
        ),

        "rule_id": rule["rule_id"],

        "cost_usd": (
            "Local inference; provider API charge $0. "
            "Hardware and electricity costs not measured."
        ),
    }

    # --------------------------------------------------
    # 8. Save usage audit log
    # --------------------------------------------------

    LOG.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with LOG.open(
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(usage) + "\n"
        )

    # --------------------------------------------------
    # 9. Return validated, advisory-only response
    # --------------------------------------------------

    return {
        "validated_policy_advice": advice,

        "usage": usage,

        "warning": (
            "Advisory only. "
            "Does not modify deletion findings "
            "or output.csv."
        ),
    }
