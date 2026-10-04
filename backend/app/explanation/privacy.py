"""Request-local string pseudonyms; never export raw evidence prose or alias mappings."""

from __future__ import annotations

import json
from typing import Any

from app.explanation.knowledge import text_sha256
from app.explanation.provider import MAX_PROMPT_BYTES, ProviderPrompt
from app.policies import POLICY_RULES

PRIVACY_VERSION = "finding-context-redaction-0.1.0"


def redact_prompt(prompt: ProviderPrompt) -> ProviderPrompt:
    original = json.loads(prompt.context_json)
    keys: dict[str, str] = {}
    values: dict[str, str] = {}

    def redact(value: Any, depth: int = 0) -> Any:
        if depth > 32:
            raise ValueError("context nesting exceeds budget")
        if isinstance(value, str):
            if value not in values:
                values[value] = f"[value_{len(values) + 1:04d}]"
            return values[value]
        if isinstance(value, dict):
            result = {}
            for key in sorted(value):
                if key not in keys:
                    keys[key] = f"field_{len(keys) + 1:04d}"
                result[keys[key]] = redact(value[key], depth + 1)
            return result
        if isinstance(value, list):
            return [redact(item, depth + 1) for item in value]
        if value is None or type(value) in {bool, int, float}:
            return value
        raise ValueError("unsupported context value")

    detector = original["detector"]
    category = original["category"]
    if detector == "policy_engine":
        if category not in {rule.rule_id for rule in POLICY_RULES}:
            raise ValueError("unsupported context category")
    else:
        category = {
            "expected_configuration": "reference_difference",
            "peer_baseline": "peer_difference",
            "isolation_forest": "structured_outlier",
        }[detector]
    context = {
        key: original[key]
        for key in (
            "vendor",
            "platform",
            "finding_sha256",
            "source_sha256",
            "detector",
            "detector_version",
            "parser",
            "formal_verification",
            "documents",
        )
    }
    context.update(
        category=category,
        observed=redact(original["observed"]),
        expected=redact(original["expected"]),
        evidence=[{"source_location": item["source_location"]} for item in original["evidence"]],
        privacy={
            "version": PRIVACY_VERSION,
            "string_values_and_keys": "request_local_pseudonyms",
            "evidence_messages": "omitted",
            "numbers_booleans_hashes_and_line_numbers": "retained",
            "alias_mapping": "not_exported",
        },
        limitations=[
            "String aliases are meaningful only within this request; mappings are not exported.",
            "Field names are pseudonyms too: do not infer their original identities.",
            "Numeric facts, counts, hashes and line numbers can still be confidential.",
            "Pseudonymization is not a proof of anonymity or elimination of prompt injection.",
        ],
    )
    serialized = json.dumps(
        context, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if (
        len((prompt.instructions + serialized + prompt.answer_schema_json).encode())
        > MAX_PROMPT_BYTES
    ):
        raise ValueError("redacted prompt exceeds budget")
    return ProviderPrompt(
        prompt.instructions, serialized, prompt.answer_schema_json, text_sha256(serialized)
    )
