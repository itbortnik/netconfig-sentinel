"""Actual owned configuration explanations, kept separate from quality/acceptance metrics."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import DocumentChunk, load_knowledge_catalog
from app.explanation.local import explain_finding
from app.explanation.privacy import redact_prompt
from app.explanation.provider import (
    SYSTEM_INSTRUCTIONS,
    DraftAnswer,
    InvalidProviderAnswer,
    ProviderPrompt,
    build_prompt,
    generate_draft,
)
from app.parsers import parse_configuration

from ml.inference.change_artifacts import safe_path
from ml.instruct.framing import GenerationLimits
from ml.instruct.runtime import GenerationObservation, LocalInstructProvider


@dataclass(frozen=True)
class OwnedCase:
    vendor: str
    category: str
    finding_sha256: str
    source_sha256: str
    prompt: ProviderPrompt
    chunks: tuple[DocumentChunk, ...]


class ObservedProvider(Protocol):
    last_generation: GenerationObservation | None

    def generate(self, prompt: ProviderPrompt) -> bytes: ...


def authored_cases() -> tuple[OwnedCase, ...]:
    cases: list[OwnedCase] = []
    for vendor, filename, text, category in (
        (
            "cisco",
            "owned-ios.cfg",
            "hostname owned-host\nline vty 0 4\n transport input telnet ssh\n!\n",
            "management.telnet_enabled",
        ),
        (
            "cisco",
            "owned-ios.cfg",
            "hostname owned-host\nip ssh version 1\nline vty 0 4\n transport input ssh\n!\n",
            "management.ssh_version_1",
        ),
        (
            "juniper",
            "owned-junos.cfg",
            "set system host-name owned-host\n"
            "set system services telnet\nset system services ssh\n",
            "management.telnet_enabled",
        ),
        (
            "juniper",
            "owned-junos.cfg",
            "set system host-name owned-host\nset system services ssh protocol-version v1\n",
            "management.ssh_version_1",
        ),
    ):
        config = parse_configuration(text, filename=filename)
        finding = next(
            item
            for item in evaluate_policies(config, device_id=UUID(int=1))
            if item.category == category
        )
        explanation = explain_finding(finding, config)
        chunks = load_knowledge_catalog().retrieve(finding)
        prompt = redact_prompt(
            build_prompt(
                finding,
                explanation,
                chunks,
                vendor=vendor,
                platform="ios" if vendor == "cisco" else "junos",
                parser_confidence=config.parser_confidence,
                warning_count=len(config.parse_warnings),
                unparsed_count=len(config.unparsed_fragments),
            )
        )
        cases.append(
            OwnedCase(
                vendor,
                category,
                explanation.finding_sha256,
                explanation.source_sha256,
                prompt,
                chunks,
            )
        )
    return tuple(cases)


def run_cases(provider: ObservedProvider, cases: tuple[OwnedCase, ...]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for case in cases:
        try:
            answer = generate_draft(provider, case.prompt, case.chunks).model_dump(mode="json")
            status = "schema_valid_draft"
        except InvalidProviderAnswer:
            answer, status = None, "rejected"
        observation = provider.last_generation
        if observation is not None and observation.context_sha256 != case.prompt.context_sha256:
            observation = None
        result.append(
            {
                "vendor": case.vendor,
                "category": case.category,
                "finding_sha256": case.finding_sha256,
                "source_sha256": case.source_sha256,
                "context_sha256": case.prompt.context_sha256,
                "status": status,
                "generation": asdict(observation) if observation else None,
                "answer": answer,
                "semantic_truth_proven": False,
                "formal_verification": "not_run",
                "requires_human_review": True,
            }
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit offline owned instruct diagnostic")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--allow-owned-context", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-new-tokens", type=int, default=1024)
    arguments = parser.parse_args(argv)
    try:
        safe_path(arguments.output)
        if (
            arguments.output.suffix != ".json"
            or arguments.output.exists()
            or not arguments.output.parent.is_dir()
        ):
            raise ValueError("output must be new JSON")
        limits = GenerationLimits(max_new_tokens=arguments.max_new_tokens)
        cases = authored_cases()
        provider = LocalInstructProvider(
            arguments.source,
            expected_inventory_sha256=arguments.expected_source_sha256,
            allow_local_context=arguments.allow_owned_context,
            limits=limits,
        )
        results = run_cases(provider, cases)
        report = {
            "version": "owned-instruct-diagnostic-0.2.0",
            "purpose": "owned_functional_check_not_quality_benchmark",
            "identity": provider.identity.model_dump(mode="json"),
            "limits": asdict(limits),
            "system_instructions_sha256": hashlib.sha256(SYSTEM_INSTRUCTIONS.encode()).hexdigest(),
            "answer_schema_sha256": hashlib.sha256(
                json.dumps(DraftAnswer.model_json_schema(), sort_keys=True).encode()
            ).hexdigest(),
            "cases": results,
            "independent_test": False,
            "production_quality_proven": False,
            "automatic_activation": False,
            "patch_generation_enabled": False,
            "formal_verification": "not_run",
            "requires_human_review": True,
        }
        encoded = (
            json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        ).encode()
        if len(encoded) > 256 * 1024:
            raise ValueError("diagnostic output exceeds budget")
        with arguments.output.open("xb") as stream:
            stream.write(encoded)
        accepted = sum(case["status"] == "schema_valid_draft" for case in results)
        print(
            json.dumps(
                {
                    "schema_valid_drafts": accepted,
                    "rejected": len(results) - accepted,
                    "production_quality_proven": False,
                    "automatic_activation": False,
                }
            )
        )
        return 0
    except Exception:
        print("Owned instruct diagnostic is unavailable.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
