"""Actual owned model-patch diagnostics; never an independent quality benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from app.detection.policy_engine import evaluate_policies
from app.explanation.knowledge import text_sha256
from app.explanation.patch_provider import (
    PATCH_INSTRUCTIONS,
    PatchDraftAnswer,
    PreparedPatchPrompt,
    build_patch_prompt,
    generate_patch_draft,
)
from app.explanation.provider import InvalidProviderAnswer
from app.parsers import parse_configuration

from ml.inference.change_artifacts import safe_path
from ml.instruct.framing import GenerationLimits
from ml.instruct.runtime import LocalInstructProvider
from ml.instruct.smoke import ObservedProvider


@dataclass(frozen=True)
class OwnedPatchCase:
    vendor: str
    prepared: PreparedPatchPrompt


def authored_patch_cases() -> tuple[OwnedPatchCase, ...]:
    cases = []
    for vendor, before, baseline, category in (
        (
            "cisco",
            "hostname owned-host\nip ssh version 2\nline vty 0 4\n transport input ssh telnet\n!\n",
            "hostname owned-host\nip ssh version 2\nline vty 0 4\n transport input ssh\n!\n",
            "management.telnet_enabled",
        ),
        (
            "cisco",
            "hostname owned-host\nip ssh version 1\n",
            "hostname owned-host\nip ssh version 2\n",
            "management.ssh_version_1",
        ),
        (
            "juniper",
            "set system host-name owned-host\nset system services ssh\n"
            "set system services telnet\n",
            "set system host-name owned-host\nset system services ssh\n",
            "management.telnet_enabled",
        ),
        (
            "juniper",
            "set system host-name owned-host\nset system services ssh protocol-version v1\n",
            "set system host-name owned-host\nset system services ssh protocol-version v2\n",
            "management.ssh_version_1",
        ),
    ):
        parsed = parse_configuration(before, filename="owned.cfg")
        finding = next(
            item
            for item in evaluate_policies(parsed, device_id=UUID(int=1))
            if item.category == category
        )
        cases.append(
            OwnedPatchCase(
                vendor,
                build_patch_prompt(
                    before,
                    finding=finding,
                    source_sha256=text_sha256(before),
                    reference_id="owned-baseline",
                    baseline=baseline,
                    allow_local_context=True,
                ),
            )
        )
    return tuple(cases)


def run_patch_cases(
    provider: ObservedProvider, cases: tuple[OwnedPatchCase, ...]
) -> list[dict[str, Any]]:
    results = []
    for case in cases:
        prepared = case.prepared
        checks = None
        candidate_sha256 = None
        try:
            generated = generate_patch_draft(provider, prepared, allow_local_context=True)
            answer = generated.answer.model_dump(mode="json")
            status = "no_candidate"
            if generated.metadata is not None and generated.candidate_text is not None:
                report = generated.metadata.review.preflight
                candidate_sha256 = text_sha256(generated.candidate_text)
                checks = {
                    "before_complete": report.before.complete,
                    "after_complete": report.after.complete,
                    "selected_category_absent_after": not any(
                        row.category == prepared.finding.category
                        for row in report.after_policy_findings
                    ),
                    "introduced_policy_findings": (
                        len(report.policy_changes.introduced) if report.policy_changes else None
                    ),
                    "review_status": generated.metadata.review.status,
                    "validation_blockers": list(generated.metadata.review.validation_blockers),
                    "device_syntax_verified": generated.metadata.device_syntax_verified,
                    "management_access_verified": generated.metadata.management_access_verified,
                    "ml_status": report.ml_status,
                    "application_supported": generated.metadata.application_supported,
                }
                status = "locally_checked_draft"
        except InvalidProviderAnswer:
            answer, status = None, "rejected"
        observation = provider.last_generation
        if observation is not None and observation.context_sha256 != prepared.prompt.context_sha256:
            observation = None
        results.append(
            {
                "vendor": case.vendor,
                "category": prepared.finding.category,
                "finding_sha256": json.loads(prepared.prompt.context_json)["finding"]["sha256"],
                "source_sha256": prepared.source_sha256,
                "context_sha256": prepared.prompt.context_sha256,
                "candidate_sha256": candidate_sha256,
                "status": status,
                "generation": asdict(observation) if observation else None,
                "answer": answer,
                "local_checks": checks,
                "formal_verification": "not_run",
                "requires_human_review": True,
                "semantic_truth_proven": False,
                "production_quality_proven": False,
            }
        )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicit offline owned model patch diagnostic")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--allow-owned-context", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        safe_path(arguments.output)
        if (
            arguments.output.suffix != ".json"
            or arguments.output.exists()
            or not arguments.output.parent.is_dir()
        ):
            raise ValueError("output must be a new JSON file")
        cases = authored_patch_cases()
        limits = GenerationLimits()
        provider = LocalInstructProvider(
            arguments.source,
            expected_inventory_sha256=arguments.expected_source_sha256,
            allow_local_context=arguments.allow_owned_context,
            allow_patch_draft=True,
            limits=limits,
        )
        results = run_patch_cases(provider, cases)
        report = {
            "version": "owned-model-patch-diagnostic-0.1.0",
            "purpose": "owned_functional_check_not_quality_benchmark",
            "identity": provider.identity.model_dump(mode="json"),
            "limits": asdict(limits),
            "patch_generation_enabled": provider.patch_generation_enabled,
            "system_instructions_sha256": text_sha256(PATCH_INSTRUCTIONS),
            "answer_schema_sha256": text_sha256(
                json.dumps(PatchDraftAnswer.model_json_schema(), sort_keys=True)
            ),
            "cases": results,
            "independent_test": False,
            "production_quality_proven": False,
            "automatic_activation": False,
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
        print(
            json.dumps(
                {
                    "locally_checked_drafts": sum(
                        row["status"] == "locally_checked_draft" for row in results
                    ),
                    "no_candidate": sum(row["status"] == "no_candidate" for row in results),
                    "rejected": sum(row["status"] == "rejected" for row in results),
                    "production_quality_proven": False,
                    "automatic_activation": False,
                }
            )
        )
        return 0
    except Exception:
        print("Owned model patch diagnostic is unavailable.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
