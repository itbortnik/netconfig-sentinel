"""Reproducible owned-fixture workflow; no external service, customer source or formal pass."""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

import httpx
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from sqlalchemy import text

from app.api.contracts import AnalysisResult, ConfigurationSnapshot, ModelSummary
from app.api.diff_contracts import SnapshotDiff
from app.api.explanation_contracts import ExplanationBundle
from app.api.feedback_contracts import FeedbackRecord
from app.api.patch_contracts import PatchDraft, VerificationRun
from app.audit.contracts import OperationPage
from app.core.permissions import PERMISSIONS, Role
from app.core.settings import ApiSettings
from app.db.migrate import upgrade_database
from app.domain import Vendor
from app.domain.fingerprints import finding_fingerprint
from app.patching.vendor_artifacts import recheck_vendor_draft, save_vendor_draft
from app.patching.vendor_drafts import create_vendor_draft


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DeviceDemonstration(Frozen):
    vendor: Literal["cisco", "juniper"]
    training_snapshots: Literal[8] = 8
    peer_snapshots: Literal[3] = 3
    policy_telnet_found: Literal[True] = True
    peer_telnet_found: Literal[True] = True
    reference_difference_found: Literal[True] = True
    statistical_status: Literal["completed"] = "completed"
    source_citations_checked: int = Field(ge=1)
    finding_anchors_checked: Literal[True] = True
    reader_write_status: Literal[403] = 403
    unavailable_llm_status: Literal[503] = 503
    unavailable_formal_status: Literal[503] = 503
    partial_analysis_status: Literal["partial"] = "partial"
    partial_risk_present: Literal[False] = False
    native_candidate_rechecked: Literal[True] = True
    engineer_feedback_replayed: Literal[True] = True
    patch_status: Literal["draft"] = "draft"
    review_status: Literal["needs_review"] = "needs_review"
    formal_verification: Literal["not_run"] = "not_run"
    fresh_application_readback_checked: Literal[True] = True
    saved_analysis_unchanged: Literal[True] = True


class DemoReport(Frozen):
    version: Literal["owned-workflow-demonstration-0.1.0"] = "owned-workflow-demonstration-0.1.0"
    transport: Literal["in_process_asgi"] = "in_process_asgi"
    database: Literal["isolated_sqlite"] = "isolated_sqlite"
    devices: tuple[DeviceDemonstration, DeviceDemonstration]
    operation_records_checked: int = Field(ge=1)
    encrypted_payloads_checked: int = Field(ge=1)
    customer_data_used: Literal[False] = False
    actual_instruct_model: Literal[False] = False
    live_batfish: Literal[False] = False
    transformer_run: Literal[False] = False
    semantic_document_encoder_run: Literal[False] = False
    device_commands_executed: Literal[False] = False
    browser_ui_run: Literal[False] = False
    individual_identity_verified: Literal[False] = False
    independent_quality_evaluation: Literal[False] = False
    production_qualified: Literal[False] = False
    mvp_accepted: Literal[False] = False


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("owned workflow observation did not match the required invariant")


def _safe_path(path: Path) -> None:
    selected = path.absolute()
    if any(item.is_symlink() or item.is_junction() for item in (selected, *selected.parents)):
        raise ValueError("linked demonstration directory is not supported")


def _fixture(
    vendor: Vendor, host: str, *, telnet: bool = False, vlans: int = 2, access_vlan: int = 10
) -> str:
    if vendor is Vendor.CISCO:
        return (
            f"hostname {host}\naaa new-model\nip ssh version 2\nline vty 0 4\n"
            f" transport input ssh{' telnet' if telnet else ''}\n!\n"
            "ntp server 192.0.2.1\nlogging host 192.0.2.2\n"
            + "".join(f"vlan {10 + index}\n name DEMO-{index}\n!\n" for index in range(vlans))
            + "interface Gi0/1\n switchport mode access\n"
            + f" switchport access vlan {access_vlan}\n!\n"
        )
    return (
        f"set system host-name {host}\nset system authentication-order radius\n"
        "set system services ssh protocol-version v2\n"
        + ("set system services telnet\n" if telnet else "")
        + "set system ntp server 192.0.2.1\nset system syslog host 192.0.2.2 any warning\n"
        + "".join(f"set vlans DEMO-{index} vlan-id {10 + index}\n" for index in range(vlans))
        + "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access\n"
        + f"set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members {access_vlan}\n"
    )


def run_demonstration(output: Path) -> DemoReport:
    """Create only a new owned SQLite/artifact directory, retaining incomplete failures."""
    _safe_path(output)
    output.mkdir(exist_ok=False)
    marker = output / ".incomplete"
    with marker.open("xb") as stream:
        stream.write(b"owned demonstration running\n")
    from app.main import create_app

    tokens = {role: secrets.token_urlsafe(40) for role in PERMISSIONS}
    settings = ApiSettings(
        f"sqlite:///{output.absolute() / 'demo.sqlite3'}",
        tokens["admin"],
        Fernet.generate_key().decode(),
        reader_token=tokens["reader"],
        analyst_token=tokens["analyst"],
        engineer_token=tokens["engineer"],
    )
    application = create_app(settings)
    store = application.state.analysis_service.store
    upgrade_database(store.engine)
    tracked: list[tuple[UUID, int, Role]] = []

    def request(
        client: TestClient,
        method: str,
        path: str,
        *,
        role: Role = "admin",
        status: int = 200,
        body: Mapping[str, object] | None = None,
    ) -> httpx.Response:
        response: httpx.Response = client.request(
            method,
            path,
            headers={"Authorization": "Bearer " + tokens[role]},
            json=body,
        )
        _require(response.status_code == status)
        _require(response.headers["Cache-Control"] == "no-store")
        tracked.append((UUID(response.headers["X-Operation-Id"]), status, role))
        return response

    def upload(
        client: TestClient, content: str, *, device: UUID | None = None
    ) -> ConfigurationSnapshot:
        response = request(
            client,
            "POST",
            "/api/v1/configurations",
            role="analyst",
            status=201,
            body={
                "device_id": str(device or uuid4()),
                "filename": "owned-demo.cfg",
                "content": content,
                "inventory": {
                    "device_role": "edge",
                    "site_class": "branch",
                    "service_profile": "owned-demo",
                },
            },
        )
        return ConfigurationSnapshot.model_validate(response.json())

    observations: list[DeviceDemonstration] = []
    retained: list[
        tuple[AnalysisResult, PatchDraft, VerificationRun, FeedbackRecord, ModelSummary]
    ] = []
    with TestClient(application) as client:
        _require(client.get("/health").status_code == 200)
        ready = client.get("/ready")
        _require(ready.status_code == 200 and ready.json()["checks"]["persistent_api"] is True)
        for vendor in (Vendor.CISCO, Vendor.JUNIPER):
            population = [
                upload(client, _fixture(vendor, f"demo-{vendor}-{index}", vlans=index % 4 + 1))
                for index in range(8)
            ]
            model = ModelSummary.model_validate(
                request(
                    client,
                    "POST",
                    "/api/v1/models/isolation-forest",
                    status=201,
                    body={"configuration_ids": [str(item.configuration_id) for item in population]},
                ).json()
            )
            _require(model.status == "experimental" and model.metadata.sample_count == 8)
            reference = upload(client, _fixture(vendor, f"demo-{vendor}-target"))
            before_text = _fixture(vendor, f"demo-{vendor}-target", telnet=True, access_vlan=11)
            before = upload(client, before_text, device=reference.device_id)
            analysis = AnalysisResult.model_validate(
                request(
                    client,
                    "POST",
                    f"/api/v1/configurations/{before.configuration_id}/analyze",
                    role="analyst",
                    status=201,
                    body={
                        "reference_configuration_id": str(reference.configuration_id),
                        "peer_configuration_ids": [
                            str(item.configuration_id) for item in population[:3]
                        ],
                        "statistical_model_id": str(model.model_id),
                    },
                ).json()
            )
            _require(analysis.status == "completed" and analysis.statistical is not None)
            _require(
                analysis.risk is not None
                and any(
                    item.source == "statistical" and item.status == "completed"
                    for item in analysis.risk.components
                )
            )
            _require(
                any(
                    item.detector == "peer_baseline"
                    and item.category == "baseline.management.telnet_enabled_deviation"
                    for item in analysis.findings
                )
            )
            _require(any(item.detector == "expected_configuration" for item in analysis.findings))
            finding = next(
                item for item in analysis.findings if item.category == "management.telnet_enabled"
            )
            _require(bool(finding.affected_lines) and bool(finding.evidence))
            explanation = next(
                item for item in analysis.explanations if item.finding_id == finding.finding_id
            )
            selection: dict[str, object] = {
                "analysis_id": str(analysis.analysis_id),
                "finding_sha256": finding_fingerprint(finding),
            }
            context = TypeAdapter(ExplanationBundle).validate_python(
                request(
                    client,
                    "POST",
                    f"/api/v1/findings/{finding.finding_id}/explain",
                    role="reader",
                    body=selection,
                ).json()
            )
            _require(
                context.explanation == explanation
                and all(item.citation for item in context.documents)
            )
            request(
                client,
                "POST",
                f"/api/v1/findings/{finding.finding_id}/explain",
                role="engineer",
                status=503,
                body={**selection, "provider": "llm", "allow_local_model_context": True},
            )
            feedback_body = {
                **selection,
                "feedback_id": str(uuid4()),
                "verdict": "needs_investigation",
                "comment": "Owned demo engineering observation, not ground truth.",
            }
            feedback = FeedbackRecord.model_validate(
                request(
                    client,
                    "POST",
                    f"/api/v1/findings/{finding.finding_id}/feedback",
                    role="engineer",
                    status=201,
                    body=feedback_body,
                ).json()
            )
            _require(
                request(
                    client,
                    "POST",
                    f"/api/v1/findings/{finding.finding_id}/feedback",
                    role="engineer",
                    body=feedback_body,
                ).json()
                == feedback.model_dump(mode="json")
            )
            private = output / vendor.value
            private.mkdir()
            original = private / "original.cfg"
            with original.open("xb") as stream:
                stream.write(before_text.encode("utf-8"))
            generated = create_vendor_draft(
                before_text,
                finding=finding,
                source_sha256=before.canonical.source.sha256,
                reference_id=str(reference.configuration_id),
            )
            native = private / "native-draft"
            save_vendor_draft(generated, native, before=before_text)
            _require(recheck_vendor_draft(native, original) == generated)
            after = upload(client, generated.candidate_text, device=before.device_id)
            diff = SnapshotDiff.model_validate(
                request(
                    client,
                    "GET",
                    f"/api/v1/configurations/{after.configuration_id}/diff?reference_configuration_id={before.configuration_id}",
                    role="reader",
                ).json()
            )
            _require(diff.coverage == "supported_complete" and diff.modified_count >= 1)
            draft_body = {
                "patch_id": str(uuid4()),
                "before_configuration_id": str(before.configuration_id),
                "after_configuration_id": str(after.configuration_id),
                "before_source_sha256": before.canonical.source.sha256,
                "after_source_sha256": after.canonical.source.sha256,
            }
            request(client, "POST", "/api/v1/patches", role="reader", status=403, body=draft_body)
            draft = PatchDraft.model_validate(
                request(
                    client, "POST", "/api/v1/patches", role="engineer", status=201, body=draft_body
                ).json()
            )
            verify_body = {"verification_id": str(uuid4()), "draft_sha256": draft.draft_sha256}
            review = VerificationRun.model_validate(
                request(
                    client,
                    "POST",
                    f"/api/v1/patches/{draft.patch_id}/verify",
                    role="engineer",
                    status=201,
                    body=verify_body,
                ).json()
            )
            _require(
                request(
                    client,
                    "POST",
                    f"/api/v1/patches/{draft.patch_id}/verify",
                    role="engineer",
                    body=verify_body,
                ).json()
                == review.model_dump(mode="json")
            )
            request(
                client,
                "POST",
                f"/api/v1/patches/{draft.patch_id}/verify",
                role="engineer",
                status=503,
                body={**verify_body, "verification_id": str(uuid4()), "mode": "batfish"},
            )
            _require(
                draft.status == "draft"
                and review.status == "needs_review"
                and review.preflight.formal_verification == "not_run"
            )
            _require("formal_verification_not_run" in review.validation_blockers)
            _require(
                not any(
                    item.category == "management.telnet_enabled"
                    for item in review.preflight.after_policy_findings
                )
            )
            partial = upload(
                client, _fixture(vendor, f"demo-{vendor}-partial") + "demo-unsupported-command\n"
            )
            partial_analysis = AnalysisResult.model_validate(
                request(
                    client,
                    "POST",
                    f"/api/v1/configurations/{partial.configuration_id}/analyze",
                    role="analyst",
                    status=201,
                ).json()
            )
            _require(
                partial_analysis.status == "partial"
                and partial_analysis.risk is None
                and bool(partial.canonical.unparsed_fragments)
            )
            retained.append((analysis, draft, review, feedback, model))
            observations.append(
                DeviceDemonstration(
                    vendor=vendor.value, source_citations_checked=len(context.documents)
                )
            )

    # A new application/store instance reads unchanged encrypted history with the same key.
    # This is not a process-crash/power-failure/backup-restore qualification.
    with TestClient(create_app(settings)) as restarted:
        for analysis, draft, review, feedback, model in retained:
            for path, expected in (
                (f"/api/v1/analyses/{analysis.analysis_id}", analysis),
                (f"/api/v1/patches/{draft.patch_id}", draft),
                (
                    f"/api/v1/patches/{draft.patch_id}/verifications/{review.verification_id}",
                    review,
                ),
                (f"/api/v1/models/{model.model_id}", model),
            ):
                _require(
                    request(restarted, "GET", path, role="reader").json()
                    == expected.model_dump(mode="json")
                )
            history = request(
                restarted,
                "GET",
                f"/api/v1/findings/{feedback.finding_id}/feedback?analysis_id={analysis.analysis_id}",
                role="reader",
            ).json()
            _require(history == [feedback.model_dump(mode="json")])
        request(restarted, "GET", "/api/v1/operation-audit", role="reader", status=403)
        expected_operations = tuple(tracked)
        page = OperationPage.model_validate(
            request(restarted, "GET", "/api/v1/operation-audit?limit=100").json()
        )
        records = {item.receipt.operation_id: item for item in page.records}
        for operation, status, role in expected_operations:
            record = records.get(operation)
            _require(record is not None)
            assert record is not None
            _require(
                record.completion is not None
                and record.completion.status_code == status
                and record.receipt.service_role == role
            )

    count = 0
    cipher = Fernet(settings.encryption_key.encode("ascii"))
    with store.engine.connect() as connection:
        for table, column in (
            ("devices", "identity_payload"),
            ("configurations", "payload"),
            ("analyses", "payload"),
            ("models", "payload"),
            ("finding_feedback", "payload"),
            ("patch_proposals", "payload"),
            ("verification_runs", "payload"),
            ("operation_receipts", "payload"),
            ("operation_completions", "payload"),
        ):
            for payload in connection.execute(text(f"SELECT {column} FROM {table}")).scalars():
                _require(
                    "demo-cisco" not in payload
                    and "demo-juniper" not in payload
                    and "Owned demo engineering" not in payload
                )
                _require(isinstance(json.loads(cipher.decrypt(payload.encode("ascii"))), dict))
                count += 1
    store.close()
    report = DemoReport(
        devices=(observations[0], observations[1]),
        operation_records_checked=len(expected_operations),
        encrypted_payloads_checked=count,
    )
    with (output / "report.json").open("x", encoding="utf-8") as report_stream:
        report_stream.write(report.model_dump_json(indent=2) + "\n")
    marker.unlink()
    return report
