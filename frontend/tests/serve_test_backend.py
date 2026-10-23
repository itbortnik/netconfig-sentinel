"""Ephemeral loopback-only backend for browser tests; never touches the working database."""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "backend"))
# Keep this child test process independent of a developer's configured API database.
for name in tuple(os.environ):
    if not name.startswith("NETCONFIG_"):
        continue
    os.environ.pop(name, None)

import uvicorn  # noqa: E402
from app.core.local_model import LocalModelSettings  # noqa: E402
from app.core.settings import ApiSettings  # noqa: E402
from app.db.migrate import upgrade_database  # noqa: E402
from app.db.store import Store  # noqa: E402
from app.main import create_app  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

TOKEN = "browser-tests-service-token-32-characters-001"


def synthetic_pair_worker(settings, job):
    """Authored two-sided numbers; never an encoder or quality measurement."""
    from ml.inference.config_contracts import ConfigurationInferenceReport
    from ml.inference.pair_contracts import ConfigurationPairReport

    if job.before.canonical.device.hostname.startswith("source-ml-fail"):
        raise ValueError("owned fixture unavailable")

    def side(source, anomaly, category):
        return ConfigurationInferenceReport.model_validate(
            {
                "model": {
                    "version": "config-model-card-0.1.0",
                    "kind": "native",
                    "model_sha256": job.model_sha256,
                    "training_format": "multitask-training-0.1.0",
                    "report_sha256": "b" * 64,
                    "encoder_sha256": "c" * 64,
                    "tokenizer_sha256": "d" * 64,
                    "source_manifest_sha256": None,
                    "train_fingerprint": "e" * 64,
                    "selection_fingerprint": "f" * 64,
                    "classes": ["telnet_enabled"],
                    "enabled_heads": {
                        "anomaly": True,
                        "category": True,
                        "localization": True,
                        "severity": False,
                        "contrastive": False,
                    },
                    "parameter_count": 200,
                    "trainable_parameters": 100,
                    "train_examples": 4,
                    "selection_examples": 2,
                    "target_semantics": "injected_mutation",
                    "external_pretraining_exposure": "not_applicable",
                },
                "prediction": {
                    "raw_source_sha256": source.snapshot.source_sha256,
                    "sanitized_source_sha256": "1" * 64,
                    "model_sha256": job.model_sha256,
                    "total_lines": len(source.content.splitlines()),
                    "anomaly_score": anomaly,
                    "category_scores": {"telnet_enabled": category},
                    "severity_scores": None,
                    "line_scores": [0.2] + [None] * (len(source.content.splitlines()) - 1),
                    "block_attention": [1.0],
                    "embedding_sha256": None,
                    "embedding_dimensions": 0,
                    "replacement_counts": {},
                },
                "runtime_torch_version": "owned-browser-pair-fixture",
            }
        )

    return ConfigurationPairReport(
        before=side(job.before_source, 0.8, 0.6), after=side(job.after_source, 0.2, 0.3)
    )


class SyntheticProvider(BaseHTTPRequestHandler):
    """Fixed owned protocol fixture; no language model, engine or external service."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if self.path != "/v1/chat/completions" or not 0 < size <= 128 * 1024:
                raise ValueError("invalid owned fixture request")
            wire = json.loads(self.rfile.read(size))
            context = json.loads(wire["messages"][1]["content"])
            if context.get("version") in (
                "grounded-explanation-context-0.1.0",
                "grounded-explanation-context-0.2.0",
            ):
                answer = {
                    "version": "grounded-explanation-answer-0.1.0",
                    "facts_binding_sha256": context["facts_binding_sha256"],
                    "fact_refs": context["available_fact_refs"],
                    "recommendation_code": context["recommendation_code"],
                    "missing_information_codes": [],
                    "patch_draft": None,
                    "citations": context["required_citations"],
                    "requires_human_review": True,
                }
                # Authored rejection input: SSHv1's current source anchor is line4.
                # This explicit software fixture has no production/model behavior.
                facts = context["source_facts"]
                if facts["vendor"] == "cisco" and any(
                    anchor["lines"] == [4] for anchor in facts["anchors"]
                ):
                    answer["fact_refs"] = ["formal_passed"]
                self.send_answer(answer)
                return
            supplied = context
            grounded = context.get("version") in (
                "source-bound-grounded-patch-context-0.1.0",
                "source-bound-grounded-patch-context-0.2.0",
            )
            if grounded:
                context = context["supplied_patch_context"]
            patch = None
            if context["vendor"] == "cisco":
                patch = {
                    "edits": [
                        {
                            "source_line": context["affected_block"][0]["source_line"],
                            "replacement": "transport input ssh"
                            if context["finding"]["category"] == "management.telnet_enabled"
                            else "ip ssh version 2",
                        }
                    ]
                }
            answer = {
                "summary": "Owned synthetic browser fixture; not a model-quality measurement.",
                "technical_explanation": "Only the selected management command is proposed.",
                "possible_impact": [],
                "recommendation": "Review independently; this fixture proves only the workflow.",
                "patch_draft": patch,
                "assumptions": [],
                "missing_information": ["Device syntax, management access and network checks."],
                "citations": [context["documents"][0]["citation"]],
                "requires_human_review": True,
            }
            if grounded:
                answer = {
                    "version": "grounded-model-patch-answer-0.1.0",
                    "facts_binding_sha256": supplied["facts_binding_sha256"],
                    "fact_refs": ["selected_finding_before", "source_management_observation"],
                    "possible_impact_codes": [],
                    "recommendation_code": "request_human_review_and_missing_checks",
                    "missing_information_codes": ["baseline_approval", "formal_verification"],
                    "patch_draft": patch,
                    "citations": answer["citations"],
                    "requires_human_review": True,
                }
                # Explicit authored browser failure fixture, never a production provider:
                # Cisco SSHv1 placed on line4 returns a forbidden positive check code.
                if (
                    context["vendor"] == "cisco"
                    and context["finding"]["category"] == "management.ssh_version_1"
                    and context["affected_block"][0]["source_line"] == 4
                ):
                    answer["fact_refs"] = ["formal_passed"]
        except (ValueError, KeyError, IndexError, TypeError):
            self.send_error(400, "Invalid owned fixture request")
            return
        self.send_answer(answer)

    def send_answer(self, answer):
        payload = json.dumps(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(answer),
                        },
                    }
                ]
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--model-patch-fixture", action="store_true")
    mode.add_argument("--source-patch-fixture", action="store_true")
    mode.add_argument("--source-ml-fixture", action="store_true")
    mode.add_argument("--source-forest-fixture", action="store_true")
    mode.add_argument("--source-deterministic-fixture", action="store_true")
    mode.add_argument("--source-evidence-fixture", action="store_true")
    mode.add_argument("--source-evidence-decision-fixture", action="store_true")
    options = parser.parse_args()
    artifacts = REPOSITORY / "artifacts"
    artifacts.mkdir(exist_ok=True)
    with TemporaryDirectory(prefix="ui-test-", dir=artifacts) as temporary:
        settings = ApiSettings(
            f"sqlite:///{Path(temporary) / 'history.sqlite3'}",
            TOKEN,
            Fernet.generate_key().decode("ascii"),
            reader_token="browser-tests-reader-service-token-000001",
            analyst_token="browser-tests-analyst-service-token-000001",
            engineer_token="browser-tests-engineer-service-token-000001",
        )
        store = Store(settings)
        upgrade_database(store.engine)
        store.close()
        server = None
        thread = None
        model = None
        if options.model_patch_fixture:
            server = ThreadingHTTPServer(("127.0.0.1", 0), SyntheticProvider)
            thread = Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
            thread.start()
            model = LocalModelSettings(
                f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                "owned-synthetic-browser-fixture",
                allow_local_context=True,
                allow_patch_draft=True,
                allow_grounded_patch_draft=True,
                allow_grounded_explanation=True,
            )
        try:
            verification = None
            configuration_model = None
            if options.source_deterministic_fixture:
                import app.patching.source_deterministic as deterministic_workflow

                deterministic_pair = deterministic_workflow.recheck_original_deterministic

                def owned_deterministic_worker(before, after, analysis, reference=None):
                    # Only this explicit authored control fails; normal requests run real detectors.
                    if (before.canonical.device.hostname or "").startswith(
                        "source-deterministic-fail-"
                    ):
                        raise ValueError("owned fixture unavailable")
                    return deterministic_pair(before, after, analysis, reference)

                deterministic_workflow.recheck_original_deterministic = owned_deterministic_worker
            if options.source_forest_fixture:
                import app.patching.source_forest as forest_workflow

                numeric_forest = forest_workflow.recheck_original_forest

                def owned_forest_worker(before, after, analysis, registered):
                    # Authored failure control; normal requests run the actual numeric Forest.
                    if (before.canonical.device.hostname or "").startswith("source-forest-fail"):
                        raise ValueError("owned fixture unavailable")
                    return numeric_forest(before, after, analysis, registered)

                forest_workflow.recheck_original_forest = owned_forest_worker
            if (
                options.source_ml_fixture
                or options.source_evidence_fixture
                or options.source_evidence_decision_fixture
            ):
                import app.patching.source_ml as source_ml_workflow
                from app.core.configuration_model import ConfigurationModelSettings

                configuration_model = ConfigurationModelSettings(
                    registry_root=Path(temporary) / "synthetic-registry", model_sha256="9" * 64
                )
                source_ml_workflow.run_configuration_pair_job = synthetic_pair_worker
            if (
                options.source_patch_fixture
                or options.source_evidence_fixture
                or options.source_evidence_decision_fixture
            ):
                import app.patching.source_review as source_workflow
                from app.core.patch_verification import PatchVerificationSettings
                from app.verification.batfish import BatfishExecution, BatfishResult

                def synthetic_source_worker(before, after, scope, **kwargs):
                    # Explicit owned software fixture: no SDK/model/engine is invoked.
                    hostname = scope.start_node
                    failed = (
                        options.source_evidence_fixture or options.source_evidence_decision_fixture
                    ) and hostname.startswith("source-evidence-error-")
                    empty = (
                        options.source_evidence_fixture or options.source_evidence_decision_fixture
                    ) and hostname.startswith("source-evidence-inconclusive-")
                    return BatfishResult(
                        before_sha256=before.digest,
                        after_sha256=after.digest,
                        scope=scope,
                        status="error"
                        if failed
                        else "inconclusive"
                        if empty
                        else "no_differences_in_scope",
                        reason="engine_error"
                        if failed
                        else "empty_reachable_scope"
                        if empty
                        else "query_completed",
                        engine_version="owned-browser-fixture",
                        difference_count=None if failed else 0,
                        before_reachable_count=None if failed else 0 if empty else 1,
                        after_reachable_count=None if failed else 0 if empty else 1,
                        cleanup_complete=True,
                    )

                source_workflow.check_with_batfish = synthetic_source_worker

                def synthetic_source_execution(before, after, scope, **kwargs):
                    # Explicit software controls for the SDK metadata wire; no SDK is loaded.
                    hostname = scope.start_node
                    if hostname.startswith("source-sdk-not-observed-"):
                        return BatfishExecution(
                            result=BatfishResult(
                                before_sha256=before.digest,
                                after_sha256=after.digest,
                                scope=scope,
                                status="error",
                                reason="worker_failed",
                            ),
                            sdk_version=None,
                            sdk_observation="not_observed",
                        )
                    unavailable = hostname.startswith("source-sdk-metadata-unavailable-")
                    return BatfishExecution(
                        result=synthetic_source_worker(before, after, scope, **kwargs),
                        sdk_version=None if unavailable else "owned-browser-sdk-0.36.0",
                        sdk_observation="metadata_unavailable" if unavailable else "observed",
                    )

                source_workflow.check_with_batfish_evidence = synthetic_source_execution
                verification = PatchVerificationSettings(allow_engine_upload=True)
            application = create_app(
                settings,
                frontend_dir=REPOSITORY / "frontend" / "dist",
                local_model=model,
                patch_verification=verification,
                configuration_model=configuration_model,
            )
            uvicorn.run(
                application,
                host="127.0.0.1",
                port=8308
                if options.source_evidence_decision_fixture
                else 8307
                if options.source_evidence_fixture
                else 8306
                if options.source_deterministic_fixture
                else 8305
                if options.source_forest_fixture
                else 8304
                if options.source_ml_fixture
                else 8303
                if options.source_patch_fixture
                else (8302 if options.model_patch_fixture else 8301),
                log_level="warning",
                access_log=False,
            )
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=2)


if __name__ == "__main__":
    main()
