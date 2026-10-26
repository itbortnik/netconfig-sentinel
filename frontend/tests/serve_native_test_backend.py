"""Owned loopback HTTP browser harness with disposable storage and real worker restarts.

Only this test executable adds authenticated control routes. Production routes, native
generation and encrypted history are the real application. No model/engine is enabled.
"""

import argparse
import asyncio
import hashlib
import os
import secrets
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "backend"))
for name in tuple(os.environ):
    if name.startswith("NETCONFIG_"):
        os.environ.pop(name, None)

import uvicorn  # noqa: E402
from app.core.settings import ApiSettings  # noqa: E402
from app.db.migrate import upgrade_database  # noqa: E402
from app.db.native_patch_records import NativePatchRecords  # noqa: E402
from app.db.store import Store  # noqa: E402
from app.db.tables import (  # noqa: E402
    AuditRow,
    ConfigurationSourceRow,
    NativePatchCandidateRow,
)
from app.main import create_app  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402
from fastapi import Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from sqlalchemy import delete, func, select  # noqa: E402

ADMIN = "native-http-test-admin-service-token-0000001"
ENGINEER = "native-http-test-engineer-service-token-001"
READER = "native-http-test-reader-service-token-00001"
CONTROL = "native-http-test-owned-control-token-000001"
MARKERS = ("owned-native-password-marker", "owned-native-community-marker")
RESTART_HISTORY = 75
RESTART_NORMAL = 76


def settings(database_url: str, key: str) -> ApiSettings:
    return ApiSettings(
        database_url, ADMIN, key, reader_token=READER, engineer_token=ENGINEER
    )


def worker(history_only: bool) -> int:
    application = create_app(
        settings(
            os.environ["SENTINEL_NATIVE_TEST_DATABASE"],
            os.environ["SENTINEL_NATIVE_TEST_KEY"],
        ),
        frontend_dir=REPOSITORY / "frontend" / "dist",
    )
    store = application.state.analysis_service.store
    state = {"generator_calls": 0, "forbidden_calls": 0, "restart_code": 0}

    import app.patching.native_patches as workflow

    actual_generate = workflow.create_vendor_draft

    def counted_generator(*args, **kwargs):
        state["generator_calls"] += 1
        return actual_generate(*args, **kwargs)

    workflow.create_vendor_draft = counted_generator
    if history_only:
        import app.detection.policy_engine as policies
        import app.ingestion.source_retention as retention
        import app.parsers as parsers
        import app.patching.vendor_drafts as drafts
        from app.db.source_records import SourceRecords

        def forbidden(*args, **kwargs):
            state["forbidden_calls"] += 1
            raise RuntimeError("Runtime access is forbidden in owned history-only worker.")

        SourceRecords.get = forbidden
        workflow.create_vendor_draft = forbidden
        workflow.prepare_original_source = forbidden
        workflow.evaluate_policies = forbidden
        drafts.create_vendor_draft = forbidden
        drafts.check_vendor_draft = forbidden
        drafts.parse_configuration = forbidden
        retention.parse_configuration = forbidden
        parsers.parse_configuration = forbidden
        policies.evaluate_policies = forbidden
        policies.POLICY_CATALOGS = {}

    async def control_allowed(request: Request, maximum: int = 0) -> bool:
        if (
            request.client is None
            or request.client.host != "127.0.0.1"
            or request.headers.get("host") != "127.0.0.1:8311"
            or not secrets.compare_digest(
                request.headers.get("authorization", ""), "Bearer " + CONTROL
            )
        ):
            return False
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > maximum:
                return False
        return True

    def private_summary(candidate_id: UUID) -> dict | None:
        private = NativePatchRecords(store).get(candidate_id)
        if private is None:
            return None
        public = private.public
        expected = (
            private.before_text.replace(" transport input ssh telnet", " transport input ssh")
            if public.metadata.review.proposal.vendor.value == "cisco"
            else private.before_text.replace("set system services telnet\n", "")
        )
        with store._sessions() as session:
            source_present = session.get(
                ConfigurationSourceRow, str(public.configuration_id)
            ) is not None
            encrypted = session.get(NativePatchCandidateRow, str(candidate_id)).payload
            audit_count = session.scalar(
                select(func.count()).select_from(AuditRow).where(
                    AuditRow.action == "native_patch.created",
                    AuditRow.resource_id == str(candidate_id),
                )
            )
        return {
            "candidate_id": str(candidate_id),
            "configuration_id": str(public.configuration_id),
            "review_sha256": public.review_sha256,
            "before_sha256": hashlib.sha256(private.before_text.encode()).hexdigest(),
            "candidate_sha256": hashlib.sha256(private.candidate_text.encode()).hexdigest(),
            "both_markers_in_before": all(m in private.before_text for m in MARKERS),
            "both_markers_in_candidate": all(m in private.candidate_text for m in MARKERS),
            "ciphertext_omits_markers": all(m not in encrypted for m in MARKERS),
            "exact_expected_transformation": expected == private.candidate_text,
            "original_source_present": source_present,
            "domain_creation_events": audit_count,
        }

    @application.get("/_test/native/state")
    async def inspect_state(request: Request):
        if not await control_allowed(request):
            return JSONResponse({"detail": "Owned control denied."}, status_code=403)
        return {
            "pid": os.getpid(), "history_only": history_only,
            "generator_calls": state["generator_calls"],
            "forbidden_calls": state["forbidden_calls"],
            "model_configured": application.state.local_model is not None,
            "network_engine_configured": (
                application.state.patch_verification.settings.allow_engine_upload
            ),
        }

    @application.get("/_test/native/private/{candidate_id}")
    async def inspect_private(candidate_id: UUID, request: Request):
        if not await control_allowed(request):
            return JSONResponse({"detail": "Owned control denied."}, status_code=403)
        try:
            result = private_summary(candidate_id)
            return result or JSONResponse({"detail": "Owned record missing."}, status_code=404)
        except Exception:
            return JSONResponse({"detail": "Owned inspection unavailable."}, status_code=503)

    @application.post("/_test/native/retire-source/{candidate_id}")
    async def retire_source(candidate_id: UUID, request: Request):
        if not await control_allowed(request):
            return JSONResponse({"detail": "Owned control denied."}, status_code=403)
        try:
            summary = private_summary(candidate_id)
            if summary is None:
                return JSONResponse({"detail": "Owned record missing."}, status_code=404)
            with store.engine.begin() as connection:
                connection.execute(delete(ConfigurationSourceRow).where(
                    ConfigurationSourceRow.configuration_id == summary["configuration_id"]
                ))
            return private_summary(candidate_id)
        except Exception:
            return JSONResponse({"detail": "Owned retirement unavailable."}, status_code=503)

    @application.post("/_test/native/restart/{mode}")
    async def restart_worker(mode: str, request: Request):
        if not await control_allowed(request) or mode not in {"normal", "history"}:
            return JSONResponse({"detail": "Owned control denied."}, status_code=403)
        state["restart_code"] = RESTART_HISTORY if mode == "history" else RESTART_NORMAL
        asyncio.get_running_loop().call_later(0.1, setattr, server, "should_exit", True)
        return {"pid": os.getpid(), "restart_requested": True}

    @application.post("/_test/native/shutdown")
    async def shutdown_worker(request: Request):
        if not await control_allowed(request):
            return JSONResponse({"detail": "Owned control denied."}, status_code=403)
        state["restart_code"] = 0
        asyncio.get_running_loop().call_later(0.1, setattr, server, "should_exit", True)
        return {"shutdown_requested": True}

    server = uvicorn.Server(uvicorn.Config(
        application, host="127.0.0.1", port=8311, log_level="warning", access_log=False,
    ))
    try:
        server.run()
    finally:
        store.close()
    return state["restart_code"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--history-only", action="store_true")
    args = parser.parse_args()
    if args.worker:
        return worker(args.history_only)
    # Neither the key nor private database is written to test evidence or the repository.
    with TemporaryDirectory(prefix="sentinel-native-http-") as folder:
        database_url = f"sqlite:///{Path(folder) / 'history.sqlite3'}"
        key = Fernet.generate_key().decode("ascii")
        store = Store(settings(database_url, key))
        upgrade_database(store.engine)
        store.close()
        environment = {
            **os.environ, "SENTINEL_NATIVE_TEST_DATABASE": database_url,
            "SENTINEL_NATIVE_TEST_KEY": key,
        }
        history_only = False
        while True:
            command = [sys.executable, str(Path(__file__).resolve()), "--worker"]
            if history_only:
                command.append("--history-only")
            child = subprocess.Popen(
                command, env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            try:
                result = child.wait()
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)
            if result not in {RESTART_HISTORY, RESTART_NORMAL}:
                break
            history_only = result == RESTART_HISTORY
    print("Owned native test storage removed.", flush=True)
    return result


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Owned native HTTP test server unavailable.", file=sys.stderr)
        raise SystemExit(1) from None
