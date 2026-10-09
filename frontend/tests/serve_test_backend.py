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
        except (ValueError, KeyError, IndexError, TypeError):
            self.send_error(400, "Invalid owned fixture request")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-patch-fixture", action="store_true")
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
            )
        try:
            application = create_app(
                settings, frontend_dir=REPOSITORY / "frontend" / "dist", local_model=model
            )
            uvicorn.run(
                application,
                host="127.0.0.1",
                port=8302 if options.model_patch_fixture else 8301,
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
