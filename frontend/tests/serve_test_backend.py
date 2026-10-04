"""Ephemeral loopback-only backend for browser tests; never touches the working database."""

import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "backend"))
# Keep this child test process independent of a developer's configured API database.
for name in (
    "NETCONFIG_DATABASE_URL",
    "NETCONFIG_API_TOKEN",
    "NETCONFIG_ENCRYPTION_KEY",
    "NETCONFIG_READER_TOKEN",
    "NETCONFIG_ANALYST_TOKEN",
    "NETCONFIG_ENGINEER_TOKEN",
    "NETCONFIG_LLM_ENDPOINT",
    "NETCONFIG_LLM_MODEL",
    "NETCONFIG_LLM_ALLOW_LOCAL_CONTEXT",
    "NETCONFIG_LLM_API_KEY",
):
    os.environ.pop(name, None)

import uvicorn  # noqa: E402
from app.core.settings import ApiSettings  # noqa: E402
from app.db.migrate import upgrade_database  # noqa: E402
from app.db.store import Store  # noqa: E402
from app.main import create_app  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

TOKEN = "browser-tests-service-token-32-characters-001"


def main() -> None:
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
        application = create_app(settings, frontend_dir=REPOSITORY / "frontend" / "dist")
        uvicorn.run(application, host="127.0.0.1", port=8301, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
