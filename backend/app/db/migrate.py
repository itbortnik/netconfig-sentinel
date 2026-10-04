"""Apply versioned schema upgrades to an explicitly configured database."""

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine

SCHEMA_REVISION = "0004_patch_reviews"


def upgrade_database(engine: Engine) -> None:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def main() -> int:
    url = os.environ.get("NETCONFIG_DATABASE_URL", "")
    if not url:
        print("Migration refused: NETCONFIG_DATABASE_URL is required.")
        return 2
    engine = None
    try:
        engine = create_engine(url, echo=False, hide_parameters=True)
        upgrade_database(engine)
    except Exception:
        print("Migration failed; verify the database configuration and availability.")
        return 2
    finally:
        if engine is not None:
            engine.dispose()
    print("Database schema upgraded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
