"""Include a previously built UI in wheels; backend-only installs remain supported."""

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class FrontendAssetsHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        directory = Path(self.root) / "frontend" / "dist"
        if self.target_name != "wheel" or not (directory / "index.html").is_file():
            return
        allowed = {".html", ".js", ".css", ".svg", ".ico", ".png", ".woff", ".woff2"}
        for path in directory.rglob("*"):
            if path.is_symlink() or (path.is_file() and path.suffix.lower() not in allowed):
                raise ValueError("Unexpected file in frontend build output")
        build_data.setdefault("force_include", {})[str(directory)] = "app/static"
