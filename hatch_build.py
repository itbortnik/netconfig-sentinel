"""Bundle allowlisted knowledge and a built UI; backend-only installs remain supported."""

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class FrontendAssetsHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name == "wheel":
            # This is an explicit public-document allowlist, never the whole workspace.
            sources = (
                "docs/policies/management-plane.md",
                "docs/policies/observability.md",
                "docs/policies/access-control.md",
                "docs/policies/routing.md",
                "docs/policies/layer2.md",
                "docs/expected-configuration.md",
                "docs/baseline.md",
                "docs/statistical-baseline.md",
            )
            for release in ("project-knowledge-0.1.0", "project-knowledge-0.2.0"):
                for source in (*sources, "manifest.json"):
                    relative = f"knowledge/versions/{release}/{source}"
                    path = Path(self.root) / "backend" / "app" / relative
                    if path.is_symlink() or not path.is_file():
                        raise ValueError("Missing reviewed knowledge source")
                    build_data.setdefault("force_include", {})[str(path)] = f"app/{relative}"
        directory = Path(self.root) / "frontend" / "dist"
        if self.target_name != "wheel" or not (directory / "index.html").is_file():
            return
        allowed = {".html", ".js", ".css", ".svg", ".ico", ".png", ".woff", ".woff2"}
        for path in directory.rglob("*"):
            if path.is_symlink() or (path.is_file() and path.suffix.lower() not in allowed):
                raise ValueError("Unexpected file in frontend build output")
        build_data.setdefault("force_include", {})[str(directory)] = "app/static"
