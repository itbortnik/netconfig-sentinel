"""Fixed service-key roles; no claims of individual identity or tenant isolation."""

from types import MappingProxyType
from typing import Literal

Role = Literal["reader", "analyst", "engineer", "admin"]
Permission = Literal[
    "read", "upload", "analyze", "train_model", "feedback", "draft", "verify", "model_explanation"
]
ROLE_PERMISSIONS: dict[Role, tuple[Permission, ...]] = {
    "reader": ("read",),
    "analyst": ("read", "upload", "analyze"),
    "engineer": ("read", "upload", "analyze", "feedback", "draft", "verify", "model_explanation"),
    "admin": (
        "read",
        "upload",
        "analyze",
        "train_model",
        "feedback",
        "draft",
        "verify",
        "model_explanation",
    ),
}
PERMISSIONS = MappingProxyType(ROLE_PERMISSIONS)
