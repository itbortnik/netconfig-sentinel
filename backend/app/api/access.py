"""Role checks before body parsing and storage access, independent of browser controls."""

from collections.abc import Callable
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict

from app.api.service import AnalysisService
from app.audit.contracts import PermissionDecision, ResultMetadata, metadata_hash
from app.core.permissions import PERMISSIONS, Permission, Role
from app.core.settings import ApiSettings

router = APIRouter(prefix="/api/v1", tags=["access"])
bearer = HTTPBearer(auto_error=False)


def authorize(request: Request, permission: Permission) -> None:
    role = cast(Role | None, getattr(request.state, "service_role", None))
    granted = role is not None and role in PERMISSIONS and permission in PERMISSIONS[role]
    decisions = cast(
        dict[Permission, PermissionDecision], getattr(request.state, "operation_permissions", {})
    )
    decisions[permission] = PermissionDecision(permission=permission, granted=granted)
    request.state.operation_permissions = decisions
    if not granted:
        raise HTTPException(status_code=403, detail="Operation is not permitted for this role.")


def require_access(permission: Permission) -> Callable[..., AnalysisService]:
    def required(
        request: Request,
        credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> AnalysisService:
        settings = cast(ApiSettings | None, request.app.state.api_settings)
        service = cast(AnalysisService | None, request.app.state.analysis_service)
        if settings is None or service is None:
            raise HTTPException(status_code=503, detail="Persistent API is not configured.")
        role = settings.role_for_token(credential.credentials) if credential is not None else None
        if role is None:
            request.state.operation_permissions = {
                permission: PermissionDecision(permission=permission, granted=False)
            }
            raise HTTPException(
                status_code=401,
                detail="Authentication required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        request.state.service_role = role
        authorize(request, permission)
        if getattr(request.state, "operation_journal_unavailable", False):
            raise HTTPException(status_code=503, detail="Storage schema is unavailable.")
        if not service.store.ready():
            raise HTTPException(status_code=503, detail="Storage schema is unavailable.")
        return service

    return required


class SessionAccess(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["service-access-0.3.0"] = "service-access-0.3.0"
    role: Role
    permissions: tuple[Permission, ...]
    individual_identity_verified: Literal[False] = False
    device_scope: Literal["all_saved_devices"] = "all_saved_devices"


@router.get("/session", response_model=SessionAccess)
def session_access(
    request: Request, service: Annotated[AnalysisService, Depends(require_access("read"))]
) -> SessionAccess:
    role = cast(Role, request.state.service_role)
    result = SessionAccess(role=role, permissions=PERMISSIONS[role])
    request.state.operation_result = ResultMetadata(
        metadata_sha256=metadata_hash(result.model_dump(mode="json")),
        result_count=1,
        versions=(result.version,),
    )
    return result
