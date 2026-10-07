"""Authenticated read-only diff of explicitly selected persisted snapshots."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request

from app.api.configurations import Service
from app.api.diff_contracts import SnapshotDiff
from app.audit.results import capture_result
from app.comparison.snapshots import DiffConflict, DiffLimitExceeded, compare_snapshots

router = APIRouter(prefix="/api/v1", tags=["snapshot comparison"])


@router.get("/configurations/{configuration_id}/diff", response_model=SnapshotDiff)
def snapshot_diff(
    configuration_id: UUID, reference_configuration_id: UUID, request: Request, service: Service
) -> SnapshotDiff:
    current = service.store.get_configuration(configuration_id)
    reference = service.store.get_configuration(reference_configuration_id)
    if current is None or reference is None:
        raise HTTPException(status_code=404, detail="Comparison snapshot not found.")
    try:
        return capture_result(request, compare_snapshots(reference, current))
    except DiffConflict:
        raise HTTPException(
            status_code=409, detail="Comparison inputs are incompatible or ambiguous."
        ) from None
    except DiffLimitExceeded:
        raise HTTPException(
            status_code=413, detail="Selected comparison exceeds size limits."
        ) from None
