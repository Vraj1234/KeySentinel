"""Rotation management endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import (
    PipelineStatusResponse,
    RotationEventListResponse,
    RotationEventResponse,
    RotationTriggerRequest,
)
from src.db.database import get_db
from src.models.rotation import RotationEvent

router = APIRouter(prefix="/api/v1/rotation", tags=["rotation"])


@router.post("/trigger", response_model=PipelineStatusResponse)
async def trigger_rotation(
    body: RotationTriggerRequest,
    db: AsyncSession = Depends(get_db),
) -> PipelineStatusResponse:
    """Trigger rotation for a secret.

    In a full deployment this would enqueue a Celery task. For now it
    creates a pending rotation event and returns the pipeline status.
    """
    from uuid import uuid4

    event = RotationEvent(
        id=str(uuid4()),
        secret_id=body.secret_id,
        triggered_by="manual",
        reason=body.reason,
    )
    db.add(event)
    await db.commit()

    return PipelineStatusResponse(
        pipeline_id=event.id,
        status="pending",
        started_at=event.started_at,
    )


@router.get("/events", response_model=RotationEventListResponse)
async def list_rotation_events(
    secret_id: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> RotationEventListResponse:
    """List rotation events with optional filters."""
    query = select(RotationEvent)

    if secret_id is not None:
        query = query.where(RotationEvent.secret_id == secret_id)
    if status is not None:
        query = query.where(RotationEvent.status == status)

    result = await db.execute(query)
    events = list(result.scalars().all())
    return RotationEventListResponse(
        items=[RotationEventResponse.model_validate(e) for e in events],
        total=len(events),
    )


@router.get("/events/{event_id}", response_model=RotationEventResponse)
async def get_rotation_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
) -> RotationEventResponse:
    """Get a single rotation event by ID."""
    result = await db.execute(
        select(RotationEvent).where(RotationEvent.id == event_id)
    )
    event = result.scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Rotation event not found")
    return RotationEventResponse.model_validate(event)
