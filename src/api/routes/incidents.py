"""Incident management and webhook endpoints."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.database import get_db
from src.incidents.models import (
    _determine_severity,
    parse_gitguardian_alert,
    parse_github_alert,
)
from src.models.incident import Incident, IncidentSeverity, IncidentStatus

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.post("/webhook/github", status_code=202)
async def github_webhook(
    payload: dict[str, Any],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Receive a GitHub secret scanning webhook and create an incident."""
    alert = parse_github_alert(payload)
    severity = _determine_severity(alert)

    incident = Incident(
        secret_id=None,
        severity=severity,
        source="github",
        title=f"GitHub alert: {alert.secret_type}",
        description=f"Secret exposed at {alert.exposed_url}",
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    return {"incident_id": incident.id, "severity": severity.value}


@router.post("/webhook/gitguardian", status_code=202)
async def gitguardian_webhook(
    payload: dict[str, Any],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Receive a GitGuardian webhook and create an incident."""
    alert = parse_gitguardian_alert(payload)
    severity = _determine_severity(alert)

    incident = Incident(
        secret_id=None,
        severity=severity,
        source="gitguardian",
        title=f"GitGuardian alert: {alert.secret_type}",
        description=f"Secret exposed at {alert.exposed_url}",
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    return {"incident_id": incident.id, "severity": severity.value}


@router.get("/")
async def list_incidents(
    severity: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """List incidents with optional filters."""
    query = select(Incident)

    if severity is not None:
        query = query.where(
            Incident.severity == IncidentSeverity(severity)
        )
    if status is not None:
        query = query.where(Incident.status == IncidentStatus(status))

    result = await db.execute(query)
    incidents = list(result.scalars().all())
    return {"items": incidents, "total": len(incidents)}


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Get incident detail including report and timeline."""
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id": incident.id,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "title": incident.title,
        "description": incident.description,
        "detected_at": incident.detected_at.isoformat()
        if incident.detected_at
        else None,
        "contained_at": incident.contained_at.isoformat()
        if incident.contained_at
        else None,
        "resolved_at": incident.resolved_at.isoformat()
        if incident.resolved_at
        else None,
        "report": incident.report,
    }


@router.put("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    body: dict[str, Any],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Update incident status (e.g., mark as resolved)."""
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    new_status = body.get("status")
    if new_status:
        incident.status = IncidentStatus(new_status)

    if new_status == IncidentStatus.CONTAINED.value:
        incident.contained_at = datetime.now(UTC)
    elif new_status == IncidentStatus.RESOLVED.value:
        incident.resolved_at = datetime.now(UTC)

    await db.commit()
    return {"id": incident.id, "status": incident.status.value}
