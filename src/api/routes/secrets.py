"""Secret inventory endpoints."""

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import (
    SecretCreateRequest,
    SecretListResponse,
    SecretResponse,
    SecretUpdateRequest,
)
from src.db.database import get_db
from src.models.secret import RiskLevel, Secret, SecretLocation, SecretType

router = APIRouter(prefix="/api/v1/secrets", tags=["secrets"])


@router.get("/", response_model=SecretListResponse)
async def list_secrets(
    risk_level: str | None = None,
    location: str | None = None,
    provider: str | None = None,
    is_active: bool | None = None,
    db: AsyncSession = Depends(get_db),
) -> SecretListResponse:
    """List secrets with optional filters."""
    query = select(Secret)

    if risk_level is not None:
        query = query.where(Secret.risk_level == RiskLevel(risk_level))
    if location is not None:
        query = query.where(Secret.location == SecretLocation(location))
    if provider is not None:
        query = query.where(Secret.provider == provider)
    if is_active is not None:
        query = query.where(Secret.is_active == is_active)

    result = await db.execute(query)
    secrets = list(result.scalars().all())
    return SecretListResponse(
        items=[SecretResponse.model_validate(s) for s in secrets],
        total=len(secrets),
    )


@router.get("/{secret_id}", response_model=SecretResponse)
async def get_secret(
    secret_id: str,
    db: AsyncSession = Depends(get_db),
) -> SecretResponse:
    """Get a single secret by ID."""
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return SecretResponse.model_validate(secret)


@router.post("/", response_model=SecretResponse, status_code=201)
async def create_secret(
    body: SecretCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> SecretResponse:
    """Register a new secret in the inventory."""
    secret = Secret(
        id=str(uuid4()),
        name=body.name,
        secret_type=SecretType(body.secret_type),
        provider=body.provider,
        location=SecretLocation(body.location),
        location_detail=body.location_detail,
        risk_level=RiskLevel(body.risk_level),
        owner_service=body.owner_service,
        description=body.description,
        max_age_days=body.max_age_days,
    )
    db.add(secret)
    await db.commit()
    await db.refresh(secret)
    return SecretResponse.model_validate(secret)


@router.put("/{secret_id}", response_model=SecretResponse)
async def update_secret(
    secret_id: str,
    body: SecretUpdateRequest,
    db: AsyncSession = Depends(get_db),
) -> SecretResponse:
    """Update secret metadata."""
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")

    update_data = body.model_dump(exclude_unset=True)
    if "risk_level" in update_data:
        update_data["risk_level"] = RiskLevel(update_data["risk_level"])

    for field, value in update_data.items():
        setattr(secret, field, value)

    await db.commit()
    await db.refresh(secret)
    return SecretResponse.model_validate(secret)


@router.delete("/{secret_id}", status_code=204)
async def delete_secret(
    secret_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Soft-delete a secret (set is_active=False)."""
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")

    secret.is_active = False
    await db.commit()
