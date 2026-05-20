"""Pydantic v2 request/response schemas for the REST API."""

from datetime import datetime

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------


class SecretResponse(BaseModel):
    id: str
    name: str
    secret_type: str
    provider: str
    location: str
    location_detail: str
    risk_level: str = "info"
    risk_score: float = 0.0
    is_active: bool = True
    created_at: datetime | None = None
    last_rotated_at: datetime | None = None
    expires_at: datetime | None = None
    max_age_days: int | None = None
    owner_service: str | None = None
    description: str | None = None

    model_config = {"from_attributes": True}


class SecretCreateRequest(BaseModel):
    name: str
    secret_type: str
    provider: str
    location: str
    location_detail: str
    risk_level: str = "info"
    owner_service: str | None = None
    description: str | None = None
    max_age_days: int | None = None


class SecretUpdateRequest(BaseModel):
    name: str | None = None
    risk_level: str | None = None
    owner_service: str | None = None
    description: str | None = None
    max_age_days: int | None = None
    is_active: bool | None = None


class SecretListResponse(BaseModel):
    items: list[SecretResponse]
    total: int


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class RotationTriggerRequest(BaseModel):
    secret_id: str
    reason: str = "Manual rotation"
    force: bool = False


class RotationEventResponse(BaseModel):
    id: str
    secret_id: str
    status: str
    triggered_by: str
    reason: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None

    model_config = {"from_attributes": True}


class RotationEventListResponse(BaseModel):
    items: list[RotationEventResponse]
    total: int


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


class RiskAssessmentRequest(BaseModel):
    secret_ids: list[str] = Field(default_factory=list)


class RiskAssessmentResponse(BaseModel):
    secret_id: str
    risk_score: float
    risk_level: str
    signal_count: int


class RiskAssessmentListResponse(BaseModel):
    assessments: list[RiskAssessmentResponse]
    total: int


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class GraphSummaryResponse(BaseModel):
    secret_count: int
    service_count: int
    edge_count: int


class BlastRadiusResponse(BaseModel):
    secret_id: str
    affected_count: int
    affected_services: list[str]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class PipelineStatusResponse(BaseModel):
    pipeline_id: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    detail: str
    status_code: int = 500
