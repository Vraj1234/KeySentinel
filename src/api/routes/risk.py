"""Risk assessment endpoints."""

from fastapi import APIRouter

from src.api.schemas import (
    RiskAssessmentListResponse,
    RiskAssessmentRequest,
    RiskAssessmentResponse,
)
from src.risk.engine import RiskEngine

router = APIRouter(prefix="/api/v1/risk", tags=["risk"])


@router.post("/assess", response_model=RiskAssessmentListResponse)
async def trigger_risk_assessment(
    body: RiskAssessmentRequest,
) -> RiskAssessmentListResponse:
    """Trigger risk assessment for specified secrets (or all).

    Accepts a list of secret context dicts via secret_ids. In a full
    deployment, secret data would be fetched from the database. For now,
    this endpoint demonstrates the risk engine integration.
    """
    engine = RiskEngine()

    contexts = [
        {"secret_id": sid, "location": "unknown"}
        for sid in body.secret_ids
    ]

    assessments = await engine.assess_batch(contexts)
    results = [
        RiskAssessmentResponse(
            secret_id=a.secret_id,
            risk_score=a.risk_score,
            risk_level=a.risk_level.value,
            signal_count=len(a.signals),
        )
        for a in assessments
    ]

    return RiskAssessmentListResponse(
        assessments=results,
        total=len(results),
    )
