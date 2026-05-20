from dataclasses import dataclass

from src.models.secret import RiskLevel


@dataclass(frozen=True)
class RotationRequest:
    """A request to rotate a single secret."""

    secret_id: str
    provider: str
    reason: str
    triggered_by: str  # "policy_engine", "incident_response", "manual"
    force: bool = False
    old_key_id: str | None = None
    risk_level: RiskLevel = RiskLevel.MEDIUM


@dataclass(frozen=True)
class RotationPlan:
    """A batch rotation plan with ordering and approval requirements."""

    requests: tuple[RotationRequest, ...]
    rotation_order: tuple[str, ...]  # secret_ids in safe rotation order
    requires_approval: tuple[str, ...]  # secret_ids needing human approval
