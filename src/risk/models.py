from dataclasses import dataclass
from datetime import datetime

from src.models.policy import ComplianceFramework, PolicyType
from src.models.secret import RiskLevel


@dataclass(frozen=True)
class RiskSignal:
    """A single risk signal produced by a rule evaluation."""

    rule_id: str
    severity: RiskLevel
    score_delta: float  # positive value increases risk score
    reason: str


@dataclass(frozen=True)
class RiskAssessment:
    """Aggregated risk assessment for a single secret."""

    secret_id: str
    signals: tuple[RiskSignal, ...]
    risk_score: float  # 0.0 - 100.0
    risk_level: RiskLevel
    assessed_at: datetime


@dataclass(frozen=True)
class PolicyViolation:
    """A policy rule that a secret violates."""

    policy_id: str
    policy_name: str
    policy_type: PolicyType
    framework: ComplianceFramework
    reason: str
    threshold_value: int | None
    actual_value: int | None
