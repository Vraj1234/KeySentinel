"""Domain models for compliance assessment and reporting."""

from dataclasses import dataclass
from datetime import datetime

from src.models.policy import ComplianceFramework
from src.risk.models import PolicyViolation


@dataclass(frozen=True)
class ComplianceResult:
    """Compliance evaluation result for a single secret."""

    secret_id: str
    violations: tuple[PolicyViolation, ...]
    is_compliant: bool


@dataclass(frozen=True)
class ComplianceScore:
    """Aggregate compliance score for a framework."""

    framework: ComplianceFramework
    total_secrets: int
    compliant_count: int
    violation_count: int
    score_percentage: float
    assessed_at: datetime


@dataclass(frozen=True)
class RemediationItem:
    """A tracked remediation action for a policy violation."""

    violation: PolicyViolation
    secret_id: str
    status: str  # "open", "in_progress", "resolved"
    recommended_action: str
    created_at: datetime


@dataclass(frozen=True)
class ComplianceReport:
    """Complete compliance report for a framework."""

    framework: ComplianceFramework
    score: ComplianceScore
    results: tuple[ComplianceResult, ...]
    remediation_items: tuple[RemediationItem, ...]
    executive_summary: str
    generated_at: datetime
