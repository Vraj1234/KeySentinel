"""Compliance enforcement engine — evaluates secrets against policies."""

import logging
from datetime import UTC, datetime
from typing import Any

from src.compliance.models import ComplianceResult, ComplianceScore, RemediationItem
from src.models.policy import ComplianceFramework, PolicyType
from src.risk.policy import PolicyEvaluator

logger = logging.getLogger(__name__)

_REMEDIATION_ACTIONS: dict[str, str] = {
    PolicyType.MAX_AGE.value: "Rotate secret immediately",
    PolicyType.NO_SOURCE_CODE.value: "Move secret to an approved vault",
    PolicyType.APPROVED_STORE_ONLY.value: "Migrate to an approved secret store",
    PolicyType.NO_SHARED_CREDENTIALS.value: "Issue per-service credentials",
    PolicyType.MIN_KEY_LENGTH.value: "Regenerate with sufficient key length",
    PolicyType.REQUIRED_ROTATION.value: "Enable automatic rotation schedule",
}


class ComplianceEngine:
    """Evaluate secrets against policies and produce compliance reports."""

    def __init__(self, policies: list[dict[str, Any]]) -> None:
        self._policies = policies
        self._evaluator = PolicyEvaluator(policies)

    def evaluate_all(
        self,
        secrets: list[dict[str, Any]],
    ) -> list[ComplianceResult]:
        """Evaluate every secret against all enabled policies."""
        results: list[ComplianceResult] = []
        for secret in secrets:
            violations = self._evaluator.evaluate(secret)
            results.append(
                ComplianceResult(
                    secret_id=secret.get("id", "unknown"),
                    violations=tuple(violations),
                    is_compliant=len(violations) == 0,
                )
            )
        return results

    def calculate_score(
        self,
        results: list[ComplianceResult],
        framework: ComplianceFramework,
    ) -> ComplianceScore:
        """Calculate compliance percentage for a specific framework."""
        framework_results = []
        for r in results:
            framework_violations = tuple(
                v for v in r.violations if v.framework == framework
            )
            framework_results.append(
                ComplianceResult(
                    secret_id=r.secret_id,
                    violations=framework_violations,
                    is_compliant=len(framework_violations) == 0,
                )
            )

        total = len(framework_results)
        compliant = sum(1 for r in framework_results if r.is_compliant)
        violation_count = total - compliant
        pct = (compliant / total * 100.0) if total > 0 else 100.0

        return ComplianceScore(
            framework=framework,
            total_secrets=total,
            compliant_count=compliant,
            violation_count=violation_count,
            score_percentage=round(pct, 1),
            assessed_at=datetime.now(UTC),
        )

    def generate_remediation_items(
        self,
        results: list[ComplianceResult],
    ) -> list[RemediationItem]:
        """Create a remediation item for every violation found."""
        items: list[RemediationItem] = []
        now = datetime.now(UTC)
        for result in results:
            for violation in result.violations:
                action = _REMEDIATION_ACTIONS.get(
                    violation.policy_type.value,
                    "Review and remediate manually",
                )
                items.append(
                    RemediationItem(
                        violation=violation,
                        secret_id=result.secret_id,
                        status="open",
                        recommended_action=action,
                        created_at=now,
                    )
                )
        return items
