import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from src.models.policy import ComplianceFramework, PolicyType
from src.models.secret import SecretLocation
from src.risk.models import PolicyViolation

logger = logging.getLogger(__name__)

# Locations considered "approved stores"
_APPROVED_STORES = frozenset(
    {
        SecretLocation.VAULT.value,
        SecretLocation.AWS_SECRETS_MANAGER.value,
        SecretLocation.GCP_SECRET_MANAGER.value,
        SecretLocation.AZURE_KEY_VAULT.value,
    }
)


class PolicyEvaluator:
    """Evaluates secrets against a set of compliance policies.

    Accepts serialized policy dicts to avoid a direct database dependency.
    Each policy dict should have: id, name, policy_type, framework,
    threshold_value, is_enabled.
    """

    def __init__(self, policies: Sequence[dict[str, Any]]) -> None:
        self._policies = [p for p in policies if p.get("is_enabled", True)]

    def evaluate(self, secret_context: dict[str, Any]) -> list[PolicyViolation]:
        """Check a secret against all enabled policies."""
        violations: list[PolicyViolation] = []

        for policy in self._policies:
            policy_type = policy.get("policy_type", "")
            violation = None

            if policy_type == PolicyType.MAX_AGE.value:
                violation = self._check_max_age(secret_context, policy)
            elif policy_type == PolicyType.NO_SOURCE_CODE.value:
                violation = self._check_no_source_code(secret_context, policy)
            elif policy_type == PolicyType.APPROVED_STORE_ONLY.value:
                violation = self._check_approved_store(secret_context, policy)

            if violation is not None:
                violations.append(violation)

        return violations

    def _check_max_age(
        self,
        secret: dict[str, Any],
        policy: dict[str, Any],
    ) -> PolicyViolation | None:
        threshold = policy.get("threshold_value")
        if threshold is None:
            return None

        last_rotated = secret.get("last_rotated_at")
        if not last_rotated:
            return PolicyViolation(
                policy_id=policy["id"],
                policy_name=policy["name"],
                policy_type=PolicyType.MAX_AGE,
                framework=ComplianceFramework(
                    policy.get("framework", ComplianceFramework.INTERNAL.value),
                ),
                reason=f"Secret has never been rotated (max age: {threshold} days)",
                threshold_value=threshold,
                actual_value=None,
            )

        if isinstance(last_rotated, str):
            last_rotated = datetime.fromisoformat(last_rotated)
        if last_rotated.tzinfo is None:
            last_rotated = last_rotated.replace(tzinfo=UTC)

        age_days = (datetime.now(UTC) - last_rotated).days
        if age_days > threshold:
            return PolicyViolation(
                policy_id=policy["id"],
                policy_name=policy["name"],
                policy_type=PolicyType.MAX_AGE,
                framework=ComplianceFramework(
                    policy.get("framework", ComplianceFramework.INTERNAL.value),
                ),
                reason=f"Secret is {age_days} days old (max: {threshold})",
                threshold_value=threshold,
                actual_value=age_days,
            )

        return None

    def _check_no_source_code(
        self,
        secret: dict[str, Any],
        policy: dict[str, Any],
    ) -> PolicyViolation | None:
        location = secret.get("location", "")
        if location == SecretLocation.SOURCE_CODE.value:
            return PolicyViolation(
                policy_id=policy["id"],
                policy_name=policy["name"],
                policy_type=PolicyType.NO_SOURCE_CODE,
                framework=ComplianceFramework(
                    policy.get("framework", ComplianceFramework.INTERNAL.value),
                ),
                reason="Secret is stored in source code",
                threshold_value=None,
                actual_value=None,
            )
        return None

    def _check_approved_store(
        self,
        secret: dict[str, Any],
        policy: dict[str, Any],
    ) -> PolicyViolation | None:
        location = secret.get("location", "")
        if location and location not in _APPROVED_STORES:
            return PolicyViolation(
                policy_id=policy["id"],
                policy_name=policy["name"],
                policy_type=PolicyType.APPROVED_STORE_ONLY,
                framework=ComplianceFramework(
                    policy.get("framework", ComplianceFramework.INTERNAL.value),
                ),
                reason=f"Secret is in '{location}', not an approved store",
                threshold_value=None,
                actual_value=None,
            )
        return None
