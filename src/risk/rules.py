import logging
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from src.models.policy import ComplianceFramework
from src.models.secret import RiskLevel, SecretLocation
from src.risk.models import RiskSignal

logger = logging.getLogger(__name__)

RuleFunction = Callable[[dict[str, Any]], Coroutine[Any, Any, RiskSignal | None]]

# Default max age when secret has no explicit policy
_DEFAULT_MAX_AGE_DAYS = 90

# Compliance frameworks that warrant elevated risk scoring
_HIGH_SEVERITY_FRAMEWORKS = frozenset(
    {
        ComplianceFramework.SOC2.value,
        ComplianceFramework.PCI_DSS.value,
        ComplianceFramework.HIPAA.value,
    }
)

# Keywords indicating high-privilege credentials
_ADMIN_KEYWORDS = frozenset(
    {
        "admin",
        "root",
        "master",
        "superuser",
        "owner",
        "FullAccess",
        "AdministratorAccess",
        "PowerUserAccess",
    }
)


async def age_check(secret_context: dict[str, Any]) -> RiskSignal | None:
    """Flag secrets that have exceeded their maximum age."""
    last_rotated = secret_context.get("last_rotated_at")
    if not last_rotated:
        # Never rotated — flag as high risk
        return RiskSignal(
            rule_id="age_check",
            severity=RiskLevel.HIGH,
            score_delta=25.0,
            reason="Secret has never been rotated",
        )

    if isinstance(last_rotated, str):
        last_rotated = datetime.fromisoformat(last_rotated)
    if last_rotated.tzinfo is None:
        last_rotated = last_rotated.replace(tzinfo=UTC)

    max_age = secret_context.get("max_age_days", _DEFAULT_MAX_AGE_DAYS)
    age_days = (datetime.now(UTC) - last_rotated).days

    if age_days > max_age * 2:
        return RiskSignal(
            rule_id="age_check",
            severity=RiskLevel.CRITICAL,
            score_delta=30.0,
            reason=f"Secret is {age_days} days old (max {max_age}), severely overdue",
        )

    if age_days > max_age:
        return RiskSignal(
            rule_id="age_check",
            severity=RiskLevel.HIGH,
            score_delta=20.0,
            reason=f"Secret is {age_days} days old (max {max_age}), overdue for rotation",
        )

    if age_days > max_age * 0.8:
        return RiskSignal(
            rule_id="age_check",
            severity=RiskLevel.MEDIUM,
            score_delta=15.0,
            reason=f"Secret is {age_days} days old, approaching max age of {max_age}",
        )

    return None


async def privilege_audit(secret_context: dict[str, Any]) -> RiskSignal | None:
    """Flag secrets with broad or administrative permissions."""
    permissions = secret_context.get("permissions", ())
    secret_name = secret_context.get("name", "")

    # Check permissions list for admin-like access
    for perm in permissions:
        perm_str = str(perm)
        if any(kw in perm_str for kw in _ADMIN_KEYWORDS):
            return RiskSignal(
                rule_id="privilege_audit",
                severity=RiskLevel.HIGH,
                score_delta=25.0,
                reason=f"Secret has admin-level permission: {perm_str}",
            )
        if "*" in perm_str:
            return RiskSignal(
                rule_id="privilege_audit",
                severity=RiskLevel.MEDIUM,
                score_delta=15.0,
                reason=f"Secret has wildcard permission: {perm_str}",
            )

    # Check secret name for admin indicators
    name_lower = secret_name.lower()
    if any(kw.lower() in name_lower for kw in _ADMIN_KEYWORDS):
        return RiskSignal(
            rule_id="privilege_audit",
            severity=RiskLevel.MEDIUM,
            score_delta=10.0,
            reason=f"Secret name suggests elevated privileges: {secret_name}",
        )

    return None


async def exposure_check(secret_context: dict[str, Any]) -> RiskSignal | None:
    """Flag secrets stored in insecure locations."""
    location = secret_context.get("location", "")

    if location == SecretLocation.SOURCE_CODE.value:
        return RiskSignal(
            rule_id="exposure_check",
            severity=RiskLevel.CRITICAL,
            score_delta=35.0,
            reason="Secret is exposed in source code",
        )

    if location == SecretLocation.CONFIG_FILE.value:
        return RiskSignal(
            rule_id="exposure_check",
            severity=RiskLevel.HIGH,
            score_delta=25.0,
            reason="Secret is stored in a config file (not a vault)",
        )

    if location == SecretLocation.ENVIRONMENT_VARIABLE.value:
        return RiskSignal(
            rule_id="exposure_check",
            severity=RiskLevel.MEDIUM,
            score_delta=20.0,
            reason="Secret is in an environment variable (consider a vault)",
        )

    return None


async def compliance_check(secret_context: dict[str, Any]) -> RiskSignal | None:
    """Flag secrets that violate active compliance policies."""
    violations = secret_context.get("policy_violations", [])
    if not violations:
        return None

    # Take the most severe violation
    max_delta = 10.0
    reasons: list[str] = []
    for v in violations:
        reasons.append(v.get("reason", "Policy violation"))
        framework = v.get("framework", "")
        if framework in _HIGH_SEVERITY_FRAMEWORKS:
            max_delta = max(max_delta, 20.0)

    return RiskSignal(
        rule_id="compliance_check",
        severity=RiskLevel.HIGH if max_delta >= 20 else RiskLevel.MEDIUM,
        score_delta=max_delta,
        reason=f"{len(violations)} policy violation(s): {'; '.join(reasons[:3])}",
    )


async def blast_radius_check(secret_context: dict[str, Any]) -> RiskSignal | None:
    """Score based on how many services depend on this secret."""
    affected_count = secret_context.get("blast_radius_affected_count", 0)

    if affected_count >= 10:
        return RiskSignal(
            rule_id="blast_radius_check",
            severity=RiskLevel.HIGH,
            score_delta=20.0,
            reason=f"Secret affects {affected_count} services (high blast radius)",
        )

    if affected_count >= 5:
        return RiskSignal(
            rule_id="blast_radius_check",
            severity=RiskLevel.MEDIUM,
            score_delta=12.0,
            reason=f"Secret affects {affected_count} services (moderate blast radius)",
        )

    if affected_count >= 2:
        return RiskSignal(
            rule_id="blast_radius_check",
            severity=RiskLevel.LOW,
            score_delta=5.0,
            reason=f"Secret affects {affected_count} services",
        )

    return None


BUILT_IN_RULES: tuple[RuleFunction, ...] = (
    age_check,
    privilege_audit,
    exposure_check,
    compliance_check,
    blast_radius_check,
)
