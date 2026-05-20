"""Pipeline steps for incident response."""

import logging
from typing import Any

from src.models.incident import IncidentSeverity
from src.pipeline.engine import StepResult, StepStatus

logger = logging.getLogger(__name__)


async def incident_assessment_step(context: dict[str, Any]) -> StepResult:
    """Validate the incoming alert and determine severity and scope.

    Reads:
        context["incident"] — serialized IncidentContext dict.

    Returns:
        StepResult with severity, affected secret type, and recommended action.
    """
    incident = context.get("incident")
    if not incident:
        return StepResult(
            status=StepStatus.FAILED,
            error="No incident data in pipeline context",
        )

    severity = incident.get("severity", "medium")
    secret_type = incident.get("secret_type", "unknown")

    action = "rotate_and_revoke" if severity in (
        IncidentSeverity.CRITICAL.value,
        IncidentSeverity.HIGH.value,
    ) else "monitor_and_assess"

    logger.info(
        "Incident assessment: severity=%s secret_type=%s action=%s",
        severity,
        secret_type,
        action,
    )

    return StepResult(
        status=StepStatus.COMPLETED,
        output={
            "severity": severity,
            "secret_type": secret_type,
            "recommended_action": action,
            "alert_source": incident.get("alert_source"),
            "exposed_url": incident.get("exposed_url"),
        },
    )


async def emergency_rotation_step(context: dict[str, Any]) -> StepResult:
    """Trigger emergency rotation with force=True, skipping approval gates.

    Reads:
        context["incident_assessment"] — output from assessment step.
        context.get("providers") — rotation providers.
        context.get("rotation_requests") — explicit requests (optional).

    Delegates to the standard rotation_step with force=True on all requests.
    """
    assessment = context.get("incident_assessment", {})
    action = assessment.get("recommended_action", "monitor_and_assess")

    if action != "rotate_and_revoke":
        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "action": "skipped",
                "reason": f"Assessment recommends '{action}', not emergency rotation",
            },
        )

    providers = context.get("providers", {})
    if not providers:
        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "action": "skipped",
                "reason": "No rotation providers available",
                "rotated": [],
                "failed": [],
            },
        )

    # Build forced rotation requests from existing requests or incident context
    explicit = context.get("rotation_requests", [])
    if explicit:
        forced = [{**req, "force": True, "triggered_by": "incident_response"} for req in explicit]
    else:
        # No explicit requests — generate one from incident context if secret info available
        incident = context.get("incident", {})
        secret_type = incident.get("secret_type", "")
        matching_providers = [
            name for name in providers
            if secret_type and secret_type in name
        ]
        forced = [
            {
                "secret_id": incident.get("incident_id", "unknown"),
                "provider": matching_providers[0] if matching_providers else next(iter(providers)),
                "reason": f"Emergency rotation: {incident.get('alert_source', 'unknown')} alert",
                "triggered_by": "incident_response",
                "force": True,
                "risk_level": "critical",
            }
        ]

    # Inject forced requests and delegate to rotation_step
    context["rotation_requests"] = forced

    try:
        from src.rotation.pipeline_step import rotation_step

        result = await rotation_step(context)
        return StepResult(
            status=result.status,
            output={
                "action": "emergency_rotation",
                **(result.output or {}),
            },
            error=result.error,
        )
    except Exception as e:
        logger.error("Emergency rotation failed: %s", e, exc_info=True)
        return StepResult(status=StepStatus.FAILED, error=str(e))
