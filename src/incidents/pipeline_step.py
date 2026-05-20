"""Pipeline steps for incident response."""

import logging
from datetime import UTC, datetime
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


async def generate_incident_report_step(
    context: dict[str, Any],
) -> StepResult:
    """Generate an AI-assisted incident report and record timeline.

    Reads:
        context["incident"] — original incident data.
        context.get("incident_assessment") — assessment output.
        context.get("emergency_rotation") — rotation results.
        context.get("anthropic_api_key") — API key for report generation.

    Returns:
        StepResult with report markdown, timeline, and response metrics.
    """
    from src.incidents.report_generator import IncidentReportGenerator
    from src.incidents.timeline import (
        IncidentTimeline,
        calculate_response_time,
        format_timeline_markdown,
    )

    incident = context.get("incident", {})
    detected_str = incident.get("detected_at")
    now = datetime.now(UTC)

    # Parse detected_at from ISO string
    detected_at = now
    if detected_str:
        try:
            detected_at = datetime.fromisoformat(detected_str)
        except (ValueError, TypeError):
            pass

    response_time = calculate_response_time(detected_at, now)

    timeline = IncidentTimeline(
        detected_at=detected_at,
        contained_at=now,
        response_time_seconds=response_time,
    )

    # Generate AI report if API key is available
    api_key = context.get("anthropic_api_key", "")
    if api_key:
        generator = IncidentReportGenerator(api_key=api_key)
        report_data = {
            "incident": incident,
            "incident_assessment": context.get("incident_assessment", {}),
            "emergency_rotation": context.get("emergency_rotation", {}),
            "timeline": {
                "detected_at": detected_at.isoformat(),
                "contained_at": now.isoformat(),
                "response_time_seconds": response_time,
            },
        }
        report_markdown = await generator.generate(report_data)
    else:
        report_markdown = IncidentReportGenerator._fallback_report(
            {"incident": incident}
        )

    timeline_md = format_timeline_markdown(timeline)

    return StepResult(
        status=StepStatus.COMPLETED,
        output={
            "report": report_markdown,
            "timeline_markdown": timeline_md,
            "contained_at": now.isoformat(),
            "response_time_seconds": response_time,
        },
    )
