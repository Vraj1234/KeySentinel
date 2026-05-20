"""Incident response orchestrator — handles alerts and builds emergency pipelines."""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from src.incidents.models import IncidentContext, WebhookAlert, _determine_severity
from src.pipeline.engine import PipelineRun, PipelineStep
from src.rotation.providers.base import RotationProvider

logger = logging.getLogger(__name__)


class IncidentHandler:
    """Receives webhook alerts and builds emergency rotation pipelines."""

    def __init__(
        self,
        providers: dict[str, RotationProvider] | None = None,
    ) -> None:
        self._providers = providers or {}

    async def handle_alert(self, alert: WebhookAlert) -> IncidentContext:
        """Create an incident context from an incoming alert.

        Returns the context to be passed into the emergency pipeline.
        """
        severity = _determine_severity(alert)
        now = datetime.now(UTC)

        ctx = IncidentContext(
            alert=alert,
            incident_id=str(uuid4()),
            secret_id=None,  # resolved during assessment step
            severity=severity,
            detected_at=now,
        )

        logger.info(
            "Incident %s created: severity=%s source=%s type=%s",
            ctx.incident_id,
            severity.value,
            alert.source,
            alert.secret_type,
        )
        return ctx

    def build_emergency_pipeline(self, ctx: IncidentContext) -> PipelineRun:
        """Build a PipelineRun for emergency incident response.

        All steps have requires_approval=False — emergency rotations
        skip approval gates.
        """
        from src.incidents.pipeline_step import (
            emergency_rotation_step,
            incident_assessment_step,
        )

        context: dict[str, Any] = {
            "incident": {
                "incident_id": ctx.incident_id,
                "alert_source": ctx.alert.source,
                "alert_type": ctx.alert.alert_type,
                "secret_type": ctx.alert.secret_type,
                "exposed_url": ctx.alert.exposed_url,
                "commit_sha": ctx.alert.commit_sha,
                "repository": ctx.alert.repository,
                "severity": ctx.severity.value,
                "detected_at": ctx.detected_at.isoformat(),
            },
            "providers": self._providers,
        }

        return PipelineRun(
            pipeline_id=f"emergency-{ctx.incident_id}",
            steps=[
                PipelineStep(
                    name="incident_assessment",
                    handler=incident_assessment_step,
                    requires_approval=False,
                ),
                PipelineStep(
                    name="emergency_rotation",
                    handler=emergency_rotation_step,
                    requires_approval=False,
                ),
            ],
            context=context,
        )
