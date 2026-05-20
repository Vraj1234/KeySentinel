"""AI-powered incident report generation using the Anthropic API."""

import json
import logging
from typing import Any

import anthropic

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security incident response analyst. Generate a structured \
markdown incident report from the provided data.

The report MUST include these sections:
1. **Executive Summary** — 2-3 sentence overview of the incident
2. **Timeline** — chronological list of events
3. **Impact Assessment** — what was exposed, blast radius, affected services
4. **Root Cause** — how the secret was leaked (if determinable from context)
5. **Remediation Steps** — what was done (rotation, revocation, propagation)
6. **Lessons Learned** — recommendations to prevent recurrence

Use markdown formatting. Be concise and factual. Do not speculate beyond the data provided."""


class IncidentReportGenerator:
    """Generate markdown incident reports via Claude API."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def generate(self, incident_data: dict[str, Any]) -> str:
        """Send incident context to Claude and return a markdown report.

        Falls back to a basic template if the API call fails.
        """
        user_message = self._build_prompt(incident_data)

        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
            return response.content[0].text

        except Exception as e:
            logger.error("Report generation failed: %s", e, exc_info=True)
            return self._fallback_report(incident_data)

    @staticmethod
    def _build_prompt(data: dict[str, Any]) -> str:
        """Format incident data into a structured prompt."""
        sections = ["Generate an incident report from the following data:\n"]

        incident = data.get("incident", {})
        if incident:
            sections.append("## Incident Details")
            sections.append(f"- Severity: {incident.get('severity', 'unknown')}")
            sections.append(f"- Source: {incident.get('alert_source', 'unknown')}")
            sections.append(f"- Secret Type: {incident.get('secret_type', 'unknown')}")
            sections.append(f"- Exposed URL: {incident.get('exposed_url', 'N/A')}")
            sections.append(f"- Detected At: {incident.get('detected_at', 'unknown')}")
            sections.append("")

        assessment = data.get("incident_assessment", {})
        if assessment:
            sections.append("## Assessment")
            sections.append(f"- Action Taken: {assessment.get('recommended_action', 'N/A')}")
            sections.append("")

        rotation = data.get("emergency_rotation", {})
        if rotation:
            sections.append("## Rotation Results")
            sections.append(f"- Rotated: {len(rotation.get('rotated', []))} secrets")
            sections.append(f"- Failed: {len(rotation.get('failed', []))} secrets")
            sections.append("")

        timeline = data.get("timeline", {})
        if timeline:
            sections.append("## Timeline Data")
            sections.append(json.dumps(timeline, indent=2, default=str))

        return "\n".join(sections)

    @staticmethod
    def _fallback_report(data: dict[str, Any]) -> str:
        """Generate a basic report without AI when the API is unavailable."""
        incident = data.get("incident", {})
        return (
            "# Incident Report (auto-generated fallback)\n\n"
            f"**Severity:** {incident.get('severity', 'unknown')}\n"
            f"**Source:** {incident.get('alert_source', 'unknown')}\n"
            f"**Secret Type:** {incident.get('secret_type', 'unknown')}\n"
            f"**Detected:** {incident.get('detected_at', 'unknown')}\n\n"
            "_AI-generated analysis was unavailable. "
            "Review incident details manually._\n"
        )
