"""AI-powered compliance executive summary generation."""

import logging
from typing import Any

import anthropic

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a compliance analyst. Generate a concise executive summary \
paragraph (3-5 sentences) from the provided compliance assessment data.

Cover: overall compliance posture, top risks, and priority remediation actions.
Be factual and direct. Output only the summary paragraph, no markdown headers."""


class ComplianceSummaryGenerator:
    """Generate executive summaries for compliance reports via Claude API."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def generate_summary(self, report_data: dict[str, Any]) -> str:
        """Call Claude API to produce a compliance executive summary.

        Falls back to a static summary on failure.
        """
        prompt = self._build_prompt(report_data)

        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text

        except Exception as e:
            logger.error("Summary generation failed: %s", e, exc_info=True)
            return self._fallback_summary(report_data)

    @staticmethod
    def _build_prompt(data: dict[str, Any]) -> str:
        """Format compliance data for the API prompt."""
        lines = ["Summarize this compliance assessment:\n"]

        score = data.get("score", {})
        if score:
            lines.append(f"- Framework: {score.get('framework', 'unknown')}")
            lines.append(f"- Score: {score.get('score_percentage', 0)}%")
            compliant = score.get('compliant_count', 0)
            total = score.get('total_secrets', 0)
            lines.append(f"- Compliant: {compliant}/{total}")
            lines.append(f"- Violations: {score.get('violation_count', 0)}")

        violations = data.get("top_violations", [])
        if violations:
            lines.append("\nTop violations:")
            for v in violations[:5]:
                lines.append(f"  - {v}")

        return "\n".join(lines)

    @staticmethod
    def _fallback_summary(data: dict[str, Any]) -> str:
        """Static summary when AI is unavailable."""
        score = data.get("score", {})
        pct = score.get("score_percentage", 0)
        total = score.get("total_secrets", 0)
        violations = score.get("violation_count", 0)
        return (
            f"Compliance assessment evaluated {total} secrets with a "
            f"{pct}% compliance score. {violations} violation(s) require "
            f"remediation. Review the detailed findings below."
        )
