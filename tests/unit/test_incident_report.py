"""Tests for incident report generation and timeline tracking."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from src.incidents.pipeline_step import generate_incident_report_step
from src.incidents.report_generator import IncidentReportGenerator
from src.incidents.timeline import (
    IncidentTimeline,
    calculate_response_time,
    format_timeline_markdown,
)
from src.pipeline.engine import StepStatus


class TestCalculateResponseTime:
    def test_positive_delta(self) -> None:
        detected = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        contained = datetime(2025, 1, 1, 12, 5, 30, tzinfo=UTC)
        assert calculate_response_time(detected, contained) == 330.0

    def test_zero_delta(self) -> None:
        now = datetime.now(UTC)
        assert calculate_response_time(now, now) == 0.0

    def test_negative_clamped_to_zero(self) -> None:
        detected = datetime(2025, 1, 1, 12, 5, 0, tzinfo=UTC)
        contained = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert calculate_response_time(detected, contained) == 0.0


class TestFormatTimelineMarkdown:
    def test_full_timeline(self) -> None:
        tl = IncidentTimeline(
            detected_at=datetime(2025, 1, 1, 12, 0, tzinfo=UTC),
            contained_at=datetime(2025, 1, 1, 12, 5, tzinfo=UTC),
            resolved_at=datetime(2025, 1, 1, 13, 0, tzinfo=UTC),
            response_time_seconds=300.0,
        )
        md = format_timeline_markdown(tl)
        assert "Detected" in md
        assert "Contained" in md
        assert "Resolved" in md
        assert "300.0s" in md

    def test_partial_timeline(self) -> None:
        tl = IncidentTimeline(
            detected_at=datetime(2025, 1, 1, 12, 0, tzinfo=UTC),
        )
        md = format_timeline_markdown(tl)
        assert "Detected" in md
        assert "Contained" not in md
        assert "Resolved" not in md


class TestIncidentReportGenerator:
    async def test_generate_calls_api(self) -> None:
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="# Incident Report\n\nTest")]

        with patch("src.incidents.report_generator.anthropic") as mock_anthropic:
            mock_client = AsyncMock()
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            mock_anthropic.AsyncAnthropic.return_value = mock_client

            generator = IncidentReportGenerator(api_key="test-key")
            generator._client = mock_client

            report = await generator.generate({
                "incident": {"severity": "critical", "secret_type": "aws_key"},
            })

            assert "Incident Report" in report
            mock_client.messages.create.assert_called_once()

    async def test_fallback_on_api_failure(self) -> None:
        with patch("src.incidents.report_generator.anthropic") as mock_anthropic:
            mock_client = AsyncMock()
            mock_client.messages.create = AsyncMock(
                side_effect=Exception("API down")
            )
            mock_anthropic.AsyncAnthropic.return_value = mock_client

            generator = IncidentReportGenerator(api_key="test-key")
            generator._client = mock_client

            report = await generator.generate({
                "incident": {"severity": "high", "alert_source": "github"},
            })

            assert "fallback" in report.lower()
            assert "high" in report.lower()

    def test_build_prompt_includes_incident_data(self) -> None:
        prompt = IncidentReportGenerator._build_prompt({
            "incident": {
                "severity": "critical",
                "alert_source": "github",
                "secret_type": "aws_access_key",
            },
        })
        assert "critical" in prompt
        assert "github" in prompt
        assert "aws_access_key" in prompt

    def test_fallback_report_structure(self) -> None:
        report = IncidentReportGenerator._fallback_report({
            "incident": {
                "severity": "high",
                "alert_source": "gitguardian",
            },
        })
        assert "high" in report.lower()
        assert "gitguardian" in report.lower()


class TestGenerateIncidentReportStep:
    async def test_generates_report_without_api_key(self) -> None:
        detected = datetime.now(UTC) - timedelta(minutes=5)
        context = {
            "incident": {
                "severity": "critical",
                "secret_type": "aws_key",
                "alert_source": "github",
                "detected_at": detected.isoformat(),
            },
            "incident_assessment": {
                "recommended_action": "rotate_and_revoke",
            },
        }

        result = await generate_incident_report_step(context)

        assert result.status == StepStatus.COMPLETED
        assert "report" in result.output
        assert "fallback" in result.output["report"].lower()
        assert result.output["response_time_seconds"] >= 0
        assert result.output["contained_at"] is not None

    async def test_includes_timeline_markdown(self) -> None:
        context = {
            "incident": {
                "severity": "high",
                "detected_at": datetime.now(UTC).isoformat(),
            },
        }

        result = await generate_incident_report_step(context)

        assert "timeline_markdown" in result.output
        assert "Detected" in result.output["timeline_markdown"]
        assert "Contained" in result.output["timeline_markdown"]
