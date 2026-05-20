"""Tests for incident response — webhook parsing, handler, and pipeline steps."""

from datetime import UTC, datetime

from src.incidents.handler import IncidentHandler
from src.incidents.models import (
    IncidentContext,
    WebhookAlert,
    _determine_severity,
    parse_gitguardian_alert,
    parse_github_alert,
)
from src.incidents.pipeline_step import (
    emergency_rotation_step,
    incident_assessment_step,
)
from src.models.incident import IncidentSeverity
from src.pipeline.engine import StepStatus


class TestParseGitHubAlert:
    def test_parses_basic_payload(self) -> None:
        payload = {
            "alert": {
                "secret_type": "aws_access_key",
                "html_url": "https://github.com/org/repo/security/alerts/1",
            },
            "repository": {"full_name": "org/repo"},
        }
        alert = parse_github_alert(payload)

        assert alert.source == "github"
        assert alert.alert_type == "secret_scanning"
        assert alert.secret_type == "aws_access_key"
        assert alert.exposed_url == "https://github.com/org/repo/security/alerts/1"
        assert alert.repository == "org/repo"
        assert alert.received_at is not None

    def test_handles_missing_fields(self) -> None:
        alert = parse_github_alert({})
        assert alert.source == "github"
        assert alert.secret_type == "unknown"
        assert alert.exposed_url == ""

    def test_flat_payload_without_alert_key(self) -> None:
        payload = {
            "secret_type": "generic_password",
            "html_url": "https://example.com",
        }
        alert = parse_github_alert(payload)
        assert alert.secret_type == "generic_password"


class TestParseGitGuardianAlert:
    def test_parses_with_occurrences(self) -> None:
        payload = {
            "type": "aws_iam",
            "occurrences": [
                {
                    "url": "https://dashboard.gitguardian.com/incident/1",
                    "commit_sha": "abc123",
                    "repository": {"name": "my-repo"},
                }
            ],
        }
        alert = parse_gitguardian_alert(payload)

        assert alert.source == "gitguardian"
        assert alert.alert_type == "secret_leak"
        assert alert.secret_type == "aws_iam"
        assert alert.exposed_url == "https://dashboard.gitguardian.com/incident/1"
        assert alert.commit_sha == "abc123"
        assert alert.repository == "my-repo"

    def test_handles_empty_occurrences(self) -> None:
        payload = {"type": "generic", "url": "https://gg.com/fallback"}
        alert = parse_gitguardian_alert(payload)
        assert alert.exposed_url == "https://gg.com/fallback"
        assert alert.commit_sha is None


class TestDetermineSeverity:
    def test_critical_source_code_leak(self) -> None:
        alert = WebhookAlert(
            source="github",
            alert_type="secret_scanning",
            secret_type="aws_access_key",
            exposed_url="",
        )
        assert _determine_severity(alert) == IncidentSeverity.CRITICAL

    def test_high_for_non_critical_source_code(self) -> None:
        alert = WebhookAlert(
            source="github",
            alert_type="secret_scanning",
            secret_type="generic_api_key",
            exposed_url="",
        )
        assert _determine_severity(alert) == IncidentSeverity.HIGH

    def test_medium_for_non_source_code(self) -> None:
        alert = WebhookAlert(
            source="scanner",
            alert_type="config_exposure",
            secret_type="aws_access_key",
            exposed_url="",
        )
        assert _determine_severity(alert) == IncidentSeverity.MEDIUM


class TestIncidentHandler:
    async def test_handle_alert_creates_context(self) -> None:
        handler = IncidentHandler()
        alert = WebhookAlert(
            source="github",
            alert_type="secret_scanning",
            secret_type="aws_access_key",
            exposed_url="https://github.com/org/repo/alerts/1",
        )

        ctx = await handler.handle_alert(alert)

        assert ctx.incident_id
        assert ctx.severity == IncidentSeverity.CRITICAL
        assert ctx.alert is alert
        assert ctx.detected_at is not None

    def test_build_emergency_pipeline_no_approval(self) -> None:
        handler = IncidentHandler()
        alert = WebhookAlert(
            source="github",
            alert_type="secret_scanning",
            secret_type="aws_access_key",
            exposed_url="",
        )

        ctx = IncidentContext(
            alert=alert,
            incident_id="test-id",
            secret_id=None,
            severity=IncidentSeverity.CRITICAL,
            detected_at=datetime.now(UTC),
        )

        run = handler.build_emergency_pipeline(ctx)

        assert run.pipeline_id.startswith("emergency-")
        assert len(run.steps) == 2
        for step in run.steps:
            assert step.requires_approval is False
        assert run.context["incident"]["severity"] == "critical"


class TestIncidentAssessmentStep:
    async def test_returns_action_for_critical(self) -> None:
        context = {
            "incident": {
                "severity": "critical",
                "secret_type": "aws_access_key",
                "alert_source": "github",
                "exposed_url": "https://example.com",
            }
        }
        result = await incident_assessment_step(context)

        assert result.status == StepStatus.COMPLETED
        assert result.output["recommended_action"] == "rotate_and_revoke"

    async def test_returns_monitor_for_medium(self) -> None:
        context = {
            "incident": {
                "severity": "medium",
                "secret_type": "generic",
                "alert_source": "scanner",
                "exposed_url": "",
            }
        }
        result = await incident_assessment_step(context)
        assert result.output["recommended_action"] == "monitor_and_assess"

    async def test_fails_without_incident_data(self) -> None:
        result = await incident_assessment_step({})
        assert result.status == StepStatus.FAILED


class TestEmergencyRotationStep:
    async def test_skips_when_action_is_monitor(self) -> None:
        context = {
            "incident_assessment": {"recommended_action": "monitor_and_assess"},
        }
        result = await emergency_rotation_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output["action"] == "skipped"

    async def test_skips_without_providers(self) -> None:
        context = {
            "incident_assessment": {"recommended_action": "rotate_and_revoke"},
            "incident": {"alert_source": "github", "incident_id": "test"},
        }
        result = await emergency_rotation_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output["action"] == "skipped"
