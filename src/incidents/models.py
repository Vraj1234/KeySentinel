"""Domain models for incident response — webhook alerts and incident context."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from src.models.incident import IncidentSeverity


@dataclass(frozen=True)
class WebhookAlert:
    """Parsed alert from an external secret scanning service."""

    source: str  # "github", "gitguardian"
    alert_type: str  # "secret_scanning", "secret_leak"
    secret_type: str  # e.g. "aws_access_key", "generic_password"
    exposed_url: str
    commit_sha: str | None = None
    repository: str | None = None
    received_at: datetime | None = None


@dataclass(frozen=True)
class IncidentContext:
    """Context object threaded through the emergency response pipeline."""

    alert: WebhookAlert
    incident_id: str
    secret_id: str | None
    severity: IncidentSeverity
    detected_at: datetime


# ---------------------------------------------------------------------------
# Alert type -> severity mapping
# ---------------------------------------------------------------------------

_SOURCE_CODE_TYPES = frozenset({"secret_scanning", "secret_leak", "commit_secret"})

_CRITICAL_SECRET_TYPES = frozenset(
    {
        "aws_access_key",
        "gcp_service_account",
        "azure_ad_credential",
        "database_password",
        "private_key",
        "ssh_key",
    }
)


def _determine_severity(alert: WebhookAlert) -> IncidentSeverity:
    """Map alert metadata to an incident severity level."""
    if alert.alert_type in _SOURCE_CODE_TYPES:
        if alert.secret_type in _CRITICAL_SECRET_TYPES:
            return IncidentSeverity.CRITICAL
        return IncidentSeverity.HIGH
    return IncidentSeverity.MEDIUM


# ---------------------------------------------------------------------------
# Webhook parsers
# ---------------------------------------------------------------------------


def parse_github_alert(payload: dict[str, Any]) -> WebhookAlert:
    """Parse a GitHub secret scanning webhook payload into a WebhookAlert."""
    alert = payload.get("alert", payload)
    return WebhookAlert(
        source="github",
        alert_type="secret_scanning",
        secret_type=alert.get("secret_type", "unknown"),
        exposed_url=alert.get("html_url", ""),
        commit_sha=alert.get("push_protection_bypassed_at") and alert.get("commit_sha"),
        repository=payload.get("repository", {}).get("full_name"),
        received_at=datetime.now(UTC),
    )


def parse_gitguardian_alert(payload: dict[str, Any]) -> WebhookAlert:
    """Parse a GitGuardian webhook payload into a WebhookAlert."""
    occurrence = {}
    occurrences = payload.get("occurrences", [])
    if occurrences:
        occurrence = occurrences[0]

    return WebhookAlert(
        source="gitguardian",
        alert_type="secret_leak",
        secret_type=payload.get("type", "unknown"),
        exposed_url=occurrence.get("url", payload.get("url", "")),
        commit_sha=occurrence.get("commit_sha"),
        repository=(
            occurrence.get("repository", {}).get("name")
            if isinstance(occurrence.get("repository"), dict)
            else None
        ),
        received_at=datetime.now(UTC),
    )
