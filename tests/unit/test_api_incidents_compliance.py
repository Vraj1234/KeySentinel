"""Tests for incident and compliance API endpoints."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.app import app
from src.db.database import get_db
from src.models.incident import IncidentSeverity, IncidentStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class MockResult:
    def __init__(self, items: list) -> None:
        self._items = items

    def scalars(self) -> "MockResult":
        return self

    def all(self) -> list:
        return self._items

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


def _make_mock_incident(**overrides) -> MagicMock:
    defaults = {
        "id": "inc-1",
        "secret_id": None,
        "severity": IncidentSeverity.HIGH,
        "status": IncidentStatus.DETECTED,
        "source": "github",
        "title": "Test incident",
        "description": "Secret leaked",
        "detected_at": datetime.now(UTC),
        "contained_at": None,
        "resolved_at": None,
        "response_time_seconds": None,
        "report": None,
    }
    defaults.update(overrides)
    mock = MagicMock()
    for k, v in defaults.items():
        setattr(mock, k, v)
    return mock


@pytest.fixture
def mock_db() -> AsyncMock:
    session = AsyncMock(spec=AsyncSession)
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.fixture(autouse=True)
def _override_db(mock_db: AsyncMock):
    async def _get_mock_db() -> AsyncGenerator[AsyncMock, None]:
        yield mock_db

    app.dependency_overrides[get_db] = _get_mock_db
    yield
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Incident webhooks
# ---------------------------------------------------------------------------


class TestGitHubWebhook:
    async def test_creates_incident(self, mock_db: AsyncMock) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/incidents/webhook/github",
                json={
                    "alert": {
                        "secret_type": "aws_access_key",
                        "html_url": "https://github.com/org/repo/alerts/1",
                    },
                    "repository": {"full_name": "org/repo"},
                },
            )

        assert resp.status_code == 202
        data = resp.json()
        assert data["severity"] == "critical"
        mock_db.add.assert_called_once()


class TestGitGuardianWebhook:
    async def test_creates_incident(self, mock_db: AsyncMock) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/incidents/webhook/gitguardian",
                json={
                    "type": "generic_secret",
                    "occurrences": [
                        {"url": "https://gg.com/1", "commit_sha": "abc"},
                    ],
                },
            )

        assert resp.status_code == 202
        mock_db.add.assert_called_once()


# ---------------------------------------------------------------------------
# Incident CRUD
# ---------------------------------------------------------------------------


class TestIncidentEndpoints:
    async def test_list_incidents(self, mock_db: AsyncMock) -> None:
        incident = _make_mock_incident()
        mock_db.execute = AsyncMock(return_value=MockResult([incident]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/incidents/")

        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    async def test_get_incident_not_found(
        self, mock_db: AsyncMock
    ) -> None:
        mock_db.execute = AsyncMock(return_value=MockResult([]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/incidents/missing")

        assert resp.status_code == 404

    async def test_get_incident_found(self, mock_db: AsyncMock) -> None:
        incident = _make_mock_incident()
        mock_db.execute = AsyncMock(return_value=MockResult([incident]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/incidents/inc-1")

        assert resp.status_code == 200
        data = resp.json()
        assert data["severity"] == "high"
        assert data["status"] == "detected"

    async def test_update_status_to_resolved(
        self, mock_db: AsyncMock
    ) -> None:
        incident = _make_mock_incident()
        mock_db.execute = AsyncMock(return_value=MockResult([incident]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.put(
                "/api/v1/incidents/inc-1/status",
                json={"status": "resolved"},
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------


class TestComplianceEndpoints:
    async def test_assess_skips_without_policies(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/compliance/assess",
                json={"secrets": [{"id": "s1"}]},
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"

    async def test_assess_with_data(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/compliance/assess",
                json={
                    "policies": [
                        {
                            "id": "p1",
                            "name": "No Source Code",
                            "policy_type": "no_source_code",
                            "framework": "soc2",
                            "is_enabled": True,
                        }
                    ],
                    "secrets": [
                        {"id": "s1", "location": "source_code"},
                        {"id": "s2", "location": "vault"},
                    ],
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["total_evaluated"] == 2
        assert data["total_violations"] == 1

    async def test_get_scores(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/compliance/score")

        assert resp.status_code == 200
        assert "scores" in resp.json()

    async def test_get_remediation(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/compliance/remediation")

        assert resp.status_code == 200
        assert "items" in resp.json()
