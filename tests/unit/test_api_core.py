"""Tests for core REST API endpoints — secrets, rotation, risk, graph."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.app import app
from src.api.routes.graph import set_graph
from src.db.database import get_db

# ---------------------------------------------------------------------------
# Fixtures — mock DB session
# ---------------------------------------------------------------------------


class MockResult:
    """Simulates SQLAlchemy result with scalars()."""

    def __init__(self, items: list) -> None:
        self._items = items

    def scalars(self) -> "MockResult":
        return self

    def all(self) -> list:
        return self._items

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


def _make_mock_secret(**overrides) -> MagicMock:
    defaults = {
        "id": str(uuid4()),
        "name": "test-secret",
        "secret_type": "api_key",
        "provider": "aws",
        "location": "vault",
        "location_detail": "vault://prod/api-key",
        "risk_level": "info",
        "risk_score": 0.0,
        "is_active": True,
        "created_at": datetime.now(UTC),
        "last_rotated_at": None,
        "expires_at": None,
        "max_age_days": None,
        "owner_service": None,
        "description": None,
    }
    defaults.update(overrides)
    mock = MagicMock()
    for k, v in defaults.items():
        setattr(mock, k, v)
    return mock


def _make_mock_event(**overrides) -> MagicMock:
    defaults = {
        "id": str(uuid4()),
        "secret_id": str(uuid4()),
        "status": "pending",
        "triggered_by": "manual",
        "reason": "test rotation",
        "started_at": datetime.now(UTC),
        "completed_at": None,
        "error_message": None,
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
# Health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    async def test_health_returns_ok(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------


class TestSecretsAPI:
    async def test_list_secrets(self, mock_db: AsyncMock) -> None:
        secret = _make_mock_secret()
        mock_db.execute = AsyncMock(return_value=MockResult([secret]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/secrets/")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["name"] == "test-secret"

    async def test_get_secret_not_found(self, mock_db: AsyncMock) -> None:
        mock_db.execute = AsyncMock(return_value=MockResult([]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/secrets/nonexistent")

        assert resp.status_code == 404

    async def test_get_secret_found(self, mock_db: AsyncMock) -> None:
        secret = _make_mock_secret(id="abc-123")
        mock_db.execute = AsyncMock(return_value=MockResult([secret]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/secrets/abc-123")

        assert resp.status_code == 200
        assert resp.json()["id"] == "abc-123"

    async def test_create_secret(self, mock_db: AsyncMock) -> None:
        async def _fake_refresh(obj: object) -> None:
            # Simulate DB defaults that SQLAlchemy would set
            if not hasattr(obj, "risk_score") or obj.risk_score is None:
                obj.risk_score = 0.0
            if not hasattr(obj, "is_active") or obj.is_active is None:
                obj.is_active = True
            if obj.created_at is None:
                obj.created_at = datetime.now(UTC)

        mock_db.refresh = AsyncMock(side_effect=_fake_refresh)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/secrets/",
                json={
                    "name": "new-key",
                    "secret_type": "api_key",
                    "provider": "stripe",
                    "location": "vault",
                    "location_detail": "vault://prod/stripe",
                },
            )

        assert resp.status_code == 201
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    async def test_delete_secret_soft_deletes(
        self, mock_db: AsyncMock
    ) -> None:
        secret = _make_mock_secret()
        mock_db.execute = AsyncMock(return_value=MockResult([secret]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.delete(f"/api/v1/secrets/{secret.id}")

        assert resp.status_code == 204
        assert secret.is_active is False


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class TestRotationAPI:
    async def test_trigger_rotation(self, mock_db: AsyncMock) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/rotation/trigger",
                json={"secret_id": "s1", "reason": "test"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["pipeline_id"] is not None

    async def test_list_events(self, mock_db: AsyncMock) -> None:
        event = _make_mock_event()
        mock_db.execute = AsyncMock(return_value=MockResult([event]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/rotation/events")

        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    async def test_get_event_not_found(self, mock_db: AsyncMock) -> None:
        mock_db.execute = AsyncMock(return_value=MockResult([]))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/rotation/events/missing")

        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


class TestRiskAPI:
    async def test_assess_empty_list(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/risk/assess",
                json={"secret_ids": []},
            )

        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    async def test_assess_with_ids(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post(
                "/api/v1/risk/assess",
                json={"secret_ids": ["s1", "s2"]},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert all("risk_score" in a for a in data["assessments"])


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraphAPI:
    async def test_graph_unavailable(self) -> None:
        set_graph(None)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/graph/summary")

        assert resp.status_code == 503

    async def test_graph_summary(self) -> None:
        mock_graph = MagicMock()
        mock_graph.to_dict.return_value = {
            "secret_count": 5,
            "service_count": 3,
            "edge_count": 7,
        }
        set_graph(mock_graph)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/graph/summary")

        assert resp.status_code == 200
        data = resp.json()
        assert data["secret_count"] == 5
        assert data["service_count"] == 3

        # Cleanup
        set_graph(None)

    async def test_blast_radius(self) -> None:
        mock_graph = MagicMock()
        mock_result = MagicMock()
        mock_result.affected_count = 2
        mock_result.affected_services = ["svc-a", "svc-b"]
        mock_graph.blast_radius.return_value = mock_result
        set_graph(mock_graph)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/api/v1/graph/blast-radius/secret-1")

        assert resp.status_code == 200
        data = resp.json()
        assert data["affected_count"] == 2
        assert "svc-a" in data["affected_services"]

        set_graph(None)
