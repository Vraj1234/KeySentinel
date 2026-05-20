from datetime import UTC, datetime

import pytest

from src.graph.dependency_graph import DependencyGraph
from src.graph.models import DependencyEdge, EdgeType, SecretNode, ServiceNode, ServiceType
from src.models.secret import RiskLevel, SecretType
from src.pipeline.engine import PipelineApprovalRequired, StepStatus
from src.rotation.executor import RotationExecutor
from src.rotation.models import RotationPlan, RotationRequest
from src.rotation.providers.base import KeyInfo, RotationProvider, RotationResult


class MockProvider(RotationProvider):
    """Test provider that returns configurable results."""

    def __init__(
        self,
        create_success: bool = True,
        verify_success: bool = True,
        deactivate_success: bool = True,
        delete_success: bool = True,
    ) -> None:
        self._create_success = create_success
        self._verify_success = verify_success
        self._deactivate_success = deactivate_success
        self._delete_success = delete_success
        self.calls: list[str] = []

    @property
    def provider_name(self) -> str:
        return "mock"

    async def create_key(self, secret_id: str) -> RotationResult:
        self.calls.append(f"create_key:{secret_id}")
        if not self._create_success:
            return RotationResult(success=False, error="create failed")
        return RotationResult(
            success=True,
            new_key_id="new-key-123",
            new_key_created_at=datetime.now(UTC),
            vault_reference="vault://mock/new-key-123",
        )

    async def verify_key(self, key_id: str) -> bool:
        self.calls.append(f"verify_key:{key_id}")
        return self._verify_success

    async def deactivate_key(self, key_id: str) -> RotationResult:
        self.calls.append(f"deactivate_key:{key_id}")
        if not self._deactivate_success:
            return RotationResult(success=False, error="deactivate failed")
        return RotationResult(success=True, old_key_id=key_id)

    async def delete_key(self, key_id: str) -> RotationResult:
        self.calls.append(f"delete_key:{key_id}")
        if not self._delete_success:
            return RotationResult(success=False, error="delete failed")
        return RotationResult(success=True, old_key_id=key_id)

    async def list_keys(self, secret_id: str) -> list[KeyInfo]:
        return []

    async def reactivate_key(self, key_id: str) -> RotationResult:
        self.calls.append(f"reactivate_key:{key_id}")
        return RotationResult(success=True)


def _request(
    secret_id: str = "secret-1",
    provider: str = "mock",
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    **kwargs: object,
) -> RotationRequest:
    return RotationRequest(
        secret_id=secret_id,
        provider=provider,
        reason="test rotation",
        triggered_by="test",
        risk_level=risk_level,
        **kwargs,
    )


class TestRotationRequest:
    def test_frozen(self) -> None:
        req = _request()
        with pytest.raises(AttributeError):
            req.secret_id = "other"  # type: ignore[misc]

    def test_defaults(self) -> None:
        req = _request()
        assert req.force is False
        assert req.old_key_id is None
        assert req.risk_level == RiskLevel.MEDIUM


class TestRotationPlan:
    async def test_plan_uses_graph_order(self) -> None:
        graph = DependencyGraph()
        graph.add_service(ServiceNode("svc-A", "A", ServiceType.API))
        graph.add_service(ServiceNode("svc-B", "B", ServiceType.API))
        graph.add_secret(SecretNode("secret-1", SecretType.API_KEY, "mock"))
        graph.add_secret(SecretNode("secret-2", SecretType.API_KEY, "mock"))
        graph.add_dependency(
            DependencyEdge("svc-A", "secret-1", EdgeType.USES),
        )
        graph.add_dependency(
            DependencyEdge("svc-B", "secret-2", EdgeType.USES),
        )
        graph.add_dependency(
            DependencyEdge("svc-B", "svc-A", EdgeType.DEPENDS_ON),
        )

        executor = RotationExecutor(
            providers={"mock": MockProvider()}, graph=graph,
        )
        plan = await executor.plan([_request("secret-2"), _request("secret-1")])
        # secret-1 should come first (leaf)
        assert plan.rotation_order.index("secret-1") < plan.rotation_order.index("secret-2")

    async def test_plan_identifies_approval(self) -> None:
        executor = RotationExecutor(
            providers={"mock": MockProvider()},
            approval_required_for_critical=True,
        )
        plan = await executor.plan([
            _request("s1", risk_level=RiskLevel.CRITICAL),
            _request("s2", risk_level=RiskLevel.MEDIUM),
        ])
        assert "s1" in plan.requires_approval
        assert "s2" not in plan.requires_approval

    async def test_force_bypasses_approval(self) -> None:
        executor = RotationExecutor(
            providers={"mock": MockProvider()},
            approval_required_for_critical=True,
        )
        plan = await executor.plan([
            _request("s1", risk_level=RiskLevel.CRITICAL, force=True),
        ])
        assert "s1" not in plan.requires_approval


class TestExecutorSingleHappyPath:
    async def test_full_rotation_without_old_key(self) -> None:
        provider = MockProvider()
        executor = RotationExecutor(providers={"mock": provider})
        req = _request()

        run = await executor.execute_single(req)
        assert run.status == StepStatus.COMPLETED
        assert "create_key:secret-1" in provider.calls
        assert "verify_key:new-key-123" in provider.calls

    async def test_full_rotation_with_old_key(self) -> None:
        provider = MockProvider()
        executor = RotationExecutor(
            providers={"mock": provider}, grace_period_hours=0,
        )
        req = _request(old_key_id="old-key-1")

        run = await executor.execute_single(req)
        assert run.status == StepStatus.COMPLETED
        assert "deactivate_key:old-key-1" in provider.calls
        assert "delete_key:old-key-1" in provider.calls

    async def test_create_output_in_context(self) -> None:
        executor = RotationExecutor(providers={"mock": MockProvider()})
        run = await executor.execute_single(_request())
        create_output = run.context.get("create_key", {})
        assert create_output.get("new_key_id") == "new-key-123"
        assert create_output.get("vault_reference") == "vault://mock/new-key-123"


class TestExecutorApprovalGates:
    async def test_critical_triggers_approval(self) -> None:
        executor = RotationExecutor(
            providers={"mock": MockProvider()},
            approval_required_for_critical=True,
        )
        req = _request(risk_level=RiskLevel.CRITICAL)

        with pytest.raises(PipelineApprovalRequired) as exc_info:
            await executor.execute_single(req)
        assert exc_info.value.step_name == "create_key"

    async def test_force_bypasses_approval(self) -> None:
        executor = RotationExecutor(
            providers={"mock": MockProvider()},
            approval_required_for_critical=True,
        )
        req = _request(risk_level=RiskLevel.CRITICAL, force=True)
        run = await executor.execute_single(req)
        assert run.status == StepStatus.COMPLETED


class TestExecutorGracePeriod:
    async def test_delete_not_included_with_grace_period(self) -> None:
        """With grace_period > 0, delete step is deferred (not in pipeline)."""
        provider = MockProvider()
        executor = RotationExecutor(
            providers={"mock": provider}, grace_period_hours=24,
        )
        req = _request(old_key_id="old-key-1")
        run = await executor.execute_single(req)

        assert run.status == StepStatus.COMPLETED
        # Only 4 steps (no delete), and scheduled_delete_at recorded
        assert len(run.results) == 4
        assert "delete_key:old-key-1" not in provider.calls
        deactivate_output = run.context.get("deactivate_key", {})
        assert "scheduled_delete_at" in deactivate_output

    async def test_delete_executes_with_zero_grace(self) -> None:
        provider = MockProvider()
        executor = RotationExecutor(
            providers={"mock": provider}, grace_period_hours=0,
        )
        req = _request(old_key_id="old-key-1")
        run = await executor.execute_single(req)

        assert "delete_key:old-key-1" in provider.calls


class TestExecutorRollback:
    async def test_verify_failure_triggers_rollback(self) -> None:
        provider = MockProvider(verify_success=False)
        executor = RotationExecutor(providers={"mock": provider})
        req = _request(old_key_id="old-key-1")

        run = await executor.execute_single(req)
        assert run.status == StepStatus.FAILED
        # Rollback should have reactivated old and deleted new
        assert "reactivate_key:old-key-1" in provider.calls
        assert "delete_key:new-key-123" in provider.calls

    async def test_create_failure_no_rollback_needed(self) -> None:
        provider = MockProvider(create_success=False)
        executor = RotationExecutor(providers={"mock": provider})
        run = await executor.execute_single(_request())
        assert run.status == StepStatus.FAILED
        # No rollback calls since create didn't produce a key
        assert not any("reactivate" in c for c in provider.calls)


class TestExecutorBatch:
    async def test_batch_respects_order(self) -> None:
        provider = MockProvider()
        graph = DependencyGraph()
        graph.add_service(ServiceNode("svc-A", "A", ServiceType.API))
        graph.add_service(ServiceNode("svc-B", "B", ServiceType.API))
        graph.add_secret(SecretNode("s1", SecretType.API_KEY, "mock"))
        graph.add_secret(SecretNode("s2", SecretType.API_KEY, "mock"))
        graph.add_dependency(DependencyEdge("svc-A", "s1", EdgeType.USES))
        graph.add_dependency(DependencyEdge("svc-B", "s2", EdgeType.USES))
        graph.add_dependency(DependencyEdge("svc-B", "svc-A", EdgeType.DEPENDS_ON))

        executor = RotationExecutor(
            providers={"mock": provider}, graph=graph,
        )
        plan = await executor.plan([_request("s2"), _request("s1")])
        runs = await executor.execute_batch(plan)

        assert len(runs) == 2
        # s1 should be rotated first (leaf)
        first_secret = runs[0].context["rotation_request"]["secret_id"]
        assert first_secret == "s1"

    async def test_missing_provider_raises(self) -> None:
        executor = RotationExecutor(providers={})
        with pytest.raises(ValueError, match="No provider"):
            await executor.execute_single(_request(provider="nonexistent"))
