import pytest

from src.graph.dependency_graph import DependencyGraph
from src.graph.models import DependencyEdge, EdgeType, SecretNode, ServiceNode, ServiceType
from src.models.secret import SecretType
from src.pipeline.engine import StepStatus
from src.propagation.engine import PropagationEngine
from src.propagation.models import PropagationReport, PropagationResult, PropagationTarget
from src.propagation.pipeline_step import propagation_step
from src.propagation.updaters.base import PropagationUpdater


class MockUpdater(PropagationUpdater):
    """Test updater that returns configurable results."""

    def __init__(
        self,
        update_success: bool = True,
        health_check_success: bool = True,
    ) -> None:
        self._update_success = update_success
        self._health_check_success = health_check_success
        self.update_calls: list[str] = []
        self.health_calls: list[str] = []
        self.rollback_calls: list[str] = []

    @property
    def updater_type(self) -> str:
        return "mock"

    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        self.update_calls.append(f"{secret_id}:{target.target_id}")
        if not self._update_success:
            return PropagationResult(
                target=target, success=False,
                health_check_passed=False, error="update failed",
            )
        return PropagationResult(
            target=target, success=True,
            health_check_passed=self._health_check_success,
        )

    async def health_check(self, target: PropagationTarget) -> bool:
        self.health_calls.append(target.target_id)
        return self._health_check_success

    async def rollback(
        self,
        secret_id: str,
        previous_vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        self.rollback_calls.append(f"{secret_id}:{target.target_id}")
        return PropagationResult(
            target=target, success=True, health_check_passed=True,
        )


def _target(
    target_id: str = "target-1",
    target_type: str = "mock",
    **config: str,
) -> PropagationTarget:
    return PropagationTarget(
        target_type=target_type,
        target_id=target_id,
        config=tuple(config.items()),
    )


class TestPropagationTarget:
    def test_frozen(self) -> None:
        t = _target()
        with pytest.raises(AttributeError):
            t.target_id = "other"  # type: ignore[misc]

    def test_config_dict(self) -> None:
        t = _target(api_url="https://k8s.local", namespace="prod")
        cfg = t.config_dict()
        assert cfg == {"api_url": "https://k8s.local", "namespace": "prod"}

    def test_empty_config(self) -> None:
        t = PropagationTarget(target_type="mock", target_id="t1")
        assert t.config_dict() == {}


class TestPropagationResult:
    def test_success_result(self) -> None:
        t = _target()
        r = PropagationResult(target=t, success=True, health_check_passed=True)
        assert r.success is True
        assert r.error is None

    def test_failure_result(self) -> None:
        t = _target()
        r = PropagationResult(
            target=t, success=False,
            health_check_passed=False, error="timeout",
        )
        assert r.error == "timeout"


class TestPropagationEngine:
    async def test_single_target_success(self) -> None:
        updater = MockUpdater()
        engine = PropagationEngine(updaters={"mock": updater})
        targets = [_target("t1")]

        report = await engine.propagate("s1", "vault://ref", targets)
        assert report.all_succeeded is True
        assert len(report.results) == 1
        assert "s1:t1" in updater.update_calls

    async def test_multi_target_success(self) -> None:
        updater = MockUpdater()
        engine = PropagationEngine(updaters={"mock": updater})
        targets = [_target("t1"), _target("t2")]

        report = await engine.propagate("s1", "vault://ref", targets)
        assert report.all_succeeded is True
        assert len(report.results) == 2

    async def test_partial_failure(self) -> None:
        success_updater = MockUpdater(update_success=True)
        fail_updater = MockUpdater(update_success=False)
        engine = PropagationEngine(
            updaters={"mock": success_updater, "failing": fail_updater},
        )
        targets = [
            _target("t1", target_type="mock"),
            _target("t2", target_type="failing"),
        ]

        report = await engine.propagate("s1", "vault://ref", targets)
        assert report.all_succeeded is False
        assert "t2" in report.failed_targets

    async def test_health_check_failure_triggers_rollback(self) -> None:
        updater = MockUpdater(
            update_success=True, health_check_success=False,
        )
        engine = PropagationEngine(updaters={"mock": updater})
        targets = [_target("t1")]

        report = await engine.propagate(
            "s1", "vault://new", targets,
            previous_vault_reference="vault://old",
        )
        assert report.all_succeeded is False
        assert "s1:t1" in updater.rollback_calls

    async def test_no_updater_for_target_type(self) -> None:
        engine = PropagationEngine(updaters={})
        targets = [_target("t1", target_type="nonexistent")]

        report = await engine.propagate("s1", "vault://ref", targets)
        assert report.all_succeeded is False
        assert "No updater" in (report.results[0].error or "")

    async def test_graph_based_target_resolution(self) -> None:
        graph = DependencyGraph()
        graph.add_service(ServiceNode("svc-api", "api", ServiceType.API))
        graph.add_secret(SecretNode("s1", SecretType.API_KEY, "mock"))
        graph.add_dependency(DependencyEdge("svc-api", "s1", EdgeType.USES))

        updater = MockUpdater()
        engine = PropagationEngine(
            updaters={"kubernetes": updater}, graph=graph,
        )

        # No explicit targets — should resolve from graph
        report = await engine.propagate("s1", "vault://ref")
        assert len(report.results) == 1

    async def test_no_graph_no_targets(self) -> None:
        engine = PropagationEngine(updaters={"mock": MockUpdater()})
        report = await engine.propagate("s1", "vault://ref")
        assert report.all_succeeded is True
        assert len(report.results) == 0


class TestPropagationPipelineStep:
    async def test_happy_path(self) -> None:
        updater = MockUpdater()
        context = {
            "rotation": {
                "rotated": [
                    {"secret_id": "s1", "vault_reference": "vault://ref"},
                ],
            },
            "updaters": {"mock": updater},
        }
        result = await propagation_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output is not None
        assert result.output["all_succeeded"] is True

    async def test_missing_rotation_context_fails(self) -> None:
        result = await propagation_step({})
        assert result.status == StepStatus.FAILED

    async def test_no_updaters_skips(self) -> None:
        context = {
            "rotation": {"rotated": [{"secret_id": "s1", "vault_reference": "v"}]},
        }
        result = await propagation_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output.get("skipped") is True

    async def test_empty_rotated_list(self) -> None:
        context = {
            "rotation": {"rotated": []},
            "updaters": {"mock": MockUpdater()},
        }
        result = await propagation_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output["all_succeeded"] is True
