import pytest

from src.pipeline.engine import (
    PipelineApprovalRequired,
    PipelineEngine,
    PipelineRun,
    PipelineStep,
    StepResult,
    StepStatus,
)


async def _success_step(context: dict) -> StepResult:
    return StepResult(status=StepStatus.COMPLETED, output={"done": True})


async def _fail_step(context: dict) -> StepResult:
    return StepResult(status=StepStatus.FAILED, error="step failed")


async def _raise_step(context: dict) -> StepResult:
    raise RuntimeError("unexpected error")


async def _rollback_handler(context: dict) -> None:
    context["rolled_back"] = True


async def _failing_rollback(context: dict) -> None:
    raise RuntimeError("rollback failed")


@pytest.fixture
def engine() -> PipelineEngine:
    return PipelineEngine()


class TestPipelineEngineHappyPath:
    async def test_single_step_completes(self, engine: PipelineEngine) -> None:
        run = PipelineRun(
            pipeline_id="test-1",
            steps=[PipelineStep(name="step1", handler=_success_step)],
        )
        result = await engine.execute(run)

        assert result.status == StepStatus.COMPLETED
        assert len(result.results) == 1
        assert result.results[0].status == StepStatus.COMPLETED
        assert result.started_at is not None
        assert result.completed_at is not None

    async def test_multiple_steps_complete_in_order(self, engine: PipelineEngine) -> None:
        run = PipelineRun(
            pipeline_id="test-2",
            steps=[
                PipelineStep(name="step1", handler=_success_step),
                PipelineStep(name="step2", handler=_success_step),
            ],
        )
        result = await engine.execute(run)

        assert result.status == StepStatus.COMPLETED
        assert len(result.results) == 2

    async def test_step_output_passed_to_context(self, engine: PipelineEngine) -> None:
        async def _check_context(context: dict) -> StepResult:
            assert context["step1"] == {"done": True}
            return StepResult(status=StepStatus.COMPLETED)

        run = PipelineRun(
            pipeline_id="test-3",
            steps=[
                PipelineStep(name="step1", handler=_success_step),
                PipelineStep(name="step2", handler=_check_context),
            ],
        )
        result = await engine.execute(run)
        assert result.status == StepStatus.COMPLETED


class TestPipelineEngineFailure:
    async def test_failed_step_triggers_rollback(self, engine: PipelineEngine) -> None:
        run = PipelineRun(
            pipeline_id="test-fail",
            steps=[
                PipelineStep(
                    name="step1",
                    handler=_success_step,
                    rollback_handler=_rollback_handler,
                ),
                PipelineStep(name="step2", handler=_fail_step),
            ],
        )
        result = await engine.execute(run)

        assert result.status == StepStatus.FAILED
        assert result.context.get("rolled_back") is True

    async def test_exception_in_step_marks_failed(self, engine: PipelineEngine) -> None:
        run = PipelineRun(
            pipeline_id="test-exc",
            steps=[PipelineStep(name="step1", handler=_raise_step)],
        )
        result = await engine.execute(run)

        assert result.status == StepStatus.FAILED
        assert "unexpected error" in (result.results[0].error or "")

    async def test_rollback_failure_marks_step(self, engine: PipelineEngine) -> None:
        run = PipelineRun(
            pipeline_id="test-rb-fail",
            steps=[
                PipelineStep(
                    name="step1",
                    handler=_success_step,
                    rollback_handler=_failing_rollback,
                ),
                PipelineStep(name="step2", handler=_fail_step),
            ],
        )
        result = await engine.execute(run)

        assert result.status == StepStatus.FAILED
        assert result.results[0].status == StepStatus.ROLLBACK_FAILED


class TestPipelineApprovalGate:
    async def test_approval_required_raises(self, engine: PipelineEngine) -> None:
        run = PipelineRun(
            pipeline_id="test-approval",
            steps=[
                PipelineStep(
                    name="step1",
                    handler=_success_step,
                    requires_approval=True,
                ),
            ],
        )
        with pytest.raises(PipelineApprovalRequired) as exc_info:
            await engine.execute(run)

        assert exc_info.value.step_name == "step1"
        assert exc_info.value.pipeline_id == "test-approval"
