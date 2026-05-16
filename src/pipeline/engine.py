import enum
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


class StepStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"
    ROLLBACK_FAILED = "rollback_failed"


@dataclass
class StepResult:
    status: StepStatus
    output: dict[str, Any] | None = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


@dataclass
class PipelineStep:
    name: str
    handler: Callable[[dict[str, Any]], Coroutine[Any, Any, StepResult]]
    requires_approval: bool = False
    rollback_handler: Callable[[dict[str, Any]], Coroutine[Any, Any, None]] | None = None


@dataclass
class PipelineRun:
    pipeline_id: str
    steps: list[PipelineStep]
    context: dict[str, Any] = field(default_factory=dict)
    results: list[StepResult] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None


class PipelineApprovalRequired(Exception):
    """Raised when a step requires human approval before proceeding."""

    def __init__(self, step_name: str, pipeline_id: str) -> None:
        self.step_name = step_name
        self.pipeline_id = pipeline_id
        super().__init__(f"Step '{step_name}' in pipeline '{pipeline_id}' requires approval")


class PipelineEngine:
    """Deterministic pipeline executor.

    Runs a sequence of steps in order. If a step fails, triggers rollback
    of all previously completed steps (in reverse order).
    """

    async def execute(self, run: PipelineRun) -> PipelineRun:
        run.status = StepStatus.RUNNING
        run.started_at = datetime.now(UTC)

        for step in run.steps:
            if step.requires_approval:
                run.status = StepStatus.WAITING_APPROVAL
                raise PipelineApprovalRequired(step.name, run.pipeline_id)

            result = await self._execute_step(step, run.context)
            run.results.append(result)

            if result.status == StepStatus.FAILED:
                run.status = StepStatus.FAILED
                await self._rollback(run)
                run.completed_at = datetime.now(UTC)
                return run

            if result.output is not None:
                run.context[step.name] = result.output

        run.status = StepStatus.COMPLETED
        run.completed_at = datetime.now(UTC)
        return run

    async def _execute_step(self, step: PipelineStep, context: dict[str, Any]) -> StepResult:
        started_at = datetime.now(UTC)
        try:
            result = await step.handler(context)
            result.started_at = started_at
            result.completed_at = datetime.now(UTC)
            return result
        except Exception as e:
            logger.error("Step '%s' failed: %s", step.name, e, exc_info=True)
            return StepResult(
                status=StepStatus.FAILED,
                error=str(e),
                started_at=started_at,
                completed_at=datetime.now(UTC),
            )

    async def _rollback(self, run: PipelineRun) -> None:
        completed_steps = [
            (step, result)
            for step, result in zip(run.steps, run.results)
            if result.status == StepStatus.COMPLETED and step.rollback_handler is not None
        ]

        for step, result in reversed(completed_steps):
            try:
                await step.rollback_handler(run.context)  # type: ignore[misc]
            except Exception as e:
                logger.error(
                    "Rollback FAILED for step '%s' in pipeline '%s': %s",
                    step.name,
                    run.pipeline_id,
                    e,
                    exc_info=True,
                )
                result.status = StepStatus.ROLLBACK_FAILED
