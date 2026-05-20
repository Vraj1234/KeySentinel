import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from src.graph.dependency_graph import DependencyGraph
from src.models.secret import RiskLevel
from src.pipeline.engine import PipelineEngine, PipelineRun, PipelineStep, StepResult, StepStatus
from src.rotation.models import RotationPlan, RotationRequest
from src.rotation.providers.base import RotationProvider

logger = logging.getLogger(__name__)


class RotationExecutor:
    """Orchestrates the 5-phase rotation lifecycle via PipelineEngine.

    Phases: create_key -> propagate -> verify_key -> deactivate_key -> delete_key

    Each phase is a PipelineStep. The executor constructs a PipelineRun
    for each RotationRequest, with rollback handlers on the create step.
    """

    def __init__(
        self,
        providers: dict[str, RotationProvider],
        graph: DependencyGraph | None = None,
        grace_period_hours: int = 24,
        approval_required_for_critical: bool = True,
        approval_required_for_high: bool = False,
    ) -> None:
        self._providers = providers
        self._graph = graph
        self._grace_period_hours = grace_period_hours
        self._approval_for_critical = approval_required_for_critical
        self._approval_for_high = approval_required_for_high
        self._engine = PipelineEngine()

    async def plan(self, requests: list[RotationRequest]) -> RotationPlan:
        """Determine rotation order and approval requirements."""
        secret_ids = [r.secret_id for r in requests]

        # Use graph for ordering if available
        if self._graph:
            try:
                ordered = self._graph.rotation_order(secret_ids)
                # Include any secrets not in the graph at the end
                remaining = [s for s in secret_ids if s not in set(ordered)]
                ordered.extend(remaining)
            except ValueError:
                logger.warning("Cycle in dependency graph, using request order")
                ordered = secret_ids
        else:
            ordered = secret_ids

        # Determine which secrets need approval
        needs_approval: list[str] = []
        for req in requests:
            if req.force:
                continue
            if self._approval_for_critical and req.risk_level == RiskLevel.CRITICAL:
                needs_approval.append(req.secret_id)
            elif self._approval_for_high and req.risk_level == RiskLevel.HIGH:
                needs_approval.append(req.secret_id)

        return RotationPlan(
            requests=tuple(requests),
            rotation_order=tuple(ordered),
            requires_approval=tuple(needs_approval),
        )

    async def execute_single(self, request: RotationRequest) -> PipelineRun:
        """Execute a full rotation for one secret."""
        plan = await self.plan([request])
        run = self._build_pipeline_run(request, plan)
        return await self._engine.execute(run)

    async def execute_batch(self, plan: RotationPlan) -> list[PipelineRun]:
        """Execute rotations in dependency-graph order."""
        request_map = {r.secret_id: r for r in plan.requests}
        results: list[PipelineRun] = []

        for secret_id in plan.rotation_order:
            request = request_map.get(secret_id)
            if not request:
                continue
            run = self._build_pipeline_run(request, plan)
            result = await self._engine.execute(run)
            results.append(result)

        return results

    def _build_pipeline_run(
        self,
        request: RotationRequest,
        plan: RotationPlan,
    ) -> PipelineRun:
        """Construct a 5-step PipelineRun for one rotation."""
        provider = self._providers.get(request.provider)
        if not provider:
            raise ValueError(
                f"No provider registered for '{request.provider}'",
            )

        needs_approval = request.secret_id in plan.requires_approval and not request.force

        # Capture request and provider in closures for step handlers
        async def create_step(context: dict[str, Any]) -> StepResult:
            return await self._create_step(provider, request, context)

        async def propagate_step(context: dict[str, Any]) -> StepResult:
            return await self._propagate_step(request, context)

        async def verify_step(context: dict[str, Any]) -> StepResult:
            return await self._verify_step(provider, context)

        async def deactivate_step(context: dict[str, Any]) -> StepResult:
            return await self._deactivate_step(provider, request, context)

        async def delete_step(context: dict[str, Any]) -> StepResult:
            return await self._delete_step(provider, request, context)

        async def rollback_create(context: dict[str, Any]) -> None:
            await self._rollback_create(provider, request, context)

        # The pipeline runs 4 phases inline: create → propagate → verify → deactivate.
        # Deletion of the old key is deferred to a scheduled task after the grace period
        # (see grace_period_hours). The deactivate step records scheduled_delete_at
        # in its output for downstream scheduling.
        steps = [
            PipelineStep(
                name="create_key",
                handler=create_step,
                requires_approval=needs_approval,
                rollback_handler=rollback_create,
            ),
            PipelineStep(name="propagate", handler=propagate_step),
            PipelineStep(name="verify_key", handler=verify_step),
            PipelineStep(name="deactivate_key", handler=deactivate_step),
        ]

        # Only include inline delete when grace period is zero (immediate deletion)
        if self._grace_period_hours == 0:
            steps.append(PipelineStep(name="delete_key", handler=delete_step))

        return PipelineRun(
            pipeline_id=f"rotation-{request.secret_id}-{uuid4().hex[:8]}",
            steps=steps,
            context={
                "rotation_request": {
                    "secret_id": request.secret_id,
                    "provider": request.provider,
                    "old_key_id": request.old_key_id,
                    "reason": request.reason,
                    "triggered_by": request.triggered_by,
                }
            },
        )

    async def _create_step(
        self,
        provider: RotationProvider,
        request: RotationRequest,
        context: dict[str, Any],
    ) -> StepResult:
        result = await provider.create_key(request.secret_id)
        if not result.success:
            return StepResult(
                status=StepStatus.FAILED,
                error=result.error or "create_key failed",
            )
        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "new_key_id": result.new_key_id,
                "vault_reference": result.vault_reference,
                "created_at": (
                    result.new_key_created_at.isoformat() if result.new_key_created_at else None
                ),
            },
        )

    async def _propagate_step(
        self,
        request: RotationRequest,
        context: dict[str, Any],
    ) -> StepResult:
        """Placeholder for propagation — Module 6 hooks in here."""
        return StepResult(
            status=StepStatus.COMPLETED,
            output={"propagated": True, "targets": []},
        )

    async def _verify_step(
        self,
        provider: RotationProvider,
        context: dict[str, Any],
    ) -> StepResult:
        create_output = context.get("create_key", {})
        new_key_id = create_output.get("new_key_id")
        if not new_key_id:
            return StepResult(
                status=StepStatus.FAILED,
                error="No new_key_id in context from create step",
            )

        is_valid = await provider.verify_key(new_key_id)
        if not is_valid:
            return StepResult(
                status=StepStatus.FAILED,
                error=f"Verification failed for key {new_key_id}",
            )
        return StepResult(
            status=StepStatus.COMPLETED,
            output={"verified": True, "key_id": new_key_id},
        )

    async def _deactivate_step(
        self,
        provider: RotationProvider,
        request: RotationRequest,
        context: dict[str, Any],
    ) -> StepResult:
        old_key_id = request.old_key_id
        if not old_key_id:
            return StepResult(
                status=StepStatus.SKIPPED,
                output={"reason": "No old key to deactivate"},
            )

        result = await provider.deactivate_key(old_key_id)
        if not result.success:
            return StepResult(
                status=StepStatus.FAILED,
                error=result.error or "deactivate_key failed",
            )
        deactivated_at = datetime.now(UTC)
        grace = timedelta(hours=self._grace_period_hours)
        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "deactivated_key_id": old_key_id,
                "deactivated_at": deactivated_at.isoformat(),
                "scheduled_delete_at": (deactivated_at + grace).isoformat(),
            },
        )

    async def _delete_step(
        self,
        provider: RotationProvider,
        request: RotationRequest,
        context: dict[str, Any],
    ) -> StepResult:
        old_key_id = request.old_key_id
        if not old_key_id:
            return StepResult(
                status=StepStatus.SKIPPED,
                output={"reason": "No old key to delete"},
            )

        result = await provider.delete_key(old_key_id)
        if not result.success:
            return StepResult(
                status=StepStatus.FAILED,
                error=result.error or "delete_key failed",
            )
        return StepResult(
            status=StepStatus.COMPLETED,
            output={"deleted_key_id": old_key_id},
        )

    async def _rollback_create(
        self,
        provider: RotationProvider,
        request: RotationRequest,
        context: dict[str, Any],
    ) -> None:
        create_output = context.get("create_key", {})
        new_key_id = create_output.get("new_key_id")
        old_key_id = request.old_key_id

        if new_key_id and old_key_id:
            result = await provider.rollback(old_key_id, new_key_id)
            if not result.success:
                logger.error(
                    "Rollback failed for secret %s: %s",
                    request.secret_id,
                    result.error,
                )
        elif new_key_id:
            result = await provider.delete_key(new_key_id)
            if not result.success:
                logger.error(
                    "Failed to delete new key %s during rollback: %s",
                    new_key_id,
                    result.error,
                )
