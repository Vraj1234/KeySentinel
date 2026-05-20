import logging

from src.graph.dependency_graph import DependencyGraph
from src.propagation.models import PropagationReport, PropagationResult, PropagationTarget
from src.propagation.updaters.base import PropagationUpdater

logger = logging.getLogger(__name__)


class PropagationEngine:
    """Coordinates propagation of rotated credentials to dependent services.

    For each target: update credential -> health check -> rollback on failure.
    """

    def __init__(
        self,
        updaters: dict[str, PropagationUpdater],
        graph: DependencyGraph | None = None,
    ) -> None:
        self._updaters = updaters
        self._graph = graph

    async def propagate(
        self,
        secret_id: str,
        vault_reference: str,
        targets: list[PropagationTarget] | None = None,
        previous_vault_reference: str | None = None,
    ) -> PropagationReport:
        """Propagate a rotated credential to all targets.

        If targets are not given, resolves them from the dependency graph.
        """
        resolved_targets = targets if targets else self._resolve_targets(secret_id)

        results: list[PropagationResult] = []
        for target in resolved_targets:
            result = await self._propagate_single(
                secret_id,
                vault_reference,
                target,
                previous_vault_reference,
            )
            results.append(result)

        failed = tuple(r.target.target_id for r in results if not r.success)
        return PropagationReport(
            secret_id=secret_id,
            results=tuple(results),
            all_succeeded=len(failed) == 0,
            failed_targets=failed,
        )

    def _resolve_targets(self, secret_id: str) -> list[PropagationTarget]:
        """Use the dependency graph to find services that need updates."""
        if not self._graph:
            logger.warning(
                "No dependency graph available, cannot resolve targets for %s",
                secret_id,
            )
            return []

        service_ids = self._graph.services_using_secret(secret_id)
        targets: list[PropagationTarget] = []
        for svc_id in service_ids:
            svc_type = self._graph.service_type(svc_id) or "unknown"

            # Map service types to target types
            target_type = _SERVICE_TYPE_TO_TARGET.get(svc_type, "vault")
            targets.append(
                PropagationTarget(
                    target_type=target_type,
                    target_id=svc_id,
                )
            )

        return targets

    async def _propagate_single(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
        previous_vault_reference: str | None = None,
    ) -> PropagationResult:
        """Update one target, run health check, rollback on failure."""
        updater = self._updaters.get(target.target_type)
        if not updater:
            return PropagationResult(
                target=target,
                success=False,
                health_check_passed=False,
                error=f"No updater for target type '{target.target_type}'",
            )

        result = await updater.update(secret_id, vault_reference, target)

        if result.success and not result.health_check_passed:
            # Health check failed — attempt rollback
            logger.warning(
                "Health check failed for %s after propagation, rolling back",
                target.target_id,
            )
            if previous_vault_reference:
                rollback_result = await updater.rollback(
                    secret_id,
                    previous_vault_reference,
                    target,
                )
                if not rollback_result.success:
                    logger.error(
                        "Rollback also failed for %s on %s: %s",
                        secret_id,
                        target.target_id,
                        rollback_result.error,
                    )
                    return PropagationResult(
                        target=target,
                        success=False,
                        health_check_passed=False,
                        error=f"Health check failed and rollback failed: {rollback_result.error}",
                    )
            return PropagationResult(
                target=target,
                success=False,
                health_check_passed=False,
                error="Health check failed after propagation",
            )

        return result


# Mapping from service_type to target_type
_SERVICE_TYPE_TO_TARGET: dict[str, str] = {
    "api": "kubernetes",
    "worker": "kubernetes",
    "database": "vault",
    "cicd": "cicd",
}
