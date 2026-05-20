import logging
from typing import Any

from src.graph.dependency_graph import DependencyGraph
from src.pipeline.engine import StepResult, StepStatus
from src.propagation.engine import PropagationEngine
from src.propagation.updaters.base import PropagationUpdater

logger = logging.getLogger(__name__)


async def propagation_step(context: dict[str, Any]) -> StepResult:
    """Pipeline step: propagates rotated credentials to dependent services.

    Reads:
        context["rotation"] — rotation output with vault_references.
        context.get("dependency_graph") — serialized graph for target resolution.
        context.get("updaters") — dict of target_type -> PropagationUpdater.

    Returns:
        StepResult with propagation results.
    """
    rotation_output = context.get("rotation")
    if not rotation_output:
        return StepResult(
            status=StepStatus.FAILED,
            error="No rotation output in pipeline context",
        )

    updaters: dict[str, PropagationUpdater] = context.get("updaters", {})
    if not updaters:
        return StepResult(
            status=StepStatus.COMPLETED,
            output={"results": [], "all_succeeded": True, "skipped": True},
        )

    # Reconstruct graph
    graph: DependencyGraph | None = None
    graph_data = context.get("dependency_graph")
    if graph_data:
        try:
            graph = DependencyGraph.from_dict(graph_data)
        except Exception as e:
            logger.warning("Could not reconstruct dependency graph: %s", e)

    try:
        engine = PropagationEngine(updaters=updaters, graph=graph)
        all_results: list[dict[str, Any]] = []
        overall_success = True

        rotated = rotation_output.get("rotated", [])
        for entry in rotated:
            secret_id = entry.get("secret_id", "")
            vault_ref = entry.get("vault_reference", "")
            if not vault_ref:
                logger.error(
                    "Secret %s missing vault_reference in rotation output, skipping propagation",
                    secret_id,
                )
                all_results.append(
                    {
                        "secret_id": secret_id,
                        "all_succeeded": False,
                        "failed_targets": [],
                        "error": "missing vault_reference",
                    }
                )
                overall_success = False
                continue

            report = await engine.propagate(secret_id, vault_ref)
            all_results.append(
                {
                    "secret_id": secret_id,
                    "all_succeeded": report.all_succeeded,
                    "failed_targets": list(report.failed_targets),
                    "target_count": len(report.results),
                }
            )
            if not report.all_succeeded:
                overall_success = False

        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "results": all_results,
                "all_succeeded": overall_success,
            },
        )

    except Exception as e:
        logger.error("Propagation step failed: %s", e, exc_info=True)
        return StepResult(status=StepStatus.FAILED, error=str(e))
