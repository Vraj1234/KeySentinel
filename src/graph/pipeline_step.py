import logging
from typing import Any

from src.graph.builder import GraphBuilder
from src.pipeline.engine import StepResult, StepStatus

logger = logging.getLogger(__name__)


async def build_dependency_graph_step(context: dict[str, Any]) -> StepResult:
    """Pipeline step: builds a dependency graph from discovery findings.

    Reads:
        context["discovery"]["findings"] — list of finding dicts from the discovery step.
        context.get("service_declarations") — optional explicit service definitions.

    Returns:
        StepResult with output containing the serialized graph and summary stats.
    """
    discovery_output = context.get("discovery")
    if not discovery_output:
        return StepResult(
            status=StepStatus.FAILED,
            error="No discovery output in pipeline context",
        )

    findings = discovery_output.get("findings", [])
    service_declarations = context.get("service_declarations")

    try:
        builder = GraphBuilder()
        graph = builder.build_from_findings(findings, service_declarations)

        graph_data = graph.to_dict()

        # Compute summary blast radius stats
        secrets = graph.secret_ids()
        blast_radii = {sid: graph.blast_radius(sid).affected_count for sid in secrets}

        output = {
            **graph_data,
            "secret_count": len(secrets),
            "service_count": graph.node_count - len(secrets),
            "edge_count": graph.edge_count,
            "blast_radii": blast_radii,
        }

        logger.info(
            "Dependency graph built: %d secrets, %d services, %d edges",
            output["secret_count"],
            output["service_count"],
            output["edge_count"],
        )

        return StepResult(status=StepStatus.COMPLETED, output=output)

    except Exception as e:
        logger.error("Dependency graph step failed: %s", e, exc_info=True)
        return StepResult(status=StepStatus.FAILED, error=str(e))
