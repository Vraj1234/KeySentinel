"""Dependency graph query endpoints."""

from typing import Any

from fastapi import APIRouter, HTTPException

from src.api.schemas import BlastRadiusResponse, GraphSummaryResponse
from src.graph.dependency_graph import DependencyGraph

router = APIRouter(prefix="/api/v1/graph", tags=["graph"])

# In-memory graph instance. In a full deployment this would be loaded
# from the database or reconstructed from the latest pipeline run.
_graph: DependencyGraph | None = None


def set_graph(graph: DependencyGraph) -> None:
    """Inject a dependency graph (called during startup or after a pipeline run)."""
    global _graph  # noqa: PLW0603
    _graph = graph


def _get_graph() -> DependencyGraph:
    if _graph is None:
        raise HTTPException(
            status_code=503,
            detail="Dependency graph not available. Run a discovery pipeline first.",
        )
    return _graph


@router.get("/summary", response_model=GraphSummaryResponse)
async def graph_summary() -> GraphSummaryResponse:
    """Get high-level graph statistics."""
    graph = _get_graph()
    data = graph.to_dict()
    return GraphSummaryResponse(
        secret_count=data.get("secret_count", 0),
        service_count=data.get("service_count", 0),
        edge_count=data.get("edge_count", 0),
    )


@router.get(
    "/blast-radius/{secret_id}",
    response_model=BlastRadiusResponse,
)
async def blast_radius(secret_id: str) -> BlastRadiusResponse:
    """Get blast radius for a specific secret."""
    graph = _get_graph()
    result = graph.blast_radius(secret_id)
    return BlastRadiusResponse(
        secret_id=secret_id,
        affected_count=result.affected_count,
        affected_services=[s for s in result.affected_services],
    )


@router.get("/dependencies/{service_id}")
async def service_dependencies(service_id: str) -> dict[str, Any]:
    """Get secrets used by a service."""
    graph = _get_graph()
    secrets = graph.secrets_for_service(service_id)
    return {"service_id": service_id, "secrets": secrets}
