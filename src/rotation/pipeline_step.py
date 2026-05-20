import logging
from typing import Any

from src.graph.dependency_graph import DependencyGraph
from src.models.secret import RiskLevel
from src.pipeline.engine import PipelineRun, StepResult, StepStatus
from src.rotation.executor import RotationExecutor
from src.rotation.models import RotationRequest
from src.rotation.providers.base import RotationProvider

logger = logging.getLogger(__name__)

_ROTATION_REQUEST_FIELDS = frozenset(
    {
        "secret_id",
        "provider",
        "reason",
        "triggered_by",
        "force",
        "old_key_id",
        "risk_level",
    }
)


def _validated_request(req_dict: dict[str, Any]) -> RotationRequest:
    """Validate and construct a RotationRequest from a context dict."""
    unknown = set(req_dict) - _ROTATION_REQUEST_FIELDS
    if unknown:
        raise ValueError(f"Unknown fields in rotation_request: {unknown}")
    return RotationRequest(
        secret_id=req_dict["secret_id"],
        provider=req_dict["provider"],
        reason=req_dict["reason"],
        triggered_by=req_dict["triggered_by"],
        force=bool(req_dict.get("force", False)),
        old_key_id=req_dict.get("old_key_id"),
        risk_level=RiskLevel(req_dict.get("risk_level", "medium")),
    )


def _build_requests(
    context: dict[str, Any],
    providers: dict[str, RotationProvider],
) -> list[RotationRequest]:
    """Build RotationRequests from explicit list or risk assessment output."""
    explicit = context.get("rotation_requests", [])
    if explicit:
        return [_validated_request(req_dict) for req_dict in explicit]

    risk_output = context.get("risk_assessment", {})
    high_risk = risk_output.get("high_risk_secrets", [])
    requests: list[RotationRequest] = []
    for secret in high_risk:
        provider_name = secret.get("provider", "")
        if provider_name in providers:
            requests.append(
                RotationRequest(
                    secret_id=secret["secret_id"],
                    provider=provider_name,
                    reason="Auto-rotation: high risk score",
                    triggered_by="policy_engine",
                    risk_level=RiskLevel(secret.get("risk_level", "medium")),
                )
            )
    return requests


def _classify_runs(
    runs: list[PipelineRun],
) -> dict[str, list[dict[str, Any]]]:
    """Classify pipeline runs into rotated/skipped/failed buckets."""
    rotated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for run in runs:
        req_info = run.context.get("rotation_request", {})
        entry: dict[str, Any] = {
            "secret_id": req_info.get("secret_id"),
            "status": run.status.value,
        }
        if run.status == StepStatus.COMPLETED:
            create_output = run.context.get("create_key", {})
            entry["vault_reference"] = create_output.get("vault_reference")
            rotated.append(entry)
        elif run.status == StepStatus.FAILED:
            failed.append(entry)
        else:
            skipped.append(entry)
    return {"rotated": rotated, "skipped": skipped, "failed": failed}


async def rotation_step(context: dict[str, Any]) -> StepResult:
    """Pipeline step: executes rotation for identified secrets.

    Reads:
        context.get("rotation_requests") — explicit RotationRequest dicts, or
        context["risk_assessment"]["high_risk_secrets"] — auto-identified.
        context.get("dependency_graph") — serialized graph for ordering.
        context.get("providers") — dict of provider_name -> RotationProvider.

    Returns:
        StepResult with rotated/skipped/failed lists.
    """
    providers: dict[str, RotationProvider] = context.get("providers", {})
    if not providers:
        return StepResult(
            status=StepStatus.FAILED,
            error="No rotation providers in pipeline context",
        )

    graph: DependencyGraph | None = None
    graph_data = context.get("dependency_graph")
    if graph_data:
        try:
            graph = DependencyGraph.from_dict(graph_data)
        except Exception as e:
            logger.warning("Could not reconstruct dependency graph: %s", e)

    requests = _build_requests(context, providers)
    if not requests:
        return StepResult(
            status=StepStatus.COMPLETED,
            output={"rotated": [], "skipped": [], "failed": []},
        )

    try:
        executor = RotationExecutor(providers=providers, graph=graph)
        plan = await executor.plan(requests)
        runs = await executor.execute_batch(plan)

        return StepResult(
            status=StepStatus.COMPLETED,
            output=_classify_runs(runs),
        )
    except Exception as e:
        logger.error("Rotation step failed: %s", e, exc_info=True)
        return StepResult(status=StepStatus.FAILED, error=str(e))
