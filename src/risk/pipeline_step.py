import hashlib
import logging
from typing import Any

from src.graph.dependency_graph import DependencyGraph
from src.pipeline.engine import StepResult, StepStatus
from src.risk.engine import RiskEngine
from src.risk.policy import PolicyEvaluator

logger = logging.getLogger(__name__)


async def risk_assessment_step(context: dict[str, Any]) -> StepResult:
    """Pipeline step: runs risk assessment on all secrets from discovery.

    Reads:
        context["discovery"]["findings"] — classified findings.
        context.get("dependency_graph") — serialized graph for blast radius.
        context.get("policies") — list of policy dicts for compliance checks.

    Returns:
        StepResult with assessments, high-risk secret IDs, and summary.
    """
    discovery_output = context.get("discovery")
    if not discovery_output:
        return StepResult(
            status=StepStatus.FAILED,
            error="No discovery output in pipeline context",
        )

    findings = discovery_output.get("findings", [])

    # Reconstruct graph for blast radius enrichment
    graph: DependencyGraph | None = None
    graph_data = context.get("dependency_graph")
    if graph_data:
        try:
            graph = DependencyGraph.from_dict(graph_data)
        except Exception as e:
            logger.warning("Could not reconstruct dependency graph: %s", e)

    # Load policies for compliance checks
    policies = context.get("policies", [])
    policy_evaluator = PolicyEvaluator(policies) if policies else None

    try:
        engine = RiskEngine()
        secret_contexts: list[dict[str, Any]] = []

        for finding in findings:
            ctx: dict[str, Any] = {**finding}

            # Enrich with blast radius from graph
            if graph and graph_data is not None:
                blast_radii = graph_data.get("blast_radii", {})
                # Match finding to its graph secret node using the same hash
                rule_id = finding.get("rule_id", "unknown")
                detail = finding.get("location_detail", "unknown")
                stable_hash = hashlib.sha256(f"{rule_id}:{detail}".encode()).hexdigest()[:12]
                graph_secret_id = f"secret-{stable_hash}"
                if graph_secret_id in blast_radii:
                    ctx["blast_radius_affected_count"] = blast_radii[graph_secret_id]

            # Enrich with policy violations
            if policy_evaluator:
                violations = policy_evaluator.evaluate(ctx)
                if violations:
                    ctx["policy_violations"] = [
                        {
                            "reason": v.reason,
                            "framework": v.framework.value,
                            "policy_type": v.policy_type.value,
                        }
                        for v in violations
                    ]

            # Use a stable ID for the assessment
            rule_id = finding.get("rule_id", "unknown")
            detail = finding.get("location_detail", "unknown")
            ctx.setdefault("secret_id", f"{rule_id}:{detail}")

            secret_contexts.append(ctx)

        assessments = await engine.assess_batch(secret_contexts)

        # Identify high-risk secrets (CRITICAL or HIGH)
        high_risk = [
            {
                "secret_id": a.secret_id,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level.value,
            }
            for a in assessments
            if a.risk_level.value in ("critical", "high")
        ]

        output = {
            "assessments": [
                {
                    "secret_id": a.secret_id,
                    "risk_score": a.risk_score,
                    "risk_level": a.risk_level.value,
                    "signal_count": len(a.signals),
                }
                for a in assessments
            ],
            "high_risk_secrets": high_risk,
            "summary": {
                "total_assessed": len(assessments),
                "critical_count": sum(1 for a in assessments if a.risk_level.value == "critical"),
                "high_count": sum(1 for a in assessments if a.risk_level.value == "high"),
            },
        }

        logger.info(
            "Risk assessment complete: %d secrets, %d critical, %d high",
            output["summary"]["total_assessed"],
            output["summary"]["critical_count"],
            output["summary"]["high_count"],
        )

        return StepResult(status=StepStatus.COMPLETED, output=output)

    except Exception as e:
        logger.error("Risk assessment step failed: %s", e, exc_info=True)
        return StepResult(status=StepStatus.FAILED, error=str(e))
