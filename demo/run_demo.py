"""End-to-end demo script — runs the full KeySentinel lifecycle with mock providers.

Usage:
    python -m demo.run_demo                  # full lifecycle
    python -m demo.run_demo --phase discovery
    python -m demo.run_demo --phase risk
    python -m demo.run_demo --phase compliance
    python -m demo.run_demo --phase incident
"""

import argparse
import asyncio
import logging
from typing import Any

from demo.mock_providers import MockAWSProvider, MockDatabaseProvider
from demo.seed_data import (
    generate_seed_policies,
    generate_seed_secrets,
    generate_service_declarations,
)
from src.compliance.engine import ComplianceEngine
from src.graph.builder import GraphBuilder
from src.incidents.handler import IncidentHandler
from src.incidents.models import WebhookAlert
from src.models.policy import ComplianceFramework
from src.pipeline.engine import PipelineEngine
from src.risk.engine import RiskEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("demo")


def _print_header(title: str) -> None:
    width = 60
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}\n")


def _print_result(label: str, value: Any) -> None:
    print(f"  {label}: {value}")


# ---------------------------------------------------------------------------
# Individual phases
# ---------------------------------------------------------------------------


async def run_discovery() -> dict[str, Any]:
    """Seed secrets as if discovered by the scanner."""
    _print_header("Phase 1: Discovery (Simulated)")
    secrets = generate_seed_secrets()
    services = generate_service_declarations()
    _print_result("Secrets found", len(secrets))
    for s in secrets:
        _print_result(f"  [{s['risk_level'].upper():>8}]", f"{s['name']} ({s['location']})")
    return {"secrets": secrets, "services": services}


async def run_dependency_graph(
    secrets: list[dict[str, Any]],
    services: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the dependency graph from seed data."""
    _print_header("Phase 2: Dependency Graph")
    builder = GraphBuilder()
    graph = builder.build_from_findings(
        secrets,
        service_declarations=services,
    )
    data = graph.to_dict()
    _print_result("Services", data.get("service_count", 0))
    _print_result("Secrets", data.get("secret_count", 0))
    _print_result("Edges", data.get("edge_count", 0))
    return data


async def run_risk_assessment(secrets: list[dict[str, Any]]) -> dict[str, Any]:
    """Run risk assessment on all secrets."""
    _print_header("Phase 3: Risk Assessment")
    engine = RiskEngine()
    assessments = await engine.assess_batch(secrets)
    for a in assessments:
        _print_result(
            f"  [{a.risk_level.value.upper():>8}]",
            f"{a.secret_id} — score {a.risk_score:.1f} ({len(a.signals)} signals)",
        )

    high_risk = [a for a in assessments if a.risk_score >= 60]
    _print_result("High risk secrets", len(high_risk))
    return {
        "assessments": [
            {
                "secret_id": a.secret_id,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level.value,
            }
            for a in assessments
        ],
        "high_risk_secrets": [
            {
                "secret_id": a.secret_id,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level.value,
            }
            for a in high_risk
        ],
    }


async def run_compliance(
    secrets: list[dict[str, Any]],
    policies: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run compliance assessment."""
    _print_header("Phase 4: Compliance Assessment")
    engine = ComplianceEngine(policies)
    results = engine.evaluate_all(secrets)

    for fw in [ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS]:
        score = engine.calculate_score(results, fw)
        _print_result(
            f"  {fw.value.upper()}",
            f"{score.score_percentage}% ({score.compliant_count}/{score.total_secrets})",
        )

    remediation = engine.generate_remediation_items(results)
    _print_result("Remediation items", len(remediation))
    for item in remediation:
        _print_result(f"    {item.secret_id}", item.recommended_action)

    return {"total_violations": len(remediation)}


async def run_incident_simulation() -> dict[str, Any]:
    """Simulate an incident from a GitHub secret scanning alert."""
    _print_header("Phase 5: Incident Response (Simulated)")

    providers = {
        "mock_aws_iam": MockAWSProvider(delay=0),
        "mock_postgresql": MockDatabaseProvider(delay=0),
    }
    handler = IncidentHandler(providers=providers)

    alert = WebhookAlert(
        source="github",
        alert_type="secret_scanning",
        secret_type="aws_access_key",
        exposed_url="https://github.com/org/repo/security/alerts/42",
        commit_sha="abc123def456",
        repository="org/repo",
    )

    ctx = await handler.handle_alert(alert)
    _print_result("Incident ID", ctx.incident_id)
    _print_result("Severity", ctx.severity.value)

    pipeline = handler.build_emergency_pipeline(ctx)
    engine = PipelineEngine()
    run = await engine.execute(pipeline)

    _print_result("Pipeline status", run.status.value)
    for i, result in enumerate(run.results):
        step_name = run.steps[i].name
        _print_result(f"  Step '{step_name}'", result.status.value)

    return {"status": run.status.value, "incident_id": ctx.incident_id}


# ---------------------------------------------------------------------------
# Full lifecycle
# ---------------------------------------------------------------------------


async def run_full_lifecycle() -> None:
    """Execute the complete KeySentinel lifecycle with mock infrastructure."""
    _print_header("KeySentinel End-to-End Demo")
    print("  Running full secret lifecycle with simulated infrastructure\n")

    # Phase 1: Discovery
    discovery = await run_discovery()
    secrets = discovery["secrets"]
    services = discovery["services"]

    # Phase 2: Dependency graph
    await run_dependency_graph(secrets, services)

    # Phase 3: Risk assessment
    await run_risk_assessment(secrets)

    # Phase 4: Compliance
    policies = generate_seed_policies()
    await run_compliance(secrets, policies)

    # Phase 5: Incident response
    await run_incident_simulation()

    _print_header("Demo Complete")
    print("  All phases executed successfully.")
    print("  In production, results would be persisted to PostgreSQL")
    print("  and credentials stored in HashiCorp Vault / AWS Secrets Manager.\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_PHASES = {
    "full": run_full_lifecycle,
    "discovery": run_discovery,
    "risk": lambda: run_risk_assessment(generate_seed_secrets()),
    "compliance": lambda: run_compliance(
        generate_seed_secrets(), generate_seed_policies()
    ),
    "incident": run_incident_simulation,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="KeySentinel E2E Demo")
    parser.add_argument(
        "--phase",
        choices=list(_PHASES.keys()),
        default="full",
        help="Run a specific phase (default: full)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    phase_fn = _PHASES[args.phase]
    asyncio.run(phase_fn())


if __name__ == "__main__":
    main()
