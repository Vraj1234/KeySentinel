# KeySentinel — Progress Tracker

## Build Checklist

- [x] **Project scaffolding & provider abstraction layer** — Set up project structure, pyproject.toml, Docker config, FastAPI app skeleton, database models, and the base provider interface for secret rotation
- [x] **Discovery engine — secret scanning & classification** — Build repo scanner, config scanner, cloud provider auditor, and AI-powered classifier to inventory all secrets with location and type
- [x] **Dependency graph — secret-to-service mapping** — Implement NetworkX-based dependency modeling, rotation order planning, and blast radius scoring
- [x] **Risk engine — scoring & policy rules** — Build configurable rule engine for age analysis, privilege auditing, exposure scoring, and compliance checks (SOC 2, PCI DSS)
- [x] **Rotation pipeline — multi-provider key rotation** — Implement deterministic rotation executor (create → propagate → verify → deactivate → delete) with rollback for AWS IAM, databases, and Stripe
- [x] **Propagation engine — dependent service updates** — Build updaters for Kubernetes secrets, CI/CD environment variables, and secret manager entries with health check verification
## Implementation Notes (for next developer)

### Pipeline Integration

All modules expose `async (context: dict[str, Any]) -> StepResult` handlers. A full lifecycle pipeline chains them:

```python
PipelineRun(steps=[
    PipelineStep(name="discovery", handler=scanner.run_as_pipeline_step),
    PipelineStep(name="dependency_graph", handler=build_dependency_graph_step),
    PipelineStep(name="risk_assessment", handler=risk_assessment_step),
    PipelineStep(name="rotation", handler=rotation_step, requires_approval=True),
    PipelineStep(name="propagation", handler=propagation_step),
])
```

Context flows: `discovery.findings` → `dependency_graph` (serialized) → `risk_assessment.high_risk_secrets` → `rotation.rotated` (with `vault_reference`) → `propagation.results`.

### Key Design Decisions

- **Grace period deletion is deferred**: The inline rotation pipeline runs 4 phases (create → propagate → verify → deactivate). Old key deletion requires a separate scheduled task (Celery) that reads `scheduled_delete_at` from the deactivate step output. This needs to be wired up in the incident response or a standalone cleanup job.
- **Propagation placeholder**: The rotation executor's `_propagate_step` is a passthrough. Module 6's `PropagationEngine` is the real implementation — the two need to be connected when building the full pipeline (pass updaters via context).
- **AWS SM propagation**: Uses boto3 via `run_in_executor` (consistent with `src/rotation/providers/aws.py`). Requires AWS credentials in the environment.
- **K8s updater uses `verify=False`**: Intentional for self-signed cluster certs. A `ca_bundle` constructor parameter should be added before production use.
- **Graph serialization**: `DependencyGraph.to_dict()` / `from_dict()` uses `nx.node_link_data`. Edge types and service types are stored as string values for JSON compatibility.

### What's Missing for Production

- **Celery task for deferred key deletion** — reads `scheduled_delete_at` from rotation events
- **Provider registry** — rotation and propagation steps expect `context["providers"]` and `context["updaters"]` dicts; need a factory/registry to construct these from config
- **Database persistence** — risk assessments and rotation events should be written to the `secrets`, `rotation_events` tables; currently only pipeline context (in-memory)
- **Stripe provider** — listed in the rotation pipeline checklist but not implemented; follows the `RotationProvider` ABC pattern

---

- [ ] **Incident response — emergency leak handling** — Implement webhook listener for GitHub secret scanning alerts, emergency rotation pipeline, and AI-assisted incident report generation
- [ ] **Compliance & reporting — audit reports** — Build policy enforcement engine, SOC 2 / PCI DSS report templates, remediation tracking, and AI-generated executive summaries
- [ ] **REST API & web dashboard** — Create FastAPI endpoints for all operations and a React dashboard showing secret inventory, risk scores, rotation history, and incident timeline
- [ ] **End-to-end demo with simulated infrastructure** — Build a Docker Compose environment simulating multiple services with secrets, run full discovery → rotation → verification cycle
