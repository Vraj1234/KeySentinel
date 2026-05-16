# KeySentinel — Progress Tracker

## Build Checklist

- [x] **Project scaffolding & provider abstraction layer** — Set up project structure, pyproject.toml, Docker config, FastAPI app skeleton, database models, and the base provider interface for secret rotation
- [ ] **Discovery engine — secret scanning & classification** — Build repo scanner, config scanner, cloud provider auditor, and AI-powered classifier to inventory all secrets with location and type
- [ ] **Dependency graph — secret-to-service mapping** — Implement NetworkX-based dependency modeling, rotation order planning, and blast radius scoring
- [ ] **Risk engine — scoring & policy rules** — Build configurable rule engine for age analysis, privilege auditing, exposure scoring, and compliance checks (SOC 2, PCI DSS)
- [ ] **Rotation pipeline — multi-provider key rotation** — Implement deterministic rotation executor (create → propagate → verify → deactivate → delete) with rollback for AWS IAM, databases, and Stripe
- [ ] **Propagation engine — dependent service updates** — Build updaters for Kubernetes secrets, CI/CD environment variables, and secret manager entries with health check verification
- [ ] **Incident response — emergency leak handling** — Implement webhook listener for GitHub secret scanning alerts, emergency rotation pipeline, and AI-assisted incident report generation
- [ ] **Compliance & reporting — audit reports** — Build policy enforcement engine, SOC 2 / PCI DSS report templates, remediation tracking, and AI-generated executive summaries
- [ ] **REST API & web dashboard** — Create FastAPI endpoints for all operations and a React dashboard showing secret inventory, risk scores, rotation history, and incident timeline
- [ ] **End-to-end demo with simulated infrastructure** — Build a Docker Compose environment simulating multiple services with secrets, run full discovery → rotation → verification cycle
