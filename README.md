# KeySentinel — Automated Secret Rotation & Lifecycle Platform

> **An automated platform that discovers, monitors, rotates, and propagates secrets across your entire stack — reliably and deterministically.**

KeySentinel is a secret lifecycle management platform built as an automated web application with event-driven pipelines. It goes beyond secret scanning — it understands your infrastructure's dependency graph, maps the blast radius of rotating any credential, executes rotations in the correct order, updates every dependent service, and verifies everything still works. When a leaked key is detected, it triggers emergency rotation in seconds, not hours.

AI is used surgically — for classifying scan findings and generating human-readable reports — but the core orchestration is deterministic pipelines you can trust with production infrastructure.

## The Problem

Secrets management is broken in most organizations:

- **Keys never get rotated** — 60% of organizations have API keys older than a year. Manual rotation is tedious and scary ("what if I break something?")
- **Secrets sprawl everywhere** — the same AWS key lives in GitHub Secrets, a .env file, a Kubernetes secret, a teammate's local machine, and a Confluence page from 2022
- **Rotation breaks things** — you rotate a database password, but forget it's also hardcoded in a cron job on a VM nobody remembers. 3 AM page
- **Leaked keys sit exposed** — a key gets committed to a public repo. You find out from GitHub's secret scanning email 4 hours later
- **No visibility** — most teams can't answer: "How many active API keys do we have? Which ones have admin privileges? When were they last rotated?"

## How It Works

KeySentinel treats secrets as first-class entities with a lifecycle:

```
Discovery → Inventory → Risk Assessment → Rotation → Propagation → Verification → Monitoring
     ^                                                                                |
     └──────────────────────── Continuous Loop <──────────────────────────────────────┘
```

The platform doesn't just find and rotate secrets — it **understands dependencies**. Before rotating a key, it maps every service, config file, and deployment that uses it, then updates them all in the correct order.

## Platform Architecture

### Pipeline Engine
The core of KeySentinel is a deterministic pipeline engine that orchestrates secret lifecycle operations:

- **Scheduled pipelines** — run discovery and risk assessment on configurable intervals (hourly, daily, weekly)
- **Event-driven pipelines** — triggered by webhooks (leak alerts, policy violations, manual rotation requests)
- **Step-based execution** — each pipeline is a sequence of deterministic steps with rollback capability
- **Approval gates** — critical operations pause for human approval before proceeding

### 1. Discovery Engine
Finds every secret in your ecosystem — known and unknown:

- **Repository scanning** — scans all repos for hardcoded secrets using pattern matching + entropy analysis
- **AI classification** — reduces false positives by classifying findings as real keys vs. test fixtures/examples
- **Cloud provider audit** — enumerates all IAM keys, service account keys, OAuth tokens across AWS/GCP/Azure
- **CI/CD inspection** — maps secrets in GitHub Actions, GitLab CI, Jenkins environment variables
- **Secret store inventory** — catalogs everything in HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager
- **Configuration file scan** — finds secrets in .env files, Docker configs, Kubernetes manifests, Terraform state

**Output**: A complete secret inventory with location, type, age, and privilege level for every credential.

### 2. Dependency Graph
The critical intelligence layer — maps which services depend on which secrets:

- **Service-to-secret mapping** — for each secret, identifies every service, job, and config that references it
- **Secret-to-provider mapping** — links each secret to the provider API that manages it (AWS IAM, Stripe, etc.)
- **Dependency chain analysis** — builds a graph showing cascading effects of rotation
- **Rotation order planning** — determines the safe order to update dependents
- **Blast radius scoring** — quantifies what breaks if rotation goes wrong

**Output**: A dependency graph with rotation ordering and blast radius scores.

### 3. Risk Engine
Evaluates and prioritizes every secret by risk using a configurable rule engine:

- **Age analysis** — flags keys past their rotation policy (30/60/90 day thresholds)
- **Privilege audit** — identifies over-privileged keys (admin keys used for read-only operations)
- **Exposure scoring** — rates exposure based on where the secret lives (Vault = low, .env in public repo = critical)
- **Usage pattern analysis** — detects unused keys, keys shared across too many services
- **Compliance rules** — evaluates against SOC 2 (90-day rotation), PCI DSS (no shared credentials), custom policies

**Output**: Risk-ranked inventory with specific policy violations and recommended actions.

### 4. Rotation Pipeline
Executes key rotation via provider APIs in a deterministic sequence:

- **Multi-provider support**:
  - AWS: IAM access keys, RDS passwords, Secrets Manager rotation
  - GCP: Service account keys, Cloud SQL passwords
  - Azure: AD app credentials, Key Vault secrets
  - SaaS: Stripe API keys, Twilio tokens, SendGrid keys, GitHub tokens
  - Databases: PostgreSQL, MySQL, MongoDB, Redis passwords
  - Custom: Webhook-based rotation for internal services
- **Graceful rotation sequence**:
  1. Create new key with provider
  2. Propagate new key to all dependents
  3. Verify all dependents work with new key
  4. Deactivate old key
  5. Delete old key after grace period
- **Automatic rollback** — if verification fails, revert to old key immediately

### 5. Propagation Engine
Updates every location that references a rotated secret:

- **Kubernetes Secrets** — patches K8s secrets and triggers rolling restarts
- **CI/CD variables** — updates GitHub Actions / GitLab CI / Jenkins environment variables via API
- **Secret managers** — updates Vault, AWS Secrets Manager, GCP Secret Manager entries
- **Configuration files** — updates .env files, Docker Compose configs (creates PR, doesn't push directly)
- **Cloud environments** — updates Lambda, ECS task definitions, Cloud Function configs
- **Health verification** — after each update, hits the service's health endpoint to confirm it's working

### 6. Compliance & Reporting
Enforces policies and generates audit reports:

- **Policy engine** — configurable rules (max key age, no secrets in source code, approved stores only)
- **Scheduled compliance scans** — runs on a schedule, alerts on policy violations
- **Audit report generation** — produces compliance reports for SOC 2, PCI DSS, HIPAA audits
- **AI-generated summaries** — natural language incident reports and executive summaries
- **Remediation tracking** — tracks which violations have been fixed and which are outstanding

### 7. Incident Response
Handles emergency scenarios via event-driven automation:

- **Webhook listener** — integrates with GitHub secret scanning, GitGuardian, TruffleHog alerts
- **Emergency rotation pipeline** — on leak detection:
  1. Assess blast radius from dependency graph
  2. Rotate the key via provider API (no grace period)
  3. Propagate new key to all dependents
  4. Verify all services recover
  5. Generate incident report with timeline
- **Response time tracking** — measures time from leak detection to full rotation (target: < 60 seconds)

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       KeySentinel Platform                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Web Dashboard                              │   │
│  │  Secret Inventory | Risk Scores | Rotation History | Alerts  │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                             │                                       │
│  ┌──────────────────────────┴──────────────────────────────────┐   │
│  │                    REST API (FastAPI)                         │   │
│  │  /secrets | /graph | /rotate | /incidents | /compliance      │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                             │                                       │
│  ┌──────────────────────────┴──────────────────────────────────┐   │
│  │                   Pipeline Engine                             │   │
│  │                                                              │   │
│  │  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐   │   │
│  │  │ Scheduler  │  │  Event     │  │  Approval Gates     │   │   │
│  │  │ (cron)     │  │  Triggers  │  │  (human-in-loop)    │   │   │
│  │  └─────┬──────┘  └─────┬──────┘  └─────────────────────┘   │   │
│  │        └────────┬───────┘                                    │   │
│  │                 ▼                                             │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │              Step Executor (deterministic)             │   │   │
│  │  │  discover → map → assess → rotate → propagate → verify│   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌───────────────────┐  ┌───────────────────┐  ┌──────────────┐   │
│  │  Discovery Engine │  │  Dependency Graph  │  │ Risk Engine  │   │
│  │  • Pattern match  │  │  • NetworkX graph  │  │ • Rule-based │   │
│  │  • Entropy scan   │  │  • Blast radius    │  │ • Configurable│  │
│  │  • AI classifier  │  │  • Rotation order  │  │ • Compliance │   │
│  └───────────────────┘  └───────────────────┘  └──────────────┘   │
│                                                                     │
│  ┌───────────────────┐  ┌───────────────────┐  ┌──────────────┐   │
│  │  Rotation Engine  │  │ Propagation Engine │  │ AI Utilities │   │
│  │  • AWS/GCP/Azure  │  │  • K8s patches     │  │ • Classify   │   │
│  │  • SaaS providers │  │  • CI/CD updates   │  │ • Summarize  │   │
│  │  • Databases      │  │  • Health checks   │  │ • Report     │   │
│  │  • Rollback       │  │  • Config PRs      │  │              │   │
│  └───────────────────┘  └───────────────────┘  └──────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Data Layer                                 │   │
│  │  PostgreSQL (inventory, audit log) | Redis (cache, queues)   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Example Workflow

### Scheduled Rotation
```
$ keysentinel scan --full

 Discovery Engine: Scanning ecosystem...
   ├── 3 GitHub repos scanned (2 hardcoded secrets found)
   ├── AWS: 12 IAM keys, 3 RDS passwords, 5 Secrets Manager entries
   ├── Kubernetes: 8 secrets across 3 namespaces
   ├── CI/CD: 15 GitHub Actions secrets, 4 Jenkins credentials
   └── Total: 47 unique secrets inventoried

 Dependency Graph: Building relationships...
   ├── aws-prod-key → used by: api-service, worker, cron-job
   ├── db-password → used by: api-service, analytics, migration-job
   ├── stripe-key → used by: payment-service only
   └── 47 secrets mapped to 23 services

 Risk Engine: Scoring...
   ├── CRITICAL: aws-prod-key is 340 days old (policy: 90 days)
   ├── CRITICAL: db-password hardcoded in docker-compose.prod.yml
   ├── HIGH: stripe-key has full admin scope (only needs read)
   ├── MEDIUM: 3 unused GCP service account keys
   └── Policy violations: 7 (SOC 2: 4, internal: 3)

 Ready to rotate 4 critical/high priority secrets.
   Review rotation plan at: http://localhost:8000/dashboard/rotation-plan
   [Approve / Edit / Skip]: approve

 Rotation Pipeline: Rotating aws-prod-key...
   ├── Created new IAM key: AKIA...NEW
   ├── Propagating to 3 dependents...
   │   ├── api-service K8s secret → updated, health check pass
   │   ├── worker K8s secret → updated, health check pass
   │   └── cron-job env var → updated, next run verified
   ├── Old key deactivated (grace period: 24h)
   └── Rotation complete

 Compliance Report generated:
   ├── /reports/audit-report.md         (SOC 2 format)
   ├── /reports/rotation-log.json       (machine-readable)
   └── /reports/inventory.json          (full secret inventory)

   Rotated: 4 | Remaining violations: 3 | Next scan: 24h
```

### Emergency Leak Response
```
 Webhook received: GitHub secret scanning alert
   └── AWS key AKIA...OLD found in public commit (repo: acme/api)

 T+0s: Blast radius lookup from dependency graph...
   ├── Key has AdministratorAccess policy
   ├── Used by: api-service, worker (production)
   └── Blast radius: CRITICAL

 T+3s: Emergency rotation pipeline triggered...
   ├── New IAM key created
   ├── Old key deactivated IMMEDIATELY (no grace period)
   └── Propagating to 2 services...

 T+12s: Propagation complete
   ├── api-service: updated, health check pass
   └── worker: updated, health check pass

 T+15s: Incident contained.
   ├── Total response time: 15 seconds
   ├── Incident report: http://localhost:8000/incidents/2026-05-15-aws-key-leak
   └── Recommendation: Enable pre-commit hook to prevent future leaks
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Backend API** | Python + FastAPI |
| **Pipeline Engine** | Celery + Redis (task queue for async pipelines) |
| **Database** | PostgreSQL (inventory, audit log, config) |
| **Cache & Queue** | Redis |
| **Secret Scanning** | TruffleHog (regex + entropy) |
| **AI Classification** | Anthropic Claude API (finding classification, report generation) |
| **Cloud APIs** | boto3 (AWS), google-cloud-iam (GCP), azure-identity (Azure) |
| **SaaS APIs** | Stripe, Twilio, SendGrid, GitHub REST API |
| **Kubernetes** | kubernetes Python client |
| **CI/CD APIs** | GitHub Actions API, GitLab API, Jenkins API |
| **Secret Stores** | hvac (Vault), cloud-native secret manager SDKs |
| **Dependency Graph** | NetworkX |
| **Web Dashboard** | React + TypeScript (Vite) |
| **Webhook Listener** | FastAPI endpoint for real-time alerts |
| **Reporting** | Markdown + JSON + HTML audit reports |
| **Containerization** | Docker + Docker Compose |

## Project Structure

```
KeySentinel/
├── src/
│   ├── api/
│   │   ├── app.py                 # FastAPI application
│   │   ├── routes/
│   │   │   ├── secrets.py         # Secret inventory endpoints
│   │   │   ├── rotation.py        # Rotation trigger/status endpoints
│   │   │   ├── incidents.py       # Incident management endpoints
│   │   │   ├── compliance.py      # Compliance report endpoints
│   │   │   └── webhooks.py        # Incoming webhook handlers
│   │   └── middleware/
│   │       ├── auth.py            # API authentication
│   │       └── audit_log.py       # Request audit logging
│   ├── pipeline/
│   │   ├── engine.py              # Pipeline orchestrator
│   │   ├── steps.py               # Base step interface
│   │   ├── scheduler.py           # Cron-based pipeline scheduling
│   │   └── approval.py            # Human approval gate logic
│   ├── discovery/
│   │   ├── scanner.py             # Unified scanning coordinator
│   │   ├── repo_scanner.py        # Git repository secret scanning
│   │   ├── cloud_auditor.py       # Cloud provider key enumeration
│   │   ├── config_scanner.py      # Configuration file scanning
│   │   └── classifier.py          # AI-powered false positive reduction
│   ├── graph/
│   │   ├── dependency_graph.py    # Secret dependency modeling (NetworkX)
│   │   ├── blast_radius.py        # Impact analysis
│   │   └── rotation_planner.py    # Safe rotation order calculation
│   ├── risk/
│   │   ├── engine.py              # Risk scoring coordinator
│   │   ├── rules.py               # Configurable risk rules
│   │   └── compliance.py          # Policy evaluation (SOC2, PCI DSS)
│   ├── rotation/
│   │   ├── executor.py            # Rotation pipeline executor
│   │   ├── rollback.py            # Rollback logic
│   │   └── providers/
│   │       ├── base.py            # Provider interface
│   │       ├── aws.py             # AWS IAM, RDS, Secrets Manager
│   │       ├── gcp.py             # GCP Service Accounts, Secret Manager
│   │       ├── azure.py           # Azure AD, Key Vault
│   │       ├── stripe.py          # Stripe API key rotation
│   │       ├── github.py          # GitHub token rotation
│   │       └── database.py        # PostgreSQL, MySQL, Redis passwords
│   ├── propagation/
│   │   ├── engine.py              # Propagation coordinator
│   │   ├── kubernetes.py          # K8s secret patching + rolling restart
│   │   ├── cicd.py                # GitHub Actions / GitLab CI updates
│   │   ├── vault.py               # HashiCorp Vault updates
│   │   └── config_files.py        # .env / Docker config updates (via PR)
│   ├── incidents/
│   │   ├── handler.py             # Incident response coordinator
│   │   ├── reporter.py            # Incident report generation (AI-assisted)
│   │   └── metrics.py             # Response time tracking
│   ├── models/
│   │   ├── secret.py              # Secret inventory models
│   │   ├── rotation.py            # Rotation event models
│   │   ├── incident.py            # Incident models
│   │   └── policy.py              # Policy/compliance models
│   └── db/
│       ├── database.py            # Database connection management
│       └── migrations/            # Alembic migrations
├── dashboard/                     # React frontend (Vite + TypeScript)
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── api/
│   └── package.json
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── alembic.ini
└── README.md
```

## Security Considerations

KeySentinel itself handles highly sensitive credentials. Built-in safeguards:

- **Least privilege** — KeySentinel's own credentials are scoped to only what's needed
- **No secret storage** — KeySentinel doesn't store secrets; it reads from and writes to your existing secret stores
- **Audit logging** — every action is logged with timestamp, actor, secret (redacted), and result
- **Dry-run mode** — `--dry-run` flag simulates all operations without making changes
- **Approval gates** — critical rotations require human approval (configurable per risk level)
- **Encrypted communication** — all API calls use TLS
- **Deterministic execution** — no AI in the critical path; rotation pipelines follow exact steps every time

## Why Not Agents?

Secret rotation is a **safety-critical operation**. The core workflow (scan, map, rotate, propagate, verify) is deterministic — it follows exact steps in an exact order. Making an LLM the orchestrator adds:

- **Non-determinism** — the last thing you want when rotating production credentials
- **Latency** — API calls to an LLM add seconds to what should be millisecond decisions
- **Cost** — running an LLM for every rotation event is expensive at scale
- **Opacity** — harder to audit exactly why a decision was made

AI is used where it genuinely helps:
- **Classifying scan findings** — distinguishing real secrets from test data (reduces false positives by ~80%)
- **Generating reports** — human-readable incident summaries and executive reports
- **Anomaly hints** — flagging unusual patterns for human review

The pipeline engine handles everything else with predictable, auditable, fast execution.

## License

MIT
