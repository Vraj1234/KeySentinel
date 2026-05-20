# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (dev)
pip install -e ".[dev]"

# Run API
uvicorn src.api.app:app --reload

# Run Celery worker
celery -A src.pipeline.worker worker --loglevel=info

# Docker (full stack)
docker compose up

# Tests
pytest                                    # all tests
pytest tests/unit/test_pipeline_engine.py # single file
pytest -k "test_single_step"              # single test by name
pytest --cov=src --cov-report=term-missing # with coverage

# Lint & type check
ruff check src/
ruff check src/ --fix                     # auto-fix
mypy src/
```

## Architecture

KeySentinel is a **deterministic** secret lifecycle platform. The core rotation path has no LLM calls — AI is only used for classification (false positive reduction) and report generation.

### Pipeline Engine (`src/pipeline/engine.py`)

The central orchestrator. A `PipelineRun` holds an ordered list of `PipelineStep`s. The engine:
- Executes steps sequentially, passing each step's output into a shared `context` dict
- On failure, rolls back completed steps in reverse order (each step can register a `rollback_handler`)
- Raises `PipelineApprovalRequired` when a step has `requires_approval=True`, pausing execution

### Provider Abstraction (`src/rotation/providers/base.py`)

All secret rotation goes through the `RotationProvider` interface:
- `create_key()` → `verify_key()` → `deactivate_key()` → `delete_key()`
- `rollback()` composes `reactivate_key()` + `delete_key()`
- Providers store new credentials directly in the target vault and return only a `vault_reference` — **`RotationResult` must never contain plaintext secret material**

Implementations: `aws.py` (IAM keys via boto3, offloaded to thread executor), `database.py` (PostgreSQL ALTER ROLE with identifier validation).

### Data Flow

```
FastAPI API  →  PipelineEngine  →  Providers (AWS/DB/etc.)
                    ↓                      ↓
               PostgreSQL             Vault/SecretsManager
            (inventory, audit)      (actual credentials)
                    ↓
                  Redis
           (Celery broker/cache)
```

### Models (`src/models/`)

SQLAlchemy async models with `DateTime(timezone=True)` columns. Four tables: `secrets` (inventory), `rotation_events` (rotation audit log), `incidents` (leak response tracking), `policies` (compliance rules).

## Key Constraints

- **No secrets in code paths**: `RotationResult.vault_reference` is a pointer, not a credential. Providers must write to the vault directly.
- **SQL identifiers validated**: Database provider validates role names against `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$` at construction and execution time.
- **Async-safe boto3**: All synchronous boto3 calls are wrapped in `run_in_executor` to avoid blocking the event loop.
- **Timezone-aware datetimes**: Use `datetime.now(UTC)`, never `datetime.utcnow()`. All DB columns use `DateTime(timezone=True)`.
- **Config via env vars**: All settings use `KEYSENTINEL_` prefix. `anthropic_api_key` is required when `debug=False`.

## Configuration

Settings in `src/config.py` via pydantic-settings. Env prefix: `KEYSENTINEL_`. Loads from `.env` file. Docker Compose uses three Redis databases (0=cache, 1=broker, 2=results).
