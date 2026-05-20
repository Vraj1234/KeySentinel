from pydantic import model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "KeySentinel"
    debug: bool = False

    database_url: str = "postgresql+asyncpg://localhost:5432/keysentinel"
    redis_url: str = "redis://localhost:6379/0"

    api_host: str = "0.0.0.0"
    api_port: int = 8000

    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    anthropic_api_key: str = ""

    rotation_grace_period_hours: int = 24
    default_scan_interval_hours: int = 24
    emergency_rotation_enabled: bool = True

    approval_required_for_critical: bool = True
    approval_required_for_high: bool = False

    # Discovery settings
    scan_repo_paths: list[str] = []
    scan_config_dirs: list[str] = []
    scan_cloud_providers: list[str] = []
    classifier_batch_size: int = 20
    classifier_model: str = "claude-sonnet-4-20250514"
    entropy_threshold: float = 4.5
    scan_max_file_size_kb: int = 512
    scan_git_history_commits: int = 100

    @model_validator(mode="after")
    def _validate_production_config(self) -> "Settings":
        if not self.debug and not self.anthropic_api_key:
            raise ValueError("KEYSENTINEL_ANTHROPIC_API_KEY is required in production (debug=False)")
        return self

    model_config = {"env_prefix": "KEYSENTINEL_", "env_file": ".env"}


settings = Settings()
