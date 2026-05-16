import enum
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, Float, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.db.database import Base


class SecretType(str, enum.Enum):
    AWS_IAM_KEY = "aws_iam_key"
    AWS_RDS_PASSWORD = "aws_rds_password"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    AZURE_AD_CREDENTIAL = "azure_ad_credential"
    DATABASE_PASSWORD = "database_password"
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SSH_KEY = "ssh_key"
    TLS_CERTIFICATE = "tls_certificate"
    GENERIC = "generic"


class SecretLocation(str, enum.Enum):
    VAULT = "vault"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    GCP_SECRET_MANAGER = "gcp_secret_manager"
    AZURE_KEY_VAULT = "azure_key_vault"
    KUBERNETES_SECRET = "kubernetes_secret"
    ENVIRONMENT_VARIABLE = "environment_variable"
    CI_CD_VARIABLE = "ci_cd_variable"
    CONFIG_FILE = "config_file"
    SOURCE_CODE = "source_code"


class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_type: Mapped[SecretType] = mapped_column(Enum(SecretType), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    location: Mapped[SecretLocation] = mapped_column(Enum(SecretLocation), nullable=False)
    location_detail: Mapped[str] = mapped_column(Text, nullable=False)

    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), default=RiskLevel.INFO)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_age_days: Mapped[int | None] = mapped_column(nullable=True)

    owner_service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)
