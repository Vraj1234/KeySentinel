import enum
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.db.database import Base


class PolicyType(str, enum.Enum):
    MAX_AGE = "max_age"
    NO_SOURCE_CODE = "no_source_code"
    APPROVED_STORE_ONLY = "approved_store_only"
    NO_SHARED_CREDENTIALS = "no_shared_credentials"
    MIN_KEY_LENGTH = "min_key_length"
    REQUIRED_ROTATION = "required_rotation"
    CUSTOM = "custom"


class ComplianceFramework(str, enum.Enum):
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    INTERNAL = "internal"
    CUSTOM = "custom"


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_type: Mapped[PolicyType] = mapped_column(Enum(PolicyType), nullable=False)
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)

    description: Mapped[str] = mapped_column(Text, nullable=False)
    threshold_value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
