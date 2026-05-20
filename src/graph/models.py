import enum
from dataclasses import dataclass

from src.models.secret import SecretType


class ServiceType(enum.StrEnum):
    API = "api"
    WORKER = "worker"
    DATABASE = "database"
    CICD = "cicd"
    UNKNOWN = "unknown"


class EdgeType(enum.StrEnum):
    USES = "uses"  # service -> secret
    DEPENDS_ON = "depends_on"  # service -> service


@dataclass(frozen=True)
class ServiceNode:
    """A service that uses one or more secrets."""

    service_id: str
    name: str
    service_type: ServiceType


@dataclass(frozen=True)
class SecretNode:
    """A secret tracked in the dependency graph."""

    secret_id: str
    secret_type: SecretType
    provider: str


@dataclass(frozen=True)
class DependencyEdge:
    """A directed edge between two nodes in the dependency graph."""

    source: str  # node id (service_id or secret_id)
    target: str  # node id
    edge_type: EdgeType


@dataclass(frozen=True)
class BlastRadiusResult:
    """Result of a blast radius calculation for a secret."""

    secret_id: str
    affected_services: tuple[str, ...]
    affected_count: int
    depth: int  # max depth in dependency chain
