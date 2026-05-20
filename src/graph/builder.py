import hashlib
import logging
import re
from typing import Any

from src.graph.dependency_graph import DependencyGraph
from src.graph.models import DependencyEdge, EdgeType, SecretNode, ServiceNode, ServiceType
from src.models.secret import SecretType

logger = logging.getLogger(__name__)

# Patterns for inferring service from location_detail
_K8S_PATTERN = re.compile(r"k8s://(?P<namespace>[^/]+)/(?P<name>[^/]+)")
_CICD_PATTERN = re.compile(r"cicd://(?P<provider>[^/]+)/(?P<repo>.+)")
_FILE_PATH_PATTERN = re.compile(r"(?:^|/)(?P<service>[a-zA-Z][\w-]+)/(?:config|\.env|secrets)")


class GraphBuilder:
    """Constructs a DependencyGraph from discovery scan output and optional service declarations."""

    def build_from_findings(
        self,
        findings: list[dict[str, Any]],
        service_declarations: list[dict[str, Any]] | None = None,
    ) -> DependencyGraph:
        """Build a dependency graph from discovery findings.

        Args:
            findings: List of finding dicts from context["discovery"]["findings"].
            service_declarations: Optional explicit service definitions with keys:
                service_id, name, service_type, and optionally depends_on (list of service_ids).
        """
        graph = DependencyGraph()

        # Add explicit service declarations first
        declared_services: dict[str, ServiceNode] = {}
        if service_declarations:
            for decl in service_declarations:
                raw_type = decl.get("service_type", "unknown")
                try:
                    svc_type = ServiceType(raw_type)
                except ValueError:
                    svc_type = ServiceType.UNKNOWN
                node = ServiceNode(
                    service_id=decl["service_id"],
                    name=decl["name"],
                    service_type=svc_type,
                )
                declared_services[node.service_id] = node
                graph.add_service(node)

            # Add depends_on edges between declared services
            for decl in service_declarations:
                for dep_id in decl.get("depends_on", []):
                    if dep_id in declared_services:
                        graph.add_dependency(
                            DependencyEdge(
                                source=decl["service_id"],
                                target=dep_id,
                                edge_type=EdgeType.DEPENDS_ON,
                            )
                        )

        # Process each finding: create secret node + infer/assign service
        seen_secrets: set[str] = set()
        for finding in findings:
            secret_node = self._create_secret_node(finding)
            if secret_node.secret_id in seen_secrets:
                continue
            seen_secrets.add(secret_node.secret_id)
            graph.add_secret(secret_node)

            # Infer or look up the owning service
            service = self._infer_service(
                finding.get("location_detail", ""),
                finding.get("owner_service"),
            )

            # Add service if not already present
            if service.service_id not in declared_services:
                declared_services[service.service_id] = service
                graph.add_service(service)

            # Add "uses" edge: service -> secret
            graph.add_dependency(
                DependencyEdge(
                    source=service.service_id,
                    target=secret_node.secret_id,
                    edge_type=EdgeType.USES,
                )
            )

        return graph

    def _infer_service(self, location_detail: str, owner_service: str | None) -> ServiceNode:
        """Infer a service from the finding's location detail or owner_service field."""
        # Try explicit owner_service first
        if owner_service:
            return ServiceNode(
                service_id=f"svc-{owner_service}",
                name=owner_service,
                service_type=ServiceType.UNKNOWN,
            )

        # Try K8s pattern: k8s://namespace/deployment
        k8s_match = _K8S_PATTERN.search(location_detail)
        if k8s_match:
            name = k8s_match.group("name")
            return ServiceNode(
                service_id=f"svc-k8s-{k8s_match.group('namespace')}-{name}",
                name=name,
                service_type=ServiceType.API,
            )

        # Try CI/CD pattern: cicd://github/org/repo
        cicd_match = _CICD_PATTERN.search(location_detail)
        if cicd_match:
            repo = cicd_match.group("repo")
            return ServiceNode(
                service_id=f"svc-cicd-{cicd_match.group('provider')}-{repo}",
                name=repo,
                service_type=ServiceType.CICD,
            )

        # Try file path pattern: service-name/config or service-name/.env
        path_match = _FILE_PATH_PATTERN.search(location_detail)
        if path_match:
            name = path_match.group("service")
            return ServiceNode(
                service_id=f"svc-{name}",
                name=name,
                service_type=ServiceType.UNKNOWN,
            )

        # Fallback: synthetic service from hash of location_detail
        detail_hash = hashlib.sha256(location_detail.encode()).hexdigest()[:8]
        return ServiceNode(
            service_id=f"svc-{detail_hash}",
            name=f"service-{detail_hash}",
            service_type=ServiceType.UNKNOWN,
        )

    def _create_secret_node(self, finding: dict[str, Any]) -> SecretNode:
        """Create a SecretNode from a discovery finding dict."""
        secret_type_value = finding.get("secret_type", "generic")
        try:
            secret_type = SecretType(secret_type_value)
        except ValueError:
            secret_type = SecretType.GENERIC

        # Use rule_id + location_detail as a stable identifier
        detail = finding.get("location_detail", "unknown")
        rule_id = finding.get("rule_id", "unknown")
        stable_hash = hashlib.sha256(f"{rule_id}:{detail}".encode()).hexdigest()[:12]

        return SecretNode(
            secret_id=f"secret-{stable_hash}",
            secret_type=secret_type,
            provider=finding.get("provider", "unknown"),
        )
