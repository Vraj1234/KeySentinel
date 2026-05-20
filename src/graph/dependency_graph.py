import logging
from collections import deque
from collections.abc import Sequence
from typing import Any

import networkx as nx

from src.graph.models import BlastRadiusResult, DependencyEdge, EdgeType, SecretNode, ServiceNode

logger = logging.getLogger(__name__)


class DependencyGraph:
    """NetworkX-backed directed graph for secret-to-service dependency mapping.

    Nodes are either services or secrets. Edges represent:
    - "uses": a service uses a secret (service -> secret)
    - "depends_on": a service depends on another service (service -> service)
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()

    # -- Mutators --

    def add_service(self, node: ServiceNode) -> None:
        self._graph.add_node(
            node.service_id,
            node_type="service",
            name=node.name,
            service_type=node.service_type.value,
        )

    def add_secret(self, node: SecretNode) -> None:
        self._graph.add_node(
            node.secret_id,
            node_type="secret",
            secret_type=node.secret_type.value,
            provider=node.provider,
        )

    def add_dependency(self, edge: DependencyEdge) -> None:
        if edge.source not in self._graph:
            raise ValueError(f"Source node '{edge.source}' not in graph")
        if edge.target not in self._graph:
            raise ValueError(f"Target node '{edge.target}' not in graph")
        self._graph.add_edge(edge.source, edge.target, edge_type=edge.edge_type.value)

    def remove_node(self, node_id: str) -> None:
        if node_id in self._graph:
            self._graph.remove_node(node_id)

    # -- Queries --

    def rotation_order(self, secret_ids: Sequence[str] | None = None) -> list[str]:
        """Return secret IDs in safe rotation order (leaf secrets first).

        Uses topological sort on the subgraph of secrets and their service
        dependencies. Secrets used only by leaf services come first.
        Raises ValueError if a cycle is detected.
        """
        all_secrets = [n for n, d in self._graph.nodes(data=True) if d.get("node_type") == "secret"]
        target_secrets = list(secret_ids) if secret_ids is not None else all_secrets

        if not target_secrets:
            return []

        # Build subgraph: include target secrets + all services connected to them
        relevant_nodes: set[str] = set(target_secrets)
        for secret_id in target_secrets:
            if secret_id not in self._graph:
                continue
            # Services that use this secret (predecessors with "uses" edge)
            for pred in self._graph.predecessors(secret_id):
                edge_data = self._graph.edges[pred, secret_id]
                if edge_data.get("edge_type") in (EdgeType.USES, EdgeType.USES.value):
                    relevant_nodes.add(pred)
                    # Also include services in the depends_on chain
                    for ancestor in nx.ancestors(self._graph, pred):
                        if self._graph.nodes[ancestor].get("node_type") == "service":
                            relevant_nodes.add(ancestor)

        subgraph = self._graph.subgraph(relevant_nodes)

        try:
            sorted_nodes = list(nx.topological_sort(subgraph))
        except nx.NetworkXUnfeasible as e:
            raise ValueError(f"Cycle detected in dependency graph: {e}") from e

        # Reverse: deepest dependencies (leaf secrets) come first so they
        # rotate before the services that depend on them are affected.
        sorted_nodes.reverse()

        # Filter to only secrets, preserving reversed topological order
        return [n for n in sorted_nodes if n in set(target_secrets)]

    def blast_radius(self, secret_id: str) -> BlastRadiusResult:
        """Calculate how many services are affected if a secret is compromised.

        BFS from the secret through reverse edges: find services that use the
        secret, then transitively find services that depend on those services.
        """
        if secret_id not in self._graph:
            return BlastRadiusResult(
                secret_id=secret_id,
                affected_services=(),
                affected_count=0,
                depth=0,
            )

        affected: list[str] = []
        max_depth = 0

        # Find direct users (services with "uses" edge to this secret)
        direct_users: list[str] = []
        for pred in self._graph.predecessors(secret_id):
            edge_data = self._graph.edges[pred, secret_id]
            if edge_data.get("edge_type") in (EdgeType.USES, EdgeType.USES.value):
                direct_users.append(pred)

        # BFS through "depends_on" edges (find services that depend on direct users)
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()

        for user in direct_users:
            if user not in visited:
                visited.add(user)
                affected.append(user)
                queue.append((user, 1))
                max_depth = max(max_depth, 1)

        while queue:
            current, depth = queue.popleft()
            # Find services that depend on `current` (current is the target of "depends_on")
            for pred in self._graph.predecessors(current):
                edge_data = self._graph.edges[pred, current]
                if (
                    edge_data.get("edge_type") in (EdgeType.DEPENDS_ON, EdgeType.DEPENDS_ON.value)
                    and pred not in visited
                ):
                    visited.add(pred)
                    affected.append(pred)
                    new_depth = depth + 1
                    max_depth = max(max_depth, new_depth)
                    queue.append((pred, new_depth))

        return BlastRadiusResult(
            secret_id=secret_id,
            affected_services=tuple(affected),
            affected_count=len(affected),
            depth=max_depth,
        )

    def affected_services(self, secret_id: str) -> list[str]:
        """Return all service IDs affected by this secret (transitive)."""
        return list(self.blast_radius(secret_id).affected_services)

    def services_using_secret(self, secret_id: str) -> list[str]:
        """Return service IDs that directly use this secret (non-transitive)."""
        if secret_id not in self._graph:
            return []
        result: list[str] = []
        for pred in self._graph.predecessors(secret_id):
            edge_data = self._graph.edges[pred, secret_id]
            if edge_data.get("edge_type") in (EdgeType.USES, EdgeType.USES.value):
                result.append(pred)
        return result

    def secrets_for_service(self, service_id: str) -> list[str]:
        """Return all secret IDs that a service directly uses."""
        if service_id not in self._graph:
            return []
        result: list[str] = []
        for succ in self._graph.successors(service_id):
            edge_data = self._graph.edges[service_id, succ]
            if edge_data.get("edge_type") in (EdgeType.USES, EdgeType.USES.value):
                result.append(succ)
        return result

    def secret_ids(self) -> list[str]:
        """Return all secret node IDs in the graph."""
        return [n for n, d in self._graph.nodes(data=True) if d.get("node_type") == "secret"]

    def service_type(self, service_id: str) -> str | None:
        """Return the service_type for a given service node, or None if not found."""
        data = self._graph.nodes.get(service_id)
        if data and data.get("node_type") == "service":
            return data.get("service_type")
        return None

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    # -- Serialization --

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph for pipeline context passing."""
        data = nx.node_link_data(self._graph)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DependencyGraph":
        """Reconstruct a DependencyGraph from a serialized dict."""
        graph = cls()
        graph._graph = nx.node_link_graph(data)
        return graph
