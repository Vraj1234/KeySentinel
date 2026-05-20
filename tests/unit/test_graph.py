import pytest

from src.graph.builder import GraphBuilder
from src.graph.dependency_graph import DependencyGraph
from src.graph.models import DependencyEdge, EdgeType, SecretNode, ServiceNode, ServiceType
from src.graph.pipeline_step import build_dependency_graph_step
from src.models.secret import SecretType
from src.pipeline.engine import StepStatus


def _svc(name: str, service_type: ServiceType = ServiceType.API) -> ServiceNode:
    return ServiceNode(service_id=f"svc-{name}", name=name, service_type=service_type)


def _secret(name: str, secret_type: SecretType = SecretType.API_KEY) -> SecretNode:
    return SecretNode(secret_id=f"secret-{name}", secret_type=secret_type, provider="test")


class TestServiceAndSecretNodes:
    def test_service_node_is_frozen(self) -> None:
        node = _svc("auth")
        with pytest.raises(AttributeError):
            node.name = "other"  # type: ignore[misc]

    def test_secret_node_attributes(self) -> None:
        node = _secret("db-pass", SecretType.DATABASE_PASSWORD)
        assert node.secret_id == "secret-db-pass"
        assert node.secret_type == SecretType.DATABASE_PASSWORD
        assert node.provider == "test"

    def test_dependency_edge_is_frozen(self) -> None:
        edge = DependencyEdge(source="a", target="b", edge_type=EdgeType.USES)
        with pytest.raises(AttributeError):
            edge.source = "c"  # type: ignore[misc]


class TestDependencyGraphMutations:
    def test_add_service_and_secret(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("api"))
        graph.add_secret(_secret("key1"))
        assert graph.node_count == 2

    def test_add_dependency(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("api"))
        graph.add_secret(_secret("key1"))
        edge = DependencyEdge(source="svc-api", target="secret-key1", edge_type=EdgeType.USES)
        graph.add_dependency(edge)
        assert graph.edge_count == 1

    def test_add_dependency_missing_source_raises(self) -> None:
        graph = DependencyGraph()
        graph.add_secret(_secret("key1"))
        edge = DependencyEdge(source="missing", target="secret-key1", edge_type=EdgeType.USES)
        with pytest.raises(ValueError, match="Source node"):
            graph.add_dependency(edge)

    def test_add_dependency_missing_target_raises(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("api"))
        edge = DependencyEdge(source="svc-api", target="missing", edge_type=EdgeType.USES)
        with pytest.raises(ValueError, match="Target node"):
            graph.add_dependency(edge)

    def test_remove_node(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("api"))
        graph.remove_node("svc-api")
        assert graph.node_count == 0

    def test_remove_nonexistent_node_no_error(self) -> None:
        graph = DependencyGraph()
        graph.remove_node("nonexistent")  # Should not raise


class TestRotationOrder:
    def test_linear_chain(self) -> None:
        """svc-A -> secret-1, svc-B -> secret-2, svc-B depends_on svc-A.
        secret-1 should rotate first (it's used by the leaf service A).
        """
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_service(_svc("B"))
        graph.add_secret(_secret("1"))
        graph.add_secret(_secret("2"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))
        graph.add_dependency(DependencyEdge(source="svc-B", target="secret-2", edge_type=EdgeType.USES))
        graph.add_dependency(DependencyEdge(source="svc-B", target="svc-A", edge_type=EdgeType.DEPENDS_ON))

        order = graph.rotation_order()
        assert "secret-1" in order
        assert "secret-2" in order
        # secret-1 is used by leaf svc-A, should come first
        assert order.index("secret-1") < order.index("secret-2")

    def test_isolated_secrets_all_returned(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_secret(_secret("1"))
        graph.add_secret(_secret("2"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))
        # secret-2 is orphaned but still returned
        order = graph.rotation_order()
        assert "secret-1" in order
        assert "secret-2" in order

    def test_subset_of_secrets(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_secret(_secret("1"))
        graph.add_secret(_secret("2"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-2", edge_type=EdgeType.USES))

        order = graph.rotation_order(secret_ids=["secret-1"])
        assert order == ["secret-1"]

    def test_empty_graph_returns_empty(self) -> None:
        graph = DependencyGraph()
        assert graph.rotation_order() == []

    def test_cycle_raises_value_error(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_service(_svc("B"))
        graph.add_secret(_secret("1"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="svc-B", edge_type=EdgeType.DEPENDS_ON))
        graph.add_dependency(DependencyEdge(source="svc-B", target="svc-A", edge_type=EdgeType.DEPENDS_ON))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))

        with pytest.raises(ValueError, match="Cycle detected"):
            graph.rotation_order()


class TestBlastRadius:
    def test_single_hop(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_secret(_secret("1"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))

        result = graph.blast_radius("secret-1")
        assert result.affected_count == 1
        assert "svc-A" in result.affected_services
        assert result.depth == 1

    def test_transitive_blast_radius(self) -> None:
        """svc-A uses secret-1, svc-B depends_on svc-A, svc-C depends_on svc-B."""
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_service(_svc("B"))
        graph.add_service(_svc("C"))
        graph.add_secret(_secret("1"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))
        graph.add_dependency(DependencyEdge(source="svc-B", target="svc-A", edge_type=EdgeType.DEPENDS_ON))
        graph.add_dependency(DependencyEdge(source="svc-C", target="svc-B", edge_type=EdgeType.DEPENDS_ON))

        result = graph.blast_radius("secret-1")
        assert result.affected_count == 3
        assert set(result.affected_services) == {"svc-A", "svc-B", "svc-C"}
        assert result.depth == 3

    def test_no_dependencies(self) -> None:
        graph = DependencyGraph()
        graph.add_secret(_secret("1"))
        result = graph.blast_radius("secret-1")
        assert result.affected_count == 0
        assert result.depth == 0

    def test_nonexistent_secret(self) -> None:
        graph = DependencyGraph()
        result = graph.blast_radius("nonexistent")
        assert result.affected_count == 0

    def test_services_using_secret_direct_only(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_service(_svc("B"))
        graph.add_secret(_secret("1"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))
        graph.add_dependency(DependencyEdge(source="svc-B", target="svc-A", edge_type=EdgeType.DEPENDS_ON))

        direct = graph.services_using_secret("secret-1")
        assert direct == ["svc-A"]

    def test_secrets_for_service(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_secret(_secret("1"))
        graph.add_secret(_secret("2"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-2", edge_type=EdgeType.USES))

        secrets = graph.secrets_for_service("svc-A")
        assert set(secrets) == {"secret-1", "secret-2"}


class TestGraphBuilder:
    def test_build_from_findings_basic(self) -> None:
        findings = [
            {
                "secret_type": "api_key",
                "location": "source_code",
                "location_detail": "auth-service/config/.env",
                "provider": "generic",
                "rule_id": "generic_api_key",
            },
        ]
        builder = GraphBuilder()
        graph = builder.build_from_findings(findings)
        assert graph.node_count == 2  # 1 secret + 1 inferred service
        assert graph.edge_count == 1

    def test_infer_service_from_owner_service(self) -> None:
        findings = [
            {
                "secret_type": "aws_iam_key",
                "location": "vault",
                "location_detail": "/some/path",
                "provider": "aws",
                "rule_id": "aws_access_key",
                "owner_service": "payment-api",
            },
        ]
        builder = GraphBuilder()
        graph = builder.build_from_findings(findings)
        services = graph.services_using_secret(
            [n for n, d in graph._graph.nodes(data=True) if d.get("node_type") == "secret"][0]
        )
        assert len(services) == 1
        assert "payment-api" in services[0]

    def test_infer_service_from_k8s_location(self) -> None:
        findings = [
            {
                "secret_type": "database_password",
                "location": "kubernetes_secret",
                "location_detail": "k8s://production/backend-api",
                "provider": "postgresql",
                "rule_id": "postgres_uri",
            },
        ]
        builder = GraphBuilder()
        graph = builder.build_from_findings(findings)
        # Should infer a k8s-based service
        service_nodes = [
            n for n, d in graph._graph.nodes(data=True)
            if d.get("node_type") == "service"
        ]
        assert len(service_nodes) == 1
        assert "k8s" in service_nodes[0]

    def test_with_service_declarations(self) -> None:
        findings = [
            {
                "secret_type": "api_key",
                "location": "vault",
                "location_detail": "some/path",
                "provider": "stripe",
                "rule_id": "generic_api_key",
                "owner_service": "billing",
            },
        ]
        declarations = [
            {"service_id": "svc-billing", "name": "billing", "service_type": "api"},
            {"service_id": "svc-gateway", "name": "gateway", "service_type": "api",
             "depends_on": ["svc-billing"]},
        ]
        builder = GraphBuilder()
        graph = builder.build_from_findings(findings, declarations)

        # Should have 2 declared services + 1 secret
        assert graph.node_count == 3
        # gateway depends_on billing (1) + billing uses secret (1)
        assert graph.edge_count == 2

    def test_deduplicates_secrets(self) -> None:
        finding = {
            "secret_type": "api_key",
            "location": "source_code",
            "location_detail": "app/.env",
            "provider": "generic",
            "rule_id": "generic_api_key",
        }
        builder = GraphBuilder()
        graph = builder.build_from_findings([finding, finding])
        secret_count = sum(
            1 for _, d in graph._graph.nodes(data=True) if d.get("node_type") == "secret"
        )
        assert secret_count == 1


class TestGraphSerialization:
    def test_roundtrip(self) -> None:
        graph = DependencyGraph()
        graph.add_service(_svc("A"))
        graph.add_secret(_secret("1"))
        graph.add_dependency(DependencyEdge(source="svc-A", target="secret-1", edge_type=EdgeType.USES))

        data = graph.to_dict()
        restored = DependencyGraph.from_dict(data)

        assert restored.node_count == 2
        assert restored.edge_count == 1
        assert restored.services_using_secret("secret-1") == ["svc-A"]

    def test_empty_graph_roundtrip(self) -> None:
        graph = DependencyGraph()
        data = graph.to_dict()
        restored = DependencyGraph.from_dict(data)
        assert restored.node_count == 0


class TestGraphPipelineStep:
    async def test_happy_path(self) -> None:
        context = {
            "discovery": {
                "findings": [
                    {
                        "secret_type": "api_key",
                        "location": "source_code",
                        "location_detail": "myapp/config/.env",
                        "provider": "generic",
                        "rule_id": "generic_api_key",
                    },
                ],
            },
        }
        result = await build_dependency_graph_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output is not None
        assert result.output["secret_count"] == 1
        assert result.output["service_count"] == 1
        assert result.output["edge_count"] == 1

    async def test_missing_discovery_context_fails(self) -> None:
        result = await build_dependency_graph_step({})
        assert result.status == StepStatus.FAILED
        assert "No discovery output" in (result.error or "")

    async def test_empty_findings(self) -> None:
        context = {"discovery": {"findings": []}}
        result = await build_dependency_graph_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output["secret_count"] == 0
