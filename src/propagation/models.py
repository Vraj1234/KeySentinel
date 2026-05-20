from dataclasses import dataclass


@dataclass(frozen=True)
class PropagationTarget:
    """A destination where rotated credentials must be propagated."""

    target_type: str  # "kubernetes", "cicd", "vault"
    target_id: str
    config: tuple[tuple[str, str], ...] = ()  # frozen-safe key-value pairs

    def config_dict(self) -> dict[str, str]:
        """Return config as a mutable dict for convenience."""
        return dict(self.config)


@dataclass(frozen=True)
class PropagationResult:
    """Result of propagating a credential to a single target."""

    target: PropagationTarget
    success: bool
    health_check_passed: bool
    error: str | None = None


@dataclass(frozen=True)
class PropagationReport:
    """Aggregated propagation results for a single secret."""

    secret_id: str
    results: tuple[PropagationResult, ...]
    all_succeeded: bool
    failed_targets: tuple[str, ...]
