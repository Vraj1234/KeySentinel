import asyncio
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from src.models.secret import RiskLevel
from src.risk.models import RiskAssessment, RiskSignal
from src.risk.rules import BUILT_IN_RULES, RuleFunction

logger = logging.getLogger(__name__)

# Score thresholds for risk level mapping
_CRITICAL_THRESHOLD = 80.0
_HIGH_THRESHOLD = 60.0
_MEDIUM_THRESHOLD = 30.0
_LOW_THRESHOLD = 10.0


class RiskEngine:
    """Configurable risk scoring engine.

    Runs a set of rules against each secret's context and aggregates
    the resulting signals into a final risk score and level.
    """

    def __init__(self, rules: Sequence[RuleFunction] | None = None) -> None:
        self._rules: list[RuleFunction] = list(rules) if rules else list(BUILT_IN_RULES)

    def add_rule(self, rule: RuleFunction) -> None:
        self._rules.append(rule)

    async def assess(self, secret_context: dict[str, Any]) -> RiskAssessment:
        """Run all rules against a secret and return an aggregated assessment."""
        signals: list[RiskSignal] = []

        for rule in self._rules:
            try:
                signal = await rule(secret_context)
                if signal is not None:
                    signals.append(signal)
            except Exception as e:
                logger.error(
                    "Rule %s failed for secret %s: %s",
                    getattr(rule, "__name__", rule),
                    secret_context.get("secret_id", "unknown"),
                    e,
                    exc_info=True,
                )

        return self._aggregate(
            secret_context.get("secret_id", "unknown"),
            signals,
        )

    async def assess_batch(
        self,
        secret_contexts: list[dict[str, Any]],
    ) -> list[RiskAssessment]:
        """Assess multiple secrets concurrently."""
        return list(await asyncio.gather(*(self.assess(ctx) for ctx in secret_contexts)))

    def _aggregate(
        self,
        secret_id: str,
        signals: list[RiskSignal],
    ) -> RiskAssessment:
        """Sum score deltas, clamp to [0, 100], and map to a risk level."""
        raw_score = sum(s.score_delta for s in signals)
        clamped_score = max(0.0, min(100.0, raw_score))

        if clamped_score >= _CRITICAL_THRESHOLD:
            level = RiskLevel.CRITICAL
        elif clamped_score >= _HIGH_THRESHOLD:
            level = RiskLevel.HIGH
        elif clamped_score >= _MEDIUM_THRESHOLD:
            level = RiskLevel.MEDIUM
        elif clamped_score >= _LOW_THRESHOLD:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO

        return RiskAssessment(
            secret_id=secret_id,
            signals=tuple(signals),
            risk_score=round(clamped_score, 1),
            risk_level=level,
            assessed_at=datetime.now(UTC),
        )
