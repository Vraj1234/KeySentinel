import json
import logging

import anthropic

from src.discovery.models import ClassificationResult, ScanFinding
from src.models.secret import RiskLevel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security analyst classifying potential secret findings from an automated scanner.

For each finding, determine its classification:
- "real": An actual secret that needs rotation or remediation
- "test": A test, example, or placeholder value (e.g., "test-api-key", "AKIAIOSFODNN7EXAMPLE", "password123")
- "false_positive": Not a secret at all (e.g., a hash used as an ID, a public key, a version string)

Also assign a risk level: "critical", "high", "medium", "low", or "info".

Consider:
- The surrounding code context
- Whether the value matches known example/test patterns
- The entropy and length of the matched value
- The variable or key name

Respond with a JSON array. Each element must have:
- "index": the finding index (0-based)
- "classification": "real" | "test" | "false_positive"
- "confidence": 0.0 to 1.0
- "reasoning": one sentence explanation
- "risk_level": "critical" | "high" | "medium" | "low" | "info"

Respond ONLY with the JSON array, no other text."""


class FindingClassifier:
    """AI-powered finding classifier using Anthropic Claude API."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        batch_size: int = 20,
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        self._batch_size = batch_size

    async def classify(
        self, findings: list[ScanFinding]
    ) -> list[ClassificationResult]:
        """Classify all findings, batching API calls."""
        if not findings:
            return []

        results: list[ClassificationResult] = []

        for i in range(0, len(findings), self._batch_size):
            batch = findings[i : i + self._batch_size]
            batch_results = await self._classify_batch(batch)
            results.extend(batch_results)

        return results

    async def _classify_batch(
        self, batch: list[ScanFinding]
    ) -> list[ClassificationResult]:
        """Send one batch to Claude API and parse structured response."""
        user_message = self._format_batch(batch)

        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )

            response_text = response.content[0].text
            classifications = json.loads(response_text)

            results: list[ClassificationResult] = []
            for item in classifications:
                idx = item["index"]
                if idx >= len(batch):
                    continue

                risk_str = item.get("risk_level", "info")
                try:
                    risk = RiskLevel(risk_str)
                except ValueError:
                    risk = RiskLevel.INFO

                results.append(
                    ClassificationResult(
                        finding=batch[idx],
                        classification=item["classification"],
                        adjusted_confidence=item["confidence"],
                        reasoning=item["reasoning"],
                        risk_level=risk,
                    )
                )

            # Any findings not in the response get fail-safe classification
            classified_indices = {item["index"] for item in classifications}
            for idx, finding in enumerate(batch):
                if idx not in classified_indices:
                    results.append(self._failsafe_result(finding))

            return results

        except Exception as e:
            logger.error("Classifier failed: %s", e, exc_info=True)
            return [self._failsafe_result(f) for f in batch]

    @staticmethod
    def _format_batch(batch: list[ScanFinding]) -> str:
        """Format a batch of findings for the API prompt."""
        lines = []
        for i, finding in enumerate(batch):
            lines.append(
                f"Finding {i}:\n"
                f"  Rule: {finding.rule_id}\n"
                f"  Type: {finding.secret_type.value}\n"
                f"  Location: {finding.location_detail}\n"
                f"  Scanner confidence: {finding.confidence:.2f}\n"
                f"  Context:\n{finding.context_snippet}\n"
            )
        return "\n".join(lines)

    @staticmethod
    def _failsafe_result(finding: ScanFinding) -> ClassificationResult:
        """Fail-safe: treat as real secret with original confidence."""
        return ClassificationResult(
            finding=finding,
            classification="real",
            adjusted_confidence=finding.confidence,
            reasoning="Classification unavailable — treated as real (fail-safe)",
            risk_level=RiskLevel.HIGH if finding.confidence > 0.7 else RiskLevel.MEDIUM,
        )
