"""Incident timeline tracking and formatting utilities."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class IncidentTimeline:
    """Key timestamps for an incident lifecycle."""

    detected_at: datetime
    contained_at: datetime | None = None
    resolved_at: datetime | None = None
    response_time_seconds: float | None = None


def calculate_response_time(
    detected_at: datetime,
    contained_at: datetime,
) -> float:
    """Return seconds between detection and containment."""
    delta = contained_at - detected_at
    return max(0.0, delta.total_seconds())


def format_timeline_markdown(timeline: IncidentTimeline) -> str:
    """Render an incident timeline as a markdown table."""
    rows = [
        "| Phase | Timestamp |",
        "|-------|-----------|",
        f"| Detected | {timeline.detected_at.isoformat()} |",
    ]

    if timeline.contained_at:
        rows.append(f"| Contained | {timeline.contained_at.isoformat()} |")
    if timeline.resolved_at:
        rows.append(f"| Resolved | {timeline.resolved_at.isoformat()} |")
    if timeline.response_time_seconds is not None:
        rows.append(
            f"| Response Time | {timeline.response_time_seconds:.1f}s |"
        )

    return "\n".join(rows)
