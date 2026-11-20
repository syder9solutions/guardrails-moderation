"""Shared exception and result types for the guardrails layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class GuardrailError(Exception):
    """Base class for guardrail-layer failures."""


class BackendUnavailable(GuardrailError):
    """The configured LLM backend could not be reached."""


@dataclass(frozen=True)
class Evidence:
    """A single detection signal with provenance, for auditability."""

    rule_id: str
    """Stable identifier, e.g. INJ-override-verb, PII-EMAIL."""

    label: str
    """Human-readable description of what matched."""

    score: int
    """Weight contributed to the decision (0 for structural notes)."""

    span: tuple[int, int] | None = None
    """(start, end) character offset of the match in the scanned text."""

    excerpt: str = ""
    """Short redacted-safe excerpt around the match (truncated)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "label": self.label,
            "score": self.score,
            "span": list(self.span) if self.span else None,
            "excerpt": self.excerpt,
        }


@dataclass
class ScanResult:
    """Outcome of one detector pass over one text channel."""

    flagged: bool
    score: int
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flagged": self.flagged,
            "score": self.score,
            "evidence": [e.to_dict() for e in self.evidence],
        }
