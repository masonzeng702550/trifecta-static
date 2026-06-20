"""The Finding object emitted by the analyzer and consumed by reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..ir import LEG_NAMES, TrustBoundary

# Severity ordering, low -> high, used for --fail-on gating.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_at_least(sev: str, threshold: str) -> bool:
    return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(threshold)


@dataclass
class LegEntry:
    """One tool contributing a leg to a finding."""

    tool: str
    label: str
    confidence: float
    classifier: str
    evidence: str
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "classifier": self.classifier,
            "evidence": self.evidence,
            "reason": self.reason,
        }


@dataclass
class Finding:
    id: str
    rule_id: str
    severity: str
    status: str  # co-located | confirmed | analysis-incomplete | near-miss
    boundary_kind: str
    boundary_name: str
    boundary_location: str
    legs: dict[str, list[LegEntry]] = field(default_factory=dict)
    dataflow: Optional[dict] = None
    blast_radius: str = ""
    mitigations: list[str] = field(default_factory=list)

    # --- locations used by SARIF / table -------------------------------------

    def primary_location(self) -> str:
        """The location the finding is anchored to: the egress sink if known,
        else the boundary definition."""
        if self.dataflow and self.dataflow.get("sink"):
            return self.dataflow["sink"]
        egress = self.legs.get(LEG_NAMES["C"], [])
        if egress:
            return egress[0].evidence
        return self.boundary_location

    def related_locations(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for leg, entries in self.legs.items():
            for e in entries:
                out.append((e.evidence, f"{leg}: {e.tool}"))
        return out

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "status": self.status,
            "trust_boundary": {
                "kind": self.boundary_kind,
                "name": self.boundary_name,
                "location": self.boundary_location,
            },
            "legs": {leg: [e.to_dict() for e in entries] for leg, entries in self.legs.items()},
            "dataflow": self.dataflow,
            "blast_radius": self.blast_radius,
            "mitigations": self.mitigations,
        }


def legs_from_boundary(boundary: TrustBoundary) -> dict[str, list[LegEntry]]:
    """Collect the best capability per (tool, leg) into LegEntry buckets."""
    legs: dict[str, list[LegEntry]] = {LEG_NAMES["A"]: [], LEG_NAMES["B"]: [], LEG_NAMES["C"]: []}
    for tool in boundary.tools:
        for leg in ("A", "B", "C"):
            cap = tool.best(leg)
            if cap is not None:
                legs[LEG_NAMES[leg]].append(
                    LegEntry(
                        tool=tool.name,
                        label=leg,
                        confidence=cap.confidence,
                        classifier=cap.classifier,
                        evidence=cap.evidence,
                        reason=cap.reason,
                    )
                )
    return legs


DEFAULT_MITIGATIONS = [
    "Capability isolation: move the egress tool into a separate sub-agent with no private-data access.",
    "Dual-LLM pattern: handle untrusted input in a quarantined LLM that cannot trigger egress.",
    "Egress allowlist: restrict the egress destination to a vetted set of hosts.",
    "Human-in-the-loop gate: require manual approval before any egress call.",
]
