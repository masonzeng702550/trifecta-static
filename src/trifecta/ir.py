"""Intermediate representation shared by every stage.

Framework adapters normalise their own formats into these objects; the
classifier annotates them with capability labels; the analyzer groups them
into trust boundaries and emits findings. Nothing downstream of the loaders
knows or cares which framework a tool came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Capability legs of the lethal trifecta.
LEG_INGRESS = "A"  # untrusted input enters the agent context
LEG_PRIVATE = "B"  # private / sensitive data can be read
LEG_EGRESS = "C"  # data can leave the trust boundary

LEG_NAMES = {
    LEG_INGRESS: "A_ingress",
    LEG_PRIVATE: "B_private",
    LEG_EGRESS: "C_egress",
}


def loc(file: str, line: int) -> str:
    """Render a clickable ``file:line`` evidence string."""
    return f"{file}:{line}"


@dataclass
class Capability:
    """One capability label attached to a tool, with its provenance."""

    label: str  # one of LEG_INGRESS / LEG_PRIVATE / LEG_EGRESS
    confidence: float
    classifier: str  # "signature" | "llm"
    evidence: str  # file:line that justifies the label
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "classifier": self.classifier,
            "evidence": self.evidence,
            "reason": self.reason,
        }


@dataclass
class Tool:
    """A normalised tool / capability definition from any framework."""

    name: str
    framework: str
    evidence: str  # file:line where the tool is defined
    description: str = ""
    # Implementation pointer used by the deep taint pass (Python only for now).
    impl_file: Optional[str] = None
    impl_func: Optional[str] = None
    labels: list[Capability] = field(default_factory=list)

    def leg_set(self) -> set[str]:
        return {c.label for c in self.labels}

    def has(self, leg: str) -> bool:
        return any(c.label == leg for c in self.labels)

    def best(self, leg: str) -> Optional[Capability]:
        cands = [c for c in self.labels if c.label == leg]
        return max(cands, key=lambda c: c.confidence) if cands else None


@dataclass
class Agent:
    """An agent assembly that mounts a set of tools (by tool name)."""

    name: str
    evidence: str
    tool_names: list[str] = field(default_factory=list)
    kind: str = "agent"  # agent | graph | crew | groupchat
    # Names of sub-agents this agent delegates to (for boundary inference).
    sub_agents: list[str] = field(default_factory=list)
    # True when the loader detected an isolation pattern (dual-LLM, quarantine,
    # human-in-the-loop gate) scoping this agent.
    isolated: bool = False
    isolation_reason: str = ""


@dataclass
class TrustBoundary:
    """A region within which co-existing capabilities are dangerous."""

    kind: str  # agent | module | graph | crew
    name: str
    location: str
    tools: list[Tool] = field(default_factory=list)
    isolated: bool = False
    isolation_reason: str = ""

    def union_legs(self) -> set[str]:
        legs: set[str] = set()
        for t in self.tools:
            legs |= t.leg_set()
        return legs

    def tools_with(self, leg: str) -> list[Tool]:
        return [t for t in self.tools if t.has(leg)]


@dataclass
class Inventory:
    """The full normalised picture handed from loaders to the analyzer."""

    tools: list[Tool] = field(default_factory=list)
    agents: list[Agent] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)

    def tool_by_name(self, name: str) -> Optional[Tool]:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def merge(self, other: "Inventory") -> None:
        existing = {t.name for t in self.tools}
        for t in other.tools:
            if t.name not in existing:
                self.tools.append(t)
                existing.add(t.name)
        agent_names = {a.name for a in self.agents}
        for a in other.agents:
            if a.name not in agent_names:
                self.agents.append(a)
                agent_names.add(a.name)
        self.frameworks |= other.frameworks
