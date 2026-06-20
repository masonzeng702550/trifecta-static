"""Infer trust boundaries from the agent/tool inventory.

Default boundary = a single agent (the tools it mounts). Sub-agents are folded
into their parent boundary *unless* an isolation pattern (dual-LLM, quarantine,
human-approval gate) was detected, in which case the boundary is cut and the
sub-agent becomes its own boundary. The bias is conservative: when isolation is
unproven we merge, favouring recall over precision (SPEC 4.2).
"""

from __future__ import annotations

from ..ir import Inventory, TrustBoundary


def build_boundaries(inv: Inventory) -> list[TrustBoundary]:
    if not inv.agents:
        return _module_boundary(inv)

    agent_by_name = {a.name: a for a in inv.agents}
    merged: set[str] = set()

    boundaries: list[TrustBoundary] = []
    for agent in inv.agents:
        if agent.name in merged:
            continue
        tool_names: list[str] = []
        _collect(agent, agent_by_name, merged, tool_names, set())
        tools = [inv.tool_by_name(n) for n in dict.fromkeys(tool_names)]
        tools = [t for t in tools if t is not None]
        boundaries.append(
            TrustBoundary(
                kind=agent.kind,
                name=agent.name,
                location=agent.evidence,
                tools=tools,
                isolated=agent.isolated,
                isolation_reason=agent.isolation_reason,
            )
        )

    # Agents merged into a parent must not also stand as their own boundary.
    return [b for b in boundaries if b.name not in merged]


def _collect(agent, agent_by_name, merged, out: list, visited: set) -> None:
    if agent.name in visited:
        return
    visited.add(agent.name)
    out.extend(agent.tool_names)
    for sub_name in agent.sub_agents:
        sub = agent_by_name.get(sub_name)
        if sub is None:
            continue
        if sub.isolated:
            # Isolation cuts the boundary: the sub-agent keeps its own.
            continue
        merged.add(sub_name)
        _collect(sub, agent_by_name, merged, out, visited)


def _module_boundary(inv: Inventory) -> list[TrustBoundary]:
    """No agent assembly found: treat all tools as one module-level boundary.

    Conservative for recall, but flagged so the reporter can note the
    boundary was inferred rather than read from an explicit agent.
    """
    if not inv.tools:
        return []
    return [
        TrustBoundary(
            kind="module",
            name="<module>",
            location=inv.tools[0].evidence,
            tools=list(inv.tools),
        )
    ]
