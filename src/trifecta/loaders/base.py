"""Shared types for loaders."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..ir import Inventory


@dataclass
class LoadResult:
    """A loader's output before cross-file reference resolution.

    ``aliases`` maps a Python identifier (the variable a tool was bound to, or
    a decorated function name) to the canonical tool name, so an agent that
    mounts ``tools=[search, fetch]`` can be resolved to real tools later.
    """

    inventory: Inventory = field(default_factory=Inventory)
    aliases: dict[str, str] = field(default_factory=dict)
    # Variable identifier -> agent name, so an agent that mounts another agent
    # as a tool (sub-agent delegation) can be resolved to a boundary edge.
    agent_aliases: dict[str, str] = field(default_factory=dict)
