"""Walk a path, run the right adapters, and resolve cross-file references."""

from __future__ import annotations

import os

from ..ir import Inventory
from .base import LoadResult
from .pyast import load_python
from .schema_json import load_json

# Directories that never hold agent code worth scanning.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env",
    "node_modules", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", ".eggs",
}


def detect_frameworks(path: str) -> set[str]:
    """Cheap pre-scan: which frameworks does this path appear to use?"""
    return _load(path, frameworks=None).inventory.frameworks


def load_path(path: str, frameworks: set[str] | None = None) -> Inventory:
    """Load every supported file under ``path`` into a single Inventory.

    ``frameworks`` optionally filters which adapters' output is kept (the
    ``--framework`` flag); ``None`` keeps everything (``auto``).
    """
    result = _load(path, frameworks)
    inv = result.inventory
    _resolve_references(inv, result.aliases, result.agent_aliases)
    if frameworks:
        _filter_frameworks(inv, frameworks)
    return inv


def _load(path: str, frameworks: set[str] | None) -> LoadResult:
    combined = LoadResult()
    for fpath in _iter_files(path):
        sub = _load_file(fpath)
        if sub is None:
            continue
        combined.inventory.merge(sub.inventory)
        combined.aliases.update(sub.aliases)
        combined.agent_aliases.update(sub.agent_aliases)
    return combined


def _iter_files(path: str):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in sorted(files):
            yield os.path.join(root, fn)


def _load_file(fpath: str) -> LoadResult | None:
    ext = os.path.splitext(fpath)[1].lower()
    if ext not in (".py", ".json"):
        return None
    try:
        with open(fpath, "r", encoding="utf-8") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError):
        return None
    rel = os.path.relpath(fpath)
    if ext == ".py":
        return load_python(rel, source)
    return load_json(rel, source)


def _resolve_references(inv: Inventory, aliases: dict, agent_aliases: dict) -> None:
    """Turn raw identifiers on agents into real tool names + sub-agent edges."""
    tool_names = {t.name for t in inv.tools}
    for agent in inv.agents:
        resolved_tools: list[str] = []
        subs: list[str] = []
        for ref in agent.tool_names:
            if ref in agent_aliases:
                subs.append(agent_aliases[ref])
            elif ref in aliases and aliases[ref] in tool_names:
                resolved_tools.append(aliases[ref])
            elif ref in tool_names:
                resolved_tools.append(ref)
            # unresolved refs (imported from elsewhere, dynamic) are dropped;
            # they surface as analysis-incomplete via the boundary builder.
        # de-dup while preserving order
        agent.tool_names = list(dict.fromkeys(resolved_tools))
        agent.sub_agents = list(dict.fromkeys(subs))


def _filter_frameworks(inv: Inventory, frameworks: set[str]) -> None:
    inv.tools = [t for t in inv.tools if t.framework in frameworks or t.framework == "unknown"]
    kept = {t.name for t in inv.tools}
    for a in inv.agents:
        a.tool_names = [n for n in a.tool_names if n in kept]
    inv.frameworks &= frameworks
