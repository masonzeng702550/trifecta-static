"""Adapter for JSON tool schemas: MCP manifests, OpenAI and Anthropic tools.

These formats describe tools declaratively, so there is no implementation body
to do taint analysis on -- classification relies on name/description/schema
signatures only. The shapes handled:

  MCP ``tools/list``  : {"tools": [{"name", "description", "inputSchema"}]}
  MCP server manifest : {"capabilities": {...}, "tools": [...]} (same tool shape)
  OpenAI              : [{"type": "function", "function": {"name", "description"}}]
                        or legacy [{"name", "description", "parameters"}]
  Anthropic           : [{"name", "description", "input_schema"}]

Detection is structural, so a single ``.json`` is classified without the user
having to declare its flavour.
"""

from __future__ import annotations

import json

from ..ir import Inventory, Tool, loc
from .base import LoadResult


def load_json(path: str, source: str) -> LoadResult:
    try:
        data = json.loads(source)
    except (json.JSONDecodeError, ValueError):
        return LoadResult()

    result = LoadResult()
    inv = result.inventory

    entries, framework = _extract(data)
    if not entries:
        return result
    inv.frameworks.add(framework)

    for raw in entries:
        tool = _to_tool(raw, path, framework)
        if tool is not None:
            inv.tools.append(tool)
            result.aliases[tool.name] = tool.name
    return result


def _extract(data) -> tuple[list, str]:
    """Return (tool_entries, framework) for a recognised JSON document."""
    if isinstance(data, dict):
        # MCP tools/list response or server manifest.
        if isinstance(data.get("tools"), list):
            return data["tools"], "mcp"
        # OpenAI request echo: {"tools": [...]} already covered above; also
        # support {"functions": [...]} legacy.
        if isinstance(data.get("functions"), list):
            return data["functions"], "openai"
        # A single tool object.
        if "name" in data and ("input_schema" in data or "inputSchema" in data or "parameters" in data):
            fw = "anthropic" if "input_schema" in data else "mcp" if "inputSchema" in data else "openai"
            return [data], fw
        return [], "unknown"

    if isinstance(data, list):
        if not data or not isinstance(data[0], dict):
            return [], "unknown"
        sample = data[0]
        if sample.get("type") == "function" or "function" in sample:
            return data, "openai"
        if "input_schema" in sample:
            return data, "anthropic"
        if "inputSchema" in sample:
            return data, "mcp"
        if "parameters" in sample:
            return data, "openai"
        if "name" in sample:
            return data, "anthropic"
    return [], "unknown"


def _to_tool(raw: dict, path: str, framework: str):
    # OpenAI wraps the real definition under "function".
    body = raw.get("function") if isinstance(raw.get("function"), dict) else raw
    name = body.get("name")
    if not name:
        return None
    description = body.get("description", "") or ""
    schema = body.get("input_schema") or body.get("inputSchema") or body.get("parameters") or {}
    # Flatten schema property names into the description so the signature
    # classifier can see field names like "url", "to", "path".
    prop_hint = ""
    if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
        prop_hint = " ".join(schema["properties"].keys())

    tool = Tool(
        name=name,
        framework=framework,
        evidence=loc(path, 1),
        description=(description + "  [schema: " + prop_hint + "]") if prop_hint else description,
    )
    return tool
