"""Python-source adapter for AST-defined tools and agents.

Covers the frameworks whose tool/agent definitions live in Python code:
LangChain / LangGraph, LlamaIndex, CrewAI, AutoGen, and FastMCP servers.
JSON/manifest formats (raw OpenAI/Anthropic schemas, MCP ``tools/list``) are
handled by :mod:`trifecta.loaders.schema_json`.

The walker is intentionally one pass over the AST: it recognises tool
*definitions* (decorators + constructor calls) and agent *assemblies* (the
calls that mount a list of tools), records ``file:line`` evidence for each, and
keeps an alias map so ``tools=[search, fetch]`` references can be resolved to
real tools after every file is loaded.
"""

from __future__ import annotations

import ast

from ..ir import Agent, Inventory, Tool, loc
from . import astutil as A
from .base import LoadResult

# Import substrings -> framework hint for a file.
_IMPORT_HINTS = {
    "langchain": "langchain",
    "langgraph": "langchain",
    "llama_index": "llamaindex",
    "crewai": "crewai",
    "autogen": "autogen",
    "mcp.server": "mcp",
    "fastmcp": "mcp",
    "mcp": "mcp",
}

# Constructor leaf-names that mint a tool, mapped to their framework.
_TOOL_CTORS = {
    "Tool": "langchain",
    "StructuredTool": "langchain",
    "FunctionTool": "llamaindex",
    "QueryEngineTool": "llamaindex",
}

# Calls that assemble an agent and the keyword/positional holding the tool list.
# value = name of the kwarg, or an int for a positional index.
_AGENT_ASSEMBLERS = {
    "initialize_agent": 0,
    "create_react_agent": "tools",
    "create_tool_calling_agent": "tools",
    "create_openai_tools_agent": "tools",
    "AgentExecutor": "tools",
    "bind_tools": 0,
    "Agent": "tools",  # crewai
    "AssistantAgent": "tools",  # autogen / autogen-agentchat
    "FunctionAgent": "tools",  # llamaindex
    "ReActAgent": "tools",  # llamaindex
}

# Decorator leaf-names that mark a function as a tool.
_TOOL_DECORATORS = {"tool"}
# MCP exposes tools via ``@mcp.tool()`` / ``@server.tool()`` -> attr "tool".
_MCP_DECORATOR_ATTRS = {"tool", "resource"}


def load_python(path: str, source: str) -> LoadResult:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return LoadResult()

    hints = _framework_hints(tree)
    result = LoadResult()
    inv = result.inventory
    inv.frameworks |= hints

    # First pass: gather tools (decorated funcs + constructor assignments) and
    # remember which function implements each, for the taint stage.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _maybe_decorated_tool(node, path, hints, inv, result.aliases)
        elif isinstance(node, ast.Assign):
            _maybe_ctor_tool(node, path, hints, inv, result.aliases)

    # Second pass: agent assemblies. Done after tools so we can attribute a
    # default framework when imports are ambiguous. Assigned assemblies are
    # visited first so we can alias the bound variable to the agent name.
    consumed: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            agent = _maybe_agent(node.value, path, hints, inv)
            if agent is not None:
                consumed.add(id(node.value))
                for tgt in _target_names(node):
                    result.agent_aliases[tgt] = agent.name
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and id(node) not in consumed:
            _maybe_agent(node, path, hints, inv)

    return result


def _framework_hints(tree: ast.Module) -> set[str]:
    hints: set[str] = set()
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for mod in mods:
            for needle, fw in _IMPORT_HINTS.items():
                if mod == needle or mod.startswith(needle + ".") or mod.startswith(needle):
                    hints.add(fw)
    return hints


def _primary_framework(hints: set[str], fallback: str = "unknown") -> str:
    # Deterministic pick when a file imports more than one framework.
    for fw in ("langchain", "llamaindex", "crewai", "autogen", "mcp"):
        if fw in hints:
            return fw
    return fallback


def _maybe_decorated_tool(func, path, hints, inv: Inventory, aliases):
    for dec in func.decorator_list:
        dotted = A.decorator_name(dec)
        leaf = A.leaf_name(dotted)
        if leaf not in _TOOL_DECORATORS and leaf not in _MCP_DECORATOR_ATTRS:
            continue
        # ``@mcp.tool()`` (attribute) -> mcp; bare ``@tool`` -> framework hint.
        is_attr_dec = dotted is not None and "." in dotted
        if is_attr_dec and leaf in _MCP_DECORATOR_ATTRS:
            framework = "mcp"
        elif leaf == "tool":
            framework = _primary_framework(hints, "langchain")
        else:
            continue

        # ``@tool("explicit_name")`` overrides the function name.
        name = func.name
        if isinstance(dec, ast.Call):
            explicit = A.str_value(A.positional(dec, 0)) or A.kwarg_str(dec, "name")
            if explicit:
                name = explicit

        tool = Tool(
            name=name,
            framework=framework,
            evidence=loc(path, func.lineno),
            description=A.docstring_of(func),
            impl_file=path,
            impl_func=func.name,
        )
        inv.tools.append(tool)
        aliases[func.name] = name
        aliases[name] = name
        return


def _maybe_ctor_tool(assign: ast.Assign, path, hints, inv: Inventory, aliases):
    call = assign.value
    if not isinstance(call, ast.Call):
        return
    dotted = A.callee_name(call)
    leaf = A.leaf_name(dotted)
    # Handle ``StructuredTool.from_function`` / ``FunctionTool.from_defaults``.
    base_leaf = leaf
    if dotted and "." in dotted and leaf in {"from_function", "from_defaults", "from_tool"}:
        base_leaf = A.leaf_name(dotted.rsplit(".", 2)[-2])
    if base_leaf not in _TOOL_CTORS:
        return

    framework = _TOOL_CTORS[base_leaf]
    name = (
        A.kwarg_str(call, "name")
        or A.str_value(A.positional(call, 0))
        or _target_name(assign)
        or base_leaf.lower()
    )
    description = A.kwarg_str(call, "description") or ""

    impl_file = impl_func = None
    func_arg = A.kwarg(call, "func") or A.kwarg(call, "fn") or A.positional(call, 1)
    fn = A.name_of(func_arg) if func_arg is not None else None
    if fn:
        impl_file, impl_func = path, fn

    tool = Tool(
        name=name,
        framework=framework,
        evidence=loc(path, assign.lineno),
        description=description,
        impl_file=impl_file,
        impl_func=impl_func,
    )
    inv.tools.append(tool)
    for tgt in _target_names(assign):
        aliases[tgt] = name
    aliases[name] = name


def _maybe_agent(call: ast.Call, path, hints, inv: Inventory):
    dotted = A.callee_name(call)
    leaf = A.leaf_name(dotted)
    if leaf not in _AGENT_ASSEMBLERS:
        return None
    selector = _AGENT_ASSEMBLERS[leaf]
    if isinstance(selector, int):
        tools_node = A.positional(call, selector)
    else:
        tools_node = A.kwarg(call, selector)
    if tools_node is None and leaf == "Agent":
        return None  # crewai Agent without tools=... is not interesting here
    refs = [A.name_of(it) for it in A.list_items(tools_node)]
    refs = [r for r in refs if r]
    if not refs:
        return None

    name = (
        A.kwarg_str(call, "name")
        or A.kwarg_str(call, "role")
        or f"{leaf}@{path}:{call.lineno}"
    )
    framework = _primary_framework(hints)
    kind = {"Crew": "crew", "Agent": "agent"}.get(leaf, "agent")
    agent = Agent(
        name=name,
        evidence=loc(path, call.lineno),
        tool_names=refs,  # raw identifiers; resolved in the registry
        kind=kind,
    )
    # Heuristic isolation hints carried on the assembly call.
    iso, reason = _isolation_hint(call, name)
    agent.isolated, agent.isolation_reason = iso, reason
    inv.agents.append(agent)
    return agent


_ISOLATION_TOKENS = ("quarantine", "sandbox", "untrusted_llm", "dual_llm", "dual-llm")


def _isolation_hint(call: ast.Call, name: str):
    lname = name.lower()
    for tok in _ISOLATION_TOKENS:
        if tok in lname:
            return True, f"name signals isolation: {tok}"
    # ``human_in_the_loop=True`` / ``require_approval=True`` style gates.
    for kw in call.keywords:
        if kw.arg in {"human_in_the_loop", "require_approval", "require_human_approval"}:
            if isinstance(kw.value, ast.Constant) and kw.value.value:
                return True, f"egress gated by {kw.arg}"
    return False, ""


def _target_name(assign: ast.Assign):
    names = _target_names(assign)
    return names[0] if names else None


def _target_names(assign: ast.Assign):
    out = []
    for tgt in assign.targets:
        if isinstance(tgt, ast.Name):
            out.append(tgt.id)
    return out
