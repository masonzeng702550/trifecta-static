"""Small helpers for reading literals and call shapes out of Python AST.

Kept deliberately forgiving: static analysis sees partial / weird code all the
time, so every helper degrades to ``None`` rather than raising.
"""

from __future__ import annotations

import ast
from typing import Optional


def callee_name(node: ast.AST) -> Optional[str]:
    """Dotted name of a call target, e.g. ``requests.post`` or ``tool``.

    Returns the full dotted path so callers can match either the leaf
    (``post``) or the qualified form (``requests.post``).
    """
    if isinstance(node, ast.Call):
        node = node.func
    return _dotted(node)


def _dotted(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def leaf_name(dotted: Optional[str]) -> Optional[str]:
    return dotted.rsplit(".", 1)[-1] if dotted else None


def str_value(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def kwarg(call: ast.Call, name: str) -> Optional[ast.AST]:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def kwarg_str(call: ast.Call, name: str) -> Optional[str]:
    return str_value(kwarg(call, name))


def positional(call: ast.Call, index: int) -> Optional[ast.AST]:
    if index < len(call.args):
        return call.args[index]
    return None


def list_items(node: Optional[ast.AST]) -> list[ast.AST]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return list(node.elts)
    return []


def name_of(node: ast.AST) -> Optional[str]:
    """Best-effort identifier for a tool reference inside a tools=[...] list.

    Handles ``my_tool`` (Name), ``module.my_tool`` (Attribute) and
    ``MyTool()`` / ``some_factory(...)`` (Call -> the called name).
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return leaf_name(callee_name(node))
    return str_value(node)


def docstring_of(func: ast.AST) -> str:
    if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
        doc = ast.get_docstring(func)
        if doc:
            return doc
    return ""


def decorator_name(dec: ast.AST) -> Optional[str]:
    """Dotted name of a decorator, ignoring any call parens.

    ``@tool`` -> ``tool``; ``@tool("x")`` -> ``tool``; ``@mcp.tool()`` ->
    ``mcp.tool``.
    """
    if isinstance(dec, ast.Call):
        return callee_name(dec.func)
    return _dotted(dec)
