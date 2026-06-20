"""Cache of parsed Python files plus per-function signal extraction.

Both the signature classifier and the deep taint pass need to look inside a
tool's implementation function. Parsing each file once and caching it here
keeps a whole-repo scan well under the CI budget.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional

from .loaders import astutil as A


@dataclass
class Signal:
    """One observable inside a function body, with its line for evidence."""

    kind: str  # "callee" | "attr" | "const"
    text: str  # lowercased dotted name or string literal
    line: int


@dataclass
class FuncInfo:
    node: ast.AST
    file: str
    signals: list[Signal] = field(default_factory=list)


class SourceIndex:
    def __init__(self) -> None:
        self._trees: dict[str, Optional[ast.Module]] = {}
        self._funcs: dict[str, dict[str, FuncInfo]] = {}

    def tree(self, path: str) -> Optional[ast.Module]:
        if path not in self._trees:
            self._trees[path] = self._parse(path)
            self._funcs[path] = self._index_funcs(path, self._trees[path])
        return self._trees[path]

    def function(self, path: str, name: str) -> Optional[FuncInfo]:
        self.tree(path)
        return self._funcs.get(path, {}).get(name)

    @staticmethod
    def _parse(path: str) -> Optional[ast.Module]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return ast.parse(fh.read())
        except (OSError, UnicodeDecodeError, SyntaxError):
            return None

    def _index_funcs(self, path: str, tree: Optional[ast.Module]) -> dict[str, FuncInfo]:
        out: dict[str, FuncInfo] = {}
        if tree is None:
            return out
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[node.name] = FuncInfo(node=node, file=path, signals=_extract_signals(node))
        return out


def _extract_signals(func: ast.AST) -> list[Signal]:
    signals: list[Signal] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            dotted = A.callee_name(node)
            if dotted:
                signals.append(Signal("callee", dotted.lower(), getattr(node, "lineno", 0)))
        elif isinstance(node, ast.Attribute):
            dotted = A.callee_name(node)
            if dotted:
                signals.append(Signal("attr", dotted.lower(), getattr(node, "lineno", 0)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            signals.append(Signal("const", node.value.lower(), getattr(node, "lineno", 0)))
    return signals
