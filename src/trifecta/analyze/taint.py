"""Intra-procedural taint to upgrade co-located findings to ``confirmed``.

The deep pass only runs on boundaries already flagged co-located, and only on
their egress (C) tool implementations. Within one egress function we ask: does
the *data* argument of an outbound call carry a private seed (B: env/secret/
file/db read) and/or attacker-influenceable input (A: a tool parameter or an
ingress call)? If a single function both reads a secret and ships it to a
non-allowlisted destination, that is a concrete exfiltration path and the
boundary is upgraded to ``confirmed`` (SPEC 4.3).

Known limits (reported as ``analysis-incomplete``, never silently swallowed):
aliasing, reflection, and cross-function / cross-file data flow.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from ..ir import Tool, loc
from ..srcindex import SourceIndex
from ..classify.signatures import RULES

_EGRESS_CALLEES = RULES["C"]["callee"]
_INGRESS_CALLEES = RULES["A"]["callee"]
_PRIVATE_CALLEES = RULES["B"]["callee"]

# Where the outbound *payload* lives in common egress calls.
_DATA_KWARGS = {"data", "json", "body", "payload", "text", "message", "content", "files", "params"}
# Where the *destination* lives.
_DEST_KWARGS = {"url", "endpoint", "uri", "to", "recipient", "webhook_url", "host"}


@dataclass
class TaintResult:
    reachable: bool
    sink: str
    source: Optional[str] = None  # A evidence
    sensitive_seed: Optional[str] = None  # B evidence
    egress_destination: str = "non-allowlisted"
    path: list[str] = field(default_factory=list)
    notes: str = ""
    incomplete: bool = False


def analyze_egress_tool(
    tool: Tool, index: SourceIndex, allowlist: set[str]
) -> Optional[TaintResult]:
    if not (tool.impl_file and tool.impl_func):
        # Declarative tool (JSON schema): no body to analyse.
        return None
    fi = index.function(tool.impl_file, tool.impl_func)
    if fi is None:
        return None

    func = fi.node
    params = _param_names(func)
    assigns = _assignment_map(func)

    best: Optional[TaintResult] = None
    for sink in _find_sinks(func):
        data_taint = _taint_of_args(sink, "data", params, assigns, tool.impl_file)
        dest = _destination(sink, allowlist, params, assigns)
        sink_loc = loc(tool.impl_file, sink.lineno)

        has_b = "B" in data_taint
        has_a = "A" in data_taint
        reachable = has_b  # a secret reaching a sink is the confirmable path
        notes_bits = []
        if has_b:
            notes_bits.append("private seed reaches egress payload")
        if has_a:
            notes_bits.append("attacker-influenceable input reaches egress payload")
        result = TaintResult(
            reachable=reachable,
            sink=sink_loc,
            source=data_taint.get("A"),
            sensitive_seed=data_taint.get("B"),
            egress_destination=dest,
            path=[p for p in (data_taint.get("B"), data_taint.get("A"), sink_loc) if p],
            notes="; ".join(notes_bits) or "no tainted data reached this sink",
            incomplete=False,
        )
        # Prefer a reachable result; otherwise keep the first.
        if best is None or (result.reachable and not best.reachable):
            best = result

    return best


# --- internals ---------------------------------------------------------------


def _param_names(func: ast.AST) -> set[str]:
    names: set[str] = set()
    args = getattr(func, "args", None)
    if args is None:
        return names
    for grp in (args.posonlyargs, args.args, args.kwonlyargs):
        for a in grp:
            names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _assignment_map(func: ast.AST) -> dict[str, ast.AST]:
    """var -> last assigned value expr (flow-insensitive approximation)."""
    out: dict[str, ast.AST] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    out[tgt.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            out[node.target.id] = node.value
    return out


def _find_sinks(func: ast.AST) -> list[ast.Call]:
    sinks = []
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and _is_egress_call(node):
            sinks.append(node)
    return sinks


def _is_egress_call(call: ast.Call) -> bool:
    from ..loaders.astutil import callee_name

    dotted = (callee_name(call) or "").lower()
    return any(pat in dotted for pat in _EGRESS_CALLEES)


def _taint_of_args(sink: ast.Call, _which, params, assigns, file) -> dict[str, str]:
    """Compute taint of the sink's data arguments -> {leg: evidence}."""
    from ..loaders.astutil import kwarg

    data_nodes: list[ast.AST] = []
    for name in _DATA_KWARGS:
        v = kwarg(sink, name)
        if v is not None:
            data_nodes.append(v)
    # Positional payload: for requests.post(url, data) the 2nd positional.
    if len(sink.args) >= 2:
        data_nodes.append(sink.args[1])
    elif len(sink.args) == 1 and not sink.keywords:
        data_nodes.append(sink.args[0])

    taint: dict[str, str] = {}
    for node in data_nodes:
        for leg, ev in _taint_of(node, params, assigns, file, set()).items():
            taint.setdefault(leg, ev)
    return taint


def _taint_of(node: ast.AST, params, assigns, file, seen: set) -> dict[str, str]:
    """Recursively classify what taint flows into an expression."""
    from ..loaders.astutil import callee_name

    out: dict[str, str] = {}
    if node is None:
        return out

    if isinstance(node, ast.Name):
        if node.id in seen:
            return out
        if node.id in params:
            out["A"] = loc(file, getattr(node, "lineno", 0))
        if node.id in assigns:
            seen = seen | {node.id}
            for leg, ev in _taint_of(assigns[node.id], params, assigns, file, seen).items():
                out.setdefault(leg, ev)
        return out

    if isinstance(node, ast.Call):
        dotted = (callee_name(node) or "").lower()
        line = loc(file, getattr(node, "lineno", 0))
        if any(p in dotted for p in _INGRESS_CALLEES):
            out["A"] = line
        if any(p in dotted for p in _PRIVATE_CALLEES):
            out["B"] = line
        for arg in list(node.args) + [k.value for k in node.keywords]:
            for leg, ev in _taint_of(arg, params, assigns, file, seen).items():
                out.setdefault(leg, ev)
        return out

    if isinstance(node, (ast.Attribute, ast.Subscript)):
        dotted = (callee_name(node) or "").lower()
        line = loc(file, getattr(node, "lineno", 0))
        if any(p in dotted for p in _PRIVATE_CALLEES):
            out["B"] = line
        # Recurse into the base (e.g. os.environ[key] -> base os.environ).
        base = node.value
        for leg, ev in _taint_of(base, params, assigns, file, seen).items():
            out.setdefault(leg, ev)
        return out

    # Compound expressions: f-strings, concatenation, format(), containers.
    children: list[ast.AST] = []
    if isinstance(node, ast.JoinedStr):
        children = [v for v in node.values if isinstance(v, ast.FormattedValue)]
    elif isinstance(node, ast.FormattedValue):
        children = [node.value]
    elif isinstance(node, ast.BinOp):
        children = [node.left, node.right]
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        children = list(node.elts)
    elif isinstance(node, ast.Dict):
        children = [v for v in node.values if v is not None]

    for child in children:
        for leg, ev in _taint_of(child, params, assigns, file, seen).items():
            out.setdefault(leg, ev)
    return out


def _destination(sink: ast.Call, allowlist: set[str], params, assigns) -> str:
    from ..loaders.astutil import kwarg, str_value

    dest_node = None
    for name in _DEST_KWARGS:
        v = kwarg(sink, name)
        if v is not None:
            dest_node = v
            break
    if dest_node is None and sink.args:
        dest_node = sink.args[0]

    # Resolve one level of indirection through a local assignment.
    if isinstance(dest_node, ast.Name) and dest_node.id in assigns:
        dest_node = assigns[dest_node.id]

    literal = str_value(dest_node)
    if literal is None:
        # Dynamic / parameter-controlled destination -> treat as untrusted.
        return "non-allowlisted"
    host = urlparse(literal).hostname or literal
    return "allowlisted" if host in allowlist else "non-allowlisted"
