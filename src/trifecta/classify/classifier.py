"""Apply signature rules (and optionally an LLM) to label every tool."""

from __future__ import annotations

from ..ir import Capability, Inventory, Tool, loc
from ..srcindex import SourceIndex
from .signatures import CONF, RULES


def classify_inventory(
    inv: Inventory,
    index: SourceIndex | None = None,
    use_llm: bool = False,
) -> None:
    """Annotate every tool in ``inv`` with capability labels, in place."""
    index = index or SourceIndex()
    for tool in inv.tools:
        _classify_tool(tool, index)
    if use_llm:
        # Optional, deterministic-by-default-off second layer. Imported lazily
        # so the core has no SDK dependency.
        from .llm import llm_augment

        llm_augment([t for t in inv.tools if not t.labels], index)


def _classify_tool(tool: Tool, index: SourceIndex) -> None:
    # Gather signal sources. Name + description are always available; callee
    # signals require a Python implementation body.
    name_text = tool.name.lower()
    desc_text = (tool.description or "").lower()
    impl_signals = []
    if tool.impl_file and tool.impl_func:
        fi = index.function(tool.impl_file, tool.impl_func)
        if fi:
            impl_signals = fi.signals

    for leg, sources in RULES.items():
        best = _match_leg(tool, leg, sources, name_text, desc_text, impl_signals)
        if best is not None:
            tool.labels.append(best)


def _match_leg(tool, leg, sources, name_text, desc_text, impl_signals):
    best: Capability | None = None

    def consider(conf, evidence, reason):
        nonlocal best
        if best is None or conf > best.confidence:
            best = Capability(
                label=leg,
                confidence=conf,
                classifier="signature",
                evidence=evidence,
                reason=reason,
            )

    # callee signals (strongest)
    for sig in impl_signals:
        if sig.kind not in ("callee", "attr"):
            continue
        for pat in sources["callee"]:
            if pat in sig.text:
                evidence = loc(tool.impl_file, sig.line) if tool.impl_file else tool.evidence
                consider(CONF["callee"], evidence, f"calls {sig.text}")
                break

    # name signals
    for pat in sources["name"]:
        if pat in name_text:
            consider(CONF["name"], tool.evidence, f"tool name matches '{pat}'")
            break

    # description / schema-field signals (weakest)
    for pat in sources["desc"]:
        if pat in desc_text:
            consider(CONF["desc"], tool.evidence, f"description matches '{pat}'")
            break

    return best
