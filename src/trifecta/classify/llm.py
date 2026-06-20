"""Optional LLM-assisted classifier for tools the signatures miss.

Disabled by default (``--llm-classify`` opts in) to keep scans deterministic
and reproducible in CI. When enabled, it asks an LLM to label only the tools
the signature layer left unlabelled, and marks results ``classifier="llm"`` so
signature results always win on conflict. Requires the optional ``anthropic``
extra; if the SDK or an API key is missing it degrades to a no-op.
"""

from __future__ import annotations

import json
import os

from ..ir import Capability, Tool
from ..srcindex import SourceIndex

_SYSTEM = (
    "You classify AI-agent tools for the lethal-trifecta security check. "
    "For each tool decide which of these capability legs apply: "
    "A = ingest untrusted/external input, B = read private/sensitive data, "
    "C = send data out of the trust boundary. A tool may have several or none. "
    "Respond ONLY with JSON: {\"labels\":[{\"leg\":\"A|B|C\",\"confidence\":0-1,"
    "\"reason\":\"...\"}]}."
)

_MODEL = "claude-opus-4-8"


def llm_augment(tools: list[Tool], index: SourceIndex) -> None:
    client = _client()
    if client is None:
        return
    for tool in tools:
        labels = _classify_one(client, tool)
        for lab in labels:
            leg = lab.get("leg", "").upper()
            if leg not in ("A", "B", "C"):
                continue
            tool.labels.append(
                Capability(
                    label=leg,
                    confidence=float(lab.get("confidence", 0.5)),
                    classifier="llm",
                    evidence=tool.evidence,
                    reason=str(lab.get("reason", ""))[:200],
                )
            )


def _client():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None
    return anthropic.Anthropic()


def _classify_one(client, tool: Tool) -> list[dict]:
    prompt = (
        f"Tool name: {tool.name}\n"
        f"Framework: {tool.framework}\n"
        f"Description: {tool.description or '(none)'}\n"
    )
    try:
        msg = client.messages.create(
            model=_MODEL,
            max_tokens=512,
            temperature=0,  # determinism for reproducible CI
            system=_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        return json.loads(text).get("labels", [])
    except Exception:
        return []
