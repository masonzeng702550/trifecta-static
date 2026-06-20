"""Human-readable coloured terminal reporter."""

from __future__ import annotations

import sys

from ..ir import LEG_NAMES

_COLORS = {
    "critical": "\033[1;37;41m",  # white on red
    "high": "\033[1;31m",  # red
    "medium": "\033[1;33m",  # yellow
    "low": "\033[36m",  # cyan
    "info": "\033[2m",  # dim
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def to_table(findings, *, frameworks=None, depth="shallow", color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty()
    c = _Painter(color)

    lines: list[str] = []
    fws = ", ".join(sorted(frameworks or [])) or "none detected"
    lines.append(c.bold(f"Trifecta-Static  ·  depth={depth}  ·  frameworks: {fws}"))

    if not findings:
        lines.append(c.dim("  No lethal-trifecta findings. ✔"))
        return "\n".join(lines)

    counts = _counts(findings)
    summary = "  ".join(
        c.sev(sev, f"{sev}:{counts[sev]}") for sev in ("critical", "high", "medium", "low", "info") if counts.get(sev)
    )
    lines.append("  " + summary)
    lines.append("")

    for f in findings:
        badge = c.sev(f.severity, f" {f.severity.upper()} ")
        lines.append(f"{badge} {c.bold(f.id)}  {f.rule_id}  ({f.status})")
        lines.append(f"    boundary: {f.boundary_name} [{f.boundary_kind}]  {c.dim(f.boundary_location)}")
        for leg_key in (LEG_NAMES["A"], LEG_NAMES["B"], LEG_NAMES["C"]):
            entries = f.legs.get(leg_key, [])
            if not entries:
                continue
            label = leg_key.replace("_", " ")
            for e in entries:
                lines.append(
                    f"      {c.bold(label):<22} {e.tool}  "
                    f"{c.dim(f'{e.evidence}  conf={e.confidence:.2f} [{e.classifier}]')}"
                )
        if f.dataflow and f.dataflow.get("reachable"):
            df = f.dataflow
            lines.append(c.sev("critical", f"      ↳ data flow: {df.get('notes','')}"))
            if df.get("path"):
                lines.append(f"        path: {' → '.join(df['path'])}")
        lines.append(f"    {c.dim('blast radius:')} {f.blast_radius}")
        if f.mitigations:
            lines.append(f"    {c.dim('fix:')} {f.mitigations[0]}")
        lines.append("")

    return "\n".join(lines)


def _counts(findings):
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


class _Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code, text):
        return f"{code}{text}{_RESET}" if self.enabled else text

    def bold(self, t):
        return self._wrap(_BOLD, t)

    def dim(self, t):
        return self._wrap(_DIM, t)

    def sev(self, sev, t):
        return self._wrap(_COLORS.get(sev, ""), t)
