"""JSON reporter: the canonical machine-readable output."""

from __future__ import annotations

import json

from .. import __version__


def to_json(findings, *, frameworks=None, depth="shallow") -> str:
    doc = {
        "tool": "trifecta-static",
        "version": __version__,
        "depth": depth,
        "frameworks_detected": sorted(frameworks or []),
        "summary": _summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _summary(findings) -> dict:
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_status[f.status] = by_status.get(f.status, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_status": by_status}
