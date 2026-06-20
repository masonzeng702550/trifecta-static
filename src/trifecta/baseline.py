"""Baseline suppression so teams can adopt the gate without drowning in
pre-existing findings -- record the current set, then only fail on new ones."""

from __future__ import annotations

import hashlib
import json


def fingerprint(finding) -> str:
    """Stable identity of a finding, independent of its sequential id.

    Built from the rule, the boundary, and the sorted leg evidence so that
    line-number drift in unrelated code does not invalidate the baseline,
    but a genuinely new capability combination is not suppressed.
    """
    parts = [finding.rule_id, finding.boundary_name]
    for _leg, entries in sorted(finding.legs.items()):
        for e in sorted(entries, key=lambda x: (x.tool, x.evidence)):
            parts.append(f"{e.label}:{e.tool}:{e.evidence}")
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def load_baseline(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("suppressed", []))


def write_baseline(path: str, findings) -> None:
    doc = {"suppressed": sorted({fingerprint(f) for f in findings})}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


def apply_baseline(findings, suppressed: set[str]):
    return [f for f in findings if fingerprint(f) not in suppressed]
