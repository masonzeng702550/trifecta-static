"""Drive boundary inference -> co-location -> (optional) taint -> findings."""

from __future__ import annotations

from ..ir import LEG_EGRESS, LEG_INGRESS, LEG_PRIVATE, Inventory, TrustBoundary
from ..report.finding import (
    DEFAULT_MITIGATIONS,
    Finding,
    legs_from_boundary,
)
from ..srcindex import SourceIndex
from .boundary import build_boundaries
from .severity import severity_for
from .taint import analyze_egress_tool

_LEGS = (LEG_INGRESS, LEG_PRIVATE, LEG_EGRESS)


def analyze(
    inv: Inventory,
    depth: str = "shallow",
    index: SourceIndex | None = None,
    egress_allowlist: set[str] | None = None,
) -> list[Finding]:
    index = index or SourceIndex()
    allowlist = egress_allowlist or set()
    boundaries = build_boundaries(inv)

    findings: list[Finding] = []
    counter = 0
    for boundary in boundaries:
        legs = boundary.union_legs()
        present = [leg for leg in _LEGS if leg in legs]

        if len(present) == 3:
            counter += 1
            findings.append(
                _trifecta_finding(boundary, counter, depth, index, allowlist)
            )
        elif len(present) == 2:
            counter += 1
            findings.append(_near_miss(boundary, counter, present))

    findings.sort(key=lambda f: _SEV_RANK[f.severity], reverse=True)
    return findings


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _trifecta_finding(boundary, counter, depth, index, allowlist) -> Finding:
    legs = legs_from_boundary(boundary)
    status = "co-located"
    dataflow = None
    gated = boundary.isolated and "approval" in (boundary.isolation_reason or "")

    # Default egress destination is unknown at the shallow level -> treat as
    # non-allowlisted (conservative) unless deep analysis proves otherwise.
    egress_destination = "non-allowlisted"

    if depth == "deep":
        taint = _deepest_egress(boundary, index, allowlist)
        if taint is not None:
            egress_destination = taint.egress_destination
            if taint.reachable:
                status = "confirmed"
                dataflow = {
                    "reachable": True,
                    "source": taint.source,
                    "sensitive_seed": taint.sensitive_seed,
                    "sink": taint.sink,
                    "path": taint.path,
                    "egress_destination": taint.egress_destination,
                    "notes": taint.notes,
                }
            else:
                dataflow = {
                    "reachable": False,
                    "sink": taint.sink,
                    "egress_destination": taint.egress_destination,
                    "notes": taint.notes
                    + "; cross-tool/cross-file flow not proven (analysis-incomplete)",
                }
        else:
            dataflow = {
                "reachable": None,
                "notes": "egress tools are declarative or lack a Python body; "
                "deep flow not analysable (analysis-incomplete)",
            }
    else:
        dataflow = {"reachable": None, "notes": "shallow mode: co-location only, data flow not analysed"}

    severity = severity_for(status, egress_destination, gated)
    rule_id = f"lethal-trifecta/{status}"

    return Finding(
        id=f"TRIFECTA-{counter:04d}",
        rule_id=rule_id,
        severity=severity,
        status=status,
        boundary_kind=boundary.kind,
        boundary_name=boundary.name,
        boundary_location=boundary.location,
        legs=legs,
        dataflow=dataflow,
        blast_radius=_blast_radius(status, egress_destination),
        mitigations=list(DEFAULT_MITIGATIONS),
    )


def _deepest_egress(boundary: TrustBoundary, index, allowlist):
    best = None
    for tool in boundary.tools_with(LEG_EGRESS):
        res = analyze_egress_tool(tool, index, allowlist)
        if res is None:
            continue
        if best is None or (res.reachable and not best.reachable):
            best = res
    return best


def _near_miss(boundary, counter, present) -> Finding:
    legs = legs_from_boundary(boundary)
    missing = [leg for leg in _LEGS if leg not in present]
    return Finding(
        id=f"TRIFECTA-{counter:04d}",
        rule_id="lethal-trifecta/near-miss",
        severity="info",
        status="near-miss",
        boundary_kind=boundary.kind,
        boundary_name=boundary.name,
        boundary_location=boundary.location,
        legs=legs,
        dataflow={"reachable": None, "notes": f"only two legs present; missing leg(s): {missing}"},
        blast_radius="Not a trifecta yet: adding the missing leg would complete it.",
        mitigations=["Keep the missing leg out of this trust boundary to avoid completing the trifecta."],
    )


def _blast_radius(status: str, egress_destination: str) -> str:
    if status == "confirmed":
        return (
            "Exfiltratable: private data (secrets/env/files) can be sent to a "
            f"{egress_destination} egress destination via a proven data-flow path."
        )
    return (
        "Capabilities to read untrusted input, read private data, and send data "
        "out all co-exist in one trust boundary; a successful prompt injection "
        "could chain them into data exfiltration."
    )
