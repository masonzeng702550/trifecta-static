"""Map an analysis verdict to a SARIF-friendly severity (SPEC 4.4)."""

from __future__ import annotations


def severity_for(status: str, egress_destination: str, gated: bool) -> str:
    """
    confirmed (data flow reachable) + non-allowlisted dest -> critical
    confirmed + allowlisted/gated dest                     -> high
    co-located + non-allowlisted egress                    -> high
    co-located + allowlist/gated egress                    -> medium
    near-miss (only two legs)                              -> info
    """
    if status == "near-miss":
        return "info"
    constrained = gated or egress_destination == "allowlisted"
    if status == "confirmed":
        return "high" if constrained else "critical"
    # co-located or analysis-incomplete
    return "medium" if constrained else "high"
