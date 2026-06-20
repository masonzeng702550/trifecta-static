"""Top-level scan orchestration shared by the CLI and any embedding code."""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyze import analyze
from .baseline import apply_baseline, load_baseline
from .classify import classify_inventory
from .loaders import load_path
from .report.finding import Finding
from .srcindex import SourceIndex


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    depth: str = "shallow"


def run_scan(
    path: str,
    *,
    frameworks: set[str] | None = None,
    depth: str = "shallow",
    use_llm: bool = False,
    egress_allowlist: set[str] | None = None,
    baseline_path: str | None = None,
) -> ScanResult:
    index = SourceIndex()
    inv = load_path(path, frameworks=frameworks)
    classify_inventory(inv, index=index, use_llm=use_llm)
    findings = analyze(
        inv,
        depth=depth,
        index=index,
        egress_allowlist=egress_allowlist,
    )
    if baseline_path:
        findings = apply_baseline(findings, load_baseline(baseline_path))
    return ScanResult(findings=findings, frameworks=inv.frameworks, depth=depth)
