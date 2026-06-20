"""End-to-end behaviour on the fixture corpus -- the recall/precision contract
from PRD section 8 and SPEC section 8."""

import pytest
from conftest import fixture

from trifecta.scan import run_scan

ALLOWLIST = {"hooks.internal.example.com"}


def _sevs(result):
    return [f.severity for f in result.findings]


def test_confirmed_langchain_is_critical():
    res = run_scan(fixture("tf-confirmed-langchain"), depth="deep")
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.status == "confirmed"
    assert f.severity == "critical"
    assert f.dataflow["reachable"] is True
    assert f.dataflow["sensitive_seed"] is not None


def test_colocated_mcp_with_allowlist_is_medium():
    res = run_scan(fixture("tf-colocated-mcp"), depth="deep", egress_allowlist=ALLOWLIST)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.status == "co-located"
    assert f.severity == "medium"


def test_colocated_anthropic_shallow_is_high():
    res = run_scan(fixture("tf-colocated-anthropic"), depth="shallow")
    assert len(res.findings) == 1
    assert res.findings[0].severity == "high"
    assert res.findings[0].status == "co-located"


def test_shallow_colocation_recall_is_100_percent():
    # Every known-positive fixture must surface a trifecta finding in shallow
    # mode (co-location is a decidable structural property -> recall = 100%).
    for name in ("tf-confirmed-langchain", "tf-colocated-mcp", "tf-colocated-anthropic"):
        res = run_scan(fixture(name), depth="shallow")
        statuses = {f.status for f in res.findings}
        assert "co-located" in statuses, name


@pytest.mark.parametrize("name", ["safe-isolated", "safe-two-legs", "safe-dual-llm"])
def test_safe_fixtures_emit_no_actionable_finding(name):
    # No critical/high/medium on safe fixtures: at most an info near-miss.
    res = run_scan(fixture(name), depth="deep")
    for f in res.findings:
        assert f.severity == "info", (name, f.severity, f.status)


def test_isolation_cuts_the_boundary():
    res = run_scan(fixture("safe-isolated"), depth="deep")
    # The main agent retains only A + B; egress is in the sandboxed sub-agent.
    assert all(f.status == "near-miss" for f in res.findings)


def test_unreachable_in_shallow_mode_has_null_dataflow():
    res = run_scan(fixture("tf-confirmed-langchain"), depth="shallow")
    f = res.findings[0]
    assert f.status == "co-located"
    assert f.dataflow["reachable"] is None
