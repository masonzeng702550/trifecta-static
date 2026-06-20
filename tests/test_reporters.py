import json

from conftest import fixture

from trifecta.report import to_json, to_sarif, to_table
from trifecta.scan import run_scan


def _findings():
    return run_scan(fixture("tf-confirmed-langchain"), depth="deep")


def test_json_is_valid_and_structured():
    res = _findings()
    doc = json.loads(to_json(res.findings, frameworks=res.frameworks, depth="deep"))
    assert doc["tool"] == "trifecta-static"
    assert doc["summary"]["total"] == 1
    f = doc["findings"][0]
    assert f["rule_id"] == "lethal-trifecta/confirmed"
    assert set(f["legs"]).issuperset({"A_ingress", "B_private", "C_egress"})


def test_sarif_2_1_0_shape():
    res = _findings()
    doc = json.loads(to_sarif(res.findings))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "trifecta-static"
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    # Three legs should appear as relatedLocations.
    assert len(result["relatedLocations"]) >= 3
    assert result["properties"]["security-severity"] == "9.5"


def test_table_renders_without_color():
    res = _findings()
    out = to_table(res.findings, frameworks=res.frameworks, depth="deep", color=False)
    assert "TRIFECTA-0001" in out
    assert "\033[" not in out  # no ANSI escapes when color disabled


def test_clean_table_when_no_findings():
    res = run_scan(fixture("safe-two-legs"), depth="shallow")
    # near-miss is info; render still works and mentions the id
    out = to_table(res.findings, frameworks=res.frameworks, color=False)
    assert "Trifecta-Static" in out
