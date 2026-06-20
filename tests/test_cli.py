import json

from conftest import fixture

from trifecta.cli import main


def test_scan_confirmed_fails_gate(capsys):
    code = main(["scan", fixture("tf-confirmed-langchain"), "--depth", "deep", "--fail-on", "high", "--no-color"])
    assert code == 1


def test_scan_safe_passes_gate():
    code = main(["scan", fixture("safe-two-legs"), "--fail-on", "high", "-o", "/dev/null"])
    assert code == 0


def test_fail_on_threshold_respected(capsys):
    # medium finding should pass a high gate but fail a medium gate.
    al = fixture("../_allowlist_tmp")
    import os
    os.makedirs(os.path.dirname(al), exist_ok=True) if os.path.dirname(al) else None
    with open(al, "w") as fh:
        fh.write("hooks.internal.example.com\n")
    base = ["scan", fixture("tf-colocated-mcp"), "--depth", "deep", "--egress-allowlist", al, "-o", "/dev/null"]
    assert main(base + ["--fail-on", "high"]) == 0
    assert main(base + ["--fail-on", "medium"]) == 1
    os.remove(al)


def test_json_format_to_stdout(capsys):
    code = main(["scan", fixture("tf-confirmed-langchain"), "--depth", "deep", "--format", "json"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["findings"][0]["severity"] == "critical"
    assert code == 1


def test_missing_path_returns_usage_error(capsys):
    code = main(["scan", "/no/such/path/xyz", "--no-color"])
    assert code == 2
