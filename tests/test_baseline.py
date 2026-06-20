import os
import tempfile

from conftest import fixture

from trifecta.baseline import apply_baseline, fingerprint, load_baseline, write_baseline
from trifecta.scan import run_scan


def test_baseline_suppresses_known_findings():
    res = run_scan(fixture("tf-confirmed-langchain"), depth="deep")
    assert res.findings

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "baseline.json")
        write_baseline(path, res.findings)
        suppressed = load_baseline(path)
        remaining = apply_baseline(res.findings, suppressed)
        assert remaining == []


def test_fingerprint_is_stable_across_runs():
    a = run_scan(fixture("tf-confirmed-langchain"), depth="deep").findings[0]
    b = run_scan(fixture("tf-confirmed-langchain"), depth="deep").findings[0]
    assert fingerprint(a) == fingerprint(b)


def test_baseline_round_trip_via_scan():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "baseline.json")
        res = run_scan(fixture("tf-confirmed-langchain"), depth="deep")
        write_baseline(path, res.findings)
        suppressed_run = run_scan(fixture("tf-confirmed-langchain"), depth="deep", baseline_path=path)
        assert suppressed_run.findings == []
