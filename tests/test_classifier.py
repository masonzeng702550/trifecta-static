from conftest import fixture

from trifecta.classify import classify_inventory
from trifecta.loaders import load_path


def _labelled(name):
    inv = load_path(fixture("tf-confirmed-langchain"))
    classify_inventory(inv)
    return inv.tool_by_name(name)


def test_ingress_tool_labeled_A():
    assert _labelled("read_email").has("A")


def test_private_tool_labeled_B():
    assert _labelled("get_secret").has("B")


def test_egress_tool_labeled_C():
    assert _labelled("http_post").has("C")


def test_egress_tool_also_B_because_it_reads_env():
    # http_post reads os.environ for an auth token -> it is also a B leg.
    assert _labelled("http_post").has("B")


def test_declarative_schema_classified_by_description():
    inv = load_path(fixture("tf-colocated-anthropic"))
    classify_inventory(inv)
    assert inv.tool_by_name("read_email").has("A")
    assert inv.tool_by_name("get_secret").has("B")
    assert inv.tool_by_name("send_email").has("C")


def test_confidence_in_range():
    tool = _labelled("read_email")
    for cap in tool.labels:
        assert 0.0 <= cap.confidence <= 1.0
        assert cap.classifier == "signature"
