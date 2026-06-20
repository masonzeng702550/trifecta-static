from conftest import fixture

from trifecta.loaders import load_path, detect_frameworks


def test_langchain_tools_and_agent_resolved():
    inv = load_path(fixture("tf-confirmed-langchain"))
    names = {t.name for t in inv.tools}
    assert {"read_email", "get_secret", "http_post"} <= names
    assert "langchain" in inv.frameworks

    agents = {a.name: a for a in inv.agents}
    assert "support_assistant" in agents
    assert set(agents["support_assistant"].tool_names) == {"read_email", "get_secret", "http_post"}


def test_impl_pointer_recorded_for_taint():
    inv = load_path(fixture("tf-confirmed-langchain"))
    http_post = inv.tool_by_name("http_post")
    assert http_post.impl_func == "http_post"
    assert http_post.impl_file.endswith("tools.py")


def test_mcp_fastmcp_decorator_tools():
    inv = load_path(fixture("tf-colocated-mcp"))
    names = {t.name for t in inv.tools}
    assert {"fetch_page", "read_config", "notify_status"} <= names
    assert "mcp" in inv.frameworks


def test_anthropic_json_schema_tools():
    inv = load_path(fixture("tf-colocated-anthropic"))
    names = {t.name for t in inv.tools}
    assert {"read_email", "get_secret", "send_email"} <= names
    assert "anthropic" in inv.frameworks


def test_sub_agent_edges_resolved():
    inv = load_path(fixture("safe-isolated"))
    main = next(a for a in inv.agents if a.name == "main_agent")
    assert "egress_sandbox" in main.sub_agents
    # The sub-agent reference must NOT leak into the tool list.
    assert "egress_sandbox" not in main.tool_names


def test_detect_frameworks():
    assert "langchain" in detect_frameworks(fixture("tf-confirmed-langchain"))
