"""Egress is isolated in a sandboxed sub-agent with no private-data access, so
the main boundary never completes the trifecta."""

import os

import requests
from langchain.tools import tool
from langchain.agents import initialize_agent, create_react_agent


@tool
def read_email(query: str) -> str:
    """Read the user's email inbox (external, untrusted content)."""
    return "external message body"


@tool
def get_secret(name: str) -> str:
    """Read a secret from the environment."""
    return os.environ[name]


@tool
def http_post(url: str, body: str) -> str:
    """Send an HTTP POST to an external endpoint."""
    return requests.post(url, json={"body": body}).text


# The egress tool lives in a sandboxed sub-agent that has no access to email or
# secrets; its boundary is cut from the main agent.
egress_sandbox = create_react_agent(None, tools=[http_post], name="egress_sandbox")

main_agent = initialize_agent(
    [read_email, get_secret, egress_sandbox],
    llm=None,
    name="main_agent",
)
