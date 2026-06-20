"""Dual-LLM pattern: a quarantined LLM handles untrusted input and cannot
trigger egress, so the privileged boundary only holds B + C (a near-miss)."""

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


# Untrusted input is processed only inside a quarantined LLM agent that has no
# egress capability; its boundary is cut from the privileged agent.
quarantine_llm = create_react_agent(None, tools=[read_email], name="quarantine_llm")

privileged_agent = initialize_agent(
    [get_secret, http_post, quarantine_llm],
    llm=None,
    name="privileged_agent",
)
