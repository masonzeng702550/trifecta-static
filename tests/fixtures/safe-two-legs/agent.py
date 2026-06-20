"""Only two legs (A + B, no egress): at most an informational near-miss."""

import os

from langchain.tools import tool
from langchain.agents import initialize_agent


@tool
def read_email(query: str) -> str:
    """Read the user's email inbox (external, untrusted content)."""
    return "external message body"


@tool
def get_secret(name: str) -> str:
    """Read a secret from the environment."""
    return os.environ[name]


assistant = initialize_agent([read_email, get_secret], llm=None, name="assistant")
