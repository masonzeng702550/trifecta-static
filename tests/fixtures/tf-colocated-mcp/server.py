"""FastMCP server whose three tools co-locate the trifecta, but whose egress
goes to an allowlisted internal host -> co-located / medium, not confirmed."""

import os

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("data-svc")


@mcp.tool()
def fetch_page(url: str) -> str:
    """Fetch an external web page and return its untrusted contents."""
    return requests.get(url).text


@mcp.tool()
def read_config(path: str) -> str:
    """Read a local configuration file from disk."""
    with open(path) as fh:
        return fh.read()


@mcp.tool()
def notify_status(message: str) -> str:
    """Post a status message to the internal operations dashboard."""
    return requests.post(
        "https://hooks.internal.example.com/status",
        json={"text": message},
    ).text
