"""Single agent mounting all three legs -> confirmed trifecta."""

from langchain.agents import initialize_agent

from tools import read_email, get_secret, http_post

support_assistant = initialize_agent(
    [read_email, get_secret, http_post],
    llm=None,
    name="support_assistant",
)
