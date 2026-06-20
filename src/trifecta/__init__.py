"""Trifecta-Static: static detection of the lethal trifecta in AI agents.

The lethal trifecta (Simon Willison): an agent that simultaneously can
(A) read untrusted input, (B) access private data, and (C) exfiltrate data
turns prompt injection from a nuisance into near-guaranteed data exfiltration.

This package detects whether A, B and C co-exist within a single trust
boundary -- and, in deep mode, whether the data actually flows -- purely by
static analysis, before deployment.
"""

__version__ = "0.1.0"
