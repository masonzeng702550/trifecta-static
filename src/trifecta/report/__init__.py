"""Reporters: render findings as table, JSON, or SARIF 2.1.0."""

from .finding import Finding, LegEntry
from .json_report import to_json
from .sarif import to_sarif
from .table import to_table

__all__ = ["Finding", "LegEntry", "to_json", "to_sarif", "to_table"]
