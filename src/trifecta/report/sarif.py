"""SARIF 2.1.0 reporter for GitHub Code Scanning / GitLab ingestion.

The egress sink (or boundary definition) is the primary result location; the
three legs are attached as ``relatedLocations`` so a reviewer can jump between
them. Severity maps to SARIF ``level`` plus a ``security-severity`` rank.
"""

from __future__ import annotations

import json

from .. import __version__

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def to_sarif(findings) -> str:
    rule_ids = sorted({f.rule_id for f in findings})
    rules = [_rule(rid) for rid in rule_ids]
    results = [_result(f) for f in findings]

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "trifecta-static",
                        "informationUri": "https://github.com/masonzeng702550/trifecta-static",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _rule(rule_id: str) -> dict:
    return {
        "id": rule_id,
        "name": rule_id.replace("/", "-"),
        "shortDescription": {"text": "Lethal trifecta capability combination in one trust boundary"},
        "helpUri": "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/",
    }


def _phys_location(evidence: str, message: str) -> dict:
    file, _, line = evidence.rpartition(":")
    if not file:
        file, line = evidence, "1"
    try:
        line_no = int(line)
    except ValueError:
        file, line_no = evidence, 1
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file},
            "region": {"startLine": max(line_no, 1)},
        },
        "message": {"text": message},
    }


def _result(f) -> dict:
    msg = _message_text(f)
    related = [_phys_location(ev, label) for ev, label in f.related_locations()]
    return {
        "ruleId": f.rule_id,
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": msg},
        "locations": [_phys_location(f.primary_location(), msg)],
        "relatedLocations": related,
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(f.severity, "5.0"),
            "trifecta-id": f.id,
            "status": f.status,
            "severity": f.severity,
        },
    }


def _message_text(f) -> str:
    head = (
        f"[{f.severity.upper()}] {f.status} lethal trifecta in trust boundary "
        f"'{f.boundary_name}'. {f.blast_radius}"
    )
    mit = " Mitigations: " + " | ".join(f.mitigations[:2]) if f.mitigations else ""
    return head + mit
