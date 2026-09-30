"""
severity.py

Shared data structures used by every check module, so all findings are
normalized into one consistent shape regardless of which AWS service
they came from. This mirrors how a CNAPP platform normalizes findings
across cloud providers and services into one unified feed.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    def __str__(self):
        return self.name


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    description: str
    runbook: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": str(self.severity),
            "resource": self.resource,
            "description": self.description,
            "runbook": self.runbook,
        }
