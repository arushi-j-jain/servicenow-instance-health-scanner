from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(Enum):
    CRITICAL = "critical"
    WARNING  = "warning"
    INFO     = "info"


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    count: int = 0
    records: List[dict] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class AreaResult:
    name: str
    score: int
    findings: List[Finding] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    error: str = ""
