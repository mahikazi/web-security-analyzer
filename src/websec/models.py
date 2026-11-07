from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"

@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    status: Status
    description: str
    evidence: str
    recommendation: str

@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)