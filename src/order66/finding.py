#For finding potentially interesting activity
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

#define severity classes
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
#define activity observed
@dataclass
class Finding:
    rule_id: str
    severity: Severity
    reason: str
    process: str
    timestamp: datetime