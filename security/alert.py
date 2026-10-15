from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """How serious a security alert is."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class SecurityAlert:
    """A single security alert produced by a detector.

    Detectors create these; the engine collects them and the UI displays them.
    """

    alert_type: str
    severity: Severity
    source: str
    description: str
    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime("%H:%M:%S")
    )
