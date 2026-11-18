from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List

from models.packet_info import PacketInfo

# How many triggering packets an alert keeps for the evidence panel.
MAX_EVIDENCE_PACKETS = 200


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
    # The packets the detector saw as part of this activity (most recent last).
    evidence: List[PacketInfo] = field(default_factory=list)
