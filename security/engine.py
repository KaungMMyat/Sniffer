from typing import Callable, List, Optional

from models.packet_info import PacketInfo
from security.alert import SecurityAlert
from security.detectors.base import BaseDetector
from security.detectors.port_scan import PortScanDetector


class SecurityEngine:
    """Runs every registered detector against the packet stream.

    The engine is the single entry point for security analysis. It feeds each
    packet to all detectors, stores the alerts they produce, and notifies a
    callback (used by the UI) whenever a new alert fires.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[SecurityAlert], None]] = None,
        detectors: Optional[List[BaseDetector]] = None,
    ):
        self.alert_callback = alert_callback
        self.detectors: List[BaseDetector] = (
            detectors if detectors is not None else [PortScanDetector()]
        )
        self.alerts: List[SecurityAlert] = []

    # ------------------------------------------------------------------

    def inspect(self, packet_info: PacketInfo) -> None:
        for detector in self.detectors:
            alert = detector.inspect(packet_info)
            if alert is not None:
                self.alerts.append(alert)
                if self.alert_callback is not None:
                    self.alert_callback(alert)

    # ------------------------------------------------------------------

    def reset(self) -> None:
        self.alerts.clear()
        for detector in self.detectors:
            detector.reset()
