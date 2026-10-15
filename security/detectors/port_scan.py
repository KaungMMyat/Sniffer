import time
from collections import defaultdict
from typing import Dict, Optional

from models.packet_info import PacketInfo
from security.alert import SecurityAlert, Severity
from security.detectors.base import BaseDetector


class PortScanDetector(BaseDetector):
    """Detects TCP port scans.

    A port scan is one source host attempting connections to many distinct
    destination ports in a short period. We count distinct destination ports
    per source (for connection attempts only) and raise an alert when the
    count crosses a threshold. A cooldown prevents repeated alerts for the
    same source.

    Only connection attempts are counted. A pure TCP SYN (flags contain "S"
    but not "A") marks an attempt, so normal established traffic does not
    inflate the count.
    """

    name = "Port Scan Detector"

    def __init__(
        self,
        port_threshold: int = 15,
        time_window: float = 10.0,
        cooldown: float = 30.0,
    ):
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.cooldown = cooldown

        # source_ip -> {destination_port: last_seen_timestamp}
        self._attempts: Dict[str, Dict[str, float]] = defaultdict(dict)
        # source_ip -> timestamp of last alert
        self._last_alert: Dict[str, float] = {}

    # ------------------------------------------------------------------

    def inspect(self, packet_info: PacketInfo) -> Optional[SecurityAlert]:
        if not self._is_syn_attempt(packet_info):
            return None

        source = packet_info.source
        destination_port = packet_info.dst_port

        now = time.time()
        ports = self._attempts[source]

        # Drop ports not seen within the window so the count reflects rate.
        cutoff = now - self.time_window
        for port, seen_at in list(ports.items()):
            if seen_at < cutoff:
                del ports[port]

        ports[destination_port] = now

        if len(ports) < self.port_threshold:
            return None

        last_alert_at = self._last_alert.get(source, 0.0)
        if now - last_alert_at < self.cooldown:
            return None

        self._last_alert[source] = now

        return SecurityAlert(
            alert_type="Port Scan",
            severity=Severity.HIGH,
            source=source,
            description=(
                f"{len(ports)} distinct ports probed within "
                f"{self.time_window:.0f}s"
            ),
        )

    # ------------------------------------------------------------------

    def reset(self) -> None:
        self._attempts.clear()
        self._last_alert.clear()

    # ------------------------------------------------------------------

    @staticmethod
    def _is_syn_attempt(packet_info: PacketInfo) -> bool:
        if packet_info.protocol != "TCP" or not packet_info.dst_port:
            return False

        flags = packet_info.tcp_flags
        return "S" in flags and "A" not in flags
