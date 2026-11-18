import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from models.packet_info import PacketInfo
from security.alert import MAX_EVIDENCE_PACKETS, SecurityAlert, Severity
from security.detectors.base import BaseDetector

ICMP_ECHO_REQUEST = 8


class IcmpFloodDetector(BaseDetector):
    """Detects ICMP echo-request floods (ping floods).

    A flood is many echo requests from one source in a short period. We keep
    the arrival times of recent requests per source and drop anything older
    than the window, so the counter reflects the current rate rather than all
    traffic since capture started.

    Only echo requests (type 8) are counted: echo replies (type 0) are normal
    responses and must not trigger the detector.
    """

    name = "ICMP Flood Detector"

    def __init__(
        self,
        packet_threshold: int = 50,
        time_window: float = 5.0,
        cooldown: float = 30.0,
    ):
        self.packet_threshold = packet_threshold
        self.time_window = time_window
        self.cooldown = cooldown

        # source_ip -> (arrival time, packet) inside the window
        self._requests: Dict[str, Deque[Tuple[float, PacketInfo]]] = (
            defaultdict(deque)
        )
        # source_ip -> timestamp of last alert
        self._last_alert: Dict[str, float] = {}

    # ------------------------------------------------------------------

    def inspect(self, packet_info: PacketInfo) -> Optional[SecurityAlert]:
        if (
            packet_info.protocol != "ICMP"
            or packet_info.icmp_type != ICMP_ECHO_REQUEST
        ):
            return None

        source = packet_info.source
        now = packet_info.timestamp or time.time()

        stamps = self._requests[source]
        stamps.append((now, packet_info))

        cutoff = now - self.time_window
        while stamps and stamps[0][0] < cutoff:
            stamps.popleft()

        if len(stamps) < self.packet_threshold:
            return None

        last_alert_at = self._last_alert.get(source, 0.0)
        if now - last_alert_at < self.cooldown:
            return None

        self._last_alert[source] = now

        return SecurityAlert(
            alert_type="ICMP Flood",
            severity=Severity.HIGH,
            source=source,
            description=(
                f"{len(stamps)} ICMP echo requests within "
                f"{self.time_window:.0f}s"
            ),
            evidence=[
                packet
                for _, packet in list(stamps)[-MAX_EVIDENCE_PACKETS:]
            ],
        )

    # ------------------------------------------------------------------

    def reset(self) -> None:
        self._requests.clear()
        self._last_alert.clear()
