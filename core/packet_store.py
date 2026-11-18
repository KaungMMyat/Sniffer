"""Thread-safe hand-off between the capture thread and the UI thread.

The capture thread only appends to the pending queues; the UI thread drains
them on its own schedule. No Flet controls are touched off the UI thread.
"""

from collections import deque


class PacketStore:
    def __init__(self):
        self.packets = []
        self.raw_packets = []
        self._pending_packets = deque()
        self._pending_alerts = deque()

    def submit_packet(self, packet_info, raw_packet):
        self._pending_packets.append((packet_info, raw_packet))

    def submit_alert(self, alert):
        self._pending_alerts.append(alert)

    @property
    def has_pending(self):
        return bool(self._pending_packets) or bool(self._pending_alerts)

    @property
    def pending_count(self):
        """Packets waiting to be rendered; used to throttle file loading."""
        return len(self._pending_packets)

    def drain_packets(self):
        while self._pending_packets:
            yield self._pending_packets.popleft()

    def drain_alerts(self):
        while self._pending_alerts:
            yield self._pending_alerts.popleft()

    def clear_pending_alerts(self):
        self._pending_alerts.clear()

    def clear(self):
        self.packets.clear()
        self.raw_packets.clear()
        self._pending_packets.clear()
        self._pending_alerts.clear()
