from capture.parser import parse_packet
from capture.sniffer import PacketSniffer
from capture.tcp_analysis import TCPAnalyzer


class CaptureController:
    def __init__(self, packet_callback, error_callback=None):

        self.packet_callback = packet_callback
        self.error_callback = error_callback

        self.sniffer = None
        self.packet_count = 0
        self.tcp_analyzer = TCPAnalyzer()

    # -------------------------------------------------------

    def start(self, interface, bpf_filter=None):

        if self.sniffer and self.sniffer.running:
            return

        self.sniffer = PacketSniffer(
            interface,
            self.packet_received,
            self.error_callback,
            bpf_filter,
        )

        self.tcp_analyzer.reset()
        self.sniffer.start()

    # -------------------------------------------------------

    def stop(self):

        if self.sniffer:
            self.sniffer.stop()

    # -------------------------------------------------------

    @property
    def is_running(self):
        """Check if capture is currently running."""
        return self.sniffer and self.sniffer.running

    # -------------------------------------------------------

    def stats(self):
        """Return ``(received, dropped)`` from libpcap, or ``None``."""
        if self.sniffer:
            return self.sniffer.stats()
        return None

    # -------------------------------------------------------

    def packet_received(self, packet):

        self.packet_count += 1

        packet_info = parse_packet(
            packet, self.packet_count, analyzer=self.tcp_analyzer
        )

        self.packet_callback(packet_info, packet)

    # -------------------------------------------------------

    def capture_error(self, error):

        if self.error_callback:
            self.error_callback(error)
