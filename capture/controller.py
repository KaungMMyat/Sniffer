from capture.parser import parse_packet
from capture.sniffer import PacketSniffer


class CaptureController:
    def __init__(self, packet_callback, error_callback=None):

        self.packet_callback = packet_callback
        self.error_callback = error_callback

        self.sniffer = None
        self.packet_count = 0

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

        self.sniffer.start()

    # -------------------------------------------------------

    def stop(self):

        if self.sniffer:
            self.sniffer.stop()

    # -------------------------------------------------------

    def packet_received(self, packet):

        self.packet_count += 1

        packet_info = parse_packet(packet, self.packet_count)

        self.packet_callback(packet_info)

    # -------------------------------------------------------

    def capture_error(self, error):

        if self.error_callback:
            self.error_callback(error)
