from scapy.all import AsyncSniffer

try:
    from scapy.arch.libpcap import L2pcapListenSocket
except Exception:  # libpcap/Npcap unavailable
    L2pcapListenSocket = None

from capture.stats import read_pcap_stats


class PacketSniffer:
    def __init__(
        self, interface, packet_callback, error_callback=None, bpf_filter=None,
        promisc=True,
    ):
        self.interface = interface
        self.packet_callback = packet_callback
        self.error_callback = error_callback
        self.bpf_filter = bpf_filter
        self.promisc = promisc

        self.sniffer = None
        self.socket = None
        self.running = False
        self.last_stats = None

    # --------------------------------------------------------------------------
    def start(self):

        if self.running:
            return

        try:
            if L2pcapListenSocket is not None:
                # Own the socket so capture statistics are readable. Scapy's
                # libpcap socket already uses the maximum snaplen (65535).
                self.socket = L2pcapListenSocket(
                    iface=self.interface,
                    promisc=self.promisc,
                    filter=self.bpf_filter,
                )
                self.sniffer = AsyncSniffer(
                    opened_socket=self.socket,
                    prn=self._packet_handler,
                    store=False,
                )
            else:
                self.sniffer = AsyncSniffer(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    filter=self.bpf_filter,
                )
            self.sniffer.start()
            self.running = True
            self.last_stats = (0, 0)
        except Exception as error:
            self.running = False
            self.sniffer = None
            self._close_socket()
            if self.error_callback:
                self.error_callback(error)

    # --------------------------------------------------------------------------
    def stop(self):

        sniffer = self.sniffer
        if sniffer is not None:
            try:
                # Do not wait forever for the capture thread inside stop().
                # A stuck join is what froze the UI in the past.
                sniffer.stop(join=False)
            except Exception:
                pass

            thread = getattr(sniffer, "thread", None)
            if thread is not None:
                thread.join(timeout=2.0)
                if thread.is_alive():
                    # Closing the capture handle unblocks a stuck select().
                    self._close_socket()
                    thread.join(timeout=1.0)

        # Sample before closing; the counters disappear with the handle.
        current = read_pcap_stats(self.socket)
        if current is not None:
            self.last_stats = current
        self._close_socket()
        self.running = False

    # --------------------------------------------------------------------------
    def stats(self):
        """Return ``(received, dropped)`` for the current/last capture."""
        if self.running:
            current = read_pcap_stats(self.socket)
            if current is not None:
                self.last_stats = current
        return self.last_stats

    # --------------------------------------------------------------------------
    def _close_socket(self):
        if self.socket is not None:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

    # --------------------------------------------------------------------------
    def _packet_handler(self, packet):

        try:
            if self.packet_callback:
                self.packet_callback(packet)

        except Exception:
            import traceback

            traceback.print_exc()
            raise
