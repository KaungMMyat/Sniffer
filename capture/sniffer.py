from scapy.all import AsyncSniffer


class PacketSniffer:
    def __init__(
        self, interface, packet_callback, error_callback=None, bpf_filter=None
    ):
        self.interface = interface
        self.packet_callback = packet_callback
        self.error_callback = error_callback
        self.bpf_filter = bpf_filter

        self.sniffer = None
        self.running = False

    # --------------------------------------------------------------------------
    def start(self):

        if self.running:  # Start capture button ကိုနှစ်ခေါက်နှိပ်မိရင် sniffer thread နှစ်ခုဖြစ်သွားမှာစိုးလို prevent လုပ်ထားတာ
            return

        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                filter=self.bpf_filter,
            )
            self.sniffer.start()
            self.running = True
        except Exception as error:
            self.running = False
            self.sniffer = None
            if self.error_callback:
                self.error_callback(error)

    # --------------------------------------------------------------------------
    def stop(self):

        if self.sniffer:
            self.sniffer.stop()

        self.running = False

    # --------------------------------------------------------------------------
    def _packet_handler(self, packet):

        # print("Packet received: ", packet.summary())
        try:
            if self.packet_callback:
                self.packet_callback(packet)

        except Exception:
            import traceback

            traceback.print_exc()
            raise

    # --------------------------------------------------------------------------
