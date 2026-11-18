# Packet ရောက်ပြီဆို raw packet object ရမယ် ၊ အဲ့ဒါကို parser က convert လုပ်ပေးပြီး ၊ flet GUI မှာထည့်မယ်
# ဘာလို့ scapy ကနေ GUI ပေါ်ကိုတန်းမတင်လဲဆိုရင် ၊ နောက်ပိုင်း scapy အစား PyShark တို့ dpkt တို့ပြောင်းသုံးရင် UI break သွားမှာစိုးလို့

from dataclasses import dataclass


@dataclass
class PacketInfo:
    number: int

    time: str

    source: str

    destination: str

    protocol: str

    length: int

    # Application protocol recognised inside TCP/UDP (HTTP, TLS, ...).
    app_protocol: str = ""

    mac_source: str = ""

    mac_destination: str = ""

    src_port: str = ""

    dst_port: str = ""

    tcp_flags: str = ""

    # ICMP type (8 = echo request, 0 = echo reply); -1 when not ICMP.
    icmp_type: int = -1

    info: str = ""

    # Epoch time from the capture itself. Detectors use it so a file loaded
    # from disk is analysed against its own timeline instead of load time.
    timestamp: float = 0.0

    @property
    def display_protocol(self):
        """Application name when known, otherwise the transport/network name."""
        return self.app_protocol or self.protocol
