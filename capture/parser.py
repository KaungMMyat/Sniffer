import time
from datetime import datetime

from scapy.config import conf
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from capture.protocols import detect_application
from capture.tcp_analysis import tcp_payload_length, tcp_summary
from models.packet_info import PacketInfo

_ICMP_LABELS = {
    0: "Echo reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo request",
    11: "Time exceeded",
}


def parse_packet(packet, number, timestamp=None, analyzer=None):

    captured_at = timestamp if timestamp is not None else float(
        getattr(packet, "time", time.time())
    )
    frame = getattr(packet, "original", b"") or bytes(packet)

    source = ""
    destination = ""

    mac_source = ""
    mac_destination = ""

    src_port = ""
    dst_port = ""
    tcp_flags = ""
    icmp_type = -1

    protocol = packet.lastlayer().name
    app_protocol = ""
    info = ""

    # -------------------------
    # Ethernet Layer
    # -------------------------

    if packet.haslayer(Ether):
        mac_source = packet[Ether].src
        mac_destination = packet[Ether].dst

    # -------------------------
    # IPv4 Layer
    # -------------------------

    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst

        protocol = "IPv4"

    # -------------------------
    # IPv6 Layer
    # -------------------------

    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst

        protocol = "IPv6"

    # -------------------------
    # ARP
    # -------------------------

    elif packet.haslayer(ARP):
        source = packet[ARP].psrc
        destination = packet[ARP].pdst

        protocol = "ARP"
        arp = packet[ARP]
        info = (f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else
                f"{arp.psrc} is at {arp.hwsrc}" if arp.op == 2 else f"ARP operation {arp.op}")

    # -------------------------
    # TCP
    # -------------------------

    if packet.haslayer(TCP):
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)

        protocol = "TCP"

        info = tcp_summary(packet[TCP])

    # -------------------------
    # UDP
    # -------------------------

    elif packet.haslayer(UDP):
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)

        protocol = "UDP"

        info = f"{src_port} → {dst_port} Len={len(packet[UDP].payload)}"

    # -------------------------
    # ICMP
    # -------------------------

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        icmp_type = int(packet[ICMP].type)
        info = _ICMP_LABELS.get(icmp_type, f"Type {icmp_type}")

    # -------------------------
    # Application layer
    # -------------------------

    if protocol != "TCP" or tcp_payload_length(packet[TCP]):
        app_protocol, app_info = detect_application(
            packet, protocol, src_port, dst_port
        )
        if app_protocol:
            info = f"{info} · {app_info or app_protocol}"

    result = PacketInfo(
        number=number,
        time=datetime.fromtimestamp(captured_at).strftime("%H:%M:%S"),
        timestamp=captured_at,
        source=source,
        destination=destination,
        protocol=protocol,
        app_protocol=app_protocol,
        length=len(frame),
        raw_frame=frame,
        link_type=conf.l2types.layer2num.get(type(packet)),
        wire_length=int(getattr(packet, "wirelen", None) or len(frame)),
        mac_source=mac_source,
        mac_destination=mac_destination,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        info=info,
    )
    if analyzer is not None:
        analyzer.analyze(result, packet)
    return result
