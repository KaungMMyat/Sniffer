from datetime import datetime

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from models.packet_info import PacketInfo


def parse_packet(packet, number):

    source = ""
    destination = ""

    mac_source = ""
    mac_destination = ""

    src_port = ""
    dst_port = ""

    protocol = packet.lastlayer().name
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

    # -------------------------
    # TCP
    # -------------------------

    if packet.haslayer(TCP):
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)

        protocol = "TCP"

        info = f"{src_port} → {dst_port}"

    # -------------------------
    # UDP
    # -------------------------

    elif packet.haslayer(UDP):
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)

        protocol = "UDP"

        info = f"{src_port} → {dst_port}"

    # -------------------------
    # ICMP
    # -------------------------

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # -------------------------
    # DNS
    # -------------------------

    if packet.haslayer(DNS):
        protocol = "DNS"

        if packet[DNS].qd:
            info = packet[DNS].qd.qname.decode(errors="ignore")

    return PacketInfo(
        number=number,
        time=datetime.now().strftime("%H:%M:%S"),
        source=source,
        destination=destination,
        protocol=protocol,
        length=len(packet),
        mac_source=mac_source,
        mac_destination=mac_destination,
        src_port=src_port,
        dst_port=dst_port,
        info=info,
    )
