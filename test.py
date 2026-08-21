from models.packet_info import PacketInfo
from utils.packet_filter import matches_filter

packet = PacketInfo(
    number=1,
    time="13:00:00",
    source="192.168.1.10",
    destination="8.8.8.8",
    protocol="TCP",
    length=64,
    src_port="50000",
    dst_port="443",
    info="",
)


tests = [
    "",
    "tcp",
    "udp",
    "192.168.1.10",
    "8.8.8.8",
    "50000",
    "443",
    "dns",
]


for filter_text in tests:
    result = matches_filter(packet, filter_text)
    print(f"{filter_text!r:20} -> {result}")
