
from models.packet_info import PacketInfo
from utils.exporter import export_packets_to_csv


packets = [
    PacketInfo(
        number=1,
        time="2026-10-14 09:30:00",
        source="192.168.1.10",
        destination="8.8.8.8",
        protocol="DNS",
        length=74,
        src_port="53000",
        dst_port="53",
        info="DNS query",
    ),
    PacketInfo(
        number=2,
        time="2026-10-14 09:30:01",
        source="192.168.1.10",
        destination="142.250.72.14",
        protocol="TCP",
        length=66,
        src_port="51000",
        dst_port="443",
        info="HTTPS connection",
    ),
]


export_packets_to_csv(packets, "test_packets.csv")

print("CSV export completed!")
