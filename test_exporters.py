"""
Test script for both CSV and PCAP exporters.
"""
from models.packet_info import PacketInfo
from exporters import CSVExporter, PCAPExporter
from scapy.all import IP, TCP, Ether, Raw


def test_csv_exporter():
    """Test CSV exporter with sample packets."""
    print("Testing CSV Exporter...")
    
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
    
    exporter = CSVExporter()
    count = exporter.export(packets, "test_export.csv")
    
    print(f"[OK] CSV export successful: {count} packets exported")
    print(f"[OK] File extension: {exporter.get_file_extension()}")
    
    # Verify file was created
    import os
    if os.path.exists("test_export.csv"):
        print("[OK] CSV file created successfully")
        os.remove("test_export.csv")
        print("[OK] Test file cleaned up")
    else:
        print("[FAIL] CSV file was not created")


def test_pcap_exporter():
    """Test PCAP exporter with sample raw packets."""
    print("\nTesting PCAP Exporter...")
    
    # Create sample raw Scapy packets
    raw_packets = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / 
        IP(src="192.168.1.10", dst="8.8.8.8") / 
        TCP(sport=53000, dport=53) / 
        Raw(load=b"dns query"),
        
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / 
        IP(src="192.168.1.10", dst="142.250.72.14") / 
        TCP(sport=51000, dport=443) / 
        Raw(load=b"https request"),
    ]
    
    exporter = PCAPExporter()
    count = exporter.export(raw_packets, "test_export.pcap")
    
    print(f"[OK] PCAP export successful: {count} packets exported")
    print(f"[OK] File extension: {exporter.get_file_extension()}")
    
    # Verify file was created
    import os
    if os.path.exists("test_export.pcap"):
        print("[OK] PCAP file created successfully")
        file_size = os.path.getsize("test_export.pcap")
        print(f"[OK] File size: {file_size} bytes")
        os.remove("test_export.pcap")
        print("[OK] Test file cleaned up")
    else:
        print("[FAIL] PCAP file was not created")


def test_error_handling():
    """Test error handling for empty packet lists."""
    print("\nTesting Error Handling...")
    
    csv_exporter = CSVExporter()
    pcap_exporter = PCAPExporter()
    
    try:
        csv_exporter.export([], "empty.csv")
        print("[FAIL] CSV exporter should have raised ValueError for empty list")
    except ValueError as e:
        print(f"[OK] CSV exporter correctly raised ValueError: {e}")
    
    try:
        pcap_exporter.export([], "empty.pcap")
        print("[FAIL] PCAP exporter should have raised ValueError for empty list")
    except ValueError as e:
        print(f"[OK] PCAP exporter correctly raised ValueError: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Running Exporter Tests")
    print("=" * 60)
    
    test_csv_exporter()
    test_pcap_exporter()
    test_error_handling()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)
