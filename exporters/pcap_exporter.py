from typing import List, Any

from scapy.data import DLT_EN10MB
from scapy.all import wrpcap

from exporters.base import BaseExporter


class PCAPExporter(BaseExporter):
    """
    Export packets to PCAP format.
    
    Creates a PCAP file that can be opened in Wireshark and other packet analyzers.
    """
    
    def export(self, packets: List[Any], file_path: str) -> int:
        """
        Export packets to a PCAP file.
        
        Args:
            packets: Raw link-layer frame bytes (or Scapy packets) to export
            file_path: Path where the PCAP file should be saved
            
        Returns:
            int: Number of packets exported
            
        Raises:
            ValueError: If no packets are provided
            IOError: If file cannot be written
        """
        if not packets:
            raise ValueError("No packets available to export.")
        
        # The app stores Ethernet frame bytes (DLT 1) to keep memory low;
        # Scapy cannot guess the link type from bytes, so pass it explicitly.
        wrpcap(file_path, packets, linktype=DLT_EN10MB)
        
        return len(packets)
    
    def get_file_extension(self) -> str:
        """
        Get the file extension for PCAP format.
        
        Returns:
            str: '.pcap'
        """
        return ".pcap"
