from typing import List, Any

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
            packets: List of raw Scapy packet objects to export
            file_path: Path where the PCAP file should be saved
            
        Returns:
            int: Number of packets exported
            
        Raises:
            ValueError: If no packets are provided
            IOError: If file cannot be written
        """
        if not packets:
            raise ValueError("No packets available to export.")
        
        wrpcap(file_path, packets)
        
        return len(packets)
    
    def get_file_extension(self) -> str:
        """
        Get the file extension for PCAP format.
        
        Returns:
            str: '.pcap'
        """
        return ".pcap"
