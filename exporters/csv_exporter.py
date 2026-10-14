import csv
from typing import List, Any

from exporters.base import BaseExporter


class CSVExporter(BaseExporter):
    """
    Export packets to CSV format.
    
    Creates a comma-separated values file with packet information.
    """
    
    def export(self, packets: List[Any], file_path: str) -> int:
        """
        Export packets to a CSV file.
        
        Args:
            packets: List of PacketInfo objects to export
            file_path: Path where the CSV file should be saved
            
        Returns:
            int: Number of packets exported
            
        Raises:
            ValueError: If no packets are provided
            IOError: If file cannot be written
        """
        if not packets:
            raise ValueError("No packets available to export.")
        
        fieldnames = [
            "number",
            "time",
            "source",
            "destination",
            "protocol",
            "length",
            "mac_source",
            "mac_destination",
            "src_port",
            "dst_port",
            "info",
        ]
        
        with open(file_path, "w", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for packet in packets:
                writer.writerow({
                    "number": packet.number,
                    "time": packet.time,
                    "source": packet.source,
                    "destination": packet.destination,
                    "protocol": packet.protocol,
                    "length": packet.length,
                    "mac_source": packet.mac_source,
                    "mac_destination": packet.mac_destination,
                    "src_port": packet.src_port,
                    "dst_port": packet.dst_port,
                    "info": packet.info,
                })
        
        return len(packets)
    
    def get_file_extension(self) -> str:
        """
        Get the file extension for CSV format.
        
        Returns:
            str: '.csv'
        """
        return ".csv"
