from abc import ABC, abstractmethod
from typing import List, Any


class BaseExporter(ABC):
    """
    Abstract base class for all packet exporters.
    
    All exporters must implement the export() method.
    This ensures a consistent interface across different export formats.
    """
    
    @abstractmethod
    def export(self, packets: List[Any], file_path: str) -> int:
        """
        Export packets to a file.
        
        Args:
            packets: List of PacketInfo objects to export
            file_path: Path where the file should be saved
            
        Returns:
            int: Number of packets exported
            
        Raises:
            ValueError: If no packets are provided
            IOError: If file cannot be written
        """
        pass
    
    @abstractmethod
    def get_file_extension(self) -> str:
        """
        Get the file extension for this export format.
        
        Returns:
            str: File extension (e.g., '.csv', '.pcap')
        """
        pass
