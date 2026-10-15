from abc import ABC, abstractmethod
from typing import Optional

from models.packet_info import PacketInfo
from security.alert import SecurityAlert


class BaseDetector(ABC):
    """Abstract base class for all security detectors.

    Every detector receives PacketInfo objects one at a time and decides
    whether that packet (combined with its own memory of recent traffic)
    represents a threat. This keeps each detection technique isolated and
    easy to test.
    """

    name = "Base Detector"

    @abstractmethod
    def inspect(self, packet_info: PacketInfo) -> Optional[SecurityAlert]:
        """Inspect a single packet.

        Returns a SecurityAlert if a threat is detected, otherwise None.
        """
        raise NotImplementedError

    def reset(self) -> None:
        """Clear any accumulated state.

        Called when a new capture session starts so old traffic does not
        bleed into the new one.
        """
        return None
