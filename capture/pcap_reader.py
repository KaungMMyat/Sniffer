"""Read a saved capture back into the same pipeline as live packets."""

import time

from scapy.utils import PcapNgReader, PcapReader

from capture.parser import parse_packet

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
SUPPORTED_SUFFIXES = (".pcap", ".pcapng", ".cap")


def is_supported_capture(path):
    """True when the file name has an extension we know how to read."""
    return str(path).lower().endswith(SUPPORTED_SUFFIXES)


def read_capture(path, on_packet, should_pause=None):
    """Parse every frame in ``path`` and hand it to ``on_packet``.

    ``on_packet(packet_info, raw_packet)`` is called once per readable frame.
    Numbers and display times come from the file, so a capture opened later
    still looks the way it did when it was recorded.

    ``should_pause`` is polled after each frame. The caller returns True while
    the UI still has a backlog, which throttles reading so a very large file
    cannot pile up thousands of parsed Scapy objects in memory.

    Returns ``(loaded, skipped)``.
    """
    reader_class = PcapNgReader if _is_pcapng(path) else PcapReader
    loaded = 0
    skipped = 0

    with reader_class(str(path)) as reader:
        for packet in reader:
            try:
                captured_at = float(packet.time)
            except (TypeError, ValueError, OSError):
                captured_at = time.time()

            try:
                packet_info = parse_packet(packet, loaded + 1, captured_at)
            except Exception:
                skipped += 1
                continue

            loaded += 1
            on_packet(packet_info, packet)

            if should_pause is not None and should_pause():
                time.sleep(0.02)

    return loaded, skipped


def _is_pcapng(path):
    with open(path, "rb") as handle:
        return handle.read(4) == PCAPNG_MAGIC
