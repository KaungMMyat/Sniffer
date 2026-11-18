"""Read capture statistics directly from Npcap/libpcap.

Scapy does not expose libpcap's counters, so this module calls `pcap_stats`
on the handle held by the capture socket. Returns ``(received, dropped)``.
"""

import ctypes
import sys


class _PcapStat(ctypes.Structure):
    # Npcap appends a fourth field; libpcap's first three are common.
    _fields_ = [
        ("ps_recv", ctypes.c_uint),
        ("ps_drop", ctypes.c_uint),
        ("ps_ifdrop", ctypes.c_uint),
        ("ps_capt", ctypes.c_uint),
    ]


_wpcap = None
_wpcap_loaded = False


def _lib():
    global _wpcap, _wpcap_loaded
    if _wpcap_loaded:
        return _wpcap
    _wpcap_loaded = True
    if sys.platform != "win32":
        return None
    for name in (
        "wpcap.dll",
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
    ):
        try:
            _wpcap = ctypes.WinDLL(name)
            break
        except OSError:
            continue
    return _wpcap


def read_pcap_stats(socket):
    """Return ``(received, dropped)`` for a live socket, or ``None``."""
    lib = _lib()
    if lib is None or socket is None:
        return None
    handle = getattr(getattr(socket, "pcap_fd", None), "pcap", None)
    if handle is None:
        return None
    stat = _PcapStat()
    if lib.pcap_stats(handle, ctypes.byref(stat)) != 0:
        return None
    return int(stat.ps_recv), int(stat.ps_drop) + int(stat.ps_ifdrop)
