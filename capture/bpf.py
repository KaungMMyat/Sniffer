"""BPF capture-filter validation and examples.

A BPF (Berkeley Packet Filter) expression is the little language libpcap /
Npcap uses to decide which packets are handed to the program. The filter runs
inside the capture driver, so non-matching packets are discarded before Python
ever sees them.

The expression is compiled here against a "dead" pcap handle: libpcap checks
the syntax exactly as it would for a real capture, but no network card is
opened and no packets are captured.
"""

import ctypes

try:
    from scapy.libs.winpcapy import (
        bpf_program,
        pcap_close,
        pcap_compile,
        pcap_freecode,
        pcap_geterr,
        pcap_open_dead,
    )
except Exception:  # Npcap/libpcap unavailable: validation is skipped
    pcap_open_dead = None

# DLT_EN10MB (Ethernet). The link type only affects the compiled instructions,
# not whether the expression is syntactically valid.
_DLT_EN10MB = 1
_MAX_PACKET = 65535

BPF_EXAMPLES = (
    ("All traffic (no filter)", ""),
    ("TCP", "tcp"),
    ("UDP", "udp"),
    ("DNS", "udp port 53"),
    ("HTTP", "tcp port 80"),
    ("HTTPS", "tcp port 443"),
    ("ICMP / ping", "icmp"),
    ("ARP", "arp"),
    ("One host", "host 8.8.8.8"),
    ("One subnet", "net 192.168.1.0/24"),
    ("Web traffic", "tcp port 80 or tcp port 443"),
    ("Exclude a host", "not host 192.168.1.1"),
)


def validate_bpf(expression):
    """Return ``None`` if *expression* is valid, else a readable error string.

    An empty expression is valid and means "capture everything". When libpcap
    cannot be loaded, validation is skipped (``None``) and the capture layer
    reports any problem instead.
    """
    expression = (expression or "").strip()
    if not expression or pcap_open_dead is None:
        return None

    handle = pcap_open_dead(_DLT_EN10MB, _MAX_PACKET)
    if not handle:
        return None

    program = bpf_program()
    try:
        raw = ctypes.create_string_buffer(expression.encode("utf-8"))
        if pcap_compile(handle, ctypes.byref(program), raw, 1, -1) >= 0:
            pcap_freecode(ctypes.byref(program))
            return None
        message = ctypes.string_at(pcap_geterr(handle)).decode(
            "utf-8", "replace"
        )
        return message.strip() or "invalid filter expression"
    finally:
        pcap_close(handle)
