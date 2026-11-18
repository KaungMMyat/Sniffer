"""Recognise application protocols inside TCP/UDP payloads.

Scapy already decapsulates Ethernet, IP and TCP/UDP. This module takes the
next step: it looks at Scapy layers, payload signatures and well-known ports
to name the application protocol (HTTP, TLS, SSH, DHCP, ...).
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.packet import Raw

_HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

_TCP_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
}

_UDP_PORTS = {
    123: "NTP",
    161: "SNMP",
    162: "SNMP",
    1900: "SSDP",
}

_DHCP_TYPES = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    4: "Decline",
    5: "ACK",
    6: "NAK",
    7: "Release",
    8: "Inform",
}

_DHCP_NAMES = {
    "discover": "Discover",
    "offer": "Offer",
    "request": "Request",
    "decline": "Decline",
    "ack": "ACK",
    "nak": "NAK",
    "release": "Release",
    "inform": "Inform",
}

_TLS_CONTENT_TYPES = {
    0x14: "Change Cipher Spec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "Application Data",
}


def detect_application(packet, transport, src_port, dst_port):
    """Return ``(app_protocol, info)`` for a decapsulated packet."""

    source = _port(src_port)
    destination = _port(dst_port)
    payload = _payload(packet)

    if packet.haslayer(DHCP) or _uses_port(transport, (67, 68), source, destination):
        return "DHCP", _dhcp_info(packet)

    if packet.haslayer(DNS) or _uses_port(transport, (53,), source, destination):
        return "DNS", _dns_info(packet)

    if transport == "TCP":
        if payload.startswith(b"SSH-") or _uses_port(transport, (22,), source, destination):
            return "SSH", _ssh_info(payload)
        if _looks_http(payload) or _uses_port(
            transport, (80, 8000, 8080, 8888), source, destination
        ):
            return "HTTP", _http_info(payload)
        if _looks_tls(payload) or _uses_port(
            transport, (443, 465, 636, 853, 993, 995, 8443), source, destination
        ):
            return "TLS", _tls_info(payload)

        service = _TCP_PORTS.get(source) or _TCP_PORTS.get(destination)
        if service:
            return service, ""

    elif transport == "UDP":
        if _uses_port(transport, (443,), source, destination):
            return "QUIC", "QUIC (encrypted)"

        service = _UDP_PORTS.get(source) or _UDP_PORTS.get(destination)
        if service:
            return service, ""

    return "", ""


def _payload(packet):
    raw = packet.getlayer(Raw)
    return bytes(raw.load) if raw is not None else b""


def _port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _uses_port(transport, ports, source, destination):
    if transport not in ("TCP", "UDP"):
        return False
    return source in ports or destination in ports


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _looks_http(payload):
    if not payload:
        return False
    if payload.startswith(b"HTTP/"):
        return True
    return any(payload.startswith(method) for method in _HTTP_METHODS)


def _http_info(payload):
    if not payload:
        return "HTTP"

    head = payload.split(b"\r\n\r\n", 1)[0]
    lines = head.decode("latin-1", errors="ignore").split("\r\n")
    first = lines[0][:140]

    if first.startswith("HTTP/"):
        return first

    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()[:100]
            break

    return f"{first} · Host: {host}" if host else first


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def _looks_tls(payload):
    if len(payload) < 3:
        return False
    return (
        payload[0] in _TLS_CONTENT_TYPES
        and payload[1] == 0x03
        and payload[2] <= 0x04
    )


def _tls_info(payload):
    if not _looks_tls(payload):
        return "TLS"

    content_type = payload[0]
    label = _TLS_CONTENT_TYPES.get(content_type, "TLS")

    if content_type == 0x16 and len(payload) > 5:
        handshake_type = payload[5]
        if handshake_type == 1:
            server_name = _client_hello_server_name(payload)
            if server_name:
                return f"Client Hello · SNI: {server_name}"
            return "Client Hello"
        if handshake_type == 2:
            return "Server Hello"
        if handshake_type == 11:
            return "Certificate"

    if content_type == 0x17:
        return "Application Data (encrypted)"

    return f"TLS {label}"


def _client_hello_server_name(payload):
    """Extract the SNI host name from a TLS Client Hello record."""

    try:
        pos = 5  # TLS record header
        if len(payload) < pos + 4:
            return ""
        handshake_length = int.from_bytes(payload[pos + 1:pos + 4], "big")
        pos += 4

        body_end = min(len(payload), pos + handshake_length)
        pos += 2 + 32  # legacy_version + random

        if pos >= body_end:
            return ""
        session_length = payload[pos]
        pos += 1 + session_length

        if pos + 2 > body_end:
            return ""
        cipher_length = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cipher_length

        if pos >= body_end:
            return ""
        compression_length = payload[pos]
        pos += 1 + compression_length

        if pos + 2 > body_end:
            return ""
        extensions_length = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        extensions_end = min(body_end, pos + extensions_length)

        while pos + 4 <= extensions_end:
            extension_type = int.from_bytes(payload[pos:pos + 2], "big")
            extension_length = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4

            if pos + extension_length > extensions_end:
                break

            if extension_type == 0:  # server_name
                data = payload[pos:pos + extension_length]
                if len(data) >= 5:
                    name_length = int.from_bytes(data[3:5], "big")
                    return data[5:5 + name_length].decode(
                        "latin-1", errors="ignore"
                    )
                return ""

            pos += extension_length
    except (IndexError, ValueError):
        return ""

    return ""


# ---------------------------------------------------------------------------
# SSH / DHCP / DNS
# ---------------------------------------------------------------------------

def _ssh_info(payload):
    if not payload.startswith(b"SSH-"):
        return "SSH"

    line = payload.split(b"\n", 1)[0].rstrip(b"\r")
    return line.decode("latin-1", errors="ignore")[:120]


def _dhcp_info(packet):
    message = ""
    client_mac = ""

    if packet.haslayer(DHCP):
        for option in packet[DHCP].options:
            if not isinstance(option, tuple):
                continue
            if option[0] == "message-type":
                value = option[1]
                if isinstance(value, int):
                    message = _DHCP_TYPES.get(value, f"Type {value}")
                else:
                    name = str(value).lower()
                    message = _DHCP_NAMES.get(name, str(value).capitalize())

    if packet.haslayer(BOOTP):
        try:
            address = bytes(packet[BOOTP].chaddr)
        except (TypeError, ValueError):
            address = b""
        if len(address) >= 6 and any(address[:6]):
            client_mac = ":".join(f"{byte:02x}" for byte in address[:6])

    parts = ["DHCP"]
    if message:
        parts.append(message)
    if client_mac:
        parts.append(f"client {client_mac}")
    return " · ".join(parts)


def _dns_info(packet):
    if packet.haslayer(DNS) and packet[DNS].qd:
        return packet[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
    return "DNS"
