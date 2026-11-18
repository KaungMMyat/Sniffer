_TRANSPORT_KEYWORDS = {"tcp", "udp", "icmp", "arp", "ipv4", "ipv6"}

_APPLICATION_KEYWORDS = {
    "dns",
    "http",
    "tls",
    "ssh",
    "dhcp",
    "ftp",
    "smtp",
    "telnet",
    "pop3",
    "imap",
    "smb",
    "mysql",
    "rdp",
    "postgresql",
    "ntp",
    "snmp",
    "quic",
    "ssdp",
}

_APPLICATION_ALIASES = {
    "https": "tls",
    "mdns": "dns",
}


def matches_filter(packet_info, filter_text):

    filter_text = filter_text.strip().lower()

    if not filter_text:
        return True

    if filter_text in _TRANSPORT_KEYWORDS:
        return packet_info.protocol.lower() == filter_text

    application = _APPLICATION_ALIASES.get(filter_text, filter_text)
    if application in _APPLICATION_KEYWORDS:
        return packet_info.app_protocol.lower() == application

    if filter_text in packet_info.source.lower():
        return True

    if filter_text in packet_info.destination.lower():
        return True

    if filter_text in packet_info.src_port:
        return True

    return filter_text in packet_info.dst_port


_FIND_FIELDS = (
    "source",
    "destination",
    "src_port",
    "dst_port",
    "mac_source",
    "mac_destination",
    "protocol",
    "app_protocol",
    "info",
)


def packet_contains(packet_info, text):
    """Case-insensitive text search over the fields shown for a packet."""

    needle = text.strip().lower()
    if not needle:
        return False

    if needle.lstrip("#") == str(packet_info.number):
        return True

    return any(
        needle in str(getattr(packet_info, field) or "").lower()
        for field in _FIND_FIELDS
    )
