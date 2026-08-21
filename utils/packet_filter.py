def matches_filter(packet_info, filter_text):

    filter_text = filter_text.strip().lower()

    if not filter_text:
        return True

    if filter_text in {
        "tcp",
        "udp",
        "icmp",
        "arp",
        "dns",
        "ipv4",
        "ipv6",
    }:
        return packet_info.protocol.lower() == filter_text

    if filter_text in packet_info.source.lower():
        return True

    if filter_text in packet_info.destination.lower():
        return True

    if filter_text in packet_info.src_port:
        return True

    return filter_text in packet_info.dst_port
