PROTOCOL_COLORS = {
    "TCP": "lightblue",
    "UDP": "lightGreen",
    "ICMP": "red",
    "ARP": "red",
    "DNS": "red",
    "HTTP": "red",
    "HTTPS/TLS": "red",
    "Other": "red",
}


def get_packet_color(protocol):

    return PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS["Other"])
