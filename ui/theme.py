"""Shared visual tokens for the packet analyzer UI."""

BACKGROUND = "#F4F6FA"
SURFACE = "#FFFFFF"
BORDER = "#DFE5EE"
TEXT = "#172334"
MUTED = "#607086"
ACCENT = "#1769D2"
ACCENT_SOFT = "#EAF3FF"
SUCCESS = "#16734A"
SUCCESS_SOFT = "#E8F6EE"
ERROR = "#B42332"
ERROR_SOFT = "#FDEDEF"
ROW_HOVER = "#F7F9FC"

PROTOCOL_STYLES = {
    "TCP": ("#EAF3FF", "#175DAD"),
    "UDP": ("#E9F7F2", "#176C50"),
    "DNS": ("#F2EDFF", "#6242A8"),
    "ICMP": ("#FFF3E7", "#9A5A16"),
    "ARP": ("#EDF3F7", "#486579"),
    "IPv4": ("#EDF3F7", "#486579"),
    "IPv6": ("#EDF3F7", "#486579"),
}


def protocol_style(protocol):
    return PROTOCOL_STYLES.get(protocol, ("#EDF3F7", "#486579"))
