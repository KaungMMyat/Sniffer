"""Shared visual tokens for the packet analyzer UI.

Material color roles resolve against the active light or dark Flet theme.
"""

import flet as ft


BACKGROUND = ft.Colors.SURFACE_CONTAINER_LOW
BACKGROUND_TOP = ft.Colors.SURFACE_CONTAINER_LOW
BACKGROUND_BOTTOM = ft.Colors.SURFACE_CONTAINER_HIGHEST
SURFACE = ft.Colors.SURFACE
ON_COLOR = "#FFFFFF"
GLASS_SURFACE = ft.Colors.with_opacity(0.88, ft.Colors.SURFACE)
GLASS_BORDER = ft.Colors.with_opacity(0.52, ft.Colors.OUTLINE)
BORDER = ft.Colors.OUTLINE_VARIANT
TEXT = ft.Colors.ON_SURFACE
MUTED = ft.Colors.ON_SURFACE_VARIANT
ACCENT = "#165AA8"
ACCENT_SOFT = ft.Colors.PRIMARY_CONTAINER
SUCCESS = "#166B53"
ERROR = "#B72F3F"
ERROR_SOFT = ft.Colors.ERROR_CONTAINER
ROW_HOVER = ft.Colors.SURFACE_CONTAINER_HIGH
TABLE_HEADER = ft.Colors.SURFACE_CONTAINER_HIGH
MOTION_FAST_MS = 140
MOTION_STANDARD_MS = 220

PROTOCOL_STYLES = {
    "TCP": ("#1B5DB2", ON_COLOR),
    "UDP": ("#0B7055", ON_COLOR),
    "DNS": ("#62479E", ON_COLOR),
    "ICMP": ("#935200", ON_COLOR),
    "ARP": ("#3C6273", ON_COLOR),
    "IPv4": ("#42566D", ON_COLOR),
    "IPv6": ("#42566D", ON_COLOR),
    "HTTP": ("#0F766E", ON_COLOR),
    "TLS": ("#166B53", ON_COLOR),
    "SSH": ("#8A3B6B", ON_COLOR),
    "DHCP": ("#9A5B00", ON_COLOR),
    "QUIC": ("#0E7490", ON_COLOR),
    "FTP": ("#2F6B9A", ON_COLOR),
    "SMTP": ("#8A6A00", ON_COLOR),
    "Telnet": ("#5A5A5A", ON_COLOR),
    "SMB": ("#6B4A2F", ON_COLOR),
    "MySQL": ("#9A5B00", ON_COLOR),
    "RDP": ("#1B5DB2", ON_COLOR),
    "PostgreSQL": ("#2F6B9A", ON_COLOR),
    "NTP": ("#0B7055", ON_COLOR),
    "SNMP": ("#3C6273", ON_COLOR),
}


PROTOCOL_ROW_COLORS = {
    "TCP": "#65A653",
    "UDP": "#63A4D8",
    "DNS": "#698DCD",
    "ICMP": "#AF8FC7",
    "ICMPv6": "#AF8FC7",
    "ARP": "#D8BB55",
    "IPv4": "#8C9BAB",
    "IPv6": "#8C9BAB",
    "HTTP": "#49B183",
    "TLS": "#55A874",
    "SSH": "#B987B2",
    "DHCP": "#D8BB55",
    "QUIC": "#59ACBB",
    "FTP": "#78A6C9",
    "SMTP": "#C5AD63",
    "Telnet": "#9A9A9A",
    "SMB": "#BF9B78",
    "MySQL": "#D3AC68",
    "RDP": "#7A9BC9",
    "PostgreSQL": "#78A6C9",
    "NTP": "#63A4D8",
    "SNMP": "#59ACBB",
}


def protocol_style(protocol):
    return PROTOCOL_STYLES.get(protocol, ("#42566D", ON_COLOR))


def protocol_row_background(protocol, hovered=False):
    color = PROTOCOL_ROW_COLORS.get(protocol)
    if color is None:
        return ROW_HOVER if hovered else SURFACE
    # Translucent tints blend with the table surface in either theme.
    return ft.Colors.with_opacity(0.30 if hovered else 0.20, color)
