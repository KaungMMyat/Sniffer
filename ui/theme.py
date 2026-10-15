"""Shared visual tokens for the packet analyzer UI.

Material color roles resolve against the active light or dark Flet theme.
"""

import flet as ft


BACKGROUND = ft.Colors.SURFACE_CONTAINER_LOW
SURFACE = ft.Colors.SURFACE
ON_COLOR = "#FFFFFF"
BORDER = ft.Colors.OUTLINE_VARIANT
TEXT = ft.Colors.ON_SURFACE
MUTED = ft.Colors.ON_SURFACE_VARIANT
ACCENT = "#165AA8"
ACCENT_SOFT = ft.Colors.PRIMARY_CONTAINER
SUCCESS = "#166B53"
ERROR = "#B72F3F"
ERROR_SOFT = ft.Colors.ERROR_CONTAINER
ROW_HOVER = ft.Colors.SURFACE_CONTAINER_LOW
TABLE_HEADER = ft.Colors.SURFACE_CONTAINER_LOW
SHADOW = ft.Colors.with_opacity(0.08, ft.Colors.SHADOW)
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
}


def protocol_style(protocol):
    return PROTOCOL_STYLES.get(protocol, ("#42566D", ON_COLOR))
