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
    "TCP": ("#1B5DB2", SURFACE),
    "UDP": ("#0B7055", SURFACE),
    "DNS": ("#62479E", SURFACE),
    "ICMP": ("#935200", SURFACE),
    "ARP": ("#3C6273", SURFACE),
    "IPv4": ("#42566D", SURFACE),
    "IPv6": ("#42566D", SURFACE),
}


def protocol_style(protocol):
    return PROTOCOL_STYLES.get(protocol, ("#42566D", SURFACE))
