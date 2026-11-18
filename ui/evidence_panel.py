import flet as ft

from security.alert import SecurityAlert
from ui import theme
from ui.alert_panel import severity_color
from ui.panel import create_panel

ROW_HEIGHT = 30


def create_evidence_header_row():
    return ft.Container(
        bgcolor=theme.TABLE_HEADER,
        padding=ft.Padding.symmetric(horizontal=8, vertical=5),
        border=ft.Border(bottom=ft.BorderSide(1, theme.BORDER)),
        content=ft.Row(
            spacing=6,
            controls=[
                _cell("No.", 38, theme.MUTED, ft.FontWeight.W_600),
                _cell("Time", 58, theme.MUTED, ft.FontWeight.W_600),
                _cell("Source", 104, theme.MUTED, ft.FontWeight.W_600),
                _cell("Protocol", 64, theme.MUTED, ft.FontWeight.W_600),
                _cell("Port", 46, theme.MUTED, ft.FontWeight.W_600),
                _cell("Detected by", None, theme.MUTED,
                      ft.FontWeight.W_600, expand=True),
            ],
        ),
    )


def create_evidence_row(alert: SecurityAlert, packet_info, on_click):
    """One triggering packet, tagged with the detector that flagged it."""
    color = severity_color(alert.severity)
    return ft.Container(
        height=ROW_HEIGHT,
        bgcolor=theme.SURFACE,
        border=ft.Border(
            left=ft.BorderSide(3, color),
            bottom=ft.BorderSide(1, theme.BORDER),
        ),
        padding=ft.Padding.only(left=8, right=8),
        ink=True,
        tooltip=(
            f"{alert.alert_type}: {alert.description}\n"
            f"{packet_info.source} → {packet_info.destination} "
            f"{packet_info.info}"
        ),
        on_click=lambda e: on_click(packet_info),
        content=ft.Row(
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                _cell(str(packet_info.number), 38, theme.MUTED),
                _cell(packet_info.time, 58),
                _cell(packet_info.source or "—", 104),
                _cell(packet_info.display_protocol, 64),
                _cell(packet_info.dst_port or "—", 46),
                _cell(alert.alert_type, expand=True, color=color,
                      weight=ft.FontWeight.W_600),
            ],
        ),
    )


def create_security_panel():
    """Alerts and the packets that triggered them, beside packet details."""
    summary = ft.Text("No alerts", size=11, color=theme.MUTED,
                      no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS)
    details_button = _header_button(
        ft.Icons.LIST_ALT, "Show every alert (block a source from here)",
    )
    maximize_button = _header_button(
        ft.Icons.OPEN_IN_FULL, "Open detected packets in a larger window",
    )
    clear_button = _header_button(
        ft.Icons.CLEANING_SERVICES_OUTLINED,
        "Clear alerts and detected packets",
    )

    latest_text = ft.Text(
        "", size=11, weight=ft.FontWeight.W_600, color=theme.ON_COLOR,
        expand=True, no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS,
    )
    latest = ft.Container(
        visible=False,
        bgcolor=theme.ERROR,
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=8, vertical=4),
        content=ft.Row(
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, size=16,
                        color=theme.ON_COLOR),
                latest_text,
            ],
        ),
    )

    # Newest evidence stays visible while an attack is ongoing.
    list_view = ft.ListView(expand=True, spacing=0, auto_scroll=True)
    table = ft.Container(
        expand=True,
        visible=False,
        border=ft.Border.all(1, theme.BORDER),
        border_radius=6,
        clip_behavior=ft.ClipBehavior.HARD_EDGE,
        content=ft.Column(
            expand=True, spacing=0,
            controls=[create_evidence_header_row(), list_view],
        ),
    )
    empty = ft.Container(
        expand=True,
        alignment=ft.Alignment.CENTER,
        content=ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=4,
            controls=[
                ft.Icon(ft.Icons.VERIFIED_USER_OUTLINED, size=28,
                        color=theme.SUCCESS),
                ft.Text("No threats detected", size=13,
                        weight=ft.FontWeight.W_600, color=theme.TEXT),
                ft.Text("Packets that trigger a detector are listed here.",
                        size=11, color=theme.MUTED),
            ],
        ),
    )

    view = create_panel(ft.Column(expand=True, spacing=6, controls=[
        ft.Row(
            spacing=6,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Icon(ft.Icons.SHIELD_OUTLINED, size=16, color=theme.TEXT),
                ft.Text("Security alerts", size=14,
                        weight=ft.FontWeight.W_600, color=theme.TEXT),
                ft.Container(expand=True, content=summary),
                details_button,
                maximize_button,
                clear_button,
            ],
        ),
        latest,
        table,
        empty,
    ]))
    view.expand = 1

    return {
        "view": view,
        "summary": summary,
        "latest": latest,
        "latest_text": latest_text,
        "list": list_view,
        "table": table,
        "empty": empty,
        "details": details_button,
        "maximize": maximize_button,
        "clear": clear_button,
    }


def _header_button(icon, tooltip):
    return ft.IconButton(
        icon=icon,
        icon_size=16,
        tooltip=tooltip,
        disabled=True,
        style=ft.ButtonStyle(
            padding=4, shape=ft.RoundedRectangleBorder(radius=6),
        ),
    )


def _cell(value, width=None, color=theme.TEXT, weight=None, expand=False):
    return ft.Text(
        value,
        width=width,
        expand=expand,
        size=11,
        color=color,
        weight=weight,
        no_wrap=True,
        overflow=ft.TextOverflow.ELLIPSIS,
        tooltip=value,
    )
