import flet as ft

from security.alert import SecurityAlert, Severity
from ui import theme

# Background colour per severity. Foreground stays white for contrast in both
# the light and dark themes.
_SEVERITY_COLORS = {
    Severity.LOW: "#165AA8",
    Severity.MEDIUM: "#B26A00",
    Severity.HIGH: theme.ERROR,
    Severity.CRITICAL: "#8E1F2B",
}


def severity_color(severity: Severity) -> str:
    return _SEVERITY_COLORS.get(severity, "#5A6472")


def create_alert_row(alert: SecurityAlert, on_block=None):
    """Render a single security alert as a coloured row."""
    color = severity_color(alert.severity)
    controls = [
        ft.Text(alert.timestamp, width=64, size=11,
                color=theme.ON_COLOR),
        ft.Text(alert.alert_type, width=96, size=11,
                weight=ft.FontWeight.W_600, color=theme.ON_COLOR),
        ft.Text(alert.source, width=120, size=11,
                color=theme.ON_COLOR, no_wrap=True,
                overflow=ft.TextOverflow.ELLIPSIS),
        ft.Text(alert.description, expand=True, size=11,
                color=theme.ON_COLOR, no_wrap=True,
                overflow=ft.TextOverflow.ELLIPSIS),
    ]
    if on_block is not None:
        controls.append(ft.IconButton(
            icon=ft.Icons.BLOCK,
            icon_size=16,
            padding=4,
            icon_color=theme.ON_COLOR,
            tooltip=f"Block {alert.source} with Windows Firewall",
            on_click=lambda e: on_block(alert),
        ))
    return ft.Container(
        bgcolor=color,
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=10, vertical=8),
        content=ft.Row(
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=controls,
        ),
    )

