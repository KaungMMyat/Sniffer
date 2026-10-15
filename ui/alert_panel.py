import flet as ft

from security.alert import SecurityAlert, Severity
from ui import theme

# Severity remains visible through a narrow edge and type color; the rows stay
# quiet enough to scan alongside packet data.
_SEVERITY_COLORS = {
    Severity.LOW: "#165AA8",
    Severity.MEDIUM: "#B26A00",
    Severity.HIGH: theme.ERROR,
    Severity.CRITICAL: "#8E1F2B",
}


def severity_color(severity: Severity) -> str:
    return _SEVERITY_COLORS.get(severity, "#5A6472")


def create_alert_row(alert: SecurityAlert):
    """Render a security alert as a flat, scannable row."""
    color = severity_color(alert.severity)
    return ft.Container(
        bgcolor=theme.SURFACE,
        border=ft.Border(left=ft.BorderSide(3, color),
                         bottom=ft.BorderSide(1, theme.BORDER)),
        padding=ft.Padding.symmetric(horizontal=10, vertical=8),
        content=ft.Row(
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Text(alert.timestamp, width=64, size=11,
                        color=theme.MUTED),
                ft.Text(alert.alert_type, width=96, size=11,
                        weight=ft.FontWeight.W_600, color=color),
                ft.Text(alert.source, width=120, size=11,
                        color=theme.TEXT, no_wrap=True,
                        overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(alert.description, expand=True, size=11,
                        color=theme.TEXT, no_wrap=True,
                        overflow=ft.TextOverflow.ELLIPSIS),
            ],
        ),
    )


def create_alert_panel():
    """Build the security alert area shown on the main window.

    Returns the panel content plus the controls the app updates when alerts
    arrive or are cleared.
    """

    banner_text = ft.Text(
        "", size=12, weight=ft.FontWeight.W_600,
        color=theme.ON_COLOR, expand=True,
    )
    banner = ft.Container(
        visible=False,
        bgcolor=theme.ERROR,
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=12, vertical=10),
        animate=ft.Animation(
            theme.MOTION_STANDARD_MS, ft.AnimationCurve.EASE_OUT_CUBIC
        ),
        content=ft.Row(
            spacing=10,
            controls=[
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED,
                        color=theme.ON_COLOR, size=18),
                banner_text,
            ],
        ),
    )

    alert_count = ft.Text("0", size=12, color=theme.MUTED)
    empty_text = ft.Text("No security alerts detected.", size=12,
                         color=theme.MUTED)
    alert_list = ft.ListView(spacing=4, height=96, auto_scroll=True,
                             visible=False)

    clear_alerts_button = ft.Button(
        "Clear alerts", disabled=True, visible=False,
        style=ft.ButtonStyle(
            bgcolor=theme.SURFACE, color=theme.MUTED, elevation=0,
            side=ft.BorderSide(1, theme.BORDER),
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        ),
    )

    header = ft.Row(
        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        controls=[
            ft.Row(
                spacing=8,
                controls=[
                    ft.Text("Security alerts", size=14,
                            weight=ft.FontWeight.W_600, color=theme.TEXT),
                    alert_count,
                    empty_text,
                ],
            ),
            clear_alerts_button,
        ],
    )

    content = ft.Column(
        spacing=8,
        controls=[header, banner, alert_list],
    )

    return {
        "content": content,
        "banner": banner,
        "banner_text": banner_text,
        "alert_list": alert_list,
        "alert_count": alert_count,
        "empty_text": empty_text,
        "clear_button": clear_alerts_button,
    }
