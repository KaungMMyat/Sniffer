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


def create_alert_row(alert: SecurityAlert):
    """Render a single security alert as a coloured row."""
    color = severity_color(alert.severity)
    return ft.Container(
        bgcolor=color,
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=10, vertical=8),
        content=ft.Row(
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
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
        border_radius=8,
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
        "Clear alerts", icon=ft.Icons.CLEANING_SERVICES, elevation=0,
        disabled=True,
    )

    header = ft.Row(
        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        controls=[
            ft.Row(
                spacing=8,
                controls=[
                    ft.Icon(ft.Icons.SHIELD_OUTLINED, size=18,
                            color=theme.TEXT),
                    ft.Text("Security alerts", size=16,
                            weight=ft.FontWeight.W_600, color=theme.TEXT),
                    alert_count,
                ],
            ),
            clear_alerts_button,
        ],
    )

    content = ft.Column(
        spacing=10,
        controls=[banner, header, empty_text, alert_list],
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
