import flet as ft

from ui import theme


def create_packet_header():
    return ft.Container(
        bgcolor=theme.BACKGROUND,
        padding=ft.Padding.symmetric(horizontal=12, vertical=10),
        border=ft.Border(bottom=ft.BorderSide(1, theme.BORDER)),
        content=ft.Row(
            spacing=8,
            controls=[
                _heading("No.", 48),
                _heading("Time", 82),
                _heading("Source", 155),
                _heading("Destination", 155),
                _heading("Protocol", 90),
                _heading("Length", 62),
                _heading("Info", expand=True),
            ],
        ),
    )


def _heading(label, width=None, expand=False):
    return ft.Text(
        label,
        width=width,
        expand=expand,
        size=12,
        color=theme.MUTED,
        weight=ft.FontWeight.W_600,
    )


def create_packet_row(packet_info, on_click, selected=False):
    badge_bg, badge_fg = theme.protocol_style(packet_info.protocol)
    row = ft.Container(
        height=40,
        bgcolor=theme.ACCENT_SOFT if selected else theme.SURFACE,
        padding=ft.Padding.symmetric(horizontal=12),
        border=ft.Border(bottom=ft.BorderSide(1, theme.BORDER)),
        ink=True,
        on_click=lambda e: on_click(packet_info),
        content=ft.Row(
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                _cell(str(packet_info.number), 48, theme.MUTED),
                _cell(packet_info.time, 82),
                _cell(packet_info.source or "—", 155),
                _cell(packet_info.destination or "—", 155),
                ft.Container(
                    width=90,
                    content=ft.Container(
                        bgcolor=badge_bg,
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=7, vertical=4),
                        content=ft.Text(
                            packet_info.protocol,
                            size=11,
                            weight=ft.FontWeight.W_600,
                            color=badge_fg,
                            no_wrap=True,
                        ),
                    ),
                ),
                _cell(str(packet_info.length), 62),
                _cell(packet_info.info or "—", expand=True),
            ],
        ),
    )

    def on_hover(e):
        row.bgcolor = (
            theme.ACCENT_SOFT if selected else
            theme.ROW_HOVER if e.data == "true" else theme.SURFACE
        )
        row.update()

    row.on_hover = on_hover
    return row


def _cell(value, width=None, color=theme.TEXT, expand=False):
    return ft.Text(
        value,
        width=width,
        expand=expand,
        size=12,
        color=color,
        no_wrap=True,
        overflow=ft.TextOverflow.ELLIPSIS,
        tooltip=value,
    )
