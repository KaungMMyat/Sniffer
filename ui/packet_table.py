import flet as ft

from ui import theme


def create_packet_header():
    return ft.Container(
        bgcolor=theme.TABLE_HEADER,
        padding=ft.Padding.symmetric(horizontal=12, vertical=10),
        border=ft.Border(bottom=ft.BorderSide(1, theme.BORDER)),
        content=ft.Row(
            spacing=8,
            controls=[
                _heading("No.", 48),
                _heading("Time", 75),
                _heading("Source", expand=2),
                _heading("Destination", expand=2),
                _heading("Protocol", 80),
                _heading("Length", 55),
                _heading("Info", expand=3),
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
        height=38,
        bgcolor=theme.SURFACE,
        padding=ft.Padding.symmetric(horizontal=12),
        animate=ft.Animation(theme.MOTION_FAST_MS, ft.AnimationCurve.EASE_OUT_CUBIC),
        ink=True,
        data={
            "number": packet_info.number,
            "selected": selected,
            "hovered": False,
        },
        on_click=lambda e: on_click(packet_info),
        content=ft.Row(
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                _cell(str(packet_info.number), 48, theme.MUTED),
                _cell(packet_info.time, 75),
                _cell(packet_info.source or "—", expand=2),
                _cell(packet_info.destination or "—", expand=2),
                ft.Container(
                    width=80,
                    content=ft.Container(
                        bgcolor=badge_bg,
                        border_radius=4,
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
                _cell(str(packet_info.length), 55),
                _cell(packet_info.info or "—", expand=3),
            ],
        ),
    )
    _paint_row(row)

    def on_hover(e):
        row.data["hovered"] = bool(e.data)
        _paint_row(row)
        row.update()

    row.on_hover = on_hover
    return row


def set_packet_row_selected(row, selected):
    row.data["selected"] = selected
    _paint_row(row)


def _paint_row(row):
    selected = row.data["selected"]
    row.bgcolor = (
        theme.ACCENT_SOFT if selected else
        theme.ROW_HOVER if row.data["hovered"] else theme.SURFACE
    )
    row.border = ft.Border(
        left=ft.BorderSide(3, theme.ACCENT) if selected else None,
        bottom=ft.BorderSide(1, theme.BORDER),
    )


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
