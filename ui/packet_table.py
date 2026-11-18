import flet as ft

from ui import theme

# Sizes at 100 % zoom: one line of text per row, close to Wireshark's density.
BASE_ROW_HEIGHT = 22
BASE_FONT_SIZE = 12
BASE_BADGE_FONT_SIZE = 10.5
ZOOM_LEVELS = (0.8, 0.9, 1.0, 1.1, 1.25, 1.4, 1.6)

# (cell key, heading, width at 100 % zoom); None takes the remaining space.
_COLUMNS = (
    ("number", "No.", 56),
    ("time", "Time", 72),
    ("source", "Source", 155),
    ("destination", "Destination", 155),
    ("protocol", "Protocol", 84),
    ("length", "Length", 56),
    ("info", "Info", None),
)
_PROTOCOL_INDEX = 4
_ROW_BORDER = 3
_ROW_PADDING = 12


def row_height(zoom):
    return round(BASE_ROW_HEIGHT * zoom)


def _font_size(zoom):
    return round(BASE_FONT_SIZE * zoom, 1)


def _scaled(width, zoom):
    return None if width is None else round(width * zoom)


def create_packet_header(zoom=1.0):
    headings = [
        ft.Text(
            label,
            expand=width is None,
            color=theme.MUTED,
            weight=ft.FontWeight.W_600,
            no_wrap=True,
        )
        for _, label, width in _COLUMNS
    ]
    header = ft.Container(
        bgcolor=theme.TABLE_HEADER,
        # Same stripe + inner padding structure as a row, so every column
        # title sits exactly above its cells.
        border=ft.Border(
            left=ft.BorderSide(_ROW_BORDER, theme.TABLE_HEADER),
            bottom=ft.BorderSide(1, theme.BORDER),
        ),
        content=ft.Container(
            padding=ft.Padding.symmetric(horizontal=_ROW_PADDING, vertical=4),
            content=ft.Row(spacing=8, controls=headings),
        ),
        data={"headings": headings},
    )
    apply_header_zoom(header, zoom)
    return header


def apply_header_zoom(header, zoom):
    size = _font_size(zoom)
    for text, (_, _, width) in zip(header.data["headings"], _COLUMNS):
        text.size = size
        text.width = _scaled(width, zoom)


def create_packet_row(packet_info, on_click, selected=False, zoom=1.0):
    cells = {
        key: _cell(theme.MUTED if key == "number" else theme.TEXT,
                   expand=width is None)
        for key, _, width in _COLUMNS
        if key != "protocol"
    }
    badge_text = ft.Text(weight=ft.FontWeight.W_600, no_wrap=True)
    badge = ft.Container(
        border_radius=3,
        padding=ft.Padding.symmetric(horizontal=5, vertical=1),
        content=badge_text,
    )
    protocol_slot = ft.Container(content=badge)
    slots = [
        protocol_slot if key == "protocol" else cells[key]
        for key, _, _ in _COLUMNS
    ]
    row = ft.Container(
        bgcolor=theme.SURFACE,
        animate=ft.Animation(theme.MOTION_FAST_MS, ft.AnimationCurve.EASE_OUT_CUBIC),
        ink=True,
        data={
            "number": packet_info.number,
            "selected": selected,
            "hovered": False,
            "protocol_color": None,
            "packet": packet_info,
            "cells": cells,
            "badge": badge,
            "badge_text": badge_text,
            "protocol_slot": protocol_slot,
        },
        # Select on press, not on release: rows are recycled every flush, so
        # the control can move away between mouse-down and mouse-up and the
        # release click would never fire. Reading the packet from the row
        # avoids showing data from before a recycle.
        on_tap_down=lambda e: on_click(row.data["packet"]),
        # Padding lives on an inner container: with ink=True Flet applied the
        # outer padding twice, shifting every cell right of its heading.
        content=ft.Container(
            padding=ft.Padding.symmetric(horizontal=_ROW_PADDING),
            content=ft.Row(
                spacing=8,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=slots,
            ),
        ),
    )
    update_packet_row(row, packet_info, selected=selected)
    apply_row_zoom(row, zoom)

    def on_hover(e):
        row.data["hovered"] = bool(e.data)
        _paint_row(row)
        row.update()

    row.on_hover = on_hover
    return row


def apply_row_zoom(row, zoom):
    # Every row shares one fixed height so a row's scroll offset is simply
    # index * row_height(zoom); find and previous/next rely on that.
    row.height = row_height(zoom)
    size = _font_size(zoom)
    cells = row.data["cells"]
    for key, _, width in _COLUMNS:
        if key == "protocol":
            row.data["protocol_slot"].width = _scaled(width, zoom)
        else:
            cells[key].size = size
            cells[key].width = _scaled(width, zoom)
    row.data["badge_text"].size = round(BASE_BADGE_FONT_SIZE * zoom, 1)


def update_packet_row(row, packet_info, selected=False):
    """Reuse an existing row for another packet instead of rebuilding it.

    Building a Flet control tree costs ~0.3 ms; reusing one is roughly an
    order of magnitude cheaper, which keeps the UI thread free on fast links.
    """
    cells = row.data["cells"]
    _set_cell(cells["number"], str(packet_info.number))
    _set_cell(cells["time"], packet_info.time)
    _set_cell(cells["source"], packet_info.source or "—")
    _set_cell(cells["destination"], packet_info.destination or "—")
    _set_cell(cells["length"], str(packet_info.length))
    _set_cell(cells["info"], packet_info.info or "—")

    badge_bg, badge_fg = theme.protocol_style(packet_info.display_protocol)
    badge_text = row.data["badge_text"]
    badge_text.value = packet_info.display_protocol
    badge_text.color = badge_fg
    row.data["badge"].bgcolor = badge_bg
    row.data["number"] = packet_info.number
    row.data["selected"] = selected
    row.data["protocol_color"] = badge_bg
    row.data["packet"] = packet_info
    _paint_row(row)


def _set_cell(cell, value):
    cell.value = value
    cell.tooltip = value


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
        left=ft.BorderSide(
            _ROW_BORDER, theme.ACCENT if selected else row.data["protocol_color"]
        ),
        bottom=ft.BorderSide(1, theme.BORDER),
    )


def _cell(color, expand=False):
    return ft.Text(
        "",
        expand=expand,
        color=color,
        no_wrap=True,
        overflow=ft.TextOverflow.ELLIPSIS,
    )
