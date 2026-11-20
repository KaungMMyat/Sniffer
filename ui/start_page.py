"""Wireshark-style start page: pick an interface or open a saved capture."""

import flet as ft

from capture.bpf import BPF_EXAMPLES
from ui import theme
from ui.panel import create_panel


def create_start_page(interfaces, selected_interface, on_select_interface):
    interface_rows = [
        create_interface_row(
            interface,
            interface["name"] == selected_interface,
            on_select_interface,
        )
        for interface in interfaces
    ]

    if interfaces:
        interface_list = ft.ListView(
            spacing=4, height=min(len(interfaces) * 58 - 4, 228),
            controls=interface_rows,
        )
    else:
        interface_list = ft.Container(
            padding=ft.Padding.symmetric(horizontal=4, vertical=8),
            content=ft.Text(
                "No capture interface found. Install Npcap, check your "
                "network adapter, then restart the app.",
                size=11,
                color=theme.ERROR,
            ),
        )

    capture_filter_field = ft.TextField(
        label="Capture filter (BPF)",
        hint_text="tcp port 443",
        expand=True,
        dense=True,
        border_radius=8,
        tooltip=(
            "Berkeley Packet Filter. Examples: tcp · udp port 53 · "
            "host 8.8.8.8 · net 192.168.1.0/24 · not port 22"
        ),
    )
    capture_filter_preset = ft.Dropdown(
        label="Preset",
        width=140,
        dense=True,
        options=[
            # An empty key would make the dropdown look unset, so "all" is a
            # sentinel that application code translates back to no filter.
            ft.dropdown.Option(key=expression or "all", text=label)
            for label, expression in BPF_EXAMPLES
        ],
    )
    record_checkbox = ft.Checkbox(label="Record to PCAP", value=False)
    setup_start_button = ft.Button(
        "Start capture",
        icon=ft.Icons.PLAY_ARROW,
        width=170,
        bgcolor=theme.ACCENT,
        color=theme.ON_COLOR,
        elevation=0,
        disabled=not interfaces,
    )
    setup_error = ft.Text(
        "", size=11, color=theme.ERROR, visible=False,
        max_lines=2, overflow=ft.TextOverflow.ELLIPSIS,
    )

    capture_card = create_panel(ft.Column(spacing=14, controls=[
        _card_header(
            ft.Icons.WIFI_TETHERING,
            "Capture interfaces",
            "Select an interface, then start capturing live traffic.",
        ),
        interface_list,
        ft.Row(
            spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.START,
            controls=[capture_filter_field, capture_filter_preset],
        ),
        ft.Text(
            "Examples: tcp · udp port 53 · host 8.8.8.8 · "
            "net 192.168.1.0/24 · not port 22",
            size=10,
            color=theme.MUTED,
        ),
        ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Column(spacing=2, controls=[
                    record_checkbox,
                    ft.Text(
                        "Saves a copy of the capture to captures/.",
                        size=10,
                        color=theme.MUTED,
                    ),
                ]),
                setup_start_button,
            ],
        ),
        setup_error,
    ]))
    capture_card.expand = False
    capture_card.width = 840
    capture_card.padding = 16

    setup_open_button = ft.OutlinedButton(
        "Open file…",
        icon=ft.Icons.FOLDER_OPEN_OUTLINED,
        width=160,
        height=36,
        tooltip="Open a saved capture; replaces the packets currently in the table.",
    )
    files_card = create_panel(ft.Row(
        spacing=12,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        controls=[
            ft.Icon(ft.Icons.INSERT_DRIVE_FILE_OUTLINED, size=24, color=theme.ACCENT),
            ft.Column(expand=True, spacing=3, controls=[
                ft.Text("Open a capture file", size=14,
                        weight=ft.FontWeight.W_600, color=theme.TEXT),
                ft.Text("Inspect saved traffic · .pcap / .pcapng / .cap",
                        size=11, color=theme.MUTED),
            ]),
            setup_open_button,
        ],
    ), glass=False)
    files_card.width = 840
    files_card.padding = ft.Padding.symmetric(horizontal=16, vertical=12)

    setup_page = ft.Column(
        expand=True,
        spacing=12,
        scroll=ft.ScrollMode.AUTO,
        alignment=ft.MainAxisAlignment.CENTER,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        controls=[files_card, capture_card],
    )

    return {
        "setup_page": setup_page,
        "interface_rows": interface_rows,
        "capture_filter_field": capture_filter_field,
        "capture_filter_preset": capture_filter_preset,
        "record_checkbox": record_checkbox,
        "setup_start_button": setup_start_button,
        "setup_open_button": setup_open_button,
        "setup_error": setup_error,
    }


def create_interface_row(interface, selected, on_select):
    name = interface["name"]
    description = interface.get("description") or ""

    icon = ft.Icon(
        _interface_icon(interface),
        size=20,
        color=theme.ACCENT if selected else theme.MUTED,
    )
    mark = ft.Icon(
        (
            ft.Icons.RADIO_BUTTON_CHECKED
            if selected else ft.Icons.RADIO_BUTTON_UNCHECKED
        ),
        size=18,
        color=theme.ACCENT if selected else theme.MUTED,
    )
    row = ft.Container(
        data={
            "name": name,
            "selected": selected,
            "icon": icon,
            "mark": mark,
        },
        bgcolor=theme.ACCENT_SOFT if selected else theme.SURFACE,
        border=ft.Border.all(
            1, theme.ACCENT if selected else theme.BORDER
        ),
        border_radius=8,
        padding=ft.Padding.symmetric(horizontal=12, vertical=8),
        ink=True,
        on_click=lambda e: on_select(row.data["name"]),
        content=ft.Row(
            spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                icon,
                ft.Column(
                    expand=True,
                    spacing=1,
                    controls=[
                        ft.Text(
                            name,
                            size=13,
                            weight=ft.FontWeight.W_600,
                            color=theme.TEXT,
                            no_wrap=True,
                            overflow=ft.TextOverflow.ELLIPSIS,
                        ),
                        ft.Text(
                            description,
                            size=11,
                            color=theme.MUTED,
                            no_wrap=True,
                            overflow=ft.TextOverflow.ELLIPSIS,
                        ),
                    ],
                ),
                mark,
            ],
        ),
    )
    return row


def set_interface_selected(row, selected):
    row.data["selected"] = selected
    row.bgcolor = theme.ACCENT_SOFT if selected else theme.SURFACE
    row.border = ft.Border.all(
        1, theme.ACCENT if selected else theme.BORDER
    )
    row.data["icon"].color = theme.ACCENT if selected else theme.MUTED
    # Flet 0.86 names the glyph property "icon" (not "name"); assigning the
    # wrong attribute leaves the old glyph on screen while the colour changes.
    row.data["mark"].icon = (
        ft.Icons.RADIO_BUTTON_CHECKED
        if selected else ft.Icons.RADIO_BUTTON_UNCHECKED
    )
    row.data["mark"].color = theme.ACCENT if selected else theme.MUTED


def _interface_icon(interface):
    description = (interface.get("description") or "").lower()
    name = interface["name"].lower()
    if "wi-fi" in description or "wireless" in description or "wi-fi" in name:
        return ft.Icons.WIFI
    if "bluetooth" in description:
        return ft.Icons.BLUETOOTH
    return ft.Icons.SETTINGS_ETHERNET


def _card_header(icon, title, subtitle):
    return ft.Row(
        spacing=12,
        controls=[
            ft.Container(
                width=42,
                height=42,
                border_radius=21,
                bgcolor=theme.ACCENT_SOFT,
                alignment=ft.Alignment.CENTER,
                content=ft.Icon(icon, size=22, color=theme.ACCENT),
            ),
            ft.Column(
                spacing=2,
                controls=[
                    ft.Text(
                        title,
                        size=19,
                        weight=ft.FontWeight.BOLD,
                        color=theme.TEXT,
                    ),
                    ft.Text(subtitle, size=12, color=theme.MUTED),
                ],
            ),
        ],
    )
