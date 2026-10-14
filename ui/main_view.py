import flet as ft

from ui import theme
from ui.packet_details import create_packet_details
from ui.packet_table import create_packet_header


def _panel(content, expand=False, glass=True):
    return ft.Container(
        bgcolor=theme.GLASS_SURFACE if glass else theme.SURFACE,
        blur=10 if glass else None,
        border=ft.Border.all(
            1, theme.GLASS_BORDER if glass else theme.BORDER
        ),
        border_radius=12,
        padding=16,
        expand=expand,
        shadow=(
            ft.BoxShadow(
                blur_radius=18,
                color="#1A163655",
                offset=ft.Offset(0, 5),
            ) if glass else None
        ),
        content=content,
    )


def create_main_view(interfaces, start_capture, stop_capture, toggle_theme=None):
    interface_dropdown = ft.Dropdown(
        label="Network interface",
        width=300,
        dense=True,
        options=[
            ft.dropdown.Option(
                key=interface["name"],
                text=interface.get("description") or interface["name"],
            )
            for interface in interfaces
        ],
        value=interfaces[0]["name"] if interfaces else None,
    )
    capture_filter_field = ft.TextField(
        label="Capture filter · optional",
        hint_text="tcp, udp port 53, host 8.8.8.8",
        width=300,
        dense=True,
        border_radius=8,
        on_submit=start_capture,
    )
    start_button = ft.Button(
        "Start capture", icon=ft.Icons.PLAY_ARROW,
        on_click=start_capture, disabled=not interfaces,
        bgcolor=theme.ACCENT, color=theme.ON_COLOR, elevation=0,
    )
    stop_button = ft.Button(
        "Stop", icon=ft.Icons.STOP, on_click=stop_capture,
        disabled=True, elevation=0,
    )

    status_text = ft.Text("Ready" if interfaces else "No interface found",
                          size=12, weight=ft.FontWeight.W_600,
                          color=theme.MUTED if interfaces else theme.ON_COLOR)
    capture_activity = ft.ProgressRing(
        width=12, height=12, stroke_width=2,
        color=theme.ON_COLOR, visible=False,
        semantics_label="Capturing network traffic",
    )
    status_box = ft.Container(
        bgcolor=theme.BACKGROUND if interfaces else theme.ERROR,
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=12, vertical=7),
        animate=ft.Animation(
            theme.MOTION_STANDARD_MS, ft.AnimationCurve.EASE_OUT_CUBIC
        ),
        content=ft.Row(
            tight=True, spacing=7,
            controls=[capture_activity, status_text],
        ),
    )
    status_message = ft.Text(
        "Choose an interface and start capture."
        if interfaces else "Install Npcap and check your network adapter, then restart the app.",
        size=12, color=theme.MUTED,
    )
    theme_toggle = ft.Switch(
        label="Light Mode",
        value=False,
        active_color=theme.ACCENT,
        on_change=toggle_theme,
    )

    filter_field = ft.TextField(
        label="Display filter",
        hint_text="Protocol, IP address, or port · e.g. tcp, 8.8.8.8, 443",
        expand=True,
        dense=True,
        border_radius=8,
    )
    apply_filter_button = ft.Button("Apply", icon=ft.Icons.SEARCH,
                                    elevation=0)
    clear_filter_button = ft.Button("Clear filter", elevation=0)
    filter_applied = ft.Text("Showing all captured packets", size=12,
                             color=theme.MUTED)

    packet_capture = ft.Text("0 captured · 0 matching · 0 visible",
                              size=12, color=theme.MUTED)
    packet_list = ft.ListView(expand=True, spacing=0, auto_scroll=True)
    empty_title = ft.Text("No packets yet", size=14,
                          weight=ft.FontWeight.W_600, color=theme.TEXT)
    empty_description = ft.Text(
        "Start a capture to see network traffic here.",
        size=12, color=theme.MUTED,
    )
    empty_state = ft.Container(
        expand=True,
        alignment=ft.Alignment.CENTER,
        content=ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=6,
            controls=[
                ft.Icon(ft.Icons.NETWORK_CHECK, size=32, color=theme.MUTED),
                empty_title,
                empty_description,
            ],
        ),
    )
    packet_list.visible = False

    export_format_dropdown = ft.Dropdown(
        label="Format", width=110, dense=True,
        options=[ft.dropdown.Option(key="csv", text="CSV"),
                 ft.dropdown.Option(key="pcap", text="PCAP")],
        value="csv",
    )
    export_button = ft.Button("Export", icon=ft.Icons.FILE_DOWNLOAD_OUTLINED,
                              disabled=True, elevation=0)
    clear_button = ft.Button("Clear packets", icon=ft.Icons.DELETE_OUTLINE,
                             disabled=True, elevation=0)
    follow_live_button = ft.Button("Follow live", disabled=True, elevation=0)
    packet_details = create_packet_details()

    layout = ft.Column(
        expand=True,
        spacing=12,
        controls=[
            ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Column(spacing=2, controls=[
                        ft.Text("Packet Sniffer", size=24,
                                weight=ft.FontWeight.BOLD, color=theme.TEXT),
                        ft.Text("Live network traffic", size=12,
                                color=theme.MUTED),
                    ]),
                    ft.Row(
                        tight=True, spacing=16,
                        controls=[theme_toggle, status_box],
                    ),
                ],
            ),
            _panel(ft.Column(spacing=10, controls=[
                ft.Row(wrap=True, spacing=10, run_spacing=10, controls=[
                    interface_dropdown, capture_filter_field,
                    start_button, stop_button,
                ]),
                status_message,
            ])),
            _panel(ft.Column(spacing=8, controls=[
                ft.Row(spacing=10, controls=[
                    filter_field, apply_filter_button, clear_filter_button,
                ]),
                filter_applied,
            ])),
            _panel(
                ft.Column(expand=True, spacing=10, controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Column(spacing=2, controls=[
                                ft.Text("Packets", size=16,
                                        weight=ft.FontWeight.W_600,
                                        color=theme.TEXT),
                                packet_capture,
                            ]),
                            ft.Row(spacing=8, controls=[
                                follow_live_button, clear_button, export_format_dropdown,
                                export_button,
                            ]),
                        ],
                    ),
                    ft.Container(
                        expand=True,
                        border=ft.Border.all(1, theme.BORDER),
                        border_radius=8,
                        clip_behavior=ft.ClipBehavior.HARD_EDGE,
                        content=ft.Column(expand=True, spacing=0, controls=[
                            create_packet_header(),
                            ft.Column(expand=True, spacing=0, controls=[
                                packet_list, empty_state,
                            ]),
                        ]),
                    ),
                ]),
                expand=True,
                glass=False,
            ),
            packet_details["view"],
        ],
    )
    layout = ft.Container(
        expand=True,
        padding=16,
        gradient=ft.LinearGradient(
            begin=ft.Alignment.TOP_LEFT,
            end=ft.Alignment.BOTTOM_RIGHT,
            colors=[theme.BACKGROUND_TOP, theme.BACKGROUND_BOTTOM],
        ),
        content=layout,
    )

    return {
        "view": layout,
        "interface_dropdown": interface_dropdown,
        "capture_filter_field": capture_filter_field,
        "start_button": start_button,
        "stop_button": stop_button,
        "status_text": status_text,
        "capture_activity": capture_activity,
        "status_box": status_box,
        "theme_toggle": theme_toggle,
        "status_message": status_message,
        "filter_field": filter_field,
        "apply_filter_button": apply_filter_button,
        "clear_filter_button": clear_filter_button,
        "filter_applied": filter_applied,
        "packet_capture": packet_capture,
        "packet_list": packet_list,
        "empty_state": empty_state,
        "empty_title": empty_title,
        "empty_description": empty_description,
        "packet_details": packet_details,
        "export_format_dropdown": export_format_dropdown,
        "export_button": export_button,
        "clear_button": clear_button,
        "follow_live_button": follow_live_button,
    }
