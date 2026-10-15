"""Main desktop workspace for capture, alerts, and packet inspection."""

import flet as ft

from ui import theme
from ui.alert_panel import create_alert_panel
from ui.packet_details import create_packet_details
from ui.packet_table import create_packet_header


def _surface(content, *, expand=False, shadow=False, padding=16):
    return ft.Container(
        bgcolor=theme.SURFACE,
        border=ft.Border.all(1, theme.BORDER),
        border_radius=8,
        padding=padding,
        expand=expand,
        shadow=(ft.BoxShadow(blur_radius=14, color=theme.SHADOW,
                             offset=ft.Offset(0, 3)) if shadow else None),
        content=content,
    )


def _button(label, *, icon=None, variant="secondary", disabled=False,
            on_click=None):
    colors = {
        "primary": (theme.ACCENT, theme.ON_COLOR, theme.ACCENT),
        "secondary": (theme.SURFACE, theme.TEXT, theme.BORDER),
        "quiet": (theme.SURFACE, theme.MUTED, theme.BORDER),
    }
    background, foreground, outline = colors[variant]
    return ft.Button(
        label, icon=icon, disabled=disabled, on_click=on_click,
        style=ft.ButtonStyle(
            bgcolor={ft.ControlState.DEFAULT: background,
                     ft.ControlState.DISABLED: theme.BACKGROUND},
            color={ft.ControlState.DEFAULT: foreground,
                   ft.ControlState.DISABLED: theme.MUTED},
            elevation=0,
            side={ft.ControlState.DEFAULT: ft.BorderSide(1, outline),
                  ft.ControlState.DISABLED: ft.BorderSide(1, theme.BORDER)},
            shape=ft.RoundedRectangleBorder(radius=6),
            padding=ft.Padding.symmetric(horizontal=14, vertical=11),
            animation_duration=theme.MOTION_FAST_MS,
        ),
    )


def _field_style():
    return dict(
        dense=True, filled=True, fill_color=theme.SURFACE,
        border_radius=6, border_color=theme.BORDER,
        focused_border_color=theme.ACCENT, focused_border_width=1.5,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=12),
    )


def _dropdown_style():
    return dict(
        **_field_style(),
        menu_style=ft.MenuStyle(
            bgcolor=theme.SURFACE, elevation=3,
            shadow_color=theme.SHADOW,
            side=ft.BorderSide(1, theme.BORDER),
            shape=ft.RoundedRectangleBorder(radius=6),
        ),
    )


def create_main_view(interfaces, start_capture, stop_capture, toggle_theme=None):
    interface_dropdown = ft.Dropdown(
        label="Network interface",
        col={"xs": 12, "sm": 6, "lg": 4},
        options=[ft.dropdown.Option(
            key=interface["name"],
            text=interface.get("description") or interface["name"],
        ) for interface in interfaces],
        value=interfaces[0]["name"] if interfaces else None,
        **_dropdown_style(),
    )
    capture_filter_field = ft.TextField(
        label="Capture filter (BPF) · optional",
        hint_text="tcp, udp port 53, host 8.8.8.8",
        tooltip="Limits incoming packets before they are captured.",
        col={"xs": 12, "sm": 6, "lg": 4},
        on_submit=start_capture, **_field_style(),
    )
    start_button = _button(
        "Start capture", icon=ft.Icons.PLAY_ARROW,
        variant="primary", on_click=start_capture, disabled=not interfaces,
    )
    stop_button = _button(
        "Stop", icon=ft.Icons.STOP, on_click=stop_capture, disabled=True,
    )

    status_text = ft.Text(
        "Ready" if interfaces else "No interface found",
        size=12, weight=ft.FontWeight.W_600,
        color=theme.MUTED if interfaces else theme.ON_COLOR,
    )
    capture_activity = ft.ProgressRing(
        width=12, height=12, stroke_width=2,
        color=theme.ON_COLOR, visible=False,
        semantics_label="Capturing network traffic",
    )
    status_box = ft.Container(
        bgcolor=theme.BACKGROUND if interfaces else theme.ERROR,
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=10, vertical=7),
        animate=ft.Animation(theme.MOTION_STANDARD_MS,
                             ft.AnimationCurve.EASE_OUT_CUBIC),
        content=ft.Row(tight=True, spacing=7,
                       controls=[capture_activity, status_text]),
    )
    status_message = ft.Text(
        "Choose an interface and start capture."
        if interfaces else "Install Npcap and check your network adapter, then restart the app.",
        size=12, color=theme.MUTED, visible=not interfaces,
    )
    theme_toggle = ft.Switch(
        label="Light Mode", value=False, active_color=theme.ACCENT,
        on_change=toggle_theme,
    )

    filter_field = ft.TextField(
        label="Display filter",
        hint_text="Search captured packets: tcp, 8.8.8.8, 443",
        tooltip="Searches captured packets; it does not change what is collected.",
        expand=True, **_field_style(),
    )
    apply_filter_button = _button("Apply", icon=ft.Icons.SEARCH)
    clear_filter_button = _button("Clear filter", variant="quiet")
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
        expand=True, alignment=ft.Alignment.CENTER,
        content=ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=6,
            controls=[ft.Icon(ft.Icons.NETWORK_CHECK, size=28,
                              color=theme.MUTED),
                      empty_title, empty_description],
        ),
    )
    packet_list.visible = False

    export_format_dropdown = ft.Dropdown(
        label="Format", width=112,
        options=[ft.dropdown.Option(key="csv", text="CSV"),
                 ft.dropdown.Option(key="pcap", text="PCAP")],
        value="csv", **_dropdown_style(),
    )
    export_button = _button("Export", icon=ft.Icons.FILE_DOWNLOAD_OUTLINED,
                            disabled=True)
    clear_button = _button("Clear packets", icon=ft.Icons.DELETE_OUTLINE,
                           variant="quiet", disabled=True)
    follow_live_button = _button("Follow live", variant="quiet", disabled=True)
    packet_details = create_packet_details()
    alert_panel = create_alert_panel()

    packet_table = ft.Container(
        expand=True, border=ft.Border.all(1, theme.BORDER),
        border_radius=6, clip_behavior=ft.ClipBehavior.HARD_EDGE,
        content=ft.Column(expand=True, spacing=0, controls=[
            create_packet_header(),
            ft.Column(expand=True, spacing=0,
                      controls=[packet_list, empty_state]),
        ]),
    )
    packet_workspace = _surface(
        ft.Column(expand=True, spacing=12, controls=[
            ft.ResponsiveRow(spacing=8, run_spacing=8, controls=[
                ft.Column(col={"xs": 12, "md": 4, "lg": 5},
                          spacing=2, controls=[
                    ft.Text("Packets", size=16, weight=ft.FontWeight.W_600,
                            color=theme.TEXT), packet_capture,
                ]),
                ft.Row(col={"xs": 12, "md": 8, "lg": 7},
                       spacing=8, run_spacing=8, wrap=True,
                       alignment=ft.MainAxisAlignment.END, controls=[
                    follow_live_button, clear_button,
                    export_format_dropdown, export_button,
                ]),
            ]),
            ft.Row(spacing=8, controls=[
                filter_field, apply_filter_button, clear_filter_button,
            ]),
            filter_applied, packet_table,
        ]), expand=True, shadow=True,
    )
    layout = ft.Container(
        expand=True, bgcolor=theme.BACKGROUND, padding=20,
        content=ft.Column(expand=True, spacing=12, controls=[
            ft.Row(alignment=ft.MainAxisAlignment.SPACE_BETWEEN, controls=[
                ft.Text("Packet Sniffer", size=23,
                        weight=ft.FontWeight.W_600, color=theme.TEXT),
                ft.Row(tight=True, spacing=14,
                       controls=[theme_toggle, status_box]),
            ]),
            _surface(ft.Column(spacing=10, controls=[
                ft.ResponsiveRow(spacing=8, run_spacing=8, controls=[
                    interface_dropdown, capture_filter_field,
                    ft.Row(col={"xs": 12, "lg": 4}, spacing=8,
                           controls=[start_button, stop_button]),
                ]),
                ft.Text("Capture filter limits incoming packets; Display filter searches captured packets.",
                        size=11, color=theme.MUTED),
                status_message,
            ])),
            _surface(alert_panel["content"], padding=12),
            packet_workspace, packet_details["view"],
        ]),
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
        "alert_panel": alert_panel,
        "export_format_dropdown": export_format_dropdown,
        "export_button": export_button,
        "clear_button": clear_button,
        "follow_live_button": follow_live_button,
    }
