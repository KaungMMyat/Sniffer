import flet as ft

from ui import theme
from ui.evidence_panel import create_security_panel
from ui.packet_details import create_packet_details
from ui.packet_table import create_packet_header, row_height
from ui.panel import create_panel
from ui.start_page import create_start_page

TOOL_ICON_SIZE = 18
FILTER_HEIGHT = 32


def create_main_view(
    interfaces,
    selected_interface,
    start_capture,
    stop_capture,
    toggle_theme=None,
    select_interface=None,
):
    # ------------------------------------------------------------------
    # Page 1: start page (interface list + open capture file)
    # ------------------------------------------------------------------

    start = create_start_page(
        interfaces, selected_interface, select_interface
    )
    # The start page has no toolbar, so it carries its own theme switch;
    # the application keeps both switches in step.
    setup_theme_toggle = _theme_switch(toggle_theme)
    setup_page = ft.Column(
        expand=True,
        spacing=0,
        controls=[
            ft.Row(alignment=ft.MainAxisAlignment.END,
                   controls=[setup_theme_toggle]),
            ft.Container(expand=True, alignment=ft.Alignment.CENTER,
                         content=start["setup_page"]),
        ],
    )

    # ------------------------------------------------------------------
    # Page 2: live capture
    # ------------------------------------------------------------------

    back_button = _tool_button(ft.Icons.ARROW_BACK, "Back to interface list")
    start_button = _tool_button(
        ft.Icons.PLAY_ARROW_ROUNDED, "Start capturing packets",
        color=theme.ACCENT, disabled=not interfaces,
    )
    start_button.on_click = start_capture
    stop_button = _tool_button(
        ft.Icons.STOP_ROUNDED, "Stop capturing packets",
        color=theme.ERROR, disabled=True,
    )
    stop_button.on_click = stop_capture
    restart_button = _tool_button(
        ft.Icons.RESTART_ALT,
        "Restart capture (discard packets and start again)",
        color=theme.SUCCESS, disabled=True,
    )
    open_button = _tool_button(
        ft.Icons.FOLDER_OPEN_OUTLINED, "Open a capture file (.pcap / .pcapng)",
    )
    save_pcap_item = ft.PopupMenuItem(
        content="Save as PCAP (full packet data)…", icon=ft.Icons.SAVE_OUTLINED,
    )
    save_csv_item = ft.PopupMenuItem(
        content="Export as CSV (packet list)…",
        icon=ft.Icons.TABLE_VIEW_OUTLINED,
    )
    save_button = ft.PopupMenuButton(
        icon=ft.Icons.SAVE_OUTLINED,
        icon_size=TOOL_ICON_SIZE,
        tooltip="Save or export captured packets",
        menu_position=ft.PopupMenuPosition.UNDER,
        items=[save_pcap_item, save_csv_item],
        disabled=True,
    )
    clear_button = _tool_button(
        ft.Icons.DELETE_SWEEP_OUTLINED,
        "Clear packets (only while capture is stopped)",
        disabled=True,
    )
    find_button = _tool_button(ft.Icons.SEARCH, "Find a packet", disabled=True)
    previous_button = _tool_button(
        ft.Icons.KEYBOARD_ARROW_UP, "Go to previous packet", disabled=True,
    )
    next_button = _tool_button(
        ft.Icons.KEYBOARD_ARROW_DOWN, "Go to next packet", disabled=True,
    )
    follow_live_button = _tool_button(
        ft.Icons.VERTICAL_ALIGN_BOTTOM,
        "Follow live: keep scrolling to the newest packet",
        disabled=True,
    )
    zoom_in_button = _tool_button(ft.Icons.ZOOM_IN, "Zoom in packet list")
    zoom_out_button = _tool_button(ft.Icons.ZOOM_OUT, "Zoom out packet list")
    zoom_reset_button = ft.TextButton(
        "100%", tooltip="Reset packet list to normal size",
        style=ft.ButtonStyle(
            padding=ft.Padding.symmetric(horizontal=6),
            shape=ft.RoundedRectangleBorder(radius=6),
        ),
    )

    # Two short lines beside the buttons replace the old extra toolbar rows:
    # what is being captured (plus Npcap counters), then the latest message.
    capture_target = _info_text(
        "No interface selected", color=theme.TEXT, weight=ft.FontWeight.W_600,
        expand=3,
    )
    capture_stats = _info_text("", expand=2)
    status_message = _info_text(
        "Choose an interface and start capture."
        if interfaces else
        "Install Npcap and check your network adapter, then restart the app.",
        expand=3,
    )
    record_status = _info_text("", expand=2)
    record_status.visible = False

    status_text = ft.Text(
        "Ready" if interfaces else "No interface found",
        size=12, weight=ft.FontWeight.W_600,
        color=theme.MUTED if interfaces else theme.ON_COLOR,
    )
    capture_activity = ft.ProgressRing(
        width=11, height=11, stroke_width=2,
        color=theme.ON_COLOR, visible=False,
        semantics_label="Working",
    )
    status_box = ft.Container(
        bgcolor=theme.BACKGROUND if interfaces else theme.ERROR,
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=10, vertical=4),
        animate=ft.Animation(
            theme.MOTION_STANDARD_MS, ft.AnimationCurve.EASE_OUT_CUBIC
        ),
        content=ft.Row(
            tight=True, spacing=6,
            controls=[capture_activity, status_text],
        ),
    )
    theme_toggle = _theme_switch(toggle_theme)

    find_field = ft.TextField(
        hint_text="Find a packet: IP, port, MAC, protocol, info text or number",
        prefix_icon=ft.Icons.SEARCH,
        expand=True,
        **_compact_field_style(),
    )
    find_next_button = _compact_button("Find next", ft.Icons.ARROW_DOWNWARD)
    find_previous_button = _compact_button(
        "Find previous", ft.Icons.ARROW_UPWARD,
    )
    find_result = ft.Text("", size=11, color=theme.MUTED, width=220,
                          no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS)
    find_close_button = ft.IconButton(
        icon=ft.Icons.CLOSE, icon_size=16, tooltip="Close find bar",
        style=ft.ButtonStyle(padding=4),
    )
    find_bar = ft.Row(
        visible=False,
        spacing=8,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
        controls=[
            find_field, find_next_button, find_previous_button,
            find_result, find_close_button,
        ],
    )

    toolbar = create_panel(ft.Column(spacing=4, controls=[
        ft.Row(spacing=1, vertical_alignment=ft.CrossAxisAlignment.CENTER,
               controls=[
                   back_button, _tool_separator(),
                   start_button, stop_button, restart_button,
                   _tool_separator(),
                   open_button, save_button, clear_button,
                   _tool_separator(),
                   find_button, previous_button, next_button,
                   follow_live_button, _tool_separator(),
                   zoom_in_button, zoom_out_button, zoom_reset_button,
                   _tool_separator(),
                   ft.Column(expand=True, spacing=0, controls=[
                       ft.Row(spacing=10, controls=[
                           capture_target, capture_stats,
                       ]),
                       ft.Row(spacing=10, controls=[
                           status_message, record_status,
                       ]),
                   ]),
                   status_box,
                   theme_toggle,
               ]),
        find_bar,
    ]))
    toolbar.padding = ft.Padding.symmetric(horizontal=8, vertical=3)

    filter_field = ft.TextField(
        hint_text="Display filter · e.g. http, tls, ssh, 8.8.8.8, 443",
        prefix_icon=ft.Icons.FILTER_ALT,
        expand=True,
        **_compact_field_style(),
    )
    apply_filter_button = _compact_button("Apply", ft.Icons.SEARCH)
    clear_filter_button = _compact_button("Clear")
    packet_capture = ft.Text(
        "0 captured · 0 matching · 0 visible",
        size=11, color=theme.MUTED, no_wrap=True,
        overflow=ft.TextOverflow.ELLIPSIS,
    )
    filter_applied = ft.Text(
        "Showing all captured packets", size=11, color=theme.MUTED,
        no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS,
        tooltip="Showing all captured packets",
    )

    # Scroll offset and size are reported (throttled) so previous/next and
    # find can tell whether the target row is already on screen. A fixed
    # item extent keeps row i at exactly i * row height, even off screen.
    packet_list = ft.ListView(
        expand=True, spacing=0, auto_scroll=True, scroll_interval=100,
        item_extent=row_height(1.0), size_change_interval=100,
    )
    packet_header = create_packet_header()
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

    packet_panel = create_panel(
        ft.Column(expand=True, spacing=6, controls=[
            ft.Row(spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER,
                   controls=[
                       filter_field, apply_filter_button, clear_filter_button,
                       ft.Column(width=250, spacing=0, controls=[
                           packet_capture, filter_applied,
                       ]),
                   ]),
            ft.Container(
                expand=True,
                border=ft.Border.all(1, theme.BORDER),
                border_radius=6,
                clip_behavior=ft.ClipBehavior.HARD_EDGE,
                content=ft.Column(expand=True, spacing=0, controls=[
                    packet_header,
                    ft.Column(expand=True, spacing=0, controls=[
                        packet_list, empty_state,
                    ]),
                ]),
            ),
        ]),
        # Fixed shares of the height, so alerts can never squeeze the list.
        expand=3,
        glass=False,
    )

    packet_details = create_packet_details()
    security_panel = create_security_panel()
    bottom_section = ft.Row(
        expand=2,
        spacing=8,
        controls=[packet_details["view"], security_panel["view"]],
    )

    capture_page = ft.Column(
        expand=True,
        spacing=8,
        controls=[toolbar, packet_panel, bottom_section],
    )

    # ------------------------------------------------------------------
    # Root: the body swaps between the start page and the capture page
    # ------------------------------------------------------------------

    body = ft.Container(expand=True, content=setup_page)
    layout = ft.Container(
        expand=True,
        padding=8,
        gradient=ft.LinearGradient(
            begin=ft.Alignment.TOP_LEFT,
            end=ft.Alignment.BOTTOM_RIGHT,
            colors=[theme.BACKGROUND_TOP, theme.BACKGROUND_BOTTOM],
        ),
        content=body,
    )

    view_config = {
        "view": layout,
        "body": body,
        "capture_page": capture_page,
        "start_button": start_button,
        "stop_button": stop_button,
        "back_button": back_button,
        "open_button": open_button,
        "capture_target": capture_target,
        "status_text": status_text,
        "capture_activity": capture_activity,
        "status_box": status_box,
        "theme_toggle": theme_toggle,
        "setup_theme_toggle": setup_theme_toggle,
        "status_message": status_message,
        "capture_stats": capture_stats,
        "record_status": record_status,
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
        "security_panel": security_panel,
        "packet_panel_view": packet_panel,
        "bottom_section": bottom_section,
        "packet_header": packet_header,
        "clear_button": clear_button,
        "follow_live_button": follow_live_button,
        "restart_button": restart_button,
        "save_button": save_button,
        "save_pcap_item": save_pcap_item,
        "save_csv_item": save_csv_item,
        "find_button": find_button,
        "previous_button": previous_button,
        "next_button": next_button,
        "zoom_in_button": zoom_in_button,
        "zoom_out_button": zoom_out_button,
        "zoom_reset_button": zoom_reset_button,
        "find_bar": find_bar,
        "find_field": find_field,
        "find_next_button": find_next_button,
        "find_previous_button": find_previous_button,
        "find_result": find_result,
        "find_close_button": find_close_button,
    }
    view_config.update(start)
    # Wrapped above with the theme switch; the body must show the wrapper.
    view_config["setup_page"] = setup_page
    return view_config


def _tool_button(icon, tooltip, color=None, disabled=False):
    """One square icon button of the main toolbar, styled like Wireshark's."""
    return ft.IconButton(
        icon=icon,
        icon_size=TOOL_ICON_SIZE,
        icon_color=color,
        tooltip=tooltip,
        disabled=disabled,
        style=ft.ButtonStyle(
            padding=4, shape=ft.RoundedRectangleBorder(radius=6),
        ),
    )


def _tool_separator():
    return ft.Container(
        width=1, height=18, bgcolor=theme.BORDER,
        margin=ft.Margin.symmetric(horizontal=5),
    )


def _theme_switch(on_change):
    return ft.Switch(
        label="Dark mode",
        label_text_style=ft.TextStyle(size=12, color=theme.MUTED),
        value=False,
        active_color=theme.ACCENT,
        scale=0.85,
        on_change=on_change,
    )


def _info_text(value, color=theme.MUTED, weight=None, expand=None):
    return ft.Text(
        value, size=11, color=color, weight=weight, expand=expand,
        no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS,
    )


def _compact_field_style():
    """Shared look of the one-line filter and find boxes (32 px tall)."""
    return {
        "height": FILTER_HEIGHT,
        "text_size": 12,
        "dense": True,
        "border_radius": 6,
        "content_padding": ft.Padding.symmetric(horizontal=8, vertical=0),
        "prefix_icon_size_constraints": ft.BoxConstraints(
            min_width=30, min_height=FILTER_HEIGHT,
        ),
    }


def _compact_button(text, icon=None):
    return ft.Button(
        text, icon=icon, height=FILTER_HEIGHT, elevation=0,
        style=ft.ButtonStyle(
            padding=ft.Padding.symmetric(horizontal=12),
            shape=ft.RoundedRectangleBorder(radius=6),
        ),
    )
