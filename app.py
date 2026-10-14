import flet as ft

from capture.controller import CaptureController
from capture.interfaces import get_interfaces
from exporters import CSVExporter, PCAPExporter
from ui import theme
from ui.main_view import create_main_view
from ui.packet_table import create_packet_row, set_packet_row_selected
from utils.packet_filter import matches_filter
from utils.packet_view import packet_view


MAX_DISPLAY_PACKETS = 500
THEME_PREFERENCE_KEY = "sniffer.ui.dark_mode"


def main(page: ft.Page):
    page.title = "Packet Sniffer"
    page.window.width = 1280
    page.window.height = 880
    page.padding = 0
    page.bgcolor = theme.BACKGROUND
    page.theme_mode = ft.ThemeMode.LIGHT
    page.theme = ft.Theme(color_scheme_seed=theme.ACCENT)
    page.dark_theme = ft.Theme(color_scheme_seed=theme.ACCENT)

    interfaces = get_interfaces()
    preferences = ft.SharedPreferences()
    capture_packets = []
    raw_packets = []
    active_filter = ""
    matching_count = 0
    selected_packet_number = None
    theme_touched = False

    def set_status(label, message, kind="neutral"):
        styles = {
            "neutral": (theme.BACKGROUND, theme.MUTED),
            "live": (theme.SUCCESS, theme.ON_COLOR),
            "error": (theme.ERROR, theme.ON_COLOR),
        }
        background, foreground = styles[kind]
        ui["status_box"].bgcolor = background
        ui["status_text"].value = label
        ui["status_text"].color = foreground
        ui["capture_activity"].visible = kind == "live"
        ui["status_message"].value = message
        ui["status_message"].color = (
            ft.Colors.ERROR if kind == "error" else theme.MUTED
        )

    async def toggle_theme(e):
        nonlocal theme_touched
        theme_touched = True
        is_dark = bool(e.control.value)
        e.control.label = "Dark Mode" if is_dark else "Light Mode"
        page.theme_mode = ft.ThemeMode.DARK if is_dark else ft.ThemeMode.LIGHT
        page.update()
        try:
            await preferences.set(THEME_PREFERENCE_KEY, is_dark)
        except Exception as error:
            print(f"Could not save theme preference: {error}")

    async def restore_theme():
        try:
            is_dark = await preferences.get(THEME_PREFERENCE_KEY)
        except Exception as error:
            print(f"Could not load theme preference: {error}")
            return
        if isinstance(is_dark, bool) and not theme_touched:
            ui["theme_toggle"].value = is_dark
            ui["theme_toggle"].label = (
                "Dark Mode" if is_dark else "Light Mode"
            )
            page.theme_mode = (
                ft.ThemeMode.DARK if is_dark else ft.ThemeMode.LIGHT
            )
            page.update()

    def update_actions():
        running = bool(controller.is_running)
        ui["start_button"].disabled = running or not interfaces
        ui["stop_button"].disabled = not running
        ui["interface_dropdown"].disabled = running
        ui["capture_filter_field"].disabled = running
        ui["clear_button"].disabled = running or not capture_packets
        ui["export_button"].disabled = running or not capture_packets

    def update_counts():
        visible_count = len(ui["packet_list"].controls)
        ui["packet_capture"].value = (
            f"{len(capture_packets):,} captured · "
            f"{matching_count:,} matching · {visible_count:,} visible"
        )

    def update_empty_state():
        has_rows = bool(ui["packet_list"].controls)
        ui["packet_list"].visible = has_rows
        ui["empty_state"].visible = not has_rows
        if not capture_packets:
            ui["empty_title"].value = "No packets yet"
            ui["empty_description"].value = (
                "Start a capture to see network traffic here."
            )
        else:
            ui["empty_title"].value = "No matching packets"
            ui["empty_description"].value = (
                "Try another display filter or clear the current filter."
            )

    def clear_selection():
        nonlocal selected_packet_number
        selected_packet_number = None
        details = ui["packet_details"]
        details["title"].value = "No packet selected"
        details["empty"].visible = True
        details["content"].visible = False

    def render_packet_list(packets):
        ui["packet_list"].controls = [
            create_packet_row(
                packet,
                show_packet_details,
                selected=packet.number == selected_packet_number,
            )
            for packet in packets
        ]
        update_empty_state()
        update_counts()

    def show_packet_details(packet_info):
        nonlocal selected_packet_number
        selected_packet_number = packet_info.number
        details = ui["packet_details"]
        details["title"].value = f"Selected packet #{packet_info.number}"
        details["empty"].visible = False
        details["content"].visible = True
        for field in (
            "protocol", "source", "destination", "src_port", "dst_port",
            "mac_source", "mac_destination", "length", "info",
        ):
            details[field].value = str(getattr(packet_info, field) or "—")

        # Keep the selected row in view while the capture continues.
        ui["packet_list"].auto_scroll = False
        ui["follow_live_button"].disabled = False
        for row in ui["packet_list"].controls:
            set_packet_row_selected(row, row.data["number"] == selected_packet_number)
        page.update()

    async def add_packet_to_table(packet_info, raw_packet):
        nonlocal matching_count
        capture_packets.append(packet_info)
        raw_packets.append(raw_packet)

        if matches_filter(packet_info, active_filter):
            matching_count += 1
            if len(ui["packet_list"].controls) >= MAX_DISPLAY_PACKETS:
                ui["packet_list"].controls.pop(0)
            ui["packet_list"].controls.append(
                create_packet_row(packet_info, show_packet_details,
                                  selected=packet_info.number == selected_packet_number)
            )

        update_empty_state()
        update_counts()
        update_actions()
        page.update()

    def apply_display_filter(e=None):
        nonlocal active_filter, matching_count
        active_filter = (ui["filter_field"].value or "").strip()
        matching_count, visible = packet_view(
            capture_packets, active_filter, MAX_DISPLAY_PACKETS
        )
        if selected_packet_number not in {packet.number for packet in visible}:
            clear_selection()
        ui["filter_applied"].value = (
            f"Active filter: {active_filter}"
            if active_filter else "Showing all captured packets"
        )
        render_packet_list(visible)
        page.update()

    def clear_display_filter(e=None):
        ui["filter_field"].value = ""
        apply_display_filter()

    def follow_live(e=None):
        ui["packet_list"].auto_scroll = True
        ui["follow_live_button"].disabled = True
        page.update()

    def clear_packets(e=None):
        nonlocal active_filter, matching_count
        if controller.is_running:
            return
        capture_packets.clear()
        raw_packets.clear()
        controller.packet_count = 0
        active_filter = ""
        matching_count = 0
        ui["filter_field"].value = ""
        ui["filter_applied"].value = "Showing all captured packets"
        ui["packet_list"].controls.clear()
        ui["packet_list"].auto_scroll = True
        ui["follow_live_button"].disabled = True
        clear_selection()
        update_empty_state()
        update_counts()
        update_actions()
        page.update()

    async def export_packets(e):
        if controller.is_running or not capture_packets:
            return

        export_format = ui["export_format_dropdown"].value or "csv"
        try:
            file_path = await ft.FilePicker().save_file(
                dialog_title="Save captured packets",
                file_name=f"packets_export.{export_format}",
                allowed_extensions=[export_format],
            )
            if not file_path:
                return

            if export_format == "csv":
                if not file_path.lower().endswith(".csv"):
                    file_path += ".csv"
                count = CSVExporter().export(capture_packets, file_path)
            elif export_format == "pcap":
                if not file_path.lower().endswith(".pcap"):
                    file_path += ".pcap"
                count = PCAPExporter().export(raw_packets, file_path)
            else:
                raise ValueError(f"Unsupported export format: {export_format}")

            page.show_dialog(ft.AlertDialog(
                title=ft.Text("Export complete"),
                content=ft.Text(f"Saved {count} packets to:\n{file_path}"),
                actions=[ft.TextButton("OK", on_click=lambda _: page.pop_dialog())],
            ))
        except Exception as error:
            page.show_dialog(ft.AlertDialog(
                title=ft.Text("Export failed"),
                content=ft.Text(str(error)),
                actions=[ft.TextButton("OK", on_click=lambda _: page.pop_dialog())],
            ))

    def packet_received(packet_info, raw_packet):
        page.run_task(add_packet_to_table, packet_info, raw_packet)

    async def show_capture_error(error):
        set_status("Capture error", str(error), "error")
        update_actions()
        page.update()

    def capture_error(error):
        page.run_task(show_capture_error, error)

    def start_capture(e=None):
        interface = ui["interface_dropdown"].value
        if not interface:
            set_status("Select an interface", "Choose a network interface first.",
                       "error")
            page.update()
            return

        bpf_filter = (ui["capture_filter_field"].value or "").strip() or None
        try:
            controller.start(interface, bpf_filter=bpf_filter)
            if not controller.is_running:
                raise RuntimeError("Capture could not start. Check Npcap and permissions.")
            set_status("Capturing", f"Listening on {interface}", "live")
        except Exception as error:
            set_status("Capture error", str(error), "error")
        update_actions()
        page.update()

    def stop_capture(e=None):
        try:
            controller.stop()
            set_status("Stopped", "Capture stopped. You can export or clear packets.")
        except Exception as error:
            set_status("Capture error", str(error), "error")
        update_actions()
        page.update()

    controller = CaptureController(packet_received, capture_error)
    ui = create_main_view(
        interfaces, start_capture, stop_capture, toggle_theme
    )
    ui["apply_filter_button"].on_click = apply_display_filter
    ui["filter_field"].on_submit = apply_display_filter
    ui["clear_filter_button"].on_click = clear_display_filter
    ui["follow_live_button"].on_click = follow_live
    ui["clear_button"].on_click = clear_packets
    ui["export_button"].on_click = export_packets
    page.add(ui["view"])
    page.run_task(restore_theme)
    return ui


if __name__ == "__main__":
    ft.run(main)
