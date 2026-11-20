"""Orchestrates the sniffer UI, capture, filtering, export, and alerts.

`app.py` stays a thin entry point; everything stateful lives here so the
application can be tested and extended without touching startup code.
"""

import asyncio
import time
from pathlib import Path

import flet as ft

from capture.bpf import validate_bpf
from capture.controller import CaptureController
from capture.interfaces import get_interfaces
from capture.pcap_reader import is_supported_capture, read_capture
from capture.recorder import DumpcapRecorder
from core.packet_store import PacketStore
from exporters import CSVExporter, PCAPExporter
from security import SecurityEngine, response
from security.alert import MAX_EVIDENCE_PACKETS
from ui import theme
from ui.alert_panel import create_alert_row, severity_color
from ui.evidence_panel import create_evidence_header_row, create_evidence_row
from ui.main_view import create_main_view
from ui.packet_details import render_packet_details
from ui.packet_table import (
    ZOOM_LEVELS,
    apply_header_zoom,
    apply_row_zoom,
    create_packet_row,
    row_height,
    set_packet_row_selected,
    update_packet_row,
)
from ui.start_page import set_interface_selected
from utils.packet_filter import matches_filter, packet_contains
from utils.packet_view import packet_view

MAX_DISPLAY_PACKETS = 500
# Creating one Flet row costs ~0.4 ms, so rebuilding the whole visible table
# in a single tick blocks the UI thread for ~200 ms. On a fast link that
# happens every 150 ms and the window stops responding. Render only the
# newest slice per tick; every packet is still stored, counted and exportable.
MAX_ROWS_PER_FLUSH = 60
THEME_PREFERENCE_KEY = "sniffer.ui.dark_mode"
FLUSH_INTERVAL = 0.15
RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "captures"
# Parsed packets waiting for the UI. Above this the file reader pauses, so a
# large capture cannot hold thousands of dissected Scapy objects in memory.
MAX_PENDING_LOAD = 2000


class SnifferApplication:
    def __init__(self, page: ft.Page):
        self.page = page
        self.interfaces = get_interfaces()
        self.selected_interface = (
            self.interfaces[0]["name"] if self.interfaces else None
        )
        self.preferences = ft.SharedPreferences()
        # Flet 0.86 services must live on the page; a throwaway FilePicker
        # cannot open a dialog because it has no page to talk to.
        self.file_picker = ft.FilePicker()
        self.store = PacketStore()
        self.controller = CaptureController(
            self._on_packet, self._on_capture_error
        )
        self.security = SecurityEngine(alert_callback=self._on_alert)
        self.recorder = None

        self.active_filter = ""
        self.matching_count = 0
        self.selected_packet_number = None
        self.zoom = 1.0
        # Scroll offset and visible height last reported by the packet list;
        # the height stays None until the list has been laid out once.
        self._list_offset = 0.0
        self._list_height = None
        self.theme_touched = False
        self._stopping = False
        self._loading = False
        self._saving = False
        # Set while the table shows a file; Npcap counters do not apply then.
        self._loaded_filename = None
        # (alert, packet) pairs shown in the detection evidence panel.
        self.evidence_entries = []

        self._configure_page()
        self.ui = create_main_view(
            self.interfaces,
            self.selected_interface,
            self.start_capture,
            self.stop_capture,
            self.toggle_theme,
            self._select_interface,
        )
        self._wire_events()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _configure_page(self):
        page = self.page
        page.title = "sniffX"
        page.window.width = 1280
        # Kept below the smallest common screen height after DPI scaling so
        # the details pane is never pushed under the taskbar.
        page.window.height = 790
        # Below this the packet list would be squeezed away by the toolbars.
        page.window.min_width = 1080
        page.window.min_height = 700
        page.padding = 0
        page.bgcolor = theme.BACKGROUND
        page.theme_mode = ft.ThemeMode.LIGHT
        page.theme = ft.Theme(color_scheme_seed=theme.ACCENT)
        page.dark_theme = ft.Theme(color_scheme_seed=theme.ACCENT)

    def mount(self):
        self.page.services.append(self.file_picker)
        self.page.add(self.ui["view"])
        self.page.on_close = self._on_close
        self.page.run_task(self._restore_theme)
        self.page.run_task(self._flush_loop)

    def _on_close(self, e=None):
        # Never leave dumpcap recording after the window is gone.
        if self.recorder is not None:
            self.recorder.stop()
            self.recorder = None

    def _wire_events(self):
        ui = self.ui
        ui["capture_filter_preset"].on_change = self._apply_capture_preset
        ui["capture_filter_field"].on_submit = self.start_from_setup
        ui["apply_filter_button"].on_click = self._apply_display_filter
        ui["filter_field"].on_submit = self._apply_display_filter
        ui["clear_filter_button"].on_click = self._clear_display_filter
        ui["follow_live_button"].on_click = self._follow_live
        ui["clear_button"].on_click = self._clear_packets
        ui["save_pcap_item"].on_click = (
            lambda _: self.page.run_task(self._export_packets, "pcap")
        )
        ui["save_csv_item"].on_click = (
            lambda _: self.page.run_task(self._export_packets, "csv")
        )
        ui["restart_button"].on_click = self._restart_capture
        ui["find_button"].on_click = self._toggle_find_bar
        ui["find_close_button"].on_click = self._toggle_find_bar
        ui["find_field"].on_submit = self._find_next
        ui["find_next_button"].on_click = self._find_next
        ui["find_previous_button"].on_click = self._find_previous
        ui["previous_button"].on_click = self._previous_packet
        ui["next_button"].on_click = self._next_packet
        ui["zoom_in_button"].on_click = lambda _: self._zoom(1)
        ui["zoom_out_button"].on_click = lambda _: self._zoom(-1)
        ui["zoom_reset_button"].on_click = lambda _: self._zoom(0)
        ui["packet_list"].on_scroll = self._on_packet_list_scroll
        ui["packet_list"].on_size_change = self._on_packet_list_resize
        ui["security_panel"]["clear"].on_click = self._clear_alerts
        ui["security_panel"]["details"].on_click = self._show_alerts_dialog
        ui["security_panel"]["maximize"].on_click = self._show_evidence_dialog
        ui["setup_start_button"].on_click = self.start_from_setup
        ui["setup_open_button"].on_click = self._open_pcap
        ui["open_button"].on_click = self._open_pcap
        ui["back_button"].on_click = self._show_setup_page

    # ------------------------------------------------------------------
    # Status and theme
    # ------------------------------------------------------------------

    def _set_status(self, label, message, kind="neutral"):
        styles = {
            "neutral": (theme.BACKGROUND, theme.MUTED),
            "live": (theme.SUCCESS, theme.ON_COLOR),
            "busy": (theme.ACCENT, theme.ON_COLOR),
            "error": (theme.ERROR, theme.ON_COLOR),
        }
        background, foreground = styles[kind]
        self.ui["status_box"].bgcolor = background
        self.ui["status_text"].value = label
        self.ui["status_text"].color = foreground
        self.ui["capture_activity"].visible = kind in ("live", "busy")
        self.ui["status_message"].value = message
        self.ui["status_message"].tooltip = message
        self.ui["status_message"].color = (
            ft.Colors.ERROR if kind == "error" else theme.MUTED
        )

    async def toggle_theme(self, e):
        self.theme_touched = True
        is_dark = bool(e.control.value)
        self._set_theme_switches(is_dark)
        self.page.theme_mode = (
            ft.ThemeMode.DARK if is_dark else ft.ThemeMode.LIGHT
        )
        self.page.update()
        try:
            await self.preferences.set(THEME_PREFERENCE_KEY, is_dark)
        except Exception as error:
            print(f"Could not save theme preference: {error}")

    async def _restore_theme(self):
        try:
            is_dark = await self.preferences.get(THEME_PREFERENCE_KEY)
        except Exception as error:
            print(f"Could not load theme preference: {error}")
            return
        if isinstance(is_dark, bool) and not self.theme_touched:
            self._set_theme_switches(is_dark)
            self.page.theme_mode = (
                ft.ThemeMode.DARK if is_dark else ft.ThemeMode.LIGHT
            )
            self.page.update()

    def _set_theme_switches(self, is_dark):
        # One switch lives on the start page, one on the toolbar.
        self.ui["theme_toggle"].value = is_dark
        self.ui["setup_theme_toggle"].value = is_dark

    def _select_interface(self, name):
        if self.controller.is_running or self._stopping or self._loading:
            return
        self.selected_interface = name
        for row in self.ui["interface_rows"]:
            set_interface_selected(row, row.data["name"] == name)
        self._update_actions()
        self.page.update()

    # ------------------------------------------------------------------
    # View state
    # ------------------------------------------------------------------

    def _update_actions(self):
        running = bool(self.controller.is_running)
        busy = running or self._stopping or self._loading or self._saving
        has_packets = bool(self.store.packets)
        has_interface = bool(self.selected_interface)
        self.ui["start_button"].disabled = busy or not has_interface
        self.ui["stop_button"].disabled = not running or self._stopping
        self.ui["restart_button"].disabled = not running or self._stopping
        self.ui["setup_start_button"].disabled = busy or not has_interface
        self.ui["setup_open_button"].disabled = busy
        self.ui["open_button"].disabled = busy
        self.ui["capture_filter_field"].disabled = busy
        self.ui["capture_filter_preset"].disabled = busy
        self.ui["clear_button"].disabled = busy or not has_packets
        self.ui["save_button"].disabled = busy or not has_packets
        for name in ("find_button", "previous_button", "next_button"):
            self.ui[name].disabled = not has_packets
        self.ui["record_checkbox"].disabled = busy

    def _update_counts(self):
        shown = len(self.ui["packet_list"].controls)
        self.ui["packet_capture"].value = (
            f"{len(self.store.packets):,} captured · "
            f"{self.matching_count:,} matching · showing latest {shown:,}"
        )

    def _apply_capture_preset(self, e):
        expression = e.control.value
        if expression is None:
            return
        # "all" is the dropdown's sentinel for "no filter".
        self.ui["capture_filter_field"].value = (
            "" if expression == "all" else expression
        )
        e.control.value = None
        self.page.update()

    def _update_capture_stats(self):
        """Show Npcap's received/dropped counters; True if the text changed."""
        if self._loaded_filename and not self.controller.is_running:
            return False
        stats = self.controller.stats()
        if stats is None:
            return False
        received, dropped = stats
        text = f"Interface received {received:,} · dropped {dropped:,}"
        color = theme.MUTED
        if dropped:
            text += " — packets are being lost"
            color = theme.ERROR
        control = self.ui["capture_stats"]
        changed = control.value != text or control.color != color
        control.value = text
        control.color = color
        return changed

    def _update_empty_state(self):
        has_rows = bool(self.ui["packet_list"].controls)
        self.ui["packet_list"].visible = has_rows
        self.ui["empty_state"].visible = not has_rows
        if not self.store.packets:
            self.ui["empty_title"].value = "No packets yet"
            self.ui["empty_description"].value = (
                "Start a capture to see network traffic here."
            )
        else:
            self.ui["empty_title"].value = "No matching packets"
            self.ui["empty_description"].value = (
                "Try another display filter or clear the current filter."
            )

    def _clear_selection(self):
        self.selected_packet_number = None
        render_packet_details(self.ui["packet_details"], None)

    def _render_packet_list(self, packets):
        self.ui["packet_list"].controls = [
            create_packet_row(
                packet,
                self._show_packet_details,
                selected=packet.number == self.selected_packet_number,
                zoom=self.zoom,
            )
            for packet in packets
        ]
        self._update_empty_state()
        self._update_counts()

    def _show_packet_details(self, packet_info):
        self.selected_packet_number = packet_info.number
        render_packet_details(self.ui["packet_details"], packet_info)

        # Keep the selected row in view while the capture continues.
        self.ui["packet_list"].auto_scroll = False
        self.ui["follow_live_button"].disabled = False
        for row in self.ui["packet_list"].controls:
            set_packet_row_selected(
                row, row.data["number"] == self.selected_packet_number
            )
        self.page.update()

    # ------------------------------------------------------------------
    # Batched UI updates
    # ------------------------------------------------------------------

    def _process_pending(self):
        """Drain queued packets/alerts and redraw the UI once."""
        stats_changed = self._update_capture_stats()
        if not self.store.has_pending:
            if stats_changed:
                self.page.update()
            return

        new_matching = []
        for packet_info, raw_packet in self.store.drain_packets():
            self.store.packets.append(packet_info)
            # Share the same bytes with packet details rather than retaining Scapy objects.
            self.store.raw_packets.append(packet_info.raw_frame)
            if matches_filter(packet_info, self.active_filter):
                self.matching_count += 1
                new_matching.append(packet_info)

        for alert in self.store.drain_alerts():
            self._render_alert(alert)

        self._append_rows(new_matching)
        self._update_empty_state()
        self._update_counts()

        self._update_actions()
        self.page.update()

    def _append_rows(self, packets):
        """Show new packets by recycling the oldest visible rows.

        Creating a Flet row costs ~0.3 ms; rebuilding the whole table in one
        tick blocked the event loop for ~200 ms and is what made the window
        freeze on fast links. Reusing rows keeps the per-tick cost small, and
        because a row is never removed mid-click the selection always works.

        A burst can contain thousands of packets while the table shows at
        most MAX_DISPLAY_PACKETS, so only the newest slice is rendered; the
        skipped packets are still stored, counted and exportable.
        """
        if not packets:
            return

        if len(packets) > MAX_ROWS_PER_FLUSH:
            packets = packets[-MAX_ROWS_PER_FLUSH:]

        rows = self.ui["packet_list"].controls
        for packet_info in packets:
            selected = packet_info.number == self.selected_packet_number
            if len(rows) >= MAX_DISPLAY_PACKETS:
                row = rows.pop(0)
                update_packet_row(row, packet_info, selected=selected)
                rows.append(row)
            else:
                rows.append(
                    create_packet_row(
                        packet_info,
                        self._show_packet_details,
                        selected=selected,
                        zoom=self.zoom,
                    )
                )

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            try:
                self._process_pending()
            except Exception as error:
                print(f"UI flush error: {error}")

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def _reset_security_panel(self):
        panel = self.ui["security_panel"]
        panel["latest"].visible = False
        panel["latest_text"].value = ""
        self.evidence_entries = []
        self._render_evidence()

    def _render_alert(self, alert):
        panel = self.ui["security_panel"]
        panel["latest"].visible = True
        panel["latest"].bgcolor = severity_color(alert.severity)
        panel["latest_text"].value = (
            f"{alert.timestamp}  {alert.alert_type} from {alert.source} — "
            f"{alert.description}"
        )
        panel["latest_text"].tooltip = panel["latest_text"].value

        self.evidence_entries.extend(
            (alert, packet_info) for packet_info in alert.evidence
        )
        self.evidence_entries = self.evidence_entries[-MAX_EVIDENCE_PACKETS:]
        self._render_evidence()

    def _render_evidence(self):
        panel = self.ui["security_panel"]
        panel["list"].controls = [
            create_evidence_row(alert, packet_info, self._show_packet_details)
            for alert, packet_info in self.evidence_entries
        ]
        alerts = len(self.security.alerts)
        packets = len(self.evidence_entries)
        if alerts:
            panel["summary"].value = (
                f"{alerts:,} alert{'' if alerts == 1 else 's'} · "
                f"{packets:,} detected packet{'' if packets == 1 else 's'}"
            )
        else:
            panel["summary"].value = "No alerts"
        panel["table"].visible = bool(packets)
        panel["empty"].visible = not packets
        panel["details"].disabled = not alerts
        panel["maximize"].disabled = not packets
        panel["clear"].disabled = not alerts and not packets

    def _show_alerts_dialog(self, e=None):
        alerts = self.security.alerts
        if not alerts:
            return
        rows = [
            create_alert_row(alert, self._request_block)
            for alert in alerts
        ]
        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text(f"Security alerts ({len(alerts)})"),
            content=ft.Container(
                width=820,
                height=380,
                content=ft.ListView(spacing=4, controls=rows),
            ),
            actions=[
                ft.TextButton(
                    "Close", on_click=lambda _: self.page.pop_dialog()
                )
            ],
        ))

    def _show_evidence_dialog(self, e=None):
        if not self.evidence_entries:
            return
        rows = [
            create_evidence_row(alert, packet_info, self._select_evidence_packet)
            for alert, packet_info in self.evidence_entries
        ]
        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text(
                f"Detected packets ({len(self.evidence_entries)})"
            ),
            content=ft.Container(
                width=880,
                height=460,
                content=ft.Column(
                    expand=True,
                    spacing=0,
                    controls=[
                        create_evidence_header_row(),
                        ft.ListView(expand=True, spacing=0, controls=rows),
                    ],
                ),
            ),
            actions=[
                ft.TextButton(
                    "Close", on_click=lambda _: self.page.pop_dialog()
                )
            ],
        ))

    def _select_evidence_packet(self, packet_info):
        self.page.pop_dialog()
        self._show_packet_details(packet_info)

    # ------------------------------------------------------------------
    # Response: block / unblock a source (never automatic)
    # ------------------------------------------------------------------

    def _show_message(self, title, message, error=False):
        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text(title),
            content=ft.Text(
                message, color=theme.ERROR if error else theme.TEXT
            ),
            actions=[
                ft.TextButton("OK", on_click=lambda _: self.page.pop_dialog())
            ],
        ))

    def _request_block(self, alert):
        self.page.run_task(self._confirm_block, alert)

    async def _confirm_block(self, alert):
        source = (alert.source or "").strip()
        if not response.is_valid_ip(source):
            self._show_message(
                "Cannot block source",
                f'"{source}" is not a valid IP address.',
                error=True,
            )
            return
        if response.is_protected(source):
            self._show_message(
                "Address is protected",
                f"{source} is your gateway, a DNS server, or one of this "
                "computer's own addresses. Blocking it would break your own "
                "network access, so it was not changed.",
                error=True,
            )
            return
        if not response.is_admin():
            self._show_message(
                "Administrator rights required",
                "Changing Windows Firewall needs an elevated app. Close the "
                "sniffer, reopen it as administrator, and try again.",
                error=True,
            )
            return

        try:
            blocked = await asyncio.to_thread(response.is_blocked, source)
        except response.ResponseError as error:
            self._show_message("Firewall check failed", str(error), error=True)
            return

        action = "Unblock" if blocked else "Block"
        warning = (
            f"This removes the firewall rule for {source}."
            if blocked else
            f"This adds a Windows Firewall rule that blocks inbound traffic "
            f"from {source}. You can undo this from the alert later."
        )
        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text(f"{action} {source}?"),
            content=ft.Text(warning),
            actions=[
                ft.TextButton(
                    "Cancel", on_click=lambda _: self.page.pop_dialog()
                ),
                ft.TextButton(
                    action,
                    on_click=lambda _: self.page.run_task(
                        self._apply_block, source, blocked
                    ),
                ),
            ],
        ))

    async def _apply_block(self, source, currently_blocked):
        self.page.pop_dialog()
        try:
            if currently_blocked:
                await asyncio.to_thread(response.unblock_source, source)
            else:
                await asyncio.to_thread(response.block_source, source)
        except response.ResponseError as error:
            self._show_message("Firewall change failed", str(error), error=True)
            return

        message = (
            f"{source} is no longer blocked."
            if currently_blocked else
            f"Windows Firewall is now blocking inbound traffic from {source}."
        )
        self._show_message("Firewall updated", message)

    def _on_alert(self, alert):
        print(
            f"[SECURITY ALERT] {alert.alert_type} from {alert.source}: "
            f"{alert.description}"
        )
        self.store.submit_alert(alert)

    def _clear_alerts(self, e=None):
        self.security.reset()
        self.store.clear_pending_alerts()
        self._reset_security_panel()
        self.page.update()

    # ------------------------------------------------------------------
    # Capture callbacks
    # ------------------------------------------------------------------

    def _on_packet(self, packet_info, raw_packet):
        self.security.inspect(packet_info)
        self.store.submit_packet(packet_info, raw_packet)

    async def _show_capture_error(self, error):
        self._set_status("Capture error", str(error), "error")
        self._update_actions()
        self.page.update()

    def _on_capture_error(self, error):
        self.page.run_task(self._show_capture_error, error)

    def _set_setup_error(self, message):
        control = self.ui["setup_error"]
        control.value = message or ""
        control.visible = bool(message)

    def start_from_setup(self, e=None):
        """Validate the setup form; move to the live view only on success."""
        if not self.start_capture():
            return
        self.ui["body"].content = self.ui["capture_page"]
        self.page.update()

    async def _show_setup_page(self, e=None):
        if self.controller.is_running:
            await self.stop_capture()
        self._set_setup_error("")
        self._set_status(
            "Ready",
            "Choose an interface, then click Start capture.",
        )
        self._update_actions()
        self.ui["body"].content = self.ui["setup_page"]
        self.page.update()

    # ------------------------------------------------------------------
    # Open a saved capture
    # ------------------------------------------------------------------

    async def _open_pcap(self, e=None):
        if self.controller.is_running or self._stopping or self._loading:
            return

        try:
            files = await self.file_picker.pick_files(
                dialog_title="Open capture file",
                file_type=ft.FilePickerFileType.CUSTOM,
                allowed_extensions=["pcap", "pcapng", "cap"],
                allow_multiple=False,
            )
        except Exception as error:
            self._show_message("Open failed", str(error), error=True)
            return
        if not files:
            return

        path = files[0].path
        if not path:
            self._show_message(
                "Cannot open file",
                "The selected file has no local path.",
                error=True,
            )
            return
        if not is_supported_capture(path):
            self._show_message(
                "Unsupported file",
                "Choose a .pcap, .pcapng or .cap capture file.",
                error=True,
            )
            return

        await self._load_capture_file(path)

    async def _load_capture_file(self, path):
        name = Path(path).name
        self._loading = True
        self._loaded_filename = name
        self._set_status("Opening file", f"Reading {name}…", "busy")
        self.ui["capture_target"].value = name
        # Show the table straight away so packets appear as they are read.
        self.ui["body"].content = self.ui["capture_page"]
        self._update_actions()
        self.page.update()

        self._reset_loaded_state()

        try:
            # Reading and dissecting a file can take seconds; keep it off the
            # UI thread so the window keeps repainting while packets arrive.
            loaded, skipped = await asyncio.to_thread(
                read_capture,
                path,
                self._collect_loaded_packet,
                lambda: self.store.pending_count > MAX_PENDING_LOAD,
            )
        except Exception as error:
            self._loading = False
            self._set_status("Open failed", str(error), "error")
            self._update_actions()
            self.page.update()
            return False

        self._loading = False
        self.controller.packet_count = loaded

        # The reader outruns the flush loop, which renders only a slice per
        # tick; finish with a full sync so the table matches the file.
        self._process_pending()
        self.matching_count, visible = packet_view(
            self.store.packets, self.active_filter, MAX_DISPLAY_PACKETS
        )
        self._render_packet_list(visible)

        message = f"Loaded {loaded:,} packets from {name}"
        if skipped:
            message += f" · skipped {skipped:,} unreadable frames"
        self._set_status("File loaded", message)
        self._update_actions()
        self.page.update()
        return True

    def _reset_loaded_state(self):
        self.store.clear()
        self.security.reset()
        self._reset_security_panel()
        self.active_filter = ""
        self.matching_count = 0
        self.selected_packet_number = None
        self.ui["filter_field"].value = ""
        self.ui["filter_applied"].value = "Showing all captured packets"
        self.ui["packet_list"].controls.clear()
        self.ui["packet_list"].auto_scroll = True
        self.ui["follow_live_button"].disabled = True
        self.ui["capture_stats"].value = ""
        self.ui["capture_stats"].color = theme.MUTED
        self._clear_selection()
        self._update_empty_state()
        self._update_counts()

    def _collect_loaded_packet(self, packet_info, raw_packet):
        self.security.inspect(packet_info)
        self.store.submit_packet(packet_info, raw_packet)

    def start_capture(self, e=None):
        self._set_setup_error("")
        self._loaded_filename = None
        interface = self.selected_interface
        if not interface:
            message = "Choose a network interface first."
            self._set_status("Select an interface", message, "error")
            self._set_setup_error(message)
            self.page.update()
            return False

        bpf_filter = (
            self.ui["capture_filter_field"].value or ""
        ).strip() or None
        if bpf_filter:
            problem = validate_bpf(bpf_filter)
            if problem:
                message = f'"{bpf_filter}" is not valid BPF: {problem}'
                self._set_status(
                    "Invalid capture filter",
                    f"Fix the BPF expression: {problem}",
                    "error",
                )
                self._set_setup_error(message)
                self.page.update()
                return False

        try:
            self.controller.start(interface, bpf_filter=bpf_filter)
            if not self.controller.is_running:
                raise RuntimeError(
                    "Capture could not start. Check Npcap and permissions."
                )
            self.security.reset()
            self.store.clear_pending_alerts()
            self._reset_security_panel()
            self._reset_capture_stats()
            self._start_recording(interface, bpf_filter)
            self._set_status(
                "Capturing",
                f"Listening on {interface}"
                + (f" · filter: {bpf_filter}" if bpf_filter else ""),
                "live",
            )
            self.ui["capture_target"].value = (
                interface
                + (f" · filter: {bpf_filter}" if bpf_filter else "")
            )
        except Exception as error:
            self._set_status("Capture error", str(error), "error")
            self._set_setup_error(str(error))
            self._update_actions()
            self.page.update()
            return False
        self._update_actions()
        self.page.update()
        return True

    async def stop_capture(self, e=None):
        if self._stopping:
            return

        self._stopping = True
        self._set_status("Stopping", "Stopping capture…", "busy")
        self._update_actions()
        self.page.update()

        recorder = self.recorder
        self.recorder = None
        try:
            # Joining Scapy's capture thread and waiting for dumpcap can take
            # seconds. Keep that work off the UI thread so the window stays
            # responsive while it happens.
            await asyncio.to_thread(self.controller.stop)
            if recorder is not None:
                try:
                    await asyncio.to_thread(recorder.stop)
                    self._set_record_status(
                        f"Recording saved: {recorder.output_path}",
                        theme.SUCCESS,
                    )
                except Exception as error:
                    self._set_record_status(
                        f"Recording stop failed: {error}", theme.ERROR
                    )
            self._set_status(
                "Stopped", "Capture stopped. You can export or clear packets."
            )
        except Exception as error:
            self._set_status("Capture error", str(error), "error")
        finally:
            self._stopping = False
            # While capturing, the table renders a sample of bursts; once the
            # stream stops, show the true newest window so it matches counts
            # and what export will write.
            self.matching_count, visible = packet_view(
                self.store.packets, self.active_filter, MAX_DISPLAY_PACKETS
            )
            self._render_packet_list(visible)
            self._update_capture_stats()
            self._update_actions()
            self.page.update()

    async def _restart_capture(self, e=None):
        """Wireshark's restart: drop the packets, keep interface and filter."""
        if not self.controller.is_running or self._stopping:
            return
        await self.stop_capture()
        self._clear_packets()
        self.start_capture()

    # ------------------------------------------------------------------
    # Recording and capture statistics
    # ------------------------------------------------------------------

    def _reset_capture_stats(self):
        self.ui["capture_stats"].value = "Waiting for packets…"
        self.ui["capture_stats"].color = theme.MUTED

    def _start_recording(self, interface, bpf_filter):
        self.ui["record_status"].visible = False
        if not self.ui["record_checkbox"].value:
            self.recorder = None
            return

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        path = RECORDINGS_DIR / f"capture_{timestamp}.pcap"
        recorder = DumpcapRecorder(interface, str(path), bpf_filter)
        try:
            recorder.start()
        except Exception as error:
            self.recorder = None
            self.ui["record_status"].value = f"Recording failed: {error}"
            self.ui["record_status"].color = theme.ERROR
            self.ui["record_status"].visible = True
            return

        self.recorder = recorder
        suffix = f" · filter: {bpf_filter}" if bpf_filter else ""
        self.ui["record_status"].value = f"Recording to {path.name}{suffix}"
        self.ui["record_status"].color = theme.MUTED
        self.ui["record_status"].visible = True

    def _set_record_status(self, message, color):
        control = self.ui["record_status"]
        control.value = message
        control.color = color
        control.visible = True

    # ------------------------------------------------------------------
    # Filter / table actions
    # ------------------------------------------------------------------

    def _apply_display_filter(self, e=None):
        self.active_filter = (self.ui["filter_field"].value or "").strip()
        self.matching_count, visible = packet_view(
            self.store.packets, self.active_filter, MAX_DISPLAY_PACKETS
        )
        if self.selected_packet_number not in {
            packet.number for packet in visible
        }:
            self._clear_selection()
        self.ui["filter_applied"].value = (
            f"Active filter: {self.active_filter}"
            if self.active_filter else "Showing all captured packets"
        )
        self.ui["filter_applied"].tooltip = self.ui["filter_applied"].value
        self._render_packet_list(visible)
        self.page.update()

    def _clear_display_filter(self, e=None):
        self.ui["filter_field"].value = ""
        self._apply_display_filter()

    def _follow_live(self, e=None):
        self.ui["packet_list"].auto_scroll = True
        self.ui["follow_live_button"].disabled = True
        self.page.update()

    def _clear_packets(self, e=None):
        if self.controller.is_running:
            return
        self.store.clear()
        self.controller.packet_count = 0
        self.active_filter = ""
        self.matching_count = 0
        self.ui["filter_field"].value = ""
        self.ui["filter_applied"].value = "Showing all captured packets"
        self.ui["packet_list"].controls.clear()
        self.ui["packet_list"].auto_scroll = True
        self.ui["follow_live_button"].disabled = True
        self.ui["capture_stats"].value = ""
        self.ui["capture_stats"].color = theme.MUTED
        self._clear_selection()
        self._update_empty_state()
        self._update_counts()
        self._update_actions()
        self.page.update()

    # ------------------------------------------------------------------
    # Toolbar navigation: previous / next, find, zoom
    # ------------------------------------------------------------------

    def _on_packet_list_scroll(self, e):
        self._list_offset = e.pixels

    def _on_packet_list_resize(self, e):
        # Opening the find bar or an alert changes the height without any
        # scrolling, so the scroll event alone would leave it stale.
        self._list_height = e.height

    def _selected_row_index(self):
        for index, row in enumerate(self.ui["packet_list"].controls):
            if row.data["number"] == self.selected_packet_number:
                return index
        return None

    async def _select_row(self, index):
        rows = self.ui["packet_list"].controls
        self._show_packet_details(rows[index].data["packet"])
        await self._scroll_row_into_view(index)

    async def _scroll_row_into_view(self, index):
        height = row_height(self.zoom)
        top = index * height
        offset, viewport = self._list_offset, self._list_height
        if viewport is None:
            target = top
        elif top < offset:
            target = top
        elif top + height > offset + viewport:
            target = top + height - viewport
        else:
            return
        # Scroll events arrive throttled; record our own move immediately so
        # a quick second click does not work from the old position.
        self._list_offset = max(0, target)
        await self.ui["packet_list"].scroll_to(offset=self._list_offset)

    async def _go_to_packet(self, step):
        rows = self.ui["packet_list"].controls
        if not rows:
            return
        index = self._selected_row_index()
        if index is None:
            index = 0 if step > 0 else len(rows) - 1
        else:
            index = max(0, min(len(rows) - 1, index + step))
        await self._select_row(index)

    async def _previous_packet(self, e=None):
        await self._go_to_packet(-1)

    async def _next_packet(self, e=None):
        await self._go_to_packet(1)

    async def _toggle_find_bar(self, e=None):
        bar = self.ui["find_bar"]
        bar.visible = not bar.visible
        self.ui["find_result"].value = ""
        self.page.update()
        if bar.visible:
            await self.ui["find_field"].focus()

    async def _find_next(self, e=None):
        await self._find_packet(1)

    async def _find_previous(self, e=None):
        await self._find_packet(-1)

    async def _find_packet(self, step):
        """Search the table from the selected row, wrapping at either end."""
        text = (self.ui["find_field"].value or "").strip()
        result = self.ui["find_result"]
        rows = self.ui["packet_list"].controls
        result.color = theme.ERROR
        if not text:
            result.value = "Type something to find."
        elif not rows:
            result.value = "No packets in the table."
        else:
            start = self._selected_row_index()
            if start is None:
                start = -1 if step > 0 else len(rows)
            for distance in range(1, len(rows) + 1):
                index = (start + step * distance) % len(rows)
                packet_info = rows[index].data["packet"]
                if packet_contains(packet_info, text):
                    result.value = f"Found packet #{packet_info.number}"
                    result.color = theme.MUTED
                    await self._select_row(index)
                    return
            result.value = f"No match in the {len(rows):,} packets shown"
        self.page.update()

    def _zoom(self, direction):
        """Step the packet list zoom: +1 in, -1 out, 0 back to 100 %."""
        if direction == 0:
            level = 1.0
        else:
            index = ZOOM_LEVELS.index(self.zoom) + direction
            if not 0 <= index < len(ZOOM_LEVELS):
                return
            level = ZOOM_LEVELS[index]
        self.zoom = level
        self.ui["packet_list"].item_extent = row_height(level)
        apply_header_zoom(self.ui["packet_header"], level)
        for row in self.ui["packet_list"].controls:
            apply_row_zoom(row, level)
        self.ui["zoom_reset_button"].content = f"{round(level * 100)}%"
        self.ui["zoom_in_button"].disabled = level == ZOOM_LEVELS[-1]
        self.ui["zoom_out_button"].disabled = level == ZOOM_LEVELS[0]
        self.page.update()
        selected = self._selected_row_index()
        if selected is not None:
            self.page.run_task(self._scroll_row_into_view, selected)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    async def _export_packets(self, export_format):
        if (self.controller.is_running or self._saving
                or not self.store.packets):
            return

        try:
            file_path = await self.file_picker.save_file(
                dialog_title="Save captured packets",
                file_name=f"packets_export.{export_format}",
                allowed_extensions=[export_format],
            )
        except Exception as error:
            self._show_message("Save failed", str(error), error=True)
            return
        if not file_path:
            return

        if export_format == "csv":
            exporter, records = CSVExporter(), list(self.store.packets)
        else:
            exporter, records = PCAPExporter(), list(self.store.raw_packets)
        if not file_path.lower().endswith(f".{export_format}"):
            file_path += f".{export_format}"
        name = Path(file_path).name

        self._saving = True
        self._set_status(
            "Saving file", f"Writing {len(records):,} packets to {name}…",
            "busy",
        )
        self._update_actions()
        self.page.update()
        try:
            # Writing a large capture takes a while; off the UI thread the
            # window stays responsive and "Saving file" actually gets drawn.
            count = await asyncio.to_thread(exporter.export, records, file_path)
        except Exception as error:
            self._set_status("Save failed", str(error), "error")
            self._show_message("Export failed", str(error), error=True)
        else:
            self._set_status("File saved", f"Saved {count:,} packets to {name}")
            self._show_message(
                "Export complete", f"Saved {count:,} packets to:\n{file_path}"
            )
        finally:
            self._saving = False
            self._update_actions()
            self.page.update()
