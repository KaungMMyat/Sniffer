"""Behavior checks for the live packet view without requiring Npcap."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import app
from models.packet_info import PacketInfo
from ui import theme
from ui.packet_table import create_packet_row, set_packet_row_selected
from utils.packet_view import packet_view


def packet(number, protocol="TCP"):
    return PacketInfo(
        number=number,
        time="12:00:00",
        source="192.168.1.10",
        destination="8.8.8.8",
        protocol=protocol,
        length=64,
        src_port="50000",
        dst_port="443",
    )


class FakePage:
    def __init__(self):
        self.window = SimpleNamespace()

    def add(self, control):
        self.view = control

    def update(self):
        pass

    def run_task(self, callback, *args):
        # Fake service calls complete immediately, so these coroutines can be
        # driven without opening a Windows event-loop socket in this sandbox.
        if callback.__name__ == "ui_flush_loop":
            return
        coroutine = callback(*args)
        try:
            coroutine.send(None)
        except StopIteration:
            pass


class FakeController:
    instance = None

    def __init__(self, packet_callback, error_callback):
        self.packet_callback = packet_callback
        self.error_callback = error_callback
        self.is_running = False
        self.packet_count = 0
        FakeController.instance = self

    def start(self, interface, bpf_filter=None):
        self.is_running = True

    def stop(self):
        self.is_running = False


class FakePreferences:
    stored = None

    async def get(self, key):
        return self.stored

    async def set(self, key, value):
        self.__class__.stored = value


class PacketViewTests(unittest.TestCase):
    def setUp(self):
        FakePreferences.stored = None

    def test_row_hover_and_selection_states(self):
        row = create_packet_row(packet(1), lambda _: None)
        with patch.object(row, "update"):
            row.on_hover(SimpleNamespace(data=True))
            self.assertEqual(row.bgcolor, theme.ROW_HOVER)
            row.on_hover(SimpleNamespace(data=False))
            self.assertEqual(row.bgcolor, theme.SURFACE)

        set_packet_row_selected(row, True)
        self.assertEqual(row.bgcolor, theme.ACCENT_SOFT)
        self.assertEqual(row.border.left.color, theme.ACCENT)

    def test_filter_and_visible_limit(self):
        packets = [packet(i) for i in range(1, 503)] + [packet(503, "UDP")]
        count, visible = packet_view(packets, "tcp", limit=500)
        self.assertEqual(count, 502)
        self.assertEqual(len(visible), 500)
        self.assertEqual(visible[0].number, 3)
        self.assertEqual(visible[-1].number, 502)

    def test_live_filter_counts_and_selection(self):
        with patch.object(app, "get_interfaces", return_value=[
            {"name": "test0", "description": "Test adapter"}
        ]), patch.object(app, "CaptureController", FakeController), \
                patch.object(app.ft, "SharedPreferences", FakePreferences):
            ui = app.main(FakePage())

        ui["start_button"].on_click(None)
        self.assertEqual(ui["status_text"].value, "Capturing")
        self.assertTrue(ui["capture_activity"].visible)
        self.assertFalse(ui["packet_details"]["content"].visible)
        FakeController.instance.packet_callback(packet(1), object())
        ui["_flush_pending"]()
        ui["filter_field"].value = "tcp"
        ui["apply_filter_button"].on_click(None)
        FakeController.instance.packet_callback(packet(2, "UDP"), object())
        FakeController.instance.packet_callback(packet(3), object())
        ui["_flush_pending"]()

        self.assertEqual(len(ui["packet_list"].controls), 2)
        self.assertEqual(ui["packet_capture"].value,
                         "3 captured · 2 matching · 2 visible")
        selected_row = ui["packet_list"].controls[0]
        selected_row.on_click(None)
        self.assertEqual(ui["packet_details"]["title"].value,
                         "Selected packet #1")
        self.assertIs(ui["packet_list"].controls[0], selected_row)
        self.assertEqual(selected_row.bgcolor, theme.ACCENT_SOFT)
        self.assertFalse(ui["packet_list"].auto_scroll)
        self.assertTrue(ui["packet_details"]["content"].visible)

        ui["clear_filter_button"].on_click(None)
        self.assertEqual(ui["packet_capture"].value,
                         "3 captured · 3 matching · 3 visible")
        ui["stop_button"].on_click(None)
        self.assertFalse(ui["capture_activity"].visible)
        self.assertFalse(ui["export_button"].disabled)
        ui["clear_button"].on_click(None)
        self.assertEqual(ui["packet_capture"].value,
                         "0 captured · 0 matching · 0 visible")
        self.assertEqual(ui["packet_details"]["title"].value,
                         "No packet selected")
        self.assertFalse(ui["packet_details"]["content"].visible)

    def test_alert_area_expands_only_when_needed(self):
        with patch.object(app, "get_interfaces", return_value=[
            {"name": "test0", "description": "Test adapter"}
        ]), patch.object(app, "CaptureController", FakeController), \
                patch.object(app.ft, "SharedPreferences", FakePreferences):
            ui = app.main(FakePage())

        panel = ui["alert_panel"]
        self.assertTrue(panel["empty_text"].visible)
        self.assertFalse(panel["banner"].visible)
        self.assertFalse(panel["alert_list"].visible)
        self.assertFalse(panel["clear_button"].visible)

        ui["start_button"].on_click(None)
        for number, port in enumerate(range(1000, 1015), start=1):
            probe = packet(number)
            probe.tcp_flags = "S"
            probe.dst_port = str(port)
            FakeController.instance.packet_callback(probe, object())
        ui["_flush_pending"]()

        self.assertEqual(panel["alert_count"].value, "1")
        self.assertTrue(panel["banner"].visible)
        self.assertTrue(panel["alert_list"].visible)
        self.assertTrue(panel["clear_button"].visible)
        self.assertFalse(panel["empty_text"].visible)

        panel["clear_button"].on_click(None)
        self.assertFalse(panel["banner"].visible)
        self.assertFalse(panel["alert_list"].visible)
        self.assertFalse(panel["clear_button"].visible)
        self.assertTrue(panel["empty_text"].visible)

    def test_theme_toggle_restores_preference_without_losing_packets(self):
        FakePreferences.stored = True
        page = FakePage()
        with patch.object(app, "get_interfaces", return_value=[
            {"name": "test0", "description": "Test adapter"}
        ]), patch.object(app, "CaptureController", FakeController), \
                patch.object(app.ft, "SharedPreferences", FakePreferences):
            ui = app.main(page)

        self.assertEqual(page.theme_mode, app.ft.ThemeMode.DARK)
        self.assertTrue(ui["theme_toggle"].value)
        self.assertEqual(ui["theme_toggle"].label, "Dark Mode")
        FakeController.instance.packet_callback(packet(1), object())
        ui["_flush_pending"]()

        ui["theme_toggle"].value = False
        page.run_task(
            ui["theme_toggle"].on_change,
            SimpleNamespace(control=ui["theme_toggle"]),
        )
        self.assertEqual(page.theme_mode, app.ft.ThemeMode.LIGHT)
        self.assertEqual(ui["theme_toggle"].label, "Light Mode")
        self.assertFalse(FakePreferences.stored)
        self.assertEqual(len(ui["packet_list"].controls), 1)


if __name__ == "__main__":
    unittest.main()
