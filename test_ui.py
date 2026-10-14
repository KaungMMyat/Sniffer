"""Behavior checks for the live packet view without requiring Npcap."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import app
from models.packet_info import PacketInfo
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
        # These app callbacks do not await I/O; drive them without opening a
        # Windows event-loop socket in the test environment.
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


class PacketViewTests(unittest.TestCase):
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
        ]), patch.object(app, "CaptureController", FakeController):
            ui = app.main(FakePage())

        ui["start_button"].on_click(None)
        self.assertEqual(ui["status_text"].value, "Capturing")
        FakeController.instance.packet_callback(packet(1), object())
        ui["filter_field"].value = "tcp"
        ui["apply_filter_button"].on_click(None)
        FakeController.instance.packet_callback(packet(2, "UDP"), object())
        FakeController.instance.packet_callback(packet(3), object())

        self.assertEqual(len(ui["packet_list"].controls), 2)
        self.assertEqual(ui["packet_capture"].value,
                         "3 captured · 2 matching · 2 visible")
        ui["packet_list"].controls[0].on_click(None)
        self.assertEqual(ui["packet_details"]["title"].value,
                         "Selected packet #1")
        self.assertFalse(ui["packet_list"].auto_scroll)

        ui["clear_filter_button"].on_click(None)
        self.assertEqual(ui["packet_capture"].value,
                         "3 captured · 3 matching · 3 visible")
        ui["stop_button"].on_click(None)
        self.assertFalse(ui["export_button"].disabled)
        ui["clear_button"].on_click(None)
        self.assertEqual(ui["packet_capture"].value,
                         "0 captured · 0 matching · 0 visible")
        self.assertEqual(ui["packet_details"]["title"].value,
                         "No packet selected")


if __name__ == "__main__":
    unittest.main()
