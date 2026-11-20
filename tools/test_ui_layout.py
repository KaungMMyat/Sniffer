"""Offline layout regressions; no Flet session, capture, or file dialogs."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import flet as ft

from core.application import SnifferApplication
from models.packet_info import PacketInfo
from ui import theme
from ui.packet_table import (
    BASE_ROW_HEIGHT,
    ZOOM_LEVELS,
    apply_header_zoom,
    apply_row_zoom,
    create_packet_header,
    create_packet_row,
    row_height,
    set_packet_row_selected,
    update_packet_row,
)
from ui.start_page import create_start_page


def packet_info(**overrides):
    values = dict(
        number=1, time="12:34:56", source="192.0.2.1",
        destination="198.51.100.2", protocol="TCP", length=64,
        info="Synthetic packet",
    )
    values.update(overrides)
    return PacketInfo(**values)


def interfaces(count):
    return [
        {"name": f"offline-{index}", "description": f"Test adapter {index}"}
        for index in range(count)
    ]


class ProtocolThemeTests(unittest.TestCase):
    def test_common_protocols_have_distinct_row_tints(self):
        protocols = ("TCP", "UDP", "DNS", "ICMP", "ARP", "HTTP", "TLS")
        for hovered in (False, True):
            with self.subTest(hovered=hovered):
                colors = [
                    theme.protocol_row_background(protocol, hovered)
                    for protocol in protocols
                ]
                self.assertEqual(len(set(colors)), len(protocols))
                self.assertNotIn(theme.SURFACE, colors)
                self.assertNotIn(theme.ROW_HOVER, colors)

    def test_known_tints_are_translucent_and_stronger_on_hover(self):
        # Shared colors for related protocols are intentional, not collisions.
        self.assertTrue(theme.PROTOCOL_ROW_COLORS)
        for protocol, color in theme.PROTOCOL_ROW_COLORS.items():
            with self.subTest(protocol=protocol):
                normal = theme.protocol_row_background(protocol)
                hovered = theme.protocol_row_background(protocol, hovered=True)
                self.assertEqual(normal, ft.Colors.with_opacity(0.20, color))
                self.assertEqual(hovered, ft.Colors.with_opacity(0.30, color))
                self.assertNotEqual(normal, hovered)
                self.assertNotEqual(normal, color)

    def test_unknown_protocols_use_neutral_theme_surfaces(self):
        for protocol in ("UNKNOWN", "", None):
            with self.subTest(protocol=protocol):
                self.assertEqual(
                    theme.protocol_row_background(protocol), theme.SURFACE
                )
                self.assertEqual(
                    theme.protocol_row_background(protocol, hovered=True),
                    theme.ROW_HOVER,
                )

    def test_badges_use_fixed_white_not_theme_dependent_text(self):
        self.assertEqual(theme.ON_COLOR, "#FFFFFF")
        self.assertNotEqual(theme.ON_COLOR, theme.TEXT)
        protocols = set(theme.PROTOCOL_STYLES) | set(theme.PROTOCOL_ROW_COLORS)
        for protocol in sorted(protocols | {"UNKNOWN"}):
            with self.subTest(protocol=protocol):
                background, foreground = theme.protocol_style(protocol)
                self.assertRegex(background, r"^#[0-9A-Fa-f]{6}$")
                self.assertEqual(foreground, theme.ON_COLOR)
                self.assertNotEqual(background, foreground)
                row = create_packet_row(packet_info(protocol=protocol), Mock())
                self.assertEqual(row.data["badge"].bgcolor, background)
                self.assertEqual(row.data["badge_text"].color, "#FFFFFF")
        self.assertEqual(theme.protocol_style("UNKNOWN"), ("#42566D", "#FFFFFF"))


class PacketRowLayoutTests(unittest.TestCase):
    def test_application_protocol_takes_precedence_over_transport(self):
        for transport, application in (
            ("TCP", "HTTP"), ("TCP", "TLS"), ("UDP", "DNS"), ("UDP", "QUIC"),
        ):
            with self.subTest(transport=transport, application=application):
                packet = packet_info(protocol=transport, app_protocol=application)
                self.assertEqual(packet.display_protocol, application)
                row = create_packet_row(packet, Mock())
                self.assertEqual(row.data["badge_text"].value, application)
                self.assertEqual(row.bgcolor, theme.protocol_row_background(application))
                self.assertNotEqual(row.bgcolor, theme.protocol_row_background(transport))
                self.assertEqual(row.data["badge"].bgcolor, theme.protocol_style(application)[0])

    def test_tint_covers_outer_row_not_just_badge_or_stripe(self):
        row = create_packet_row(packet_info(), Mock())
        self.assertEqual(row.bgcolor, theme.protocol_row_background("TCP"))
        self.assertIsNone(row.content.bgcolor)
        self.assertIsNone(row.data["protocol_slot"].bgcolor)
        self.assertIsInstance(row.content.content, ft.Row)
        self.assertEqual(len(row.content.content.controls), 7)
        self.assertEqual(row.border.left.color, theme.protocol_style("TCP")[0])
        self.assertNotEqual(row.bgcolor, row.data["badge"].bgcolor)

    def test_hover_and_selection_priority_and_restoration(self):
        for protocol in ("DNS", "UNKNOWN"):
            with self.subTest(protocol=protocol):
                row = create_packet_row(packet_info(protocol=protocol), Mock())
                normal = theme.protocol_row_background(protocol)
                hovered = theme.protocol_row_background(protocol, hovered=True)
                self.assertEqual(row.bgcolor, normal)
                # Unmounted controls cannot send updates to a Flet page.
                with patch.object(row, "update") as refresh:
                    row.on_hover(SimpleNamespace(data=True))
                    self.assertTrue(row.data["hovered"])
                    self.assertEqual(row.bgcolor, hovered)
                    set_packet_row_selected(row, True)
                    self.assertEqual(row.bgcolor, theme.ACCENT_SOFT)
                    self.assertEqual(row.border.left.color, theme.ACCENT)
                    for hovering in (False, True):
                        row.on_hover(SimpleNamespace(data=hovering))
                        self.assertEqual(row.bgcolor, theme.ACCENT_SOFT)
                    set_packet_row_selected(row, False)
                    self.assertEqual(row.bgcolor, hovered)
                    self.assertEqual(row.border.left.color, theme.protocol_style(protocol)[0])
                    row.on_hover(SimpleNamespace(data=False))
                    self.assertFalse(row.data["hovered"])
                    self.assertEqual(row.bgcolor, normal)
                    self.assertEqual(refresh.call_count, 4)

    def test_initial_selection_overrides_protocol_tint(self):
        row = create_packet_row(packet_info(app_protocol="HTTP"), Mock(), selected=True)
        self.assertTrue(row.data["selected"])
        self.assertEqual(row.bgcolor, theme.ACCENT_SOFT)
        self.assertEqual(row.border.left.color, theme.ACCENT)
        set_packet_row_selected(row, False)
        self.assertEqual(row.bgcolor, theme.protocol_row_background("HTTP"))

    def test_recycle_updates_content_colors_and_click_packet(self):
        for hovered in (False, True):
            for selected in (False, True):
                with self.subTest(hovered=hovered, selected=selected):
                    old = packet_info()
                    new = packet_info(
                        number=42, time="23:45:01", source="203.0.113.7",
                        destination="192.0.2.53", protocol="UDP", app_protocol="DNS",
                        length=128, info="Synthetic DNS query",
                    )
                    clicked = Mock()
                    row = create_packet_row(old, clicked, selected=not selected)
                    slots = tuple(row.content.content.controls)
                    badge = row.data["badge"]
                    row.on_tap_down(None)
                    clicked.assert_called_once_with(old)
                    clicked.reset_mock()
                    with patch.object(row, "update"):
                        row.on_hover(SimpleNamespace(data=hovered))
                    update_packet_row(row, new, selected=selected)
                    self.assertIs(row.data["packet"], new)
                    self.assertEqual(row.data["number"], 42)
                    self.assertEqual(row.data["selected"], selected)
                    self.assertEqual(row.data["hovered"], hovered)
                    for key, expected in (
                        ("number", "42"), ("time", "23:45:01"),
                        ("source", "203.0.113.7"), ("destination", "192.0.2.53"),
                        ("length", "128"), ("info", "Synthetic DNS query"),
                    ):
                        cell = row.data["cells"][key]
                        self.assertEqual(cell.value, expected)
                        self.assertEqual(cell.tooltip, expected)
                    self.assertIs(row.data["badge"], badge)
                    for before, after in zip(slots, row.content.content.controls):
                        self.assertIs(before, after)
                    self.assertEqual(row.data["badge_text"].value, "DNS")
                    self.assertEqual(row.data["badge_text"].color, theme.ON_COLOR)
                    self.assertEqual(badge.bgcolor, theme.protocol_style("DNS")[0])
                    self.assertEqual(row.data["protocol_color"], badge.bgcolor)
                    self.assertEqual(
                        row.bgcolor, theme.ACCENT_SOFT if selected else
                        theme.protocol_row_background("DNS", hovered),
                    )
                    self.assertEqual(
                        row.border.left.color, theme.ACCENT if selected else badge.bgcolor
                    )
                    row.on_tap_down(None)
                    clicked.assert_called_once_with(new)
                    self.assertIs(clicked.call_args.args[0], new)
                    self.assertEqual(row.height, 22)

    def test_recycle_to_unknown_clears_previous_tint_and_empty_content(self):
        row = create_packet_row(packet_info(app_protocol="TLS"), Mock())
        update_packet_row(row, packet_info(
            protocol="UNKNOWN", source="", destination="", info="",
        ))
        self.assertEqual(row.bgcolor, theme.SURFACE)
        self.assertEqual(row.data["badge_text"].value, "UNKNOWN")
        for key in ("source", "destination", "info"):
            self.assertEqual(row.data["cells"][key].value, "—")
            self.assertEqual(row.data["cells"][key].tooltip, "—")

    def test_zoom_keeps_22px_baseline_alignment_and_recycled_dimensions(self):
        self.assertEqual(BASE_ROW_HEIGHT, 22)
        self.assertEqual(ZOOM_LEVELS, (0.8, 0.9, 1.0, 1.1, 1.25, 1.4, 1.6))
        widths = (56, 72, 155, 155, 84, 56, None)
        header = create_packet_header()
        for zoom in ZOOM_LEVELS:
            with self.subTest(zoom=zoom):
                row = create_packet_row(packet_info(), Mock(), zoom=zoom)
                apply_header_zoom(header, zoom)
                self.assertEqual(row_height(zoom), round(22 * zoom))
                self.assertEqual(row.height, round(22 * zoom))
                slots = row.content.content.controls
                for slot, heading, width in zip(slots, header.data["headings"], widths):
                    expected = None if width is None else round(width * zoom)
                    self.assertEqual(slot.width, expected)
                    self.assertEqual(heading.width, expected)
                    self.assertEqual(heading.size, round(12 * zoom, 1))
                for cell in row.data["cells"].values():
                    self.assertEqual(cell.size, round(12 * zoom, 1))
                self.assertEqual(row.data["badge_text"].size, round(10.5 * zoom, 1))
                update_packet_row(row, packet_info(number=2, app_protocol="HTTP"))
                self.assertEqual(row.height, round(22 * zoom))
                self.assertEqual(row.data["protocol_slot"].width, round(84 * zoom))
                self.assertEqual(row.data["cells"]["source"].size, round(12 * zoom, 1))
                self.assertEqual(row.data["badge_text"].size, round(10.5 * zoom, 1))
                apply_row_zoom(row, 1.0)
                self.assertEqual(row.height, 22)
                self.assertEqual(row.data["cells"]["source"].width, 155)
                self.assertEqual(row.data["cells"]["source"].size, 12)


class StartPageLayoutTests(unittest.TestCase):
    def test_scrollable_setup_keeps_compact_file_strip_first_and_public_keys(self):
        ui = create_start_page(interfaces(1), "offline-0", Mock())
        self.assertEqual(set(ui), {
            "setup_page", "interface_rows", "capture_filter_field",
            "capture_filter_preset", "record_checkbox", "setup_start_button",
            "setup_open_button", "setup_error",
        })
        page = ui["setup_page"]
        self.assertIsInstance(page, ft.Column)
        self.assertEqual(page.scroll, ft.ScrollMode.AUTO)
        self.assertTrue(page.expand)
        self.assertEqual(len(page.controls), 2)
        files_card, capture_card = page.controls
        self.assertEqual((files_card.width, capture_card.width), (840, 840))
        self.assertFalse(files_card.expand)
        self.assertFalse(capture_card.expand)
        self.assertIsInstance(files_card.content, ft.Row)
        self.assertEqual(files_card.content.vertical_alignment, ft.CrossAxisAlignment.CENTER)
        icon, description, button = files_card.content.controls
        self.assertIsInstance(icon, ft.Icon)
        self.assertIsInstance(description, ft.Column)
        self.assertTrue(description.expand)
        self.assertEqual(description.controls[0].value, "Open a capture file")
        self.assertIs(button, ui["setup_open_button"])
        self.assertIsInstance(button, ft.OutlinedButton)
        self.assertEqual(button.content, "Open file…")
        self.assertEqual((button.width, button.height), (160, 36))
        self.assertEqual(files_card.padding.top, 12)
        self.assertEqual(files_card.padding.bottom, 12)
        self.assertIsInstance(capture_card.content, ft.Column)
        self.assertIs(capture_card.content.controls[1].controls[0], ui["interface_rows"][0])
        self.assertFalse(ui["setup_start_button"].disabled)

    def test_interface_list_is_bounded_without_dropping_large_lists(self):
        for count, expected_height in ((1, 54), (2, 112), (3, 170), (100, 228)):
            with self.subTest(count=count):
                selected = Mock()
                ui = create_start_page(interfaces(count), "offline-0", selected)
                capture_card = ui["setup_page"].controls[1]
                listing = capture_card.content.controls[1]
                self.assertIsInstance(listing, ft.ListView)
                self.assertEqual(listing.height, expected_height)
                self.assertLessEqual(listing.height, 228)
                self.assertEqual(len(listing.controls), count)
                self.assertEqual(len(ui["interface_rows"]), count)
                for listed, returned in zip(listing.controls, ui["interface_rows"]):
                    self.assertIs(listed, returned)
                self.assertTrue(listing.controls[0].data["selected"])
                self.assertEqual(listing.controls[-1].data["name"], f"offline-{count - 1}")
                listing.controls[-1].on_click(None)
                selected.assert_called_once_with(f"offline-{count - 1}")

    def test_no_interfaces_keeps_file_open_enabled_and_capture_disabled(self):
        ui = create_start_page([], None, Mock())
        self.assertEqual(ui["interface_rows"], [])
        self.assertTrue(ui["setup_start_button"].disabled)
        self.assertFalse(ui["setup_open_button"].disabled)
        self.assertTrue(ui["setup_open_button"].visible)
        files_card, capture_card = ui["setup_page"].controls
        self.assertIs(files_card.content.controls[-1], ui["setup_open_button"])
        empty = capture_card.content.controls[1]
        self.assertIsInstance(empty, ft.Container)
        self.assertIsInstance(empty.content, ft.Text)
        self.assertIn("No capture interface found", empty.content.value)


class ApplicationLayoutTests(unittest.TestCase):
    def test_page_title_without_starting_application(self):
        # Bypass __init__: no interface discovery, controller, or FilePicker.
        app = SnifferApplication.__new__(SnifferApplication)
        app.page = SimpleNamespace(title="Old title", window=SimpleNamespace())
        app._configure_page()
        self.assertEqual(app.page.title, "sniffX")

    def test_idle_action_refresh_without_interfaces_still_allows_file_open(self):
        app = SnifferApplication.__new__(SnifferApplication)
        app.controller = SimpleNamespace(is_running=False)
        app.store = SimpleNamespace(packets=[])
        app.selected_interface = None
        app._stopping = app._loading = app._saving = False
        app.ui = create_start_page([], None, Mock())
        for name in (
            "start_button", "stop_button", "restart_button", "open_button",
            "clear_button", "save_button", "find_button", "previous_button", "next_button",
        ):
            app.ui[name] = SimpleNamespace(disabled=False)
        app._update_actions()
        self.assertTrue(app.ui["setup_start_button"].disabled)
        self.assertTrue(app.ui["start_button"].disabled)
        self.assertFalse(app.ui["setup_open_button"].disabled)
        self.assertFalse(app.ui["open_button"].disabled)


if __name__ == "__main__":
    unittest.main()
