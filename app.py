import flet as ft

from capture.controller import CaptureController
from capture.interfaces import get_interfaces
from ui.main_view import create_main_view
from ui.packet_table import create_packet_row
from utils.packet_filter import matches_filter


def main(page: ft.Page):

    page.title = "Python Packet Sniffer"

    page.window.width = 1000
    page.window.height = 900
    page.padding = 20
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    MAX_DISPLAY_PACKETS = 500

    interfaces = get_interfaces()

    ui = None
    capture_packets = []  # store captured packets for later inspection
    # -------------------------------------------------------

    def show_packet_details(packet_info):

        details = ui["packet_details"]

        details["protocol"].value = packet_info.protocol

        details["source"].value = packet_info.source

        details["destination"].value = packet_info.destination

        details["src_port"].value = packet_info.src_port

        details["dst_port"].value = packet_info.dst_port

        details["mac_source"].value = packet_info.mac_source

        details["mac_destination"].value = packet_info.mac_destination

        details["length"].value = str(packet_info.length)

        details["info"].value = packet_info.info

        page.update()

    # -------------------------------------------------------

    async def add_packet_to_table(packet_info):

        capture_packets.append(packet_info)  # save packet information

        if len(ui["packet_list"].controls) >= MAX_DISPLAY_PACKETS:
            ui["packet_list"].controls.pop(0)

        ui["packet_list"].controls.append(
            create_packet_row(packet_info, show_packet_details)
        )

        ui["packet_capture"].value = f"Packets Captured: {packet_info.number}"

        page.update()

    # -------------------------------------------------------
    def apply_display_filter(e=None):

        filter_text = ui["filter_field"].value or ""

        ui["packet_list"].controls.clear()  #  clear the current displayed packets

        if not filter_text.strip():
            packets_to_show = capture_packets
        else:
            packets_to_show = [
                packet
                for packet in capture_packets
                if matches_filter(packet, filter_text)
            ]

        for packet_info in packets_to_show:
            ui["packet_list"].controls.append(
                create_packet_row(packet_info, show_packet_details)
            )

        ui["packet_capture"].value = (
            f"Packets Captured: {len(packets_to_show)} | "
            f"Showing: {len(packets_to_show)}"
        )

        page.update()

    # -------------------------------------------------------
    def clear_packets(e=None):

        capture_packets.clear()  # clear the stored packets

        ui["packet_list"].controls.clear()  # clear the displayed packets

        ui["packet_capture"].value = "Packets Captured: 0"  # reset the counter text

        ui["filter_field"].value = ""  # clear the filter field

        details = ui["packet_details"]
        details["protocol"].value = "-"
        details["source"].value = "-"
        details["destination"].value = "-"
        details["src_port"].value = "-"
        details["dst_port"].value = "-"
        details["mac_source"].value = "-"
        details["mac_destination"].value = "-"
        details["length"].value = "-"
        details["info"].value = "-"

        page.update()

    def packet_received(packet_info):
        # print(packet_info.protocol)
        page.run_task(add_packet_to_table, packet_info)

    # -------------------------------------------------------

    def start_capture(e):

        interface = ui["interface_dropdown"].value

        if not interface:
            print("Select interface first")
            return

        bpf_filter = ui["capture_filter_field"].value or None
        if bpf_filter:
            bpf_filter = bpf_filter.strip()
        else:
            bpf_filter = None

        # Start capture through controller
        controller.start(interface, bpf_filter=bpf_filter)

        ui["start_button"].disabled = True
        ui["stop_button"].disabled = False

        if bpf_filter:
            print(f"Capture started on {interface} with filter: {bpf_filter}")
        else:
            print(f"Capture started on {interface} with no filter")
        page.update()

        print("Capture started")

    # -------------------------------------------------------

    def stop_capture(e):

        # Stop capture through controller
        controller.stop()

        ui["start_button"].disabled = False
        ui["stop_button"].disabled = True

        page.update()

        print("Capture stopped")

    # -------------------------------------------------------

    def capture_error(error):

        print(f"Capture Error: {error}")

    # -------------------------------------------------------

    controller = CaptureController(packet_received)

    ui = create_main_view(  # 1. main_view ကနေပြီး UI ကိုယူလိုက်ပြီ
        interfaces,
        start_capture,  # main_view စီကို app.py  ထဲက start/stop capture function passing ပေးလိုက်ပြီ
        stop_capture,
    )
    # Connect the Apply Filter button
    ui["apply_filter_button"].on_click = apply_display_filter
    ui["clear_button"].on_click = clear_packets

    page.add(ui["view"])


ft.run(main)
