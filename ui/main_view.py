import flet as ft

from ui.packet_details import create_packet_details
from ui.packet_table import create_packet_row


def create_main_view(
    interfaces,
    start_capture,
    stop_capture,
):

    interface_dropdown = ft.Dropdown(
        label="Select Network Interface",
        width=300,
        options=[
            ft.dropdown.Option(key=interface["name"], text=interface["name"])
            for interface in interfaces
        ],
    )

    if interfaces:
        interface_dropdown.value = interfaces[0]["name"]

    start_button = ft.Button(
        "Start Capture",
        on_click=start_capture,
    )

    stop_button = ft.Button(
        "Stop Capture",
        on_click=stop_capture,
        disabled=True,
    )

    filter_field = ft.TextField(
        label="Display Filter",
        hint_text="e.g., tcp, udp, ip.addr==",
        width=300,
        dense=True,
    )

    apply_filter_button = ft.Button(
        "Apply Filter",
    )

    clear_button = ft.Button(
        "Clear",
        bgcolor=ft.Colors.RED_400,
        color=ft.Colors.WHITE,
    )

    capture_filter_field = ft.TextField(
        label="Capture Filter (BPF Syntax)",
        hint_text="e.g., tcp, udp port 53, host 8.8.8.8, tcp port 443",
        width=300,
        dense=True,
    )

    packet_capture = ft.Text(
        "Packets Captured: 0",
        size=16,
    )

    packet_header = ft.Row(
        controls=[
            ft.Text("No", width=50),
            ft.Text("Time", width=120),
            ft.Text("Source", width=150),
            ft.Text("Destination", width=150),
            ft.Text("Protocol", width=80),
            ft.Text("Length", width=80),
        ],
        spacing=10,
    )

    packet_list = ft.ListView(
        expand=True,
        spacing=2,
        auto_scroll=True,
    )

    packet_details = create_packet_details()

    table_container = ft.Container(
        content=packet_list,
        expand=True,
    )

    layout = ft.Column(
        controls=[
            ft.Text(
                "Python Packet Sniffer",
                size=30,
            ),
            ft.Text(
                "Live Network Traffic Monitor",
                size=16,
            ),
            interface_dropdown,
            ft.Row(
                controls=[
                    start_button,
                    stop_button,
                    filter_field,
                    apply_filter_button,
                    clear_button,
                ],
                spacing=15,
                alignment=ft.MainAxisAlignment.CENTER,
                wrap=True,
            ),
            ft.Row(
                controls=[
                    capture_filter_field,
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            ft.Divider(),
            packet_capture,
            packet_header,
            ft.Divider(),
            table_container,
            ft.Divider(),
            packet_details["view"],
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        expand=True,
    )

    return {
        "view": layout,
        "interface_dropdown": interface_dropdown,
        "start_button": start_button,
        "stop_button": stop_button,
        "packet_capture": packet_capture,
        "packet_list": packet_list,
        "packet_details": packet_details,
        "filter_field": filter_field,
        "apply_filter_button": apply_filter_button,
        "clear_button": clear_button,
        "capture_filter_field": capture_filter_field,
    }
