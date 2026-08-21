import flet as ft


def create_packet_details():

    protocol = ft.Text("-")
    source = ft.Text("-")
    destination = ft.Text("-")

    src_port = ft.Text("-")
    dst_port = ft.Text("-")

    mac_source = ft.Text("-")
    mac_destination = ft.Text("-")

    length = ft.Text("-")
    info = ft.Text("-")

    details_view = ft.Column(
        controls=[
            ft.Text(
                "Packet Details",
                size=18,
                weight=ft.FontWeight.BOLD,
            ),
            ft.Divider(),
            ft.Row(
                controls=[
                    ft.Text("Protocol", width=140),
                    protocol,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Source", width=140),
                    source,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Destination", width=140),
                    destination,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Source Port", width=140),
                    src_port,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Destination Port", width=140),
                    dst_port,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Source MAC", width=140),
                    mac_source,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Destination MAC", width=140),
                    mac_destination,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Length", width=140),
                    length,
                ]
            ),
            ft.Row(
                controls=[
                    ft.Text("Info", width=140),
                    info,
                ]
            ),
        ]
    )

    return {
        "view": details_view,
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "src_port": src_port,
        "dst_port": dst_port,
        "mac_source": mac_source,
        "mac_destination": mac_destination,
        "length": length,
        "info": info,
    }
