import flet as ft
from utils.packet_color import get_packet_color


def create_packet_row(packet_info, on_click):

    row_color = get_packet_color(packet_info.protocol)

    return ft.Container(
        bgcolor=row_color,
        content=ft.Row(
            controls=[
                ft.Text(str(packet_info.number), width=50),
                ft.Text(packet_info.time, width=120),
                ft.Text(packet_info.source, width=150),
                ft.Text(packet_info.destination, width=150),
                ft.Text(packet_info.protocol, width=80),
                ft.Text(str(packet_info.length), width=80),
            ],
            spacing=10,
        ),
        on_click=lambda e: on_click(packet_info),
    )
