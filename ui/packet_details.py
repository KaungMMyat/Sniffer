import flet as ft

from ui import theme


def _detail(label, value):
    return ft.Row(
        spacing=8,
        controls=[
            ft.Text(label, width=112, size=12, color=theme.MUTED),
            value,
        ],
    )


def create_packet_details():
    fields = {
        name: ft.Text("—", size=12, color=theme.TEXT, selectable=True)
        for name in (
            "protocol", "source", "destination", "src_port", "dst_port",
            "mac_source", "mac_destination", "length", "info",
        )
    }
    title = ft.Text("No packet selected", size=14, weight=ft.FontWeight.W_600,
                    color=theme.TEXT)
    empty = ft.Text("Select a row above to inspect its details.",
                    size=12, color=theme.MUTED)
    content = ft.Column(
        visible=False,
        spacing=8,
        controls=[
            ft.Row(
                spacing=24,
                controls=[
                    ft.Column(
                        expand=True,
                        spacing=6,
                        controls=[
                            _detail("Protocol", fields["protocol"]),
                            _detail("Source", fields["source"]),
                            _detail("Destination", fields["destination"]),
                            _detail("Length", fields["length"]),
                        ],
                    ),
                    ft.Column(
                        expand=True,
                        spacing=6,
                        controls=[
                            _detail("Source port", fields["src_port"]),
                            _detail("Destination port", fields["dst_port"]),
                            _detail("Source MAC", fields["mac_source"]),
                            _detail("Destination MAC", fields["mac_destination"]),
                        ],
                    ),
                ],
            ),
            _detail("Info", fields["info"]),
        ],
    )

    view = ft.Container(
        bgcolor=theme.GLASS_SURFACE,
        blur=10,
        border=ft.Border.all(1, theme.GLASS_BORDER),
        border_radius=12,
        padding=16,
        animate_size=ft.Animation(
            theme.MOTION_STANDARD_MS, ft.AnimationCurve.EASE_OUT_CUBIC
        ),
        shadow=ft.BoxShadow(
            blur_radius=18,
            color="#1A163655",
            offset=ft.Offset(0, 5),
        ),
        content=ft.Column(
            spacing=12,
            controls=[title, empty, content],
        ),
    )
    return {"view": view, "title": title, "empty": empty,
            "content": content, **fields}
