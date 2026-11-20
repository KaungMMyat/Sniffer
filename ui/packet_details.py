import flet as ft

from capture.packet_details import decode_packet_details, plain_text
from ui import theme


def _node_control(node):
    text = f"{node.label}: {node.value}" if node.value else node.label
    label = ft.Text(text, size=11, color=theme.TEXT,
                    selectable=not node.children, no_wrap=False)
    if not node.children:
        return ft.Container(content=label, padding=ft.Padding.only(left=8, top=2, bottom=2))
    return ft.ExpansionTile(
        title=label,
        controls=[_node_control(child) for child in node.children],
        affinity=ft.TileAffinity.LEADING,
        expanded=False,
        maintain_state=True,
        min_tile_height=30,
        visual_density=ft.VisualDensity.COMPACT,
        tile_padding=ft.Padding.symmetric(horizontal=2),
        controls_padding=ft.Padding.only(left=12, bottom=4),
        expanded_cross_axis_alignment=ft.CrossAxisAlignment.STRETCH,
        icon_color=theme.ACCENT,
        collapsed_icon_color=theme.MUTED,
    )


def render_packet_details(details, packet_info):
    if packet_info is None:
        details["title"].value = "No packet selected"
        details["empty"].visible = True
        details["content"].visible = False
        details["content"].controls = []
        details["sections"] = []
        return
    sections = decode_packet_details(packet_info)
    protocol = getattr(packet_info, "app_protocol", "") or getattr(packet_info, "protocol", "")
    details["title"].value = plain_text(f"Selected packet #{packet_info.number} · {protocol}")
    details["empty"].visible = False
    details["content"].visible = True
    details["content"].controls = [_node_control(section) for section in sections]
    details["sections"] = sections


def create_packet_details():
    title = ft.Text("No packet selected", size=14, weight=ft.FontWeight.W_600,
                    color=theme.TEXT, selectable=True)
    empty = ft.Text("Select a row above to inspect its details.",
                    size=12, color=theme.MUTED)
    content = ft.Column(
        visible=False,
        spacing=0,
        expand=True,
        scroll=ft.ScrollMode.AUTO,
        horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        controls=[],
    )
    view = ft.Container(
        # Shares the bottom row equally with the security panel.
        expand=1,
        bgcolor=theme.GLASS_SURFACE,
        blur=10,
        border=ft.Border.all(1, theme.GLASS_BORDER),
        border_radius=10,
        padding=10,
        shadow=ft.BoxShadow(
            blur_radius=18,
            color="#1A163655",
            offset=ft.Offset(0, 5),
        ),
        content=ft.Column(
            spacing=8,
            expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            controls=[title, empty, content],
        ),
    )
    return {"view": view, "title": title, "empty": empty,
            "content": content, "sections": []}
