"""Shared rounded surface used by the start and live pages."""

import flet as ft

from ui import theme


def create_panel(content, expand=False, glass=True):
    return ft.Container(
        bgcolor=theme.GLASS_SURFACE if glass else theme.SURFACE,
        blur=10 if glass else None,
        border=ft.Border.all(
            1, theme.GLASS_BORDER if glass else theme.BORDER
        ),
        border_radius=10,
        padding=10,
        expand=expand,
        shadow=(
            ft.BoxShadow(
                blur_radius=18,
                color="#1A163655",
                offset=ft.Offset(0, 5),
            ) if glass else None
        ),
        content=content,
    )
