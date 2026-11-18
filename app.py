"""Packet Sniffer entry point.

All application behaviour lives in `core.application.SnifferApplication`;
this module only wires the app into Flet.
"""

import flet as ft

from core.application import SnifferApplication


def main(page: ft.Page):
    SnifferApplication(page).mount()


if __name__ == "__main__":
    ft.run(main)
