"""Prepare the visible packet window without discarding captured data."""

from utils.packet_filter import matches_filter


def packet_view(packets, filter_text, limit=500):
    matching = [packet for packet in packets if matches_filter(packet, filter_text)]
    return len(matching), matching[-limit:]
