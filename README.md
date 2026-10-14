# Packet Sniffer

A Windows desktop network traffic viewer built with Python, Scapy, and Flet.
Select a network interface, capture packets, filter the displayed results,
inspect packet details, and export the capture as CSV or PCAP.

## Run

Install [Npcap](https://npcap.com/) and run the terminal as Administrator for
live packet capture. Then, from this directory:

```powershell
uv sync
uv run python app.py
```

If no interface appears, check that Npcap is installed and a physical network
adapter is available. The application currently targets Windows.

## Using the interface

1. Select a **Network interface**. Add an optional **Capture filter** using BPF
   syntax, such as `tcp` or `udp port 53`. This filter decides which packets
   are captured.
2. Select **Start capture**. The status indicator confirms when capture is
   running. Select **Stop** before exporting or clearing packets.
3. Use **Display filter** to search captured packets by protocol, IP address,
   or port. Examples: `tcp`, `8.8.8.8`, `443`. Press Enter or select **Apply**.
   **Clear filter** restores the full packet list.
4. Select a row to inspect its details. This pauses automatic scrolling; use
   **Follow live** to resume it.
5. Choose CSV or PCAP and select **Export**. CSV contains packet metadata;
   PCAP contains the original captured packets for tools such as Wireshark.

The table displays the latest 500 matching packets. The counters distinguish
the total captured packets, packets matching the display filter, and rows
currently visible. Export includes the complete capture, not only visible
rows.

## Project structure

- `capture/`: interface discovery, Scapy capture, packet parsing, controller
- `models/`: packet data contract
- `ui/`: Flet layout, packet rows, details, and visual tokens
- `utils/`: display filtering and visible packet selection
- `exporters/`: CSV and PCAP output
- `app.py`: application state and UI event handlers

## Checks

```powershell
uv run python -m unittest -v test_ui.py
uv run python test_exporters.py
```
