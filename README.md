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
   or port. Examples: `tcp`, `http`, `tls`, `ssh`, `dhcp`, `8.8.8.8`, `443`.
   Press Enter or select **Apply**. **Clear filter** restores the full list.
4. Select a row to inspect its details. This pauses automatic scrolling; use
   **Follow live** to resume it.
5. Choose CSV or PCAP and select **Export**. CSV contains packet metadata;
   PCAP contains the original captured packets for tools such as Wireshark.

Use the mode switch in the top-right header to change appearance.
The choice is saved on this device for the next launch.

The table displays the latest 500 matching packets. The counters distinguish
the total captured packets, packets matching the display filter, and rows
currently visible. Export includes the complete capture, not only visible
rows.

## Recognised protocols

The parser decapsulates Ethernet, IPv4/IPv6, ARP, TCP, UDP, and ICMP, then
names the application protocol inside TCP/UDP payloads:

- HTTP (request line, path, Host header)
- TLS (Client Hello with SNI, encrypted application data)
- HTTPS/IMAPS/POP3S/SMTPS/LDAPS (TLS on their well-known ports)
- SSH (banner)
- DHCP (message type and client MAC)
- DNS (queried name)
- FTP, SMTP, Telnet, POP3, IMAP, SMB, MySQL, PostgreSQL, RDP, NTP, SNMP,
  SSDP, and QUIC

The table shows the application name (for example `TLS`) and the details pane
shows both the application protocol and its transport (`TLS` / `TCP`). The CSV
export includes a separate `app_protocol` column.

## Project structure

- `capture/`: interface discovery, Scapy capture, packet parsing (including
  application-protocol detection), controller
- `models/`: packet data contract
- `ui/`: Flet layout, packet rows, details, and visual tokens
- `utils/`: display filtering and visible packet selection
- `exporters/`: CSV and PCAP output
- `app.py`: application state and UI event handlers

## Manual checks

The app opens on a setup page. Choose an interface, optionally set a BPF
capture filter, then click **Next**. An invalid filter stays on the setup page
and shows the libpcap error.

```powershell
# Bounded ICMP burst on your own LAN to exercise the flood detector
uv run python tools/icmp_flood_test.py
```
