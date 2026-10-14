
import csv


def export_packets_to_csv(packets, file_path):
    """Export PacketInfo objects to a CSV file."""

    if not packets:
        raise ValueError("No packets available to export.")

    fieldnames = [
        "number",
        "time",
        "source",
        "destination",
        "protocol",
        "length",
        "mac_source",
        "mac_destination",
        "src_port",
        "dst_port",
        "info",
    ]

    with open(file_path, "w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for packet in packets:
            writer.writerow({
                "number": packet.number,
                "time": packet.time,
                "source": packet.source,
                "destination": packet.destination,
                "protocol": packet.protocol,
                "length": packet.length,
                "mac_source": packet.mac_source,
                "mac_destination": packet.mac_destination,
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
                "info": packet.info,
            })
            
    return len(packets)
