"""Send a short, bounded ICMP echo-request burst to test flood detection.

This is a detector test tool, not an attack tool: it only sends a limited
number of packets, caps the rate, and refuses public targets unless
``--allow-public`` is given.

Usage
    uv run python tools/icmp_flood_test.py
    uv run python tools/icmp_flood_test.py --target 192.168.1.1 --count 80 --rate 40
"""

import argparse
import ipaddress
import sys

from scapy.all import ICMP, IP, Raw, conf, send

MAX_COUNT = 5000
MAX_RATE = 500.0


def auto_target():
    """Use the default gateway: reachable from this machine, always on-LAN."""
    try:
        gateway = conf.route.route("0.0.0.0")[2]
    except Exception:
        return ""
    return "" if gateway in ("0.0.0.0", "::") else gateway


def is_lan(address):
    ip = ipaddress.ip_address(address)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def main():
    parser = argparse.ArgumentParser(
        description="Send a bounded ICMP echo-request burst (ICMP flood test)."
    )
    parser.add_argument("--target", default=auto_target(),
                        help="destination IPv4 address (default: gateway)")
    parser.add_argument("--count", type=int, default=80,
                        help="number of echo requests to send (default 80)")
    parser.add_argument("--rate", type=float, default=40.0,
                        help="packets per second (default 40)")
    parser.add_argument("--size", type=int, default=56,
                        help="ICMP payload size in bytes (default 56)")
    parser.add_argument("--allow-public", action="store_true",
                        help="allow a public destination (only test hosts you own)")
    args = parser.parse_args()

    if not args.target:
        print("No default gateway found. Pass --target explicitly.")
        return 1

    try:
        ip = ipaddress.ip_address(args.target)
    except ValueError:
        print(f"Invalid IP address: {args.target}")
        return 1

    if not is_lan(args.target) and not args.allow_public:
        print(f"{args.target} is a public address. Test only networks you own, "
              f"or pass --allow-public if you are sure.")
        return 1

    count = max(1, min(args.count, MAX_COUNT))
    rate = max(1.0, min(args.rate, MAX_RATE))
    payload = b"x" * max(0, args.size)

    print(f"Sending {count} ICMP echo requests to {ip} at ~{rate:.0f}/s")
    print("Start the sniffer capture first. The detector alerts at "
          "50 echo requests within 5 seconds.")

    try:
        send(
            IP(dst=str(ip)) / ICMP() / Raw(payload),
            count=count,
            inter=1.0 / rate,
            verbose=False,
        )
    except Exception as error:
        print(f"Could not send packets: {error}")
        print("Raw packet sending normally needs Npcap and Administrator rights.")
        return 1

    print("Done. An ICMP Flood alert should appear in the security alert panel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
