
#!/usr/bin/env python3
"""
Network Traffic Analyzer

A command-line tool that passively analyzes IPv4 TCP, UDP, and ICMP packets.
It displays packet metadata such as source and destination IP addresses,
protocol, port numbers, packet size, and processing timestamp.

This tool does not intentionally modify or inject network packets.

Use only on networks and systems you own or are explicitly authorized
to monitor.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from typing import Any

try:
    from scapy.all import ICMP, IP, TCP, UDP, get_if_list, sniff
except ImportError:
    # Keep the program importable so it can display a helpful error message.
    ICMP = IP = TCP = UDP = None
    get_if_list = None
    sniff = None


# Scapy uses these BPF capture filters to select packets before analysis.
PROTOCOL_FILTERS = {
    "all": None,
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
}


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Passively analyze IPv4 TCP, UDP, and ICMP packet metadata."
        )
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture on, such as eth0, ens33, or lo.",
    )

    parser.add_argument(
        "-p",
        "--protocol",
        choices=tuple(PROTOCOL_FILTERS),
        default="all",
        help="Protocol to capture: all, tcp, udp, or icmp (default: all).",
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Maximum number of captured packets; 0 means unlimited.",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Display available network interfaces and exit.",
    )

    return parser


def packet_metadata(packet: Any) -> dict[str, Any] | None:
    """
    Extract metadata from a supported IPv4 TCP, UDP, or ICMP packet.

    Return a dictionary for supported packets or None for unsupported
    packets. Payload contents are not printed.
    """

    # Ignore packets that do not contain an IPv4 layer.
    if IP is None or IP not in packet:
        return None

    ip_layer = packet[IP]

    # TCP and UDP have port numbers; ICMP does not.
    source_port: int | str = "N/A"
    destination_port: int | str = "N/A"

    if TCP in packet:
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)

    elif UDP in packet:
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    elif ICMP in packet:
        protocol = "ICMP"

    else:
        # Ignore IPv4 packets using protocols outside this tool's scope.
        return None

    # This is the local processing time, not necessarily the original
    # hardware or network capture timestamp.
    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    return {
        "timestamp": timestamp,
        "protocol": protocol,
        "source_ip": str(ip_layer.src),
        "destination_ip": str(ip_layer.dst),
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": len(packet),
    }


def display_packet(metadata: dict[str, Any]) -> None:
    """Print extracted packet metadata in a readable format."""

    print("-" * 68)
    print(f"Timestamp   : {metadata['timestamp']}")
    print(f"Protocol    : {metadata['protocol']}")
    print(f"Source IP   : {metadata['source_ip']}")
    print(f"Destination : {metadata['destination_ip']}")
    print(f"Source Port : {metadata['source_port']}")
    print(f"Dest Port   : {metadata['destination_port']}")
    print(f"Packet Size : {metadata['packet_size']} bytes")


def analyze_packet(packet: Any) -> None:
    """
    Process each packet received by Scapy.

    Scapy calls this function through the sniff() prn callback.
    """

    metadata = packet_metadata(packet)

    if metadata is not None:
        display_packet(metadata)


def main(argv: list[str] | None = None) -> int:
    """Validate arguments and start packet capture."""

    parser = build_parser()
    args = parser.parse_args(argv)

    # A negative capture count is invalid.
    if args.count < 0:
        parser.error("--count must be zero or a positive integer.")

    # Check whether Scapy was successfully imported.
    if get_if_list is None or sniff is None:
        print(
            "Scapy is not installed. Install project dependencies with:\n"
            "python -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    # List interfaces without starting packet capture.
    if args.list_interfaces:
        try:
            interfaces = get_if_list()

            if not interfaces:
                print("No network interfaces were found.")
                return 0

            print("Available network interfaces:")
            for interface in interfaces:
                print(f"  {interface}")

            return 0

        except Exception as exc:
            print(
                f"Could not list network interfaces: {exc}",
                file=sys.stderr,
            )
            return 1

    # Validate the requested interface before starting capture.
    if args.interface:
        try:
            interfaces = get_if_list()
        except Exception as exc:
            print(
                f"Could not retrieve network interfaces: {exc}",
                file=sys.stderr,
            )
            return 1

        if args.interface not in interfaces:
            parser.error(
                f"Interface '{args.interface}' was not found. "
                "Run with --list-interfaces to view available interfaces."
            )

    capture_filter = PROTOCOL_FILTERS[args.protocol]

    print("=" * 68)
    print("NETWORK TRAFFIC ANALYZER")
    print("=" * 68)
    print(f"Interface    : {args.interface or 'Scapy default'}")
    print(f"Protocol     : {args.protocol.upper()}")
    print(
        f"Packet limit : "
        f"{args.count if args.count else 'Unlimited'}"
    )
    print("Press Ctrl+C to stop capture.")
    print("Monitor only networks you own or have permission to inspect.")
    print("=" * 68)

    try:
        sniff(
            iface=args.interface,
            filter=capture_filter,
            prn=analyze_packet,
            store=False,
            count=args.count,
        )

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    except PermissionError:
        print(
            "Permission denied. Packet capture may require elevated "
            "privileges on your operating system.",
            file=sys.stderr,
        )
        return 1

    except OSError as exc:
        print(f"Packet capture failed: {exc}", file=sys.stderr)
        print(
            "Check the network interface, capture permissions, and "
            "libpcap/Npcap installation.",
            file=sys.stderr,
        )
        return 1

    except Exception as exc:
        print(
            f"Unexpected packet capture error: {exc}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())