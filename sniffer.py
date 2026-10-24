#!/usr/bin/env python3
"""Basic Network Sniffer: passive IPv4 TCP/UDP/ICMP packet metadata analyzer.

Use only on networks and systems you own or are explicitly authorized to monitor.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from typing import Any

try:
    from scapy.all import ICMP, IP, TCP, UDP, get_if_list, sniff
except ImportError:  # Friendly message if Scapy is not installed.
    ICMP = IP = TCP = UDP = None  # type: ignore[assignment]
    get_if_list = sniff = None  # type: ignore[assignment]


PROTOCOL_FILTERS = {
    "all": None,
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Passively inspect IPv4 TCP, UDP, and ICMP packet metadata."
    )
    parser.add_argument(
        "-i", "--interface",
        help="Interface to capture on (for example, eth0, ens33, or lo).",
    )
    parser.add_argument(
        "-p", "--protocol",
        choices=tuple(PROTOCOL_FILTERS),
        default="all",
        help="Protocol filter (default: all).",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Stop after this many captured packets; 0 means unlimited.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available interfaces and exit.",
    )
    return parser


def packet_metadata(packet: Any) -> dict[str, Any] | None:
    """Return relevant metadata for a supported IPv4 packet, or None."""
    if IP is None or IP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = None
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
        return None

    return {
        "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "protocol": protocol,
        "source_ip": str(ip_layer.src),
        "destination_ip": str(ip_layer.dst),
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_size": len(packet),
    }


def display_packet(metadata: dict[str, Any]) -> None:
    """Print packet metadata in a readable format."""
    print("-" * 68)
    print(f"Time        : {metadata['timestamp']}")
    print(f"Protocol    : {metadata['protocol']}")
    print(f"Source IP   : {metadata['source_ip']}")
    print(f"Destination : {metadata['destination_ip']}")
    print(f"Source Port : {metadata['source_port']}")
    print(f"Dest Port   : {metadata['destination_port']}")
    print(f"Packet Size : {metadata['packet_size']} bytes")


def analyze_packet(packet: Any) -> None:
    """Scapy callback: extract and print supported packet metadata."""
    metadata = packet_metadata(packet)
    if metadata is not None:
        display_packet(metadata)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.count < 0:
        parser.error("--count must be zero or a positive integer.")

    if get_if_list is None or sniff is None:
        print(
            "Scapy is not installed. Install it with: sudo apt install python3-scapy",
            file=sys.stderr,
        )
        return 2

    if args.list_interfaces:
        try:
            for interface in get_if_list():
                print(interface)
            return 0
        except Exception as exc:
            print(f"Could not list interfaces: {exc}", file=sys.stderr)
            return 1

    if args.interface and args.interface not in get_if_list():
        parser.error(
            f"Interface '{args.interface}' was not found. "
            "Run with --list-interfaces to see available interfaces."
        )

    capture_filter = PROTOCOL_FILTERS[args.protocol]
    print("=" * 68)
    print("BASIC NETWORK SNIFFER")
    print("=" * 68)
    print(f"Interface   : {args.interface or 'Scapy default'}")
    print(f"Protocol    : {args.protocol.upper()}")
    print(f"Packet limit: {args.count if args.count else 'Unlimited'}")
    print("Press Ctrl+C to stop. Capture only authorized traffic.")
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
        print("Permission denied. On Linux, packet capture may require sudo.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        print(
            "Check the interface, capture permissions, and libpcap/BPF support.",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(f"Unexpected capture error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
