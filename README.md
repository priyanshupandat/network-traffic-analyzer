
# Network Traffic Analyzer

A Python-based command-line tool for passive IPv4 network traffic analysis using Scapy. It captures packets on a selected network interface and displays metadata for TCP, UDP, and ICMP traffic.

This project demonstrates practical knowledge of Python, TCP/IP networking, packet analysis, Linux networking tools, and unit testing.

> **Authorized use only:** Capture traffic only on systems and networks you own or have explicit permission to monitor. Live packet capture may require elevated privileges.

## Features

- Live packet capture using Scapy
- IPv4 source and destination addresses
- TCP and UDP source and destination ports
- ICMP packet identification (ports displayed as `N/A`)
- Protocol filtering: `all`, `tcp`, `udp`, and `icmp`
- Network interface listing and selection
- Configurable packet-count limit
- Packet processing timestamp and packet size
- Unit tests using synthetic packets
- Error handling for missing dependencies, invalid interfaces, and capture failures

## Technologies

- **Language:** Python
- **Packet analysis:** Scapy
- **Networking:** IPv4, TCP, UDP, ICMP
- **Testing:** Python `unittest`
- **Platforms:** Windows with compatible packet-capture support; Kali Linux and other compatible Linux distributions

## Requirements

- Python 3.10 or newer
- Scapy
- Npcap on Windows or compatible packet-capture support on Linux
- Appropriate permissions for live packet capture

## Project Structure

```text
network-traffic-analyzer/
├── sniffer.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── tests/
│   └── test_sniffer.py
└── screenshots/
    └── README.md
```

## Installation

### Option 1: Kali Linux

Install Scapy using the distribution package manager:

```bash
sudo apt update
sudo apt install -y python3-scapy
```

Verify the installation:

```bash
python3 -c "from scapy.all import sniff; print('Scapy installed successfully')"
```

### Option 2: Python virtual environment

From the project directory:

```bash
sudo apt install -y python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Avoid using `sudo pip` or forcing packages into Kali's externally managed system Python.

### Option 3: Windows

Install Python and Npcap if required for packet capture. Open PowerShell in the project directory and run:

```powershell
py -m pip install -r requirements.txt
```

List the available interfaces:

```powershell
py sniffer.py --list-interfaces
```

Some Windows interfaces require elevated privileges or additional packet-capture configuration.

## Usage

Run commands from the project directory.

### Display help

Linux:

```bash
python3 sniffer.py --help
```

Windows:

```powershell
py sniffer.py --help
```

### List available interfaces

Linux:

```bash
sudo python3 sniffer.py --list-interfaces
```

Windows:

```powershell
py sniffer.py --list-interfaces
```

### Capture packets

Capture supported protocols on the default interface:

```bash
sudo python3 sniffer.py
```

Capture only a selected protocol:

```bash
sudo python3 sniffer.py --protocol tcp
sudo python3 sniffer.py --protocol udp
sudo python3 sniffer.py --protocol icmp
```

Capture up to 20 packets:

```bash
sudo python3 sniffer.py --count 20
```

Select a specific interface:

```bash
sudo python3 sniffer.py --interface eth0 --protocol tcp
```

Replace `eth0` with an exact interface name returned by `--list-interfaces`.

Press `Ctrl+C` to stop an unlimited capture.

## Example Output

The following output is illustrative and is not a claim of a verified live capture:

```text
====================================================================
NETWORK TRAFFIC ANALYZER
====================================================================
Interface    : lo
Protocol     : ICMP
Packet limit : Unlimited
Press Ctrl+C to stop capture.
Monitor only networks you own or have permission to inspect.
====================================================================
--------------------------------------------------------------------
Timestamp   : 2026-10-24T18:30:12+05:30
Protocol    : ICMP
Source IP   : 127.0.0.1
Destination : 127.0.0.1
Source Port : N/A
Dest Port   : N/A
Packet Size : 84 bytes
```

Actual timestamps, packet sizes, interfaces, and packet addresses depend on the capture environment.

## Safe Lab Testing

Perform packet-capture experiments only in an authorized lab.

### ICMP test on Linux

In terminal 1:

```bash
sudo python3 sniffer.py --interface lo --protocol icmp
```

In terminal 2:

```bash
ping -c 4 127.0.0.1
```

The loopback interface is used for local traffic. Depending on the operating system and capture backend, the number and representation of observed packets may vary.

### Generate ordinary network traffic

For a TCP test, use a suitable interface and make an ordinary HTTPS request:

```bash
curl --head https://example.com
```

For DNS traffic:

```bash
nslookup example.com
```

DNS commonly uses UDP but can also use TCP. Select the interface that can observe the generated traffic; traffic visibility depends on the network topology and capture configuration.

## Running Tests

Unit tests use synthetic packets and do not require root privileges or live network access.

```bash
python3 -m unittest discover -s tests -v
```

On Windows:

```powershell
py -m unittest discover -s tests -v
```

The current test suite covers packet metadata extraction, protocol handling, parser defaults, and invalid packet-count arguments.

## Architecture

1. **Argument parsing:** Reads the selected interface, protocol filter, and packet limit.
2. **Interface validation:** Checks the requested interface against the available interfaces.
3. **Packet capture:** Scapy captures packets using the selected interface and filter.
4. **Metadata extraction:** Identifies supported IPv4 TCP, UDP, and ICMP packets.
5. **Output:** Displays packet metadata without printing application payload contents.
6. **Testing:** Unit tests validate packet parsing and argument handling using synthetic inputs.

## Limitations

- Supports IPv4 TCP, UDP, and ICMP metadata only.
- Does not decrypt HTTPS/TLS traffic.
- Does not save PCAP files or inspect application payloads.
- Does not guarantee visibility into every packet on a network.
- Packet timestamps represent callback processing time, not necessarily hardware capture time.
- Capture filters depend on compatible packet-capture support.
- Live capture behavior depends on interface selection, permissions, and operating-system configuration.

## Troubleshooting

**Scapy is missing**

Install the project dependencies or use the appropriate operating-system package manager.

**Permission denied**

Use appropriate privileges for live packet capture on Linux or Windows.

**Interface not found**

Run `--list-interfaces` and copy the exact interface name.

**No packets appear**

Check the interface, protocol filter, permissions, and whether suitable test traffic is being generated.

**Capture-filter error**

Check the availability of Npcap, libpcap, or other compatible packet-capture support.

## Future Enhancements

- CSV or JSON metadata export
- Protocol counters and traffic summaries
- Time-based capture duration
- IPv6 support
- Optional PCAP export
- Graphical interface

## Resume Description

**Network Traffic Analyzer | Python, Scapy, TCP/IP**

- Developed a Python command-line tool to analyze IPv4 TCP, UDP, and ICMP packet metadata.
- Implemented protocol filtering, interface selection, packet-count limits, and structured packet output.
- Created unit tests using synthetic packets and documented authorized packet-capture testing procedures.

Only claim functionality and testing that you have personally verified.
