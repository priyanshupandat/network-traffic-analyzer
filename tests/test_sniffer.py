import unittest

from scapy.all import ICMP, IP, TCP, UDP, Raw

import sniffer


class PacketMetadataTests(unittest.TestCase):
    def test_tcp_metadata(self):
        packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
            sport=12345, dport=443
        ) / Raw(b"test")
        result = sniffer.packet_metadata(packet)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["source_ip"], "192.0.2.10")
        self.assertEqual(result["destination_ip"], "198.51.100.20")
        self.assertEqual(result["source_port"], 12345)
        self.assertEqual(result["destination_port"], 443)
        self.assertEqual(result["packet_size"], len(packet))

    def test_udp_metadata(self):
        packet = IP(src="192.0.2.1", dst="192.0.2.2") / UDP(
            sport=53000, dport=53
        )
        result = sniffer.packet_metadata(packet)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["protocol"], "UDP")
        self.assertEqual(result["source_port"], 53000)
        self.assertEqual(result["destination_port"], 53)

    def test_icmp_has_no_ports(self):
        packet = IP(src="127.0.0.1", dst="127.0.0.1") / ICMP()
        result = sniffer.packet_metadata(packet)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["protocol"], "ICMP")
        self.assertEqual(result["source_port"], "N/A")
        self.assertEqual(result["destination_port"], "N/A")

    def test_non_ipv4_packet_is_ignored(self):
        packet = TCP(sport=1234, dport=80)
        self.assertIsNone(sniffer.packet_metadata(packet))

    def test_unsupported_ipv4_protocol_is_ignored(self):
        packet = IP(src="192.0.2.1", dst="192.0.2.2") / Raw(b"unknown")
        self.assertIsNone(sniffer.packet_metadata(packet))

    def test_parser_defaults(self):
        args = sniffer.build_parser().parse_args([])
        self.assertEqual(args.protocol, "all")
        self.assertEqual(args.count, 0)
        self.assertIsNone(args.interface)

    def test_negative_count_is_rejected(self):
        with self.assertRaises(SystemExit):
            sniffer.main(["--count", "-1"])


if __name__ == "__main__":
    unittest.main()
