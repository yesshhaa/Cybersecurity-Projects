"""Decoder tests using hand-built packets (no capture privileges or Scapy needed)."""

import os
import socket
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sniffer  # noqa: E402

SRC4, DST4 = "192.168.1.10", "93.184.216.34"
SRC6, DST6 = "2001:db8::1", "2001:db8::2"


def ipv4(proto, payload, src=SRC4, dst=DST4, ttl=64, flags_frag=0x4000, total_len=None):
    total = 20 + len(payload) if total_len is None else total_len
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, flags_frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def ipv6(nxt, payload, src=SRC6, dst=DST6):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nxt, 64,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload


def tcp(sport, dport, flags, payload=b"", seq=1000, ack=0):
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(icmp_type, code, rest=b"\x00\x00\x00\x00", payload=b""):
    return struct.pack("!BBH", icmp_type, code, 0) + rest + payload


def ether(payload, ethertype=0x0800, vlan=None):
    hdr = bytes.fromhex("ffffffffffff") + bytes.fromhex("001122334455")
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan)
    return hdr + struct.pack("!H", ethertype) + payload


def args(**kw):
    base = dict(proto=None, host=None, port=None)
    base.update(kw)
    return SimpleNamespace(**base)


class DecodeTests(unittest.TestCase):
    def test_tcp_syn_over_ethernet(self):
        pkt = sniffer.decode(ether(ipv4(6, tcp(51544, 443, 0x02))), sniffer.LINK_ETHERNET, 0)
        self.assertEqual(pkt.eth["src"], "00:11:22:33:44:55")
        self.assertEqual(pkt.proto, "TCP")
        self.assertEqual((pkt.ip["src"], pkt.ip["dst"], pkt.ip["ttl"], pkt.ip["flags"]), (SRC4, DST4, 64, "DF"))
        self.assertEqual((pkt.l4["sport"], pkt.l4["dport"], pkt.l4["flags"]), (51544, 443, "S"))
        self.assertIn("192.168.1.10:51544 > 93.184.216.34:443  [S]", sniffer.summary(pkt))

    def test_tcp_payload_and_flags(self):
        pkt = sniffer.decode(ipv4(6, tcp(80, 50000, 0x18, b"HTTP/1.1 200 OK", ack=7)), sniffer.LINK_IP, 0)
        self.assertEqual(pkt.l4["flags"], "AP")
        self.assertEqual(pkt.payload, b"HTTP/1.1 200 OK")
        self.assertIn("HTTP/1.1 200 OK", sniffer.hexdump(pkt.payload))

    def test_vlan_tagged_udp(self):
        pkt = sniffer.decode(ether(ipv4(17, udp(5353, 53, b"q")), vlan=42), sniffer.LINK_ETHERNET, 0)
        self.assertEqual(pkt.eth["vlan"], "42")
        self.assertEqual((pkt.proto, pkt.l4["dport"], pkt.payload), ("UDP", 53, b"q"))

    def test_ethernet_trailer_padding_is_dropped(self):
        frame = ether(ipv4(17, udp(1, 2, b"x"))) + b"\x00" * 20  # min-frame padding
        pkt = sniffer.decode(frame, sniffer.LINK_ETHERNET, 0)
        self.assertEqual(pkt.payload, b"x")

    def test_icmp_echo(self):
        pkt = sniffer.decode(ipv4(1, icmp(8, 0, struct.pack("!HH", 7, 3), b"ping")), sniffer.LINK_IP, 0)
        self.assertEqual((pkt.l4["name"], pkt.l4["id"], pkt.l4["seq"]), ("echo-request", 7, 3))
        self.assertIn("echo-request id=7 seq=3", sniffer.summary(pkt))

    def test_icmp_port_unreachable_quotes_original(self):
        inner = ipv4(17, udp(40000, 33434), src=DST4, dst=SRC4)[:28]
        pkt = sniffer.decode(ipv4(1, icmp(3, 3, payload=inner)), sniffer.LINK_IP, 0)
        self.assertEqual(pkt.l4["reason"], "port")
        self.assertEqual(pkt.l4["orig"], f"{DST4}:40000 > {SRC4}:33434 UDP")

    def test_ipv6_udp_and_icmpv6(self):
        pkt = sniffer.decode(ipv6(17, udp(546, 547)), sniffer.LINK_IP, 0)
        self.assertIn("[2001:db8::1]:546 > [2001:db8::2]:547", sniffer.summary(pkt))
        pkt = sniffer.decode(ether(ipv6(58, icmp(128, 0, struct.pack("!HH", 1, 9))), 0x86DD),
                             sniffer.LINK_ETHERNET, 0)
        self.assertEqual((pkt.proto, pkt.l4["name"], pkt.l4["seq"]), ("ICMPv6", "echo-request", 9))

    def test_ipv6_extension_header_skipped(self):
        hop_by_hop = struct.pack("!BB", 6, 0) + b"\x00" * 6  # next=TCP, 8 bytes
        pkt = sniffer.decode(ipv6(0, hop_by_hop + tcp(1, 2, 0x10)), sniffer.LINK_IP, 0)
        self.assertEqual((pkt.proto, pkt.l4["flags"]), ("TCP", "A"))

    def test_tso_zero_total_length(self):
        pkt = sniffer.decode(ipv4(6, tcp(1, 2, 0x10, b"data"), total_len=0), sniffer.LINK_IP, 0)
        self.assertEqual(pkt.payload, b"data")

    def test_non_first_fragment_not_decoded_as_l4(self):
        pkt = sniffer.decode(ipv4(17, b"\xde\xad" * 8, flags_frag=0x2000 | 185), sniffer.LINK_IP, 0)
        self.assertIsNone(pkt.l4)
        self.assertEqual(pkt.note, "fragment offset=1480")

    def test_arp_and_truncated_do_not_raise(self):
        pkt = sniffer.decode(ether(b"\x00" * 28, 0x0806), sniffer.LINK_ETHERNET, 0)
        self.assertEqual(pkt.note, "ARP")
        pkt = sniffer.decode(ipv4(6, b"\x00\x50"), sniffer.LINK_IP, 0)
        self.assertTrue(pkt.note.startswith("truncated"))
        for junk in (b"", b"\x45", b"\xff" * 3):
            sniffer.decode(junk, sniffer.LINK_IP, 0)
            sniffer.decode(junk, sniffer.LINK_ETHERNET, 0)


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.tcp = sniffer.decode(ipv4(6, tcp(51544, 443, 0x02)), sniffer.LINK_IP, 0)
        self.icmp6 = sniffer.decode(ipv6(58, icmp(129, 0)), sniffer.LINK_IP, 0)

    def test_proto(self):
        self.assertTrue(sniffer.matches(self.tcp, args(proto=["tcp"])))
        self.assertFalse(sniffer.matches(self.tcp, args(proto=["udp", "icmp"])))
        self.assertTrue(sniffer.matches(self.icmp6, args(proto=["icmp"])))

    def test_host_and_port(self):
        self.assertTrue(sniffer.matches(self.tcp, args(host=DST4, port=443)))
        self.assertFalse(sniffer.matches(self.tcp, args(port=80)))
        self.assertFalse(sniffer.matches(self.icmp6, args(port=443)))


class PcapTests(unittest.TestCase):
    def test_roundtrip(self):
        packets = [ipv4(6, tcp(1, 2, 0x02)), ipv4(17, udp(3, 4, b"hi"))]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.pcap")
            w = sniffer.PcapWriter(path)
            for i, p in enumerate(packets):
                w.write(1700000000.25 + i, p)
            w.close()
            read = list(sniffer.read_pcap(path))
        self.assertEqual([r[0] for r in read], packets)
        self.assertEqual(read[0][1], sniffer.LINK_IP)
        self.assertAlmostEqual(read[1][2], 1700000001.25, places=5)


if __name__ == "__main__":
    unittest.main()
