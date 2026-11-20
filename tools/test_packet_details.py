import random
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import flet as ft
from scapy.all import (
    ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Ether, ICMP, ICMPv6EchoRequest,
    IP, IPOption, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop,
    Padding, Raw, TCP, UDP, conf,
)
from scapy.layers.l2 import CookedLinux, Dot1Q, Loopback

from capture.packet_details import (
    MAX_ITEMS, MAX_LAYERS, MAX_NODES, MAX_PREVIEW_BYTES, MAX_TEXT,
    DetailNode, decode_packet_details, plain_text,
)
from ui.packet_details import create_packet_details, render_packet_details


SOURCE_MAC = "02:00:00:00:00:01"
DESTINATION_MAC = "02:00:00:00:00:02"


def ethernet():
    return Ether(src=SOURCE_MAC, dst=DESTINATION_MAC)


def ipv4(**kwargs):
    return IP(src="192.0.2.1", dst="198.51.100.2", **kwargs)


def ipv6(**kwargs):
    return IPv6(src="2001:db8::1", dst="2001:db8::2", **kwargs)


def packet_info(packet=None, **overrides):
    raw = bytes(packet) if packet is not None else b""
    values = dict(
        number=7, time="12:34:56", timestamp=1700000000.25,
        source="192.0.2.1", destination="198.51.100.2", protocol="TCP",
        app_protocol="", length=len(raw), mac_source=SOURCE_MAC,
        mac_destination=DESTINATION_MAC, src_port="12345", dst_port="443",
        tcp_flags="S", icmp_type=-1, info="Synthetic packet",
        raw_frame=raw, link_type=conf.l2types.layer2num.get(type(packet)),
        wire_length=len(raw), tcp_analysis=(), tcp_stream=None,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def walk(nodes):
    for node in nodes:
        yield node
        yield from walk(node.children)


def text_of(nodes):
    return "\n".join(f"{node.label}: {node.value}" for node in walk(nodes))


def section(nodes, label):
    return next(node for node in nodes if node.label == label)


def value_of(nodes, label):
    return next(node.value for node in walk(nodes) if node.label == label)


class DecoderTests(unittest.TestCase):
    def decode(self, packet, **overrides):
        return decode_packet_details(packet_info(packet, **overrides))

    def test_ethernet_ipv4_tcp_fields_flags_options_and_analysis(self):
        packet = ethernet() / ipv4(flags="DF", options=[IPOption(b"\x01")]) / TCP(
            sport=12345, dport=443, seq=4294967294, ack=123456789,
            flags="SA", window=4096, chksum=0, options=[("MSS", 1460), ("WScale", 7)],
        ) / Raw(b"hello")
        nodes = self.decode(packet, tcp_stream=0, tcp_analysis=("Possible retransmission",))
        tcp = section(nodes, "TCP")
        self.assertIn("Seq 4294967294 Ack 123456789", tcp.value)
        self.assertEqual(value_of(tcp.children, "Sequence number (absolute)"), "4294967294")
        self.assertEqual(value_of(tcp.children, "Acknowledgment number (absolute)"), "123456789")
        self.assertEqual(value_of(tcp.children, "Header length"), "28 bytes")
        self.assertEqual(value_of(tcp.children, "Window (raw, unscaled)"), "4096")
        self.assertEqual(value_of(tcp.children, "Payload length (captured)"), "5")
        self.assertEqual(value_of(tcp.children, "Checksum"), "0x0000 (not validated)")
        self.assertEqual(value_of(tcp.children, "SYN"), "Set")
        self.assertEqual(value_of(tcp.children, "FIN"), "Not set")
        self.assertEqual(value_of(tcp.children, "MSS"), "1460")
        self.assertEqual(value_of(tcp.children, "WScale"), "7")
        self.assertEqual(value_of(tcp.children, "Stream index"), "0")
        self.assertIn("not proof", text_of(tcp.children))
        self.assertIn("Possible retransmission", text_of(tcp.children))
        self.assertIn("Don't fragment: Set", text_of(section(nodes, "IPv4").children))
        self.assertIn(SOURCE_MAC, section(nodes, "Ethernet").value)
        self.assertNotIn("Decode error", text_of(nodes))

    def test_frame_lengths_timestamp_and_truncation(self):
        packet = ethernet() / ipv4() / TCP(sport=12345, dport=80)
        nodes = self.decode(packet, wire_length=len(bytes(packet)) + 40)
        frame = section(nodes, "Frame")
        self.assertIn("captured bytes", frame.value)
        self.assertEqual(value_of(frame.children, "Timestamp (epoch seconds)"), "1700000000.25")
        self.assertEqual(value_of(frame.children, "Truncated capture"), "40 wire bytes not captured.")
        self.assertIn("no IP fragment or TCP stream reassembly", text_of(nodes))

    def test_non_ethernet_link_types(self):
        for packet in (
            ipv4() / UDP(sport=10000, dport=10001),
            ipv6() / TCP(sport=10000, dport=10001),
            CookedLinux(proto=0x800) / ipv4() / ICMP(),
            Loopback(type=2) / ipv4() / UDP(sport=10000, dport=10001),
        ):
            with self.subTest(root=type(packet).__name__):
                nodes = self.decode(packet)
                labels = [node.label for node in nodes]
                self.assertNotIn("Ethernet", labels)
                self.assertTrue("IPv4" in labels or "IPv6" in labels)
                self.assertNotIn("Decode error", text_of(nodes))

    def test_registered_custom_link_decoder_is_used(self):
        decoder = Mock(side_effect=IP)
        packet = ipv4() / TCP(sport=10000, dport=10001)
        with patch.dict(conf.l2types.num2layer, {90001: decoder}):
            nodes = self.decode(packet, link_type=90001)
        decoder.assert_called_once_with(bytes(packet))
        self.assertIn("IPv4", [node.label for node in nodes])

    def test_unknown_or_missing_link_type_never_assumes_ethernet(self):
        for link_type in (None, -123456):
            nodes = self.decode(ethernet() / ipv4() / TCP(), link_type=link_type)
            self.assertIn("Ethernet is not assumed", text_of(nodes))
            self.assertNotIn("Ethernet", [node.label for node in nodes])
            self.assertIn("Frame preview", text_of(nodes))

    def test_empty_and_legacy_metadata(self):
        info = SimpleNamespace(number=1, time="00:00:00", protocol="TCP", length=42)
        nodes = decode_packet_details(info)
        self.assertIn("No captured frame bytes", text_of(nodes))
        self.assertEqual(value_of(nodes, "Reported length"), "42")
        self.assertEqual(value_of(nodes, "Wire length"), "Unknown")

    def test_arp(self):
        nodes = self.decode(ethernet() / ARP(
            op=1, hwsrc=SOURCE_MAC, hwdst="00:00:00:00:00:00", psrc="192.0.2.1", pdst="192.0.2.2",
        ))
        arp = section(nodes, "ARP")
        self.assertIn("who-has", arp.value)
        self.assertEqual(value_of(arp.children, "Sender IP"), "192.0.2.1")
        self.assertEqual(value_of(arp.children, "Target MAC"), "00:00:00:00:00:00")

    def test_ipv6_extension_header_udp(self):
        nodes = self.decode(ethernet() / ipv6() / IPv6ExtHdrHopByHop() / UDP(sport=101, dport=102))
        self.assertIn("2001:db8::1", section(nodes, "IPv6").value)
        self.assertTrue(any("Hop-by-Hop" in node.label for node in nodes))
        self.assertEqual(value_of(section(nodes, "UDP").children, "Datagram length"), "8")

    def test_vlan_preserves_inner_decoding(self):
        nodes = self.decode(ethernet() / Dot1Q(vlan=42) / ipv4() / UDP(sport=101, dport=102))
        self.assertEqual(value_of(nodes, "vlan"), "42")
        self.assertIn("UDP", [node.label for node in nodes])

    def test_icmp_and_icmpv6(self):
        for packet, label in (
            (ethernet() / ipv4() / ICMP(type=8, id=123, seq=456) / Raw(b"ping"), "ICMP"),
            (ethernet() / ipv6() / ICMPv6EchoRequest(id=123, seq=456, data=b"ping"), "ICMPv6"),
        ):
            with self.subTest(protocol=label):
                fields = section(self.decode(packet), label).children
                self.assertEqual(value_of(fields, "Identifier"), "123")
                self.assertEqual(value_of(fields, "Sequence"), "456")
                self.assertIn("not validated", value_of(fields, "Checksum"))

    def test_icmp_quote_does_not_inherit_stream_analysis(self):
        nodes = self.decode(ethernet() / ipv4() / ICMP(type=3, code=1) / ipv4() / TCP(),
                            tcp_stream=17, tcp_analysis=("Outer-frame observation",))
        tcp = section(nodes, "TCP")
        self.assertIn("Quoted inside an ICMP error", text_of(tcp.children))
        self.assertNotIn("Stream index", text_of(tcp.children))
        self.assertNotIn("Outer-frame observation", text_of(tcp.children))

    def test_dns_questions_answers_and_flags(self):
        packet = ethernet() / ipv4() / UDP(sport=53, dport=12345) / DNS(
            id=0x1234, qr=1, rd=1, ra=1,
            qd=DNSQR(qname="example.test", qtype="A"),
            an=[DNSRR(rrname="example.test", type="A", ttl=300, rdata="203.0.113.8"),
                DNSRR(rrname="example.test", type="AAAA", ttl=301, rdata="2001:db8::8")],
        )
        dns = section(self.decode(packet), "DNS")
        self.assertIn("Response 0x1234", dns.value)
        self.assertIn("example.test", dns.value)
        self.assertIn("2 declared · 2 decoded", value_of(dns.children, "Answers"))
        self.assertIn("203.0.113.8", text_of(dns.children))
        self.assertIn("2001:db8::8", text_of(dns.children))
        self.assertIn("ttl: 300", text_of(dns.children))
        self.assertEqual(value_of(dns.children, "Recursion available"), "1")

    def test_dns_tcp_and_query(self):
        dns = DNS(id=123, qd=DNSQR(qname="query.test"))
        nodes = self.decode(ethernet() / ipv4() / TCP(sport=12345, dport=53) / dns)
        self.assertIn("Query", section(nodes, "DNS").value)
        self.assertIn("query.test", text_of(nodes))

    def test_dhcp_options_and_bootp(self):
        packet = ethernet() / ipv4() / UDP(sport=68, dport=67) / BOOTP(
            xid=0x12345678, chaddr=bytes.fromhex("020000000001"), flags=0x8000,
        ) / DHCP(options=[("message-type", "discover"), ("hostname", b"test-client"),
                           ("param_req_list", [1, 3, 6]), "end"])
        nodes = self.decode(packet)
        self.assertIn("Discover", section(nodes, "DHCP").value)
        self.assertIn("hostname: b'test-client'", text_of(section(nodes, "DHCP").children))
        self.assertEqual(value_of(section(nodes, "BOOTP").children, "Broadcast"), "Set")
        self.assertIn("0x12345678", section(nodes, "BOOTP").value)

    def test_port_hint_does_not_invent_application_fields(self):
        for hint, port in (("DNS", 53), ("TLS", 443), ("DHCP", 67)):
            nodes = self.decode(ethernet() / ipv4() / TCP(sport=12345, dport=port) / Raw(b"garbage"),
                                app_protocol=hint)
            self.assertNotIn(hint, [node.label for node in nodes])
            self.assertNotIn("TLS record headers (inferred)", [node.label for node in nodes])
            self.assertEqual(value_of(nodes, "Application hint (not proof of decoding)"), hint)

    def test_tls_header_only_multiple_records(self):
        data = b"\x16\x03\x03\x00\x02\x01\x00\x17\x03\x03\x00\x03abc"
        nodes = self.decode(ethernet() / ipv4() / TCP(sport=12345, dport=443) / Raw(data))
        tls = section(nodes, "TLS record headers (inferred)")
        self.assertIn("Record 2", text_of(tls.children))
        self.assertIn("Legacy record version: 0x0303", text_of(tls.children))
        self.assertIn("not the negotiated TLS version", text_of(tls.children))
        self.assertIn("Encrypted application data; not decrypted", text_of(tls.children))
        self.assertNotIn("Client Hello", text_of(tls.children))

    def test_incomplete_tls_and_header_signature(self):
        for data in (b"\x17\x03\x03\x00\x20abc", b"\x17\x03\x03\x00\x00\x16"):
            nodes = self.decode(ethernet() / ipv4() / TCP(sport=12345, dport=443) / Raw(data))
            self.assertIn("Incomplete record", text_of(nodes))
            self.assertNotIn("Decode error", text_of(nodes))
        nodes = self.decode(ethernet() / ipv4() / TCP(sport=12345, dport=443) / Raw(b"\x17\x03\x03"))
        self.assertNotIn("TLS record headers (inferred)", [node.label for node in nodes])

    def test_padding_not_counted_as_transport_payload(self):
        for transport in (TCP(sport=101, dport=102), UDP(sport=101, dport=102)):
            nodes = self.decode(ethernet() / ipv4() / transport / Raw(b"abc") / Padding(b"padding"))
            self.assertEqual(value_of(section(nodes, type(transport).__name__).children,
                                      "Payload length (captured)"), "3")
            self.assertEqual(section(nodes, "Padding").value, "7 bytes")

    def test_truncated_and_malformed_frames(self):
        raw = bytes(ethernet() / ipv4() / TCP(sport=12345, dport=443) / Raw(b"hello"))
        for length in (1, 13, 15, 30, 35, 50, len(raw) - 1):
            with self.subTest(length=length):
                nodes = decode_packet_details(packet_info(raw_frame=raw[:length], link_type=1, wire_length=len(raw)))
                text = text_of(nodes)
                self.assertIn("Truncated capture", text)
                self.assertTrue("Decode error" in text or "Decode warning" in text or "Undissected data" in text)
        for packet in (ethernet() / ipv4(ihl=4) / TCP(),
                       ethernet() / ipv4() / TCP(dataofs=4),
                       ethernet() / ipv4() / UDP(len=4)):
            with self.subTest(packet=type(packet).__name__):
                self.assertIn("Decode warning", text_of(self.decode(packet)))

    def test_dns_record_count_mismatch_is_visible(self):
        nodes = self.decode(ethernet() / ipv4() / UDP(sport=53, dport=12345) / DNS(
            id=1, qr=1, ancount=2, an=DNSRR(rrname="x.test", rdata="203.0.113.1"),
        ))
        self.assertIn("Record count mismatch", text_of(nodes))

    def test_fragmented_application_is_not_decoded(self):
        for packet in (
            ethernet() / ipv4(flags="MF") / UDP(sport=53, dport=12345) / DNS(qd=DNSQR(qname="fragment.test")),
            ethernet() / ipv6() / IPv6ExtHdrFragment(m=1) / UDP(sport=53, dport=12345) / DNS(qd=DNSQR(qname="fragment.test")),
        ):
            nodes = self.decode(packet)
            self.assertIn("Fragment note", text_of(nodes))
            self.assertNotIn("DNS", [node.label for node in nodes])

    def test_bounded_records_payload_and_plain_serializable_nodes(self):
        records = [DNSRR(rrname=f"host{i}.test", type="A", rdata="203.0.113.1") for i in range(MAX_ITEMS + 20)]
        info = packet_info(ethernet() / ipv4() / UDP(sport=53, dport=12345) / DNS(qr=1, an=records))
        raw = info.raw_frame
        nodes = decode_packet_details(info)
        self.assertIs(info.raw_frame, raw)
        self.assertIn(f"Showing {MAX_ITEMS} of {len(records)}", text_of(nodes))
        for node in walk(nodes):
            self.assertIsInstance(node, DetailNode)
            self.assertIs(type(node.label), str)
            self.assertIs(type(node.value), str)
            self.assertLessEqual(len(node.label), MAX_TEXT)
            self.assertLessEqual(len(node.value), MAX_TEXT)
        self.assertLessEqual(len(list(walk(nodes))), MAX_NODES)
        payload = b"x" * 60000
        nodes = self.decode(ethernet() / ipv4() / TCP(sport=10000, dport=10001) / Raw(payload))
        self.assertIn("60000 bytes total", text_of(nodes))
        self.assertNotIn("x" * (MAX_PREVIEW_BYTES + 1), text_of(nodes))

    def test_global_field_and_layer_limits(self):
        records = [DNSRR(rrname=f"host{i}.test", rdata="203.0.113.1") for i in range(MAX_ITEMS)]
        nodes = self.decode(ethernet() / ipv4() / UDP(sport=53, dport=12345) / DNS(qr=1, an=records, ns=records, ar=records))
        self.assertLessEqual(len(list(walk(nodes))), MAX_NODES)
        self.assertIn("Additional fields omitted; full bytes remain in raw_frame", text_of(nodes))
        packet = ethernet()
        for _ in range(MAX_LAYERS + 4):
            packet /= ipv4()
        packet /= TCP(sport=101, dport=102)
        nodes = self.decode(packet)
        self.assertLessEqual(len(list(walk(nodes))), MAX_NODES)
        self.assertIn("Display limit", text_of(nodes))

    def test_deterministic_malformed_bytes_never_raise(self):
        rng = random.Random(2048)
        for link in (1, 101, 113, 0, 229):
            for size in (1, 8, 16, 40, 64, 128):
                with self.subTest(link=link, size=size):
                    nodes = decode_packet_details(packet_info(raw_frame=rng.randbytes(size), link_type=link))
                    self.assertTrue(nodes)
                    self.assertLessEqual(len(list(walk(nodes))), MAX_NODES)

    def test_control_characters_markup_and_analysis_limits(self):
        info = packet_info(ethernet() / ipv4() / TCP(sport=101, dport=102),
                           info="<script>alert(1)</script>\n\x00\u202e", tcp_analysis=("hint",) * 100)
        text = text_of(decode_packet_details(info))
        self.assertIn("<script>alert(1)</script>", text)
        self.assertIn("\\n\\x00\\u202e", text)
        self.assertNotIn("\x00", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("Additional analysis observations omitted", text)
        self.assertLessEqual(len(plain_text("\x00" * 10000)), MAX_TEXT)


class UITests(unittest.TestCase):
    def test_initial_layout_and_selection_only_decoding(self):
        with patch("ui.packet_details.decode_packet_details", wraps=decode_packet_details) as decode:
            details = create_packet_details()
            decode.assert_not_called()
            self.assertEqual(details["view"].expand, 1)
            self.assertFalse(details["content"].visible)
            self.assertEqual(details["content"].scroll, ft.ScrollMode.AUTO)
            self.assertEqual(details["sections"], [])
            info = packet_info(ethernet() / ipv4() / TCP(sport=12345, dport=443))
            render_packet_details(details, info)
            decode.assert_called_once_with(info)
        self.assertIn("#7", details["title"].value)
        self.assertTrue(details["content"].visible)
        self.assertFalse(details["empty"].visible)
        tiles = details["content"].controls
        self.assertIsInstance(tiles[0], ft.ExpansionTile)
        self.assertIn("captured bytes", tiles[0].title.value)
        self.assertFalse(tiles[0].expanded)
        self.assertTrue(tiles[0].maintain_state)
        self.assertEqual(tiles[0].affinity, ft.TileAffinity.LEADING)
        self.assertEqual(tiles[0].expanded_cross_axis_alignment, ft.CrossAxisAlignment.STRETCH)
        tiles[0].expanded = True
        self.assertTrue(tiles[0].expanded)

    def test_selectable_plain_wrapping_text_and_nested_tiles(self):
        details = create_packet_details()
        info = packet_info(ethernet() / ipv4() / TCP(sport=12345, dport=80, flags="SA"), info="<b>literal</b>")
        render_packet_details(details, info)
        nested_tiles = []

        def check(control, selectable=True):
            if isinstance(control, ft.Text):
                self.assertEqual(control.selectable, selectable)
                self.assertFalse(control.no_wrap)
                self.assertIsNone(control.width)
            elif isinstance(control, ft.ExpansionTile):
                nested_tiles.append(control)
                check(control.title, selectable=False)
                for child in control.controls:
                    check(child)
            else:
                self.assertIsInstance(control, ft.Container)
                check(control.content)

        for control in details["content"].controls:
            check(control)
        self.assertGreater(len(nested_tiles), len(details["content"].controls))
        self.assertIn("<b>literal</b>", text_of(details["sections"]))

    def test_reselection_and_clear_replace_old_tree(self):
        details = create_packet_details()
        render_packet_details(details, packet_info(ethernet() / ipv4() / TCP(sport=12345, dport=443)))
        old = details["content"].controls
        render_packet_details(details, packet_info(ethernet() / ARP(hwsrc=SOURCE_MAC, psrc="192.0.2.1", pdst="192.0.2.2"), number=8))
        self.assertIsNot(old, details["content"].controls)
        self.assertIn("#8", details["title"].value)
        self.assertNotIn("TCP", [node.label for node in details["sections"]])
        render_packet_details(details, None)
        self.assertEqual(details["title"].value, "No packet selected")
        self.assertTrue(details["empty"].visible)
        self.assertFalse(details["content"].visible)
        self.assertEqual(details["content"].controls, [])
        self.assertEqual(details["sections"], [])


if __name__ == "__main__":
    unittest.main()
