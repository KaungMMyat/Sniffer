import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, wrpcap
from scapy.layers.inet6 import IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.layers.l2 import Dot1Q
from scapy.packet import Padding

from capture.controller import CaptureController
from capture.parser import parse_packet
from capture.pcap_reader import read_capture
from capture.tcp_analysis import TCPAnalyzer


def tcp_packet(seq, ack=5001, flags="A", data=b"", reverse=False, window=8192,
               timestamp=100.0, ipv6=False, port=80):
    source, destination = (("2001:db8::1", "2001:db8::2") if ipv6
                           else ("192.0.2.1", "192.0.2.2"))
    sport, dport = 40000, port
    if reverse:
        source, destination, sport, dport = destination, source, dport, sport
    network = IPv6(src=source, dst=destination) if ipv6 else IP(src=source, dst=destination)
    packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / network / TCP(
        sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=window
    )
    if data:
        packet /= Raw(data)
    packet = Ether(bytes(packet))
    packet.time = timestamp
    return packet


def sample_conversation():
    return [
        tcp_packet(1000, ack=0, flags="S"),
        tcp_packet(5000, ack=1001, flags="SA", reverse=True, timestamp=100.1),
        tcp_packet(1001, timestamp=100.2),
        tcp_packet(1001, flags="PA", data=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", timestamp=100.3),
        tcp_packet(1001, flags="PA", data=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", timestamp=101.0),
        tcp_packet(1100, flags="PA", data=b"later", timestamp=102.0),
        tcp_packet(1104, timestamp=104.0),
    ]


class TCPAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = TCPAnalyzer()
        self.number = 0

    def feed(self, seq, **kwargs):
        self.number += 1
        return parse_packet(tcp_packet(seq, **kwargs), self.number, analyzer=self.analyzer)

    def handshake(self, ipv6=False):
        packets = [self.feed(1000, ack=0, flags="S", ipv6=ipv6),
                   self.feed(5000, ack=1001, flags="SA", reverse=True, ipv6=ipv6),
                   self.feed(1001, ipv6=ipv6)]
        for packet in packets:
            self.assertEqual(packet.tcp_analysis, ())
        return packets

    def test_control_summary_and_raw_bytes(self):
        syn = self.feed(1000, flags="S", ack=0, port=443)
        self.assertEqual(syn.display_protocol, "TCP")
        self.assertIn("[SYN] Seq=1000 Win=8192 Len=0", syn.info)
        self.assertNotIn("Ack=", syn.info)
        self.assertEqual(syn.link_type, 1)
        self.assertEqual(len(syn.raw_frame), syn.length)
        self.assertEqual(Ether(syn.raw_frame)[TCP].seq, 1000)
        self.assertEqual(syn.timestamp, 100.0)

    def test_application_summary_preserves_transport_fields(self):
        info = self.feed(1001, flags="PA", data=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        self.assertEqual(info.app_protocol, "HTTP")
        self.assertIn("[ACK, PSH]", info.info)
        self.assertIn("Seq=1001 Ack=5001", info.info)
        self.assertIn("GET / HTTP/1.1", info.info)

    def test_retransmission_and_partial_overlap(self):
        self.handshake()
        self.feed(1001, data=b"abcdefghij")
        duplicate = self.feed(1001, data=b"abcdefghij")
        self.assertIn("[TCP Retransmission]", duplicate.info)
        partial = self.feed(1006, data=b"fghijklmno")
        self.assertIn("[TCP Retransmission]", partial.info)
        following = self.feed(1016, data=b"next")
        self.assertEqual(following.tcp_analysis, ())

    def test_gap_and_late_missing_segment(self):
        self.handshake()
        gap = self.feed(1011, data=b"abcdefghij")
        self.assertIn("[TCP Previous segment not captured]", gap.info)
        late = self.feed(1001, data=b"0123456789")
        self.assertIn("[TCP Out-Of-Order]", late.info)
        self.assertNotIn("[TCP Retransmission]", late.info)

    def test_keep_alive_and_reply(self):
        self.handshake()
        keep_alive = self.feed(1000, timestamp=110.0)
        self.assertIn("[TCP Keep-Alive]", keep_alive.info)
        reply = self.feed(5001, ack=1001, reverse=True, timestamp=110.1)
        self.assertIn("[TCP Keep-Alive ACK]", reply.info)
        self.assertNotIn("Dup ACK", reply.info)
        normal = self.feed(1001, data=b"abc", timestamp=111.0)
        self.assertEqual(normal.tcp_analysis, ())

    def test_one_byte_retransmission_not_early_keepalive(self):
        self.handshake()
        self.feed(1001, data=b"a", timestamp=100.1)
        repeat = self.feed(1001, data=b"a", timestamp=100.2)
        self.assertIn("[TCP Retransmission]", repeat.info)

    def test_idle_one_byte_keepalive(self):
        self.handshake()
        probe = self.feed(1000, data=b"x", timestamp=110.0)
        self.assertIn("[TCP Keep-Alive]", probe.info)

    def test_duplicate_ack_requires_outstanding_observed_data(self):
        self.handshake()
        self.feed(1001, data=b"abcdefghij")
        first = self.feed(5001, ack=1001, reverse=True)
        self.assertEqual(first.tcp_analysis, ())
        next_ack = self.feed(5001, ack=1001, reverse=True)
        self.assertIn("#1]", next_ack.info)
        self.assertIn("#2]", self.feed(5001, ack=1001, reverse=True).info)
        complete = self.feed(5001, ack=1011, reverse=True)
        self.assertEqual(complete.tcp_analysis, ())
        repeated_complete = self.feed(5001, ack=1011, reverse=True)
        self.assertEqual(repeated_complete.tcp_analysis, ())

    def test_zero_window_probe_and_window_update(self):
        self.handshake()
        zero = self.feed(5001, ack=1001, reverse=True, window=0)
        self.assertIn("[TCP ZeroWindow]", zero.info)
        probe = self.feed(1001, data=b"x")
        self.assertIn("[TCP ZeroWindowProbe]", probe.info)
        self.assertNotIn("Keep-Alive", probe.info)
        update = self.feed(5001, ack=1001, reverse=True, window=4096)
        self.assertIn("[TCP Window Update]", update.info)
        data = self.feed(1001, data=b"hello")
        self.assertEqual(data.tcp_analysis, ())

    def test_acked_unseen_and_no_claim_on_first_midstream_packet(self):
        first = self.feed(10000, ack=99000, data=b"abc")
        self.assertEqual(first.tcp_analysis, ())
        unseen = self.feed(99000, ack=20000, reverse=True)
        self.assertIn("[TCP ACKed unseen segment]", unseen.info)

    def test_syn_fin_and_reset_consume_correct_sequence_space(self):
        self.handshake()
        fin = self.feed(1001, flags="FA")
        self.assertEqual(fin.tcp_analysis, ())
        again = self.feed(1001, flags="FA")
        self.assertIn("[TCP Retransmission]", again.info)
        self.feed(5001, ack=1002, flags="RA", reverse=True)
        new = self.feed(1000, ack=0, flags="S")
        self.assertEqual(new.tcp_stream, 1)
        self.assertEqual(new.tcp_analysis, ())

    def test_repeated_syn_is_not_new_connection_but_new_isn_is(self):
        first = self.feed(1000, ack=0, flags="S")
        repeat = self.feed(1000, ack=0, flags="S")
        self.assertEqual(first.tcp_stream, repeat.tcp_stream)
        self.assertIn("[TCP Retransmission]", repeat.info)
        new = self.feed(9000, ack=0, flags="S")
        self.assertNotEqual(new.tcp_stream, first.tcp_stream)
        self.assertEqual(new.tcp_analysis, ())

    def test_sequence_wrap_and_ipv6(self):
        first = self.feed(2**32 - 4, data=b"12345678", ipv6=True)
        second = self.feed(4, data=b"next", ipv6=True)
        self.assertEqual(first.tcp_stream, second.tcp_stream)
        self.assertEqual(second.tcp_analysis, ())
        repeat = self.feed(2**32 - 4, data=b"12345678", ipv6=True)
        self.assertIn("[TCP Retransmission]", repeat.info)

    def test_ack_wrap_and_ipv6_extensions(self):
        self.feed(2**32 - 4, data=b"12345678", ipv6=True)
        ack = self.feed(5001, ack=4, reverse=True, ipv6=True)
        self.assertEqual(ack.tcp_analysis, ())
        self.analyzer.reset()
        base = tcp_packet(100, data=b"abc", ipv6=True)
        extended = Ether(src=base.src, dst=base.dst) / IPv6(
            src=base[IPv6].src, dst=base[IPv6].dst
        ) / IPv6ExtHdrHopByHop() / base[TCP]
        first = parse_packet(Ether(bytes(extended)), 1, analyzer=self.analyzer)
        repeat = parse_packet(Ether(bytes(extended)), 2, analyzer=self.analyzer)
        self.assertIsNotNone(first.tcp_stream)
        self.assertIn("[TCP Retransmission]", repeat.info)

    def test_vlan_namespaces_do_not_share_sequence_history(self):
        base = tcp_packet(100, data=b"abc")
        results = []
        for vlan in (10, 20):
            tagged = Ether(src=base.src, dst=base.dst) / Dot1Q(vlan=vlan) / base[IP]
            results.append(parse_packet(Ether(bytes(tagged)), vlan, analyzer=self.analyzer))
        self.assertNotEqual(results[0].tcp_stream, results[1].tcp_stream)
        self.assertEqual(results[1].tcp_analysis, ())

    def test_separate_connections_and_capture_reset(self):
        a = self.feed(1000, data=b"a", port=80)
        b = self.feed(1000, data=b"b", port=443)
        self.assertNotEqual(a.tcp_stream, b.tcp_stream)
        self.assertEqual(b.tcp_analysis, ())
        self.analyzer.reset()
        after = self.feed(1000, data=b"a", port=80)
        self.assertEqual(after.tcp_stream, 0)
        self.assertEqual(after.tcp_analysis, ())

    def test_stream_history_is_bounded_and_expires(self):
        self.analyzer = TCPAnalyzer(max_streams=2, idle_timeout=30)
        self.feed(1001, port=80)
        self.feed(1001, port=81)
        self.feed(1001, port=82)
        self.assertEqual(len(self.analyzer._connections), 2)
        self.assertEqual(self.feed(1001, port=80).tcp_stream, 3)
        self.assertEqual(self.feed(1001, port=80, timestamp=200).tcp_stream, 4)
        self.assertLessEqual(len(self.analyzer._connections), 2)

    def test_padding_does_not_become_application_data(self):
        packet = tcp_packet(1000, flags="S", ack=0)
        packet = Ether(bytes(packet) + b"\x00" * 6)
        self.assertTrue(packet.haslayer(Padding))
        info = parse_packet(packet, 1, analyzer=self.analyzer)
        self.assertIn("Len=0", info.info)
        self.assertEqual(info.display_protocol, "TCP")

    def test_truncated_packet_is_not_used_for_analysis(self):
        packet = tcp_packet(1001, data=b"1234567890")
        packet = Ether(bytes(packet)[:-5])
        info = parse_packet(packet, 1, analyzer=self.analyzer)
        self.assertIn("skipped", info.tcp_analysis[0])
        following = self.feed(1011, data=b"next")
        self.assertEqual(following.tcp_analysis, ())

    def test_fragmented_tcp_is_not_used_for_analysis(self):
        packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.0.2.1", dst="192.0.2.2", flags="MF") / TCP(seq=1)
        info = parse_packet(packet, 1, analyzer=self.analyzer)
        self.assertIsNone(info.tcp_stream)
        packet6 = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment(m=1) / TCP(seq=1)
        self.assertIsNone(parse_packet(packet6, 2, analyzer=self.analyzer).tcp_stream)

    def test_udp_is_not_analyzed_as_tcp(self):
        packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="example.test"))
        info = parse_packet(packet, 1, analyzer=self.analyzer)
        self.assertEqual(info.display_protocol, "DNS")
        self.assertIn("example.test", info.info)
        self.assertIsNone(info.tcp_stream)

    def test_live_and_file_share_analysis_with_per_file_reset(self):
        source = sample_conversation()
        received = []
        controller = CaptureController(lambda info, raw: received.append(info))
        for packet in source:
            controller.packet_received(packet)
        self.assertIn("[TCP Retransmission]", received[4].info)
        self.assertIn("[TCP Keep-Alive]", received[6].info)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "analysis.pcap"
            wrpcap(str(path), source)
            for _ in range(2):
                loaded = []
                result = read_capture(path, lambda info, raw: loaded.append(info))
                self.assertEqual(result, (len(source), 0))
                self.assertEqual([p.info for p in loaded], [p.info for p in received])
                self.assertEqual([p.timestamp for p in loaded], [p.timestamp for p in received])
        with patch("capture.controller.PacketSniffer"):
            controller.start("synthetic-test-only")
            controller.packet_received(source[0])
        self.assertEqual(received[-1].tcp_analysis, ())


if __name__ == "__main__":
    unittest.main()
