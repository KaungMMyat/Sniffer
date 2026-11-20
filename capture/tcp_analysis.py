from collections import OrderedDict
from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import Dot1Q
from scapy.packet import Padding

TCP_FLAGS = ((0x100, "NS"), (0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"),
             (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"),
             (0x01, "FIN"))


def tcp_payload_length(tcp):
    padding = tcp.payload.getlayer(Padding)
    return max(0, len(tcp.payload) - (len(padding) if padding is not None else 0))


def tcp_summary(tcp):
    flags = ", ".join(label for bit, label in TCP_FLAGS if int(tcp.flags) & bit)
    ack = f" Ack={tcp.ack}" if int(tcp.flags) & 0x10 else ""
    return (f"{tcp.sport} → {tcp.dport} [{flags or 'NONE'}] Seq={tcp.seq}{ack} "
            f"Win={tcp.window} Len={tcp_payload_length(tcp)}")


def _unwrap(value, reference):
    if reference is None:
        return value
    # TCP sequence numbers wrap at 2**32; compare within the nearest half-space.
    return reference + ((value - reference + 2**31) % 2**32 - 2**31)


@dataclass
class _Direction:
    next_seq: int | None = None
    ranges: list[tuple[int, int]] = field(default_factory=list)
    syn_seq: int | None = None
    fin: bool = False
    window: int | None = None
    last_ack: int | None = None
    last_ack_seq: int | None = None
    last_ack_packet: int | None = None
    dup_acks: int = 0
    keep_alive: bool = False
    last_advance: float = 0.0

    def remember(self, start, end):
        merged = []
        for left, right in self.ranges:
            if right < start:
                merged.append((left, right))
            elif end < left:
                merged.append((start, end))
                start, end = left, right
            else:
                start, end = min(start, left), max(end, right)
        merged.append((start, end))
        self.ranges = merged[-128:]


@dataclass
class _Connection:
    stream: int
    last_seen: float
    directions: tuple[_Direction, _Direction] = field(
        default_factory=lambda: (_Direction(), _Direction())
    )
    reset_seen: bool = False


class TCPAnalyzer:
    def __init__(self, max_streams=10000, idle_timeout=300.0):
        self.max_streams = max_streams
        self.idle_timeout = idle_timeout
        self.reset()

    def reset(self):
        self._connections = OrderedDict()
        self._stream_number = 0

    def analyze(self, info, packet):
        tcp = packet.getlayer(TCP)
        if tcp is None or info.protocol != "TCP":
            return
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network is None or (network.version == 4 and (
                network.frag or int(network.flags) & 1)):
            return
        if packet.haslayer(IPv6ExtHdrFragment):
            return
        parent = tcp.underlayer
        while parent is not None and parent is not network:
            if not parent.name.startswith("IPv6 Extension Header"):
                return
            parent = parent.underlayer
        if parent is None:
            return

        endpoints = ((info.source, info.src_port), (info.destination, info.dst_port))
        ordered = tuple(sorted(endpoints))
        vlans = tuple(layer.vlan for layer in packet.iterpayloads()
                      if isinstance(layer, Dot1Q))
        key = (network.version, vlans, ordered)
        index = 0 if endpoints[0] == ordered[0] else 1
        now = info.timestamp
        flags = int(tcp.flags)
        syn, fin, rst, ack = (bool(flags & bit) for bit in (2, 1, 4, 16))
        connection = self._connections.pop(key, None)
        if connection is not None:
            direction = connection.directions[index]
            new_syn = syn and not ack and (
                connection.reset_seen
                or all(side.fin for side in connection.directions)
                or (direction.syn_seq is not None and direction.syn_seq != tcp.seq)
                or (direction.syn_seq is None and direction.next_seq is not None)
            )
            if new_syn or now - connection.last_seen > self.idle_timeout:
                connection = None
        if connection is None:
            while self._connections:
                oldest = next(iter(self._connections.values()))
                if (len(self._connections) < self.max_streams
                        and now - oldest.last_seen <= self.idle_timeout):
                    break
                self._connections.popitem(last=False)
            connection = _Connection(self._stream_number, now)
            self._stream_number += 1
        connection.last_seen = max(connection.last_seen, now)
        self._connections[key] = connection
        info.tcp_stream = connection.stream
        side, peer = connection.directions[index], connection.directions[1 - index]

        captured_network_length = len(network)
        padding = network.getlayer(Padding)
        if padding is not None:
            captured_network_length -= len(padding)
        declared_length = (network.len if network.version == 4
                           else 40 + network.plen if network.plen else None)
        if (info.wire_length > info.length
                or (declared_length and declared_length > captured_network_length)
                or (tcp.dataofs is not None and tcp.dataofs < 5)):
            info.tcp_analysis = ("TCP analysis skipped: truncated or malformed segment",)
            self._connections.pop(key)
            return

        length = tcp_payload_length(tcp)
        seq = _unwrap(int(tcp.seq), side.next_seq)
        ack_number = _unwrap(int(tcp.ack), peer.next_seq) if ack else None
        consumed = length + int(syn) + int(fin)
        end = seq + consumed
        labels, notes = [], []

        def mark(label, explanation):
            labels.append(f"[{label}]")
            notes.append(explanation)

        probe = (length == 1 and not (syn or fin or rst)
                 and peer.window == 0 and seq == side.next_seq)
        keep_alive = (ack and not (syn or fin or rst) and length <= 1
                      and side.next_seq is not None and seq == side.next_seq - 1
                      and peer.window != 0 and int(tcp.window) != 0
                      and (length == 0 or now - side.last_advance >= 1.0))
        keep_alive_ack = (ack and not (syn or fin or rst) and length == 0
                          and peer.keep_alive and ack_number == peer.next_seq
                          and seq == side.next_seq and int(tcp.window) == side.window)
        if probe:
            mark("TCP ZeroWindowProbe", "One-byte probe while the peer advertises a zero window.")
        elif keep_alive:
            mark("TCP Keep-Alive", "Possible keep-alive: sequence is one before the next expected byte.")
        elif keep_alive_ack:
            mark("TCP Keep-Alive ACK", "Acknowledges the observed keep-alive without advancing the acknowledgment.")
        elif consumed and not rst:
            if side.next_seq is not None:
                if seq > side.next_seq:
                    mark("TCP Previous segment not captured",
                         f"Sequence gap: expected {side.next_seq % 2**32}, observed {tcp.seq}. "
                         "Missing capture data or packet reordering is possible.")
                elif any(seq < right and end > left for left, right in side.ranges):
                    mark("TCP Retransmission",
                         "Suspected retransmission: sequence space overlaps a previously captured segment. "
                         "Duplicate capture is also possible.")
                elif seq < side.next_seq:
                    mark("TCP Out-Of-Order",
                         "Earlier sequence space arrived after later data; it may fill a capture gap.")
            side.remember(seq, end)

        if ack and not (syn or rst):
            if peer.next_seq is not None and ack_number > peer.next_seq:
                mark("TCP ACKed unseen segment",
                     "Acknowledgment covers sequence space not observed in the opposite direction.")
            if (not labels and length == 0 and not fin and side.last_ack == ack_number
                    and side.last_ack_seq == seq and side.window == int(tcp.window)
                    and int(tcp.window) > 0 and peer.next_seq is not None
                    and ack_number < peer.next_seq):
                side.dup_acks += 1
                mark(f"TCP Dup ACK {side.last_ack_packet}#{side.dup_acks}",
                     "Repeated acknowledgment while observed data remains unacknowledged.")
            elif (not labels and length == 0 and not fin and side.last_ack == ack_number
                  and side.last_ack_seq == seq and side.window is not None
                  and side.window != int(tcp.window) and int(tcp.window) > 0):
                mark("TCP Window Update", "Receiver changed its advertised window without advancing the acknowledgment.")
            else:
                side.dup_acks = 0

        if int(tcp.window) == 0 and not (syn or rst):
            mark("TCP ZeroWindow", "Sender advertises no receive buffer space; this does not prove packet loss.")

        if not probe and not keep_alive and not rst:
            if side.next_seq is None or (consumed and end > side.next_seq):
                side.next_seq = end
                side.last_advance = now
        if ack:
            if side.last_ack != ack_number:
                side.last_ack_packet = info.number
            side.last_ack, side.last_ack_seq = ack_number, seq
            peer.keep_alive = False
        if syn:
            side.syn_seq = int(tcp.seq)
        side.keep_alive = keep_alive
        side.fin = side.fin or fin
        side.window = int(tcp.window)
        connection.reset_seen = connection.reset_seen or rst
        info.tcp_analysis = tuple(notes)
        if labels:
            info.info = " ".join(labels) + " " + info.info
