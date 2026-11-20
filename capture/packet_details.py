from dataclasses import dataclass, field
from itertools import islice

from scapy.all import conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, _ICMPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import NoPayload, Packet, Padding, Raw


MAX_NODES = 320
MAX_ITEMS = 16
MAX_LAYERS = 24
MAX_TEXT = 256
MAX_PREVIEW_BYTES = 48


@dataclass(slots=True)
class DetailNode:
    label: str
    value: str = ""
    children: list["DetailNode"] = field(default_factory=list)


def plain_text(value):
    if value is None:
        return "—"
    if isinstance(value, bytes):
        sample = value[:MAX_PREVIEW_BYTES]
        suffix = f" … ({len(value)} bytes total)" if len(value) > len(sample) else ""
        value = repr(sample) + suffix
    elif isinstance(value, Packet):
        value = value.name
    elif isinstance(value, (tuple, list)):
        value = ", ".join(plain_text(item) for item in value[:4])
        if len(value) > MAX_TEXT:
            value = value[:MAX_TEXT] + "…"
    else:
        value = str(value)
    # Escape control and bidi-format characters; never interpret captured markup.
    text = "".join(c if c.isprintable() else ascii(c)[1:-1] for c in value[:MAX_TEXT])
    return text[:MAX_TEXT - 1] + "…" if len(text) > MAX_TEXT or len(value) > MAX_TEXT else text


class _Tree:
    def __init__(self):
        self.sections = []
        self.count = 0
        self.limited = False

    def add(self, parent, label, value=""):
        if self.count >= MAX_NODES - 1:
            self.limited = True
            return []
        node = DetailNode(plain_text(label), plain_text(value))
        parent.append(node)
        self.count += 1
        return node.children

    def finish(self):
        if self.limited:
            self.sections.append(DetailNode("Display limit", "Additional fields omitted; full bytes remain in raw_frame."))
        return self.sections


def _number(layer, name, default=0):
    return int(layer.fields.get(name, default) or 0)


def _enum(layer, name):
    value = layer.fields.get(name)
    descriptor = layer.get_field(name)
    mapping = getattr(descriptor, "i2s", {})
    label = mapping.get(value) if isinstance(mapping, dict) else None
    return f"{value} ({label})" if label else value


def _fields(tree, parent, layer, names):
    for name, label in names:
        if name in layer.fields:
            value = layer.fields[name]
            if name in ("chksum", "cksum"):
                value = f"0x{int(value):04x} (not validated)"
            tree.add(parent, label, value)


def _generic_fields(tree, parent, layer, depth=0):
    for name, value in islice(layer.fields.items(), MAX_ITEMS):
        if isinstance(value, Packet) and depth < 2:
            nested = tree.add(parent, name, value.name)
            _generic_fields(tree, nested, value, depth + 1)
        elif isinstance(value, (list, tuple)) and depth < 2:
            nested = tree.add(parent, name, f"{len(value)} items")
            _items(tree, nested, value, depth + 1)
        else:
            tree.add(parent, name, value)
    if len(layer.fields) > MAX_ITEMS:
        tree.add(parent, "Display limit", "Additional fields omitted.")


def _items(tree, parent, values, depth=0):
    for index, value in enumerate(islice(values, MAX_ITEMS), 1):
        if isinstance(value, Packet):
            fields = tree.add(parent, f"{index}. {value.name}", _record_summary(value))
            if depth < 3:
                _generic_fields(tree, fields, value, depth)
        elif isinstance(value, tuple) and value:
            tree.add(parent, value[0], value[1:] if len(value) > 2 else (value[1] if len(value) == 2 else ""))
        else:
            tree.add(parent, str(index), value)
    if len(values) > MAX_ITEMS:
        tree.add(parent, "Display limit", f"Showing {MAX_ITEMS} of {len(values)} items.")


def _flags(tree, parent, value, names):
    flags = tree.add(parent, "Flags", f"0x{int(value):03x} · {value or 'none'}")
    for mask, label in names:
        tree.add(flags, label, "Set" if int(value) & mask else "Not set")


def _options(tree, parent, layer):
    values = layer.fields.get("options", [])
    options = tree.add(parent, "Options", f"{len(values)} decoded")
    _items(tree, options, values)


def _payload_bytes(layer):
    header = len(layer.raw_packet_cache or b"")
    original = layer.original
    end = len(original)
    if isinstance(layer, UDP) and _number(layer, "len") >= 8:
        end = min(end, _number(layer, "len"))
    return original[header:end]


def _record_summary(record):
    fields = record.fields
    if "qname" not in fields and "rrname" not in fields:
        return " · ".join(f"{name}={plain_text(value)}" for name, value in islice(fields.items(), 3))
    name = fields.get("qname", fields.get("rrname", ""))
    if isinstance(name, bytes):
        name = name[:MAX_TEXT].decode("utf-8", errors="backslashreplace")
    kind = "qtype" if "qtype" in fields else "type"
    summary = f"{plain_text(name)} · {_enum(record, kind)}"
    if "rdata" in fields:
        summary += f" · {plain_text(fields['rdata'])}"
    return summary


def _metadata(tree, info, raw):
    wire = getattr(info, "wire_length", 0)
    fields = tree.add(tree.sections, "Frame", f"#{getattr(info, 'number', '?')} · {len(raw)} captured bytes · {wire or 'unknown'} bytes on wire")
    for label, name in (
        ("Number", "number"), ("Capture time", "time"), ("Timestamp (epoch seconds)", "timestamp"),
        ("Source summary", "source"), ("Destination summary", "destination"),
        ("Transport/network summary", "protocol"), ("Application hint (not proof of decoding)", "app_protocol"),
        ("Source port summary", "src_port"), ("Destination port summary", "dst_port"),
        ("Source MAC summary", "mac_source"), ("Destination MAC summary", "mac_destination"),
        ("Reported length", "length"), ("Summary", "info"),
    ):
        value = getattr(info, name, None)
        if value is not None and value != "":
            tree.add(fields, label, value)
    tree.add(fields, "Captured length", len(raw))
    tree.add(fields, "Wire length", wire if wire else "Unknown")
    tree.add(fields, "Link type", getattr(info, "link_type", None))
    tree.add(fields, "Decoding scope", "Selected frame only; no IP fragment or TCP stream reassembly. Checksums are not validated.")
    if wire and wire > len(raw):
        tree.add(fields, "Truncated capture", f"{wire - len(raw)} wire bytes not captured.")
    elif wire and wire < len(raw):
        tree.add(fields, "Length mismatch", "Captured bytes exceed reported wire length.")


def _header_warning(layer):
    available = len(layer.original)
    if isinstance(layer, IP):
        header = _number(layer, "ihl") * 4
        total = _number(layer, "len")
        if _number(layer, "version") != 4 or header < 20 or total < header:
            return "Malformed IPv4 version, header length or total length."
        if header > available or total > available:
            return "Truncated IPv4 header or payload (declared length exceeds captured bytes)."
    elif isinstance(layer, IPv6):
        if _number(layer, "version") != 6:
            return "Malformed IPv6 version."
        if available < 40 + _number(layer, "plen"):
            return "Truncated IPv6 payload (declared length exceeds captured bytes)."
    elif isinstance(layer, TCP):
        header = _number(layer, "dataofs") * 4
        if header < 20:
            return "Malformed TCP header length (less than 20 bytes)."
        if header > available:
            return "Truncated TCP header/options."
    elif isinstance(layer, UDP):
        length = _number(layer, "len")
        if length < 8:
            return "UDP length below 8; malformed or IPv6 jumbogram (not interpreted)."
        if length > available:
            return "Truncated UDP datagram (declared length exceeds captured bytes)."
    return ""


def _decode_layer(tree, layer, info, quoted=False):
    roots = tree.sections
    if isinstance(layer, Ether):
        fields = tree.add(roots, "Ethernet", f"{layer.src} → {layer.dst} · Type 0x{layer.type:04x}")
        _fields(tree, fields, layer, (("src", "Source"), ("dst", "Destination")))
        tree.add(fields, "Type", f"0x{layer.type:04x}")
    elif isinstance(layer, ARP):
        fields = tree.add(roots, "ARP", f"{_enum(layer, 'op')} · {layer.psrc} → {layer.pdst}")
        _fields(tree, fields, layer, (("hwtype", "Hardware type"), ("ptype", "Protocol type"),
                                     ("hwlen", "Hardware address length"), ("plen", "Protocol address length"),
                                     ("op", "Operation"), ("hwsrc", "Sender MAC"), ("psrc", "Sender IP"),
                                     ("hwdst", "Target MAC"), ("pdst", "Target IP")))
    elif isinstance(layer, IP):
        fields = tree.add(roots, "IPv4", f"{layer.src} → {layer.dst} · {_enum(layer, 'proto')} · Len {layer.len}")
        _fields(tree, fields, layer, (("version", "Version"), ("src", "Source"), ("dst", "Destination"),
                                     ("tos", "DS field"), ("len", "Total length"), ("id", "Identification"),
                                     ("ttl", "Time to live"), ("chksum", "Header checksum")))
        tree.add(fields, "Header length", f"{_number(layer, 'ihl') * 4} bytes")
        tree.add(fields, "Protocol", _enum(layer, "proto"))
        tree.add(fields, "Fragment offset", f"{_number(layer, 'frag')} units ({_number(layer, 'frag') * 8} bytes)")
        _flags(tree, fields, layer.flags, ((4, "Reserved"), (2, "Don't fragment"), (1, "More fragments")))
        _options(tree, fields, layer)
    elif isinstance(layer, IPv6):
        fields = tree.add(roots, "IPv6", f"{layer.src} → {layer.dst} · Next header {_enum(layer, 'nh')}")
        _fields(tree, fields, layer, (("version", "Version"), ("src", "Source"), ("dst", "Destination"),
                                     ("tc", "Traffic class"), ("fl", "Flow label"), ("plen", "Payload length"),
                                     ("hlim", "Hop limit")))
        tree.add(fields, "Next header", _enum(layer, "nh"))
        if not _number(layer, "plen"):
            tree.add(fields, "Length note", "Zero payload length; IPv6 jumbogram length is not interpreted.")
    elif isinstance(layer, TCP):
        payload_length = len(_payload_bytes(layer))
        fields = tree.add(roots, "TCP", f"{layer.sport} → {layer.dport} · [{layer.flags}] · Seq {layer.seq} Ack {layer.ack} · Len {payload_length}")
        _fields(tree, fields, layer, (("sport", "Source port"), ("dport", "Destination port"),
                                     ("seq", "Sequence number (absolute)"), ("ack", "Acknowledgment number (absolute)"),
                                     ("window", "Window (raw, unscaled)"), ("chksum", "Checksum"),
                                     ("urgptr", "Urgent pointer"), ("reserved", "Reserved bits")))
        tree.add(fields, "Header length", f"{_number(layer, 'dataofs') * 4} bytes")
        tree.add(fields, "Payload length (captured)", payload_length)
        _flags(tree, fields, layer.flags, ((1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"),
                                          (32, "URG"), (64, "ECE"), (128, "CWR"), (256, "NS")))
        _options(tree, fields, layer)
        if not quoted:
            stream = getattr(info, "tcp_stream", None)
            analysis = tree.add(fields, "Stream / analysis", f"Stream {stream if stream is not None else 'unknown'} · heuristic")
            tree.add(analysis, "Stream index", stream)
            notes = getattr(info, "tcp_analysis", ()) or ()
            for note in islice(notes, MAX_ITEMS):
                tree.add(analysis, "Observation", note)
            if len(notes) > MAX_ITEMS:
                tree.add(analysis, "Display limit", "Additional analysis observations omitted.")
            tree.add(analysis, "Limitations", "Heuristic capture-order observations, not proof of loss or retransmission; missing, reordered or offloaded packets and reused connections can mislead. No stream reassembly or window scaling applied.")
    elif isinstance(layer, UDP):
        fields = tree.add(roots, "UDP", f"{layer.sport} → {layer.dport} · Length {layer.len}")
        _fields(tree, fields, layer, (("sport", "Source port"), ("dport", "Destination port"),
                                     ("len", "Datagram length"), ("chksum", "Checksum")))
        tree.add(fields, "Header length", "8 bytes")
        tree.add(fields, "Payload length (captured)", len(_payload_bytes(layer)))
    elif isinstance(layer, (ICMP, _ICMPv6)):
        label = "ICMPv6" if isinstance(layer, _ICMPv6) else "ICMP"
        fields = tree.add(roots, label, f"{_enum(layer, 'type')} · Code {layer.code}")
        _fields(tree, fields, layer, (("type", "Type"), ("code", "Code"), ("chksum", "Checksum"),
                                     ("cksum", "Checksum"), ("id", "Identifier"), ("seq", "Sequence"),
                                     ("ptr", "Pointer"), ("gw", "Gateway"), ("nexthopmtu", "Next-hop MTU"),
                                     ("mtu", "MTU"), ("tgt", "Target"), ("data", "Data preview")))
        tree.add(fields, "Payload note", "Any quoted inner packet is decoded below, not a separate captured flow.")
    elif isinstance(layer, DNS):
        question = layer.fields.get("qd", [])
        summary = _record_summary(question[0]) if question and isinstance(question[0], Packet) else "No decoded question"
        fields = tree.add(roots, "DNS", f"{'Response' if layer.qr else 'Query'} 0x{layer.id:04x} · {summary}")
        tree.add(fields, "Transaction ID", f"0x{layer.id:04x}")
        tree.add(fields, "Opcode", _enum(layer, "opcode"))
        tree.add(fields, "Response code", _enum(layer, "rcode"))
        flags = tree.add(fields, "Flags", f"{'Response' if layer.qr else 'Query'} · RCODE {_enum(layer, 'rcode')}")
        _fields(tree, flags, layer, (("qr", "Response"), ("aa", "Authoritative"), ("tc", "Truncated message"),
                                    ("rd", "Recursion desired"), ("ra", "Recursion available"),
                                    ("z", "Reserved"), ("ad", "Authenticated data bit (not verified)"),
                                    ("cd", "Checking disabled")))
        for name, count, label in (("qd", "qdcount", "Questions"), ("an", "ancount", "Answers"),
                                   ("ns", "nscount", "Authority records"), ("ar", "arcount", "Additional records")):
            records = layer.fields.get(name, [])
            decoded = sum(isinstance(record, Packet) and not isinstance(record, Raw) for record in records)
            group = tree.add(fields, label, f"{_number(layer, count)} declared · {decoded} decoded")
            _items(tree, group, records)
            if decoded != _number(layer, count):
                tree.add(group, "Decode warning", "Record count mismatch; message may be truncated or malformed.")
    elif isinstance(layer, BOOTP):
        fields = tree.add(roots, "BOOTP", f"{_enum(layer, 'op')} · Transaction 0x{layer.xid:08x} · Client {layer.ciaddr}")
        _fields(tree, fields, layer, (("op", "Operation"), ("htype", "Hardware type"), ("hlen", "Hardware address length"),
                                     ("hops", "Hops"), ("xid", "Transaction ID"), ("secs", "Seconds elapsed"),
                                     ("ciaddr", "Client IP"), ("yiaddr", "Your IP"), ("siaddr", "Server IP"),
                                     ("giaddr", "Relay IP"), ("chaddr", "Client hardware address"),
                                     ("sname", "Server name"), ("file", "Boot file")))
        _flags(tree, fields, layer.flags, ((0x8000, "Broadcast"),))
    elif isinstance(layer, DHCP):
        options = layer.fields.get("options", [])
        message = next((option[1] for option in islice(options, MAX_ITEMS)
                        if isinstance(option, tuple) and len(option) > 1 and option[0] == "message-type"), None)
        message = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}.get(message, plain_text(message))
        fields = tree.add(roots, "DHCP", f"{message} · {len(options)} decoded options")
        group = tree.add(fields, "Options", f"{len(options)} decoded")
        _items(tree, group, options)
    else:
        summary = " · ".join(f"{name}={plain_text(value)}" for name, value in islice(layer.fields.items(), 3))
        fields = tree.add(roots, layer.name, summary or "Decoded layer")
        _generic_fields(tree, fields, layer)
    return fields


_TLS_TYPES = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}


def _tls_records(tree, data):
    if len(data) < 5 or data[0] not in _TLS_TYPES or data[1] != 3 or data[2] > 4:
        return False
    fields = tree.add(tree.sections, "TLS record headers (inferred)", f"{_TLS_TYPES[data[0]]} · {len(data)} captured TCP payload bytes")
    tree.add(fields, "Scope", "Header signature only, not authenticated TLS. No decryption or TCP reassembly; the legacy record version is not the negotiated TLS version.")
    position = 0
    for index in range(MAX_ITEMS):
        if position >= len(data):
            break
        if position + 5 > len(data):
            tree.add(fields, "Incomplete record header", "May continue in another TCP segment; no reassembly.")
            break
        kind, major, minor = data[position:position + 3]
        if kind not in _TLS_TYPES or major != 3 or minor > 4:
            tree.add(fields, "Undecoded remainder", "Not a recognized TLS record header.")
            break
        length = int.from_bytes(data[position + 3:position + 5], "big")
        record = tree.add(fields, f"Record {index + 1}", f"{_TLS_TYPES[kind]} · {length} declared bytes")
        tree.add(record, "Content type", f"{kind} ({_TLS_TYPES[kind]})")
        tree.add(record, "Legacy record version", f"0x{major:02x}{minor:02x}")
        tree.add(record, "Record length", length)
        tree.add(record, "Content", "Encrypted application data; not decrypted." if kind == 23 else "Record body not interpreted; it may be encrypted.")
        if position + 5 + length > len(data):
            tree.add(record, "Incomplete record body", "Declared bytes exceed this segment; segmentation or truncation, not necessarily malformed.")
            break
        position += 5 + length
    else:
        if position < len(data):
            tree.add(fields, "Display limit", "Additional TLS records omitted.")
    return True


def decode_packet_details(packet_info):
    tree = _Tree()
    raw = getattr(packet_info, "raw_frame", b"") or b""
    if not isinstance(raw, bytes):
        raw = b""
    _metadata(tree, packet_info, raw)
    if not raw:
        tree.add(tree.sections, "Decode unavailable", "No captured frame bytes; only stored metadata is available.")
        return tree.finish()
    link_type = getattr(packet_info, "link_type", None)
    decoder = conf.l2types.num2layer.get(link_type)
    if decoder is None:
        fields = tree.add(tree.sections, "Decode unavailable", f"Unknown or missing link type: {link_type}. Ethernet is not assumed.")
        tree.add(fields, "Frame preview", raw)
        return tree.finish()
    try:
        layer = decoder(raw)
        fragmented = False
        quoted = False
        for _ in range(MAX_LAYERS):
            if isinstance(layer, NoPayload):
                break
            if isinstance(layer, (Raw, Padding)):
                data = layer.fields.get("load", b"")
                label = "Padding" if isinstance(layer, Padding) else "Undissected data"
                fields = tree.add(tree.sections, label, f"{len(data)} bytes")
                tree.add(fields, "Byte preview", data)
                if not isinstance(layer, Padding):
                    tree.add(fields, "Decode note", "May be application data, encrypted, fragmented, unsupported, truncated or malformed; no further fields decoded.")
            else:
                fields = _decode_layer(tree, layer, packet_info, quoted)
                if quoted:
                    tree.add(fields, "Context", "Quoted inside an ICMP error; stored TCP stream/analysis belongs to the captured frame, not necessarily this quoted flow.")
                warning = _header_warning(layer)
                if warning:
                    tree.add(fields, "Decode warning", warning)
                    if "Malformed" in warning or "header/options" in warning or "below 8" in warning:
                        break
                if isinstance(layer, IP) and (_number(layer, "frag") or int(layer.flags) & 1):
                    fragmented = True
                if isinstance(layer, IPv6ExtHdrFragment) and (layer.offset or layer.m):
                    fragmented = True
                if isinstance(layer, TCP) and not fragmented and not quoted:
                    _tls_records(tree, _payload_bytes(layer))
                if isinstance(layer, ICMP) and layer.type in (3, 4, 5, 11, 12):
                    quoted = True
                if isinstance(layer, _ICMPv6) and layer.type < 128:
                    quoted = True
                if fragmented and isinstance(layer, (TCP, UDP, IPv6ExtHdrFragment)):
                    tree.add(fields, "Fragment note", "Fragmented datagram; application decoding skipped without reassembly.")
                    break
            layer = layer.payload
        else:
            tree.add(tree.sections, "Display limit", f"Stopped after {MAX_LAYERS} layers; remaining bytes not displayed.")
    except Exception as error:
        # Scapy dissectors can fail at any nested layer on untrusted/truncated input.
        fields = tree.add(tree.sections, "Decode error", f"Malformed, truncated or unsupported frame ({type(error).__name__}); partial details retained.")
        tree.add(fields, "Frame preview", raw)
    return tree.finish()
