"""Scapy layer for a single-question DNS *query* over UDP/53 (RFC 1035).

A flat, verifier-friendly model of the DNS header + first question. The
nested Scapy `DNS(qd=DNSQR(...))` form cannot be expressed in the task.yaml
flat layer-list, so this layer carries the header flag bits broken out
(so a test can set `qr: 0` / `qr: 1` directly) plus a single question
(`qname` as an RFC 1035 §3.1 length-prefixed label sequence via Scapy's
DNSStrField, `qtype`, `qclass`). The switch under test parses these raw
bytes; the verifier asserts on the decoded fields (qname / qtype) for the
payload-preservation invariant and routes/drops on the envelope.

Scapy natively binds its own DNS layer to UDP port 53; we split that
binding and bind DNSQuery instead so the harness re-dissects the egress
pcap into this flat layer.
"""

from scapy.fields import BitField, ShortField
from scapy.layers.dns import DNS, DNSStrField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers, split_layers


class DNSQuery(Packet):
    name = "DNSQuery"
    fields_desc = [
        ShortField("id", 0x1234),
        # 16-bit flags field, broken out (RFC 1035 §4.1.1)
        BitField("qr", 0, 1),         # 0 = query, 1 = response
        BitField("opcode", 0, 4),
        BitField("aa", 0, 1),
        BitField("tc", 0, 1),
        BitField("rd", 0, 1),
        BitField("ra", 0, 1),
        BitField("z", 0, 3),
        BitField("rcode", 0, 4),
        ShortField("qdcount", 1),
        ShortField("ancount", 0),
        ShortField("nscount", 0),
        ShortField("arcount", 0),
        # First question (RFC 1035 §4.1.2)
        DNSStrField("qname", "example.com"),   # length-prefixed labels + root
        ShortField("qtype", 1),                # A=1, NS=2, CNAME=5, MX=15, AAAA=28
        ShortField("qclass", 1),               # IN=1
    ]


# Replace Scapy's native DNS binding on port 53 with the flat query layer.
split_layers(UDP, DNS, dport=53)
split_layers(UDP, DNS, sport=53)
bind_layers(UDP, DNSQuery, dport=53)
