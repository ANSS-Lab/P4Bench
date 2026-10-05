"""Scapy layer defs for the IGMP-snooping task.

IGMP is not in the harness's stock Scapy build set (the packet builder knows
only {Ether, IP, TCP, UDP, ICMP, ARP, Raw}), so we ship a minimal IGMPv2/v3
message layer and bind it under IPv4 protocol 0x02. The wire format is RFC 2236
§2.1: Type(8) MaxRespTime(8) Checksum(16) GroupAddr(32).

Field names exposed for verifier / packet-builder use: `type`, `mrtime`,
`chksum`, `gaddr`. The membership-snooping oracle classifies on `type`
(0x16/0x12 = Report/join, 0x17 = Leave, 0x11 = Query, 0x22 = v3 report) and
keys the per-group port-set on `gaddr`.

Multicast DATA packets are plain IPv4 frames (no IGMP layer) with a 224.0.0.0/4
destination; they need no custom layer.
"""
from scapy.all import (  # noqa: F401
    Packet, ByteField, ShortField, IPField, bind_layers, IP,
)


class IGMP(Packet):
    name = "IGMP"
    fields_desc = [
        ByteField("type", 0x16),       # 0x16 v2 Report / 0x12 v1 Report / 0x17 Leave / 0x11 Query / 0x22 v3 Report
        ByteField("mrtime", 0),        # Max Response Time (also v3 record-type flag in source-filter mode)
        ShortField("chksum", 0),
        IPField("gaddr", "0.0.0.0"),   # multicast Group Address
    ]


bind_layers(IP, IGMP, proto=2)
