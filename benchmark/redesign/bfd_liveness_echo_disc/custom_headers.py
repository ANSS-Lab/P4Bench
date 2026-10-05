"""Scapy layer for the RFC 5880 §4.1 mandatory BFD control header.

This is the 24-byte (Authentication absent) form. Bound to UDP destination
port 3784 (single-hop) and 4784 (multi-hop) per RFC 5881 / RFC 5883.
"""

from scapy.fields import BitField, ByteField, IntField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers


class BFD(Packet):
    name = "BFD"
    fields_desc = [
        BitField("version", 1, 3),
        BitField("diag", 0, 5),
        BitField("state", 1, 2),                 # 0=AdminDown, 1=Down, 2=Init, 3=Up
        BitField("flag_P", 0, 1),
        BitField("flag_F", 0, 1),
        BitField("flag_C", 0, 1),
        BitField("flag_A", 0, 1),
        BitField("flag_D", 0, 1),
        BitField("flag_M", 0, 1),
        ByteField("detect_mult", 3),
        ByteField("length", 24),
        IntField("my_discr", 0),
        IntField("your_discr", 0),
        IntField("desired_min_tx_interval", 1000000),
        IntField("required_min_rx_interval", 1000000),
        IntField("required_min_echo_rx_interval", 0),
    ]


bind_layers(UDP, BFD, dport=3784)
bind_layers(UDP, BFD, dport=4784)
