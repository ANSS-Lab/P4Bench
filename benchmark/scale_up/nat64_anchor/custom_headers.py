"""Scapy layer exports for the NAT64 translation task.

The evaluation verifier (evaluation/verifier.py::_resolve_layer_cls) and the
packet builder (evaluation/packet_builder.py::_build_layer) natively resolve
Ether/IP/TCP/UDP/ICMP/ARP. NAT64 also handles IPv6 packets on the client side,
so re-export scapy's IPv6 by name here: the packet builder uses it to build the
v6->v4 test inputs, and the verifier uses the same class identity when
asserting on the v4->v6 EGRESS packet's IPv6 fields (IPv6.src, IPv6.dst,
IPv6.hlim).

The IPv4 EGRESS of the v6->v4 direction is plain scapy IP and needs no custom
class. Only the IPv6 family is non-native, so that is all this module exports.
"""
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting  # noqa: F401
