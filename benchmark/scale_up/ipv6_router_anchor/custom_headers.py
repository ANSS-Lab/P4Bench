"""Scapy layer exports for the IPv6 forwarding task.

The evaluation verifier (evaluation/verifier.py::_resolve_layer_cls) only
natively resolves Ether/IP/TCP/UDP/ICMP/ARP plus whatever this module exports.
Re-export scapy's IPv6 (and the common extension headers) by name so the
packet builder and the verifier use the same class identity when asserting
on IPv6 fields (e.g. IPv6.hlim, IPv6.src).
"""
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting  # noqa: F401
