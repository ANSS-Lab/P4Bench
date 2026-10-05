"""Scapy layer exports for the SRv6 endpoint task.

Re-export IPv6 and the Segment Routing Header so the packet builder and the
verifier share class identity. `SRH` is an alias for scapy's
IPv6ExtHdrSegmentRouting; the verifier asserts on SRH.segleft and IPv6.dst /
IPv6.hlim.
"""
from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting  # noqa: F401

SRH = IPv6ExtHdrSegmentRouting
