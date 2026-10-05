"""Scapy layer exports for the MPLS label-switching task.

Re-export scapy's contrib MPLS shim so the packet builder and the verifier
share its class identity (and so importing this module registers the
Ether(0x8847)->MPLS and MPLS->IP bindings needed to re-dissect emitted
packets). The verifier asserts on MPLS.label / MPLS.ttl.
"""
from scapy.contrib.mpls import MPLS  # noqa: F401
