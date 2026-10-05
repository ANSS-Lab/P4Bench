"""Scapy layer exports for the SR-MPLS segment-routing task.

Re-export scapy's contrib MPLS shim so the packet builder and the verifier
share its class identity (and so importing this module registers the
Ether(0x8847)->MPLS and MPLS->MPLS/IP bindings needed to re-dissect emitted
label stacks). P-SR-MPLS reuses the MPLS shim defined for P-MPLSLabelSwitch
rather than introducing a new header type; the verifier asserts on
MPLS.label / MPLS.ttl / MPLS.s.
"""
from scapy.contrib.mpls import MPLS  # noqa: F401
