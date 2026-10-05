"""Scapy layer exports for the 802.1Q VLAN bridge task.

Re-export scapy's Dot1Q so the packet builder and the verifier share its class
identity. The verifier asserts on Dot1Q.vlan (tag push) and Ether.type
(tag pop: 0x8100 tagged vs 0x0800 untagged).
"""
from scapy.all import Dot1Q  # noqa: F401
