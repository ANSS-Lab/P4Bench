"""Scapy layer exports for the GRE keyed-tunnel task.

GRE is used in the input packets (outer IPv4 + GRE + inner IPv4). Re-export it
so the packet builder resolves it consistently. The verifier only asserts on
the decapsulated inner IPv4 (native), so GRE need not be resolved at verify
time, but exporting it is harmless and keeps class identity consistent.
"""
from scapy.all import GRE  # noqa: F401
