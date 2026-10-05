"""Scapy layer export for the in-switch lock service task.

The evaluation verifier (evaluation/verifier.py::_resolve_layer_cls) only
natively resolves Ether/IP/TCP/UDP/ICMP/ARP/VXLAN/GTPU. A task asserting on
lock-message fields (LockMsg.status, LockMsg.client_id, ...) MUST ship the
custom layer here so the packet builder and the verifier share the same class
identity.

The lock control message rides UDP on a fixed service port. A single
LockMsg layer carries the whole control message:

    op         1 = LOCK, 2 = UNLOCK
    mode       0 = EXCLUSIVE, 1 = SHARED          (exclusive-only in canonical)
    status     0 = REQ, 1 = GRANT, 2 = NACK       (set by the switch on reply)
    lock_id    target lock id (the register slot it indexes)
    client_id  requesting client's id (the holder bound on a grant)

bind_layers(UDP, LockMsg, dport=LOCK_UDP_PORT) so build_packet auto-parses the
header beneath a UDP datagram addressed to the service port. We also bind on
sport for the switch-emitted reply (which preserves the requester's sport).
"""
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField, IntField
from scapy.layers.inet import UDP

LOCK_UDP_PORT = 0xABCD  # 43981 — the in-switch lock service UDP port


class LockMsg(Packet):
    name = "LockMsg"
    fields_desc = [
        ByteField("op", 1),         # 1=LOCK, 2=UNLOCK
        ByteField("mode", 0),       # 0=EXCLUSIVE, 1=SHARED
        ByteField("status", 0),     # 0=REQ, 1=GRANT, 2=NACK
        ByteField("reserved", 0),   # pad to 4-byte alignment
        ShortField("lock_id", 0),
        IntField("client_id", 0),
    ]


bind_layers(UDP, LockMsg, dport=LOCK_UDP_PORT)
bind_layers(UDP, LockMsg, sport=LOCK_UDP_PORT)
