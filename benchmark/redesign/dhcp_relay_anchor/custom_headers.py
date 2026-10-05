"""Scapy layer for the fixed-format BOOTP/DHCP header (RFC 951 / RFC 2131 §2).

DHCP/BOOTP is NOT one of the layers the verifier builds natively, so the relay's
gradable field (giaddr) and the direction/hops fields are exposed here as a
custom layer. Bound to the BOOTP UDP ports (server 67, client 68) so that when
the engine reparses an emitted packet via Ether(bytes(pkt)) the DHCP header is
dissected automatically and DHCP.giaddr / DHCP.hops / DHCP.op become readable by
the verifier's _get_field.

NOTE (BOOTP-shadowing fix): scapy's built-in BOOTP layer is already bound to UDP
67/68 at import time and wins payload_guess (first-match), so a plain
bind_layers(UDP, DHCP, ...) is never reached and the reparse dissects as BOOTP —
making `DHCP.giaddr` unresolvable and capping the score. We split_layers() the
built-in BOOTP bindings off ports 67/68 first, so the custom DHCP layer wins the
reparse. Field offsets are identical, so this only changes the layer name the
verifier sees, not the bytes.

Only the 236-byte fixed header is modelled (no options / Option 82 in the
canonical seed). chaddr/sname/file are fixed-width byte fields padded with
zeros; the relay never touches them.
"""

from scapy.fields import (
    ByteField, ShortField, IntField, IPField, StrFixedLenField, XIntField,
)
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers, split_layers

BOOTP_SERVER_PORT = 67
BOOTP_CLIENT_PORT = 68


class DHCP(Packet):
    name = "DHCP"
    fields_desc = [
        ByteField("op", 1),            # 1=BOOTREQUEST, 2=BOOTREPLY
        ByteField("htype", 1),         # 1 = Ethernet
        ByteField("hlen", 6),
        ByteField("hops", 0),
        XIntField("xid", 0),
        ShortField("secs", 0),
        ShortField("flags", 0),
        IPField("ciaddr", "0.0.0.0"),
        IPField("yiaddr", "0.0.0.0"),
        IPField("siaddr", "0.0.0.0"),
        IPField("giaddr", "0.0.0.0"),
        StrFixedLenField("chaddr", b"\x00" * 16, 16),
        StrFixedLenField("sname", b"\x00" * 64, 64),
        StrFixedLenField("file", b"\x00" * 128, 128),
    ]


# Evict the built-in BOOTP bindings on 67/68 so the custom DHCP layer wins the
# reparse (see module docstring). Best-effort: ignore if BOOTP is unavailable.
try:
    from scapy.layers.dhcp import BOOTP
    for _port in (BOOTP_SERVER_PORT, BOOTP_CLIENT_PORT):
        split_layers(UDP, BOOTP, dport=_port)
        split_layers(UDP, BOOTP, sport=_port)
except Exception:
    pass

bind_layers(UDP, DHCP, dport=BOOTP_SERVER_PORT)
bind_layers(UDP, DHCP, dport=BOOTP_CLIENT_PORT)
bind_layers(UDP, DHCP, sport=BOOTP_SERVER_PORT)
bind_layers(UDP, DHCP, sport=BOOTP_CLIENT_PORT)
