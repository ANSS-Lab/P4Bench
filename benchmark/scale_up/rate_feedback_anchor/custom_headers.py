"""Scapy layer definition for the RCP-style explicit-rate feedback shim,
for benchmark/scale_up/rate_feedback_anchor.

RCP (Dukkipati & McKeown, "Rate Control Protocol") carries a single rate field
R that every router on the path overwrites with its own locally-computed
fair-share rate ONLY IF the router's rate is smaller (the path-minimum fold).
This v1 instance carries R as a 32-bit field in a UDP-demuxed shim:

    Ether / IP / UDP(dport=9999) / RCPFeedback{ value(32) }

  - value : the 32-bit advertised rate; the switch folds it to
            MIN(value, switch_advertised_value) before forwarding.

`bind_layers` chains the dissection on UDP dport 9999 so the verifier can parse
a SUT's egress packet and read RCPFeedback.value regardless of which P4 module
produced it. The Python oracle parses the same field defensively from the raw
UDP payload, so the two agree on the wire format.
"""
from scapy.packet import Packet, bind_layers
from scapy.fields import IntField
from scapy.all import UDP

FEEDBACK_UDP_PORT = 9999


class RCPFeedback(Packet):
    name = "RCPFeedback"
    fields_desc = [
        IntField("value", 0),         # 32-bit advertised rate (path-min folded)
    ]


bind_layers(UDP, RCPFeedback, dport=FEEDBACK_UDP_PORT)
