"""Scapy layer definition for the in-network sequencer header (over UDP),
for benchmark/relocate/in_network_sequencer_anchor.

NOPaxos (Li et al., OSDI'16) / Eris (Li et al., SOSP'17) carry an ordered
multicast request in a custom sequencing header. This canonical instance uses a
single fixed-width form over UDP:

    Ether / IP / UDP(dport=9000) / Sequencer{ group_id(16) type(8)
                                              session(32) seq_no(32) }

  - group_id : which sequencing group / replica set this request targets
               (selects WHICH monotone counter to read-increment)
  - type     : message class. 1 = REQUEST (the ordered OUM class the switch
               stamps + multicasts); other values are non-sequenced traffic
               that forwards untouched; 2 = SESSION_RESET (dormant in this
               canonical instance — enable_session_reset is false)
  - session  : session / epoch the switch STAMPS into every ordered packet so
               replicas can detect a sequencer reset (NOPaxos session)
  - seq_no   : the sequence-number field the switch STAMPS with the
               post-increment monotone counter value (write-only output)

`bind_layers` chains the dissection so the verifier can parse a SUT's egress
packet (the stamped + multicast request) regardless of which P4 module
produced it, and so the packet builder appends the header by name.
"""
from scapy.packet import Packet, bind_layers
from scapy.fields import ShortField, ByteField, IntField
from scapy.all import UDP

SEQUENCER_UDP_PORT = 9000

TYPE_REQUEST = 1        # the ordered OUM traffic class (sequencing_class)
TYPE_NON_SEQUENCED = 0  # non-sequenced traffic (forwarded untouched)
TYPE_SESSION_RESET = 2  # session/epoch reset control message (dormant here)


class Sequencer(Packet):
    name = "Sequencer"
    fields_desc = [
        ShortField("group_id", 0),   # 16-bit sequencing group / replica set id
        ByteField("type", TYPE_REQUEST),
        IntField("session", 1),      # 32-bit session / epoch (stamped)
        IntField("seq_no", 0),       # 32-bit sequence number (stamped output)
    ]


bind_layers(UDP, Sequencer, dport=SEQUENCER_UDP_PORT)
