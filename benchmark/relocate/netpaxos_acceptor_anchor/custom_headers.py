"""Scapy layer definition for the Paxos consensus header (over UDP), for
benchmark/relocate/netpaxos_acceptor_anchor.

NetPaxos / P4xos (Dang et al., SOSR'15 / ToN'20) carry Paxos consensus messages
in a custom application header riding a UDP datagram. This single-slot anchor
instance uses the default field widths (round_width=16, value_width=32):

    Ether / IP / UDP(dport=34952) / Paxos{ msg_type(8) inst(16) rnd(16)
                                            vrnd(16) vvalue(32) }

  - msg_type : 0 = PHASE_1A (prepare), 1 = PHASE_2A (accept),
               2 = PROMISE (acceptor->proposer), 3 = ACCEPTED (acceptor->learner)
  - inst     : 16-bit consensus instance / slot id (always 0 at this single-slot
               anchor; multi-slot siblings index a register array by it)
  - rnd      : proposer's ballot / round number for this message
  - vrnd     : round at which vvalue was accepted (echoed on a PROMISE; set to
               rnd on an ACCEPTED)
  - vvalue   : the consensus value (carried on a PHASE_2A and echoed on the
               acceptor's replies)

`bind_layers` chains the dissection on the paxos UDP port so the evaluation
packet_builder constructs the header from a test_cases layer spec and the
verifier reads `Paxos.msg_type` / `Paxos.vrnd` / `Paxos.vvalue` off a SUT's
egress packet regardless of which P4 program produced it.
"""
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField, IntField
from scapy.all import UDP

PAXOS_UDP_PORT = 34952

PHASE_1A = 0
PHASE_2A = 1
PROMISE = 2
ACCEPTED = 3


class Paxos(Packet):
    name = "Paxos"
    fields_desc = [
        ByteField("msg_type", PHASE_1A),
        ShortField("inst", 0),       # 16-bit slot id
        ShortField("rnd", 0),        # 16-bit ballot (round_width=16)
        ShortField("vrnd", 0),       # 16-bit accepted round
        IntField("vvalue", 0),       # 32-bit value (value_width=32)
    ]


bind_layers(UDP, Paxos, dport=PAXOS_UDP_PORT)
