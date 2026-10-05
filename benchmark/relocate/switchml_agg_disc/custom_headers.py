"""Scapy layer for the SwitchML/ATP in-network-aggregation header.

A minimal on-the-wire aggregation block carried directly over Ethernet
(ethertype 0x88B5, the IEEE Local Experimental EtherType). The block
stamps the (job_id, slot_id, worker_id) triple the switch needs to route
a contribution to its aggregation slot and detect the barrier, followed
by the single integer value carried by this packet at vector_width=1.

The aggregated *result* the switch returns to the workers is the same
header with `val` rewritten to the slot's reduction — there is no
separate result header, exactly as in SwitchML (the result packet is the
completing packet, multicast back to the worker group).
"""

from scapy.fields import ShortField, IntField
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers


class SwitchML(Packet):
    name = "SwitchML"
    fields_desc = [
        ShortField("job_id", 1),       # tenant / training-job id
        ShortField("slot_id", 0),      # pool index — which aggregation slot
        ShortField("worker_id", 0),    # contributing worker (bitmap index)
        ShortField("reserved", 0),     # alignment / future flags
        IntField("val", 0),            # the single int32 value (vector_width == 1)
    ]


bind_layers(Ether, SwitchML, type=0x88B5)
