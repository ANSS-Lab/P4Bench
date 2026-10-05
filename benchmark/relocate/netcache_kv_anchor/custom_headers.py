"""Scapy layer definition for the NetCache key-value application header
(over UDP), for benchmark/relocate/netcache_kv_disc.

NetCache (Jin et al., SOSP'17) carries KV operations in a custom application
header. This v1 instance uses a fixed-width single-value form:

    Ether / IP / UDP(dport=8888) / NetCache{ op(8) key(64) value(32) }

  - op    : 0 = GET, 1 = PUT, 2 = DELETE, 3 = GET_RESPONSE (switch-originated)
  - key   : 64-bit KV key
  - value : 32-bit value (carried on a GET_RESPONSE the switch originates, and
            on a PUT request; ignored on GET / DELETE requests)

`bind_layers` chains the dissection so the verifier can parse a SUT's egress
packet (e.g. a forwarded miss) regardless of which P4 module produced it.
"""
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, LongField, IntField
from scapy.all import UDP

NETCACHE_UDP_PORT = 8888

OP_GET = 0
OP_PUT = 1
OP_DELETE = 2
OP_GET_RESPONSE = 3


class NetCache(Packet):
    name = "NetCache"
    fields_desc = [
        ByteField("op", OP_GET),
        LongField("key", 0),          # 64-bit KV key
        IntField("value", 0),         # 32-bit value
    ]


bind_layers(UDP, NetCache, dport=NETCACHE_UDP_PORT)
