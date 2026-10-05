"""Scapy layer for the IEEE 1588-2008/2019 PTP common header (34 bytes).

This is the PTP common message header carried, in this task, over UDP/IPv4
(IEEE 1588 Annex D): event messages on UDP destination port 319, general
messages on port 320. The byte layout matches the on-wire format the task
description specifies so a SUT-authored P4 parser reads the same bytes:

  byte  0 : transportSpecific(4) ++ messageType(4)   -- messageType = low nibble
  byte  1 : minorVersionPTP(4)    ++ versionPTP(4)
  bytes 2-3 : messageLength
  byte  4 : domainNumber
  byte  5 : minorSdoId / reserved
  bytes 6-7 : flagField
  bytes 8-15 : correctionField (bit<64>, units of 2^-16 ns)
  bytes 16-19 : messageTypeSpecific / reserved  (cleared after correction)
  bytes 20-29 : sourcePortIdentity (clockIdentity[8] ++ portNumber[2])
  bytes 30-31 : sequenceId
  byte 32 : controlField
  byte 33 : logMessageInterval

The PTP message-body (after the common header) is treated as opaque UDP
payload by the transparent clock and is not modelled here.
"""

from scapy.fields import BitField, ByteField, ShortField, SignedByteField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers


class PTP(Packet):
    name = "PTP"
    fields_desc = [
        BitField("transportSpecific", 0, 4),
        BitField("messageType", 0, 4),            # 0x0 Sync, 0x1 Delay_Req, 0x2 Pdelay_Req,
                                                  # 0x3 Pdelay_Resp, 0x8 Follow_Up, 0x9 Delay_Resp,
                                                  # 0xA Pdelay_Resp_Follow_Up, 0xB Announce,
                                                  # 0xC Signaling, 0xD Management
        BitField("minorVersionPTP", 0, 4),
        BitField("versionPTP", 2, 4),
        ShortField("messageLength", 44),
        ByteField("domainNumber", 0),
        ByteField("minorSdoId", 0),
        ShortField("flagField", 0),
        BitField("correctionField", 0, 64),       # 2^-16 ns units; transparent clock ADDS residence here
        BitField("reserved", 0, 32),               # messageTypeSpecific; cleared after correction
        BitField("clockIdentity", 0, 64),          # sourcePortIdentity high 8 bytes
        ShortField("portNumber", 1),               # sourcePortIdentity low 2 bytes
        ShortField("sequenceId", 0),
        ByteField("controlField", 0),
        SignedByteField("logMessageInterval", 0),
    ]


# IEEE 1588 Annex D: PTP over UDP/IPv4. Event port 319, general port 320.
bind_layers(UDP, PTP, dport=319)
bind_layers(UDP, PTP, dport=320)
