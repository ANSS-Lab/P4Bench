"""Scapy layer definitions for GTP-U (3GPP TS 29.281), for
benchmark/composition/upf_router_anchor (the GTP-U-UPF ∘ IPv4-router composite).

Reused from the audited P-GTPUEncap convention. Three layers:
  - GTPU            — the 8-byte mandatory GTPv1-U header
  - GTPUOpt         — the 4-byte optional field (Seq / N-PDU / Next-Ext-Type),
                      present whenever any of the E/S/PN flags is set
  - GTPUPduSession  — the 4-byte 5G PDU Session Container extension header
                      (Next Extension Header Type 0x85), carrying the QFI

The anchor (D5.0) seed emits only the bare GTPU header (E=0, no container);
the optional/container layers are bound so the verifier can still parse a
SUT egress packet that adds them (and so the same headers serve harder bands).

`guess_payload_class` chains the dissection:
  UDP(dport=2152) → GTPU → [GTPUOpt → GTPUPduSession*] → inner IP
"""
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, ShortField, IntField, XByteField
from scapy.all import UDP, IP

GTPU_UDP_PORT = 2152
GTPU_MSG_GPDU = 255
GTPU_MSG_END_MARKER = 254
NEXT_EXT_PDU_SESSION = 0x85
NEXT_EXT_NONE = 0x00


class GTPU(Packet):
    name = "GTPU"
    fields_desc = [
        BitField("version", 1, 3),      # GTPv1-U: MUST be 1
        BitField("pt", 1, 1),           # Protocol Type: MUST be 1 (GTP, not GTP')
        BitField("spare", 0, 1),
        BitField("e", 0, 1),            # Extension Header flag
        BitField("s", 0, 1),            # Sequence Number flag
        BitField("pn", 0, 1),           # N-PDU Number flag
        ByteField("msgtype", GTPU_MSG_GPDU),
        ShortField("length", 0),        # octets after the first 8 mandatory octets
        IntField("teid", 0),
    ]

    def guess_payload_class(self, payload):
        if self.e or self.s or self.pn:
            return GTPUOpt
        if self.msgtype == GTPU_MSG_GPDU:
            return IP
        return Packet           # End Marker (254) etc. carry no T-PDU


class GTPUOpt(Packet):
    name = "GTPUOpt"
    fields_desc = [
        ShortField("seqnum", 0),
        ByteField("npdu", 0),
        XByteField("next_ext", NEXT_EXT_NONE),
    ]

    def guess_payload_class(self, payload):
        if self.next_ext == NEXT_EXT_PDU_SESSION:
            return GTPUPduSession
        return IP


class GTPUPduSession(Packet):
    name = "GTPUPduSession"
    fields_desc = [
        ByteField("ext_len", 1),        # extension-header length in 4-octet units
        BitField("pdu_type", 0, 4),     # 0 = DL PDU Session Information
        BitField("spare0", 0, 4),
        BitField("ppp", 0, 1),
        BitField("rqi", 0, 1),
        BitField("qfi", 0, 6),          # QoS Flow Identifier
        XByteField("next_ext", NEXT_EXT_NONE),
    ]

    def guess_payload_class(self, payload):
        if self.next_ext == NEXT_EXT_PDU_SESSION:
            return GTPUPduSession
        return IP


bind_layers(UDP, GTPU, dport=GTPU_UDP_PORT)
