"""Scapy layers for a BOUNDED, fixed-offset TLS ClientHello carrying SNI.

Full RFC 8446 §4.1.2 ClientHello is variable-length: the SNI sits behind
three length-prefixed lists (legacy_session_id, cipher_suites,
legacy_compression_methods) and a variable-length extension list. A v1model
parser cannot walk that with dynamic offset arithmetic, so P-TLSSNIRoute
constrains the layout to a BOUNDED, FIXED-OFFSET prefix that a loop-free
match-action parser can `extract` in a finite number of states (pattern
bridging_notes, "PARSING FEASIBILITY"). This module models exactly that
bounded layout so the verifier's packet builder can construct it and the
transformation assertions can read the SNI HostName by name.

The bounded layout this instance settles on (all fields fixed-width — the
variable-length lists are pinned to their configured maxima, shorter inputs
are zero-padded to the field width, longer inputs are out of scope and
handled per malformed_handling):

  TLSRecord     : content_type(8) legacy_version(16) length(16)        = 5 B
  TLSHandshake  : msg_type(8) length(24)                               = 4 B
  TLSClientHello: legacy_version(16) random(256)                       = 34 B
                  session_id_len(8) session_id(256, fixed 32 B)        = 33 B
                  cipher_suites_len(16) cipher_suites(128, fixed 16 B) = 18 B
                  comp_len(8) comp_methods(8, fixed 1 B)               = 2 B
                  extensions_len(16)                                   = 2 B
  TLSExtSNI     : ext_type(16=0x0000) ext_len(16)                      = 4 B
                  sni_list_len(16) name_type(8=host_name) name_len(16) = 5 B
                  host_name(128, fixed 16 B — the bounded SNI key)     = 16 B

`host_name` is a fixed 16-byte field: the bounded fixed-width SNI key the
classifier matches on. A name shorter than 16 bytes is right-padded with
NUL (0x00); the policy table is keyed on the NUL-padded 16-byte value so
the data-plane match is a plain exact match. The SNI sits at a fixed byte
offset from the start of the record (a single admissible extension before
it, within max_extension_count), so the parser reaches it without a loop.

The verifier (evaluation/verifier.py::_resolve_layer_cls) only natively
resolves Ether/IP/TCP/UDP/ICMP/ARP plus whatever this module exports, so
every layer the tests assert on (TLSExtSNI.host_name, the TLSRecord /
TLSHandshake / TLSClientHello sub-headers for the payload-persistence
round-trip) is declared here. Scapy is told to bind the TLS record after
TCP/443 so it re-dissects egress pcaps into these flat layers.
"""

from scapy.fields import (
    BitField,
    ShortField,
    StrFixedLenField,
    XByteField,
    XShortField,
)
from scapy.layers.inet import TCP
from scapy.packet import Packet, bind_layers


# Fixed widths for the bounded layout (bytes).
SESSION_ID_W = 32          # legacy_session_id<0..32>, pinned to its 32-byte max
CIPHER_W = 16              # cipher_suites prefix walked within the byte budget
COMP_W = 1                 # legacy_compression_methods<1..>, the null(0) byte
HOSTNAME_W = 16            # bounded fixed-width SNI key


class TLSRecord(Packet):
    name = "TLSRecord"
    fields_desc = [
        XByteField("content_type", 22),        # 22 = handshake
        XShortField("legacy_version", 0x0301),  # TLS 1.0 record version (common)
        ShortField("length", 0),                # record payload length
    ]


class TLSHandshake(Packet):
    name = "TLSHandshake"
    fields_desc = [
        XByteField("msg_type", 1),              # 1 = client_hello
        BitField("length", 0, 24),              # 3-octet handshake length
    ]


class TLSClientHello(Packet):
    name = "TLSClientHello"
    fields_desc = [
        XShortField("legacy_version", 0x0303),  # TLS 1.2 ClientHello version
        StrFixedLenField("random", b"\x00" * 32, 32),
        XByteField("session_id_len", SESSION_ID_W),
        StrFixedLenField("session_id", b"\x00" * SESSION_ID_W, SESSION_ID_W),
        ShortField("cipher_suites_len", CIPHER_W),
        StrFixedLenField("cipher_suites", b"\x00" * CIPHER_W, CIPHER_W),
        XByteField("comp_len", COMP_W),
        StrFixedLenField("comp_methods", b"\x00" * COMP_W, COMP_W),
        ShortField("extensions_len", 0),
    ]


class TLSExtSNI(Packet):
    name = "TLSExtSNI"
    fields_desc = [
        XShortField("ext_type", 0x0000),        # server_name extension
        ShortField("ext_len", 0),
        ShortField("sni_list_len", 0),          # ServerNameList length
        XByteField("name_type", 0),             # 0 = host_name(0)
        ShortField("name_len", 0),              # declared HostName length
        StrFixedLenField("host_name", b"\x00" * HOSTNAME_W, HOSTNAME_W),
    ]


def sni_key(name: str) -> bytes:
    """NUL-pad an ASCII hostname to the fixed HOSTNAME_W key width.

    Names longer than HOSTNAME_W are out of scope for this bounded layout
    (they would not fit the fixed SNI key field); the generator never
    builds one.
    """
    b = name.encode("ascii")
    if len(b) > HOSTNAME_W:
        raise ValueError(f"SNI {name!r} exceeds {HOSTNAME_W}-byte bounded key")
    return b + b"\x00" * (HOSTNAME_W - len(b))


# Bind the bounded TLS record after TCP/443 so the harness re-dissects the
# egress pcap into these flat layers (matching the DNSQuery precedent).
bind_layers(TCP, TLSRecord, dport=443)
bind_layers(TLSRecord, TLSHandshake)
bind_layers(TLSHandshake, TLSClientHello)
bind_layers(TLSClientHello, TLSExtSNI)
