"""Python oracle for benchmark/relocate/gtpu_encap_disc.

Implements P-GTPUEncap's rule sequence under the
discriminating-band D5.1 seed:

  - R0   non-handled drop (no Ether / no IP / no UDP on N3 / unbound port)
  - R1   uplink decap   (N3 + UDP(2152) + G-PDU + outer dst == UPF N3 IP
                          + TEID lookup → strip outer IP/UDP/GTP-U, rewrite
                          L2 toward N6, forward inner T-PDU)
  - R2   downlink encap (N6 + bare IP to a UE bearer + nexthop → push outer
                          IP/UDP(2152)/GTP-U(egress TEID) + PDU Session
                          Container(QFI), rewrite L2 toward the gNB, forward)
  - R3   uplink unknown-TEID drop
  - R4   uplink malformed-GTP-U drop (version != 1 ∨ pt != 1, strict mode)
  - R5   uplink End Marker (msgtype 254) drop
  - R6   downlink unknown-UE drop
  - R7   downlink encap-oversize drop (gated; mtu_enforcement == ignore here)

Per the parametric-source contract: every parameter
named in the pattern's `mutation_operators` surface is read from `state`
at runtime (`state["config"]` for scalars, `state[<table>]` for the
PDR/FAR/nexthop tables). Seed values never enter as source-level constants —
this is what lets parameter rebinding reuse the same
audited module.

step() is the standard oracle form: step(packet, ingress_port,
state) -> StepResult. Packet introspection is string-name based so it
tolerates a Scapy packet built from any custom_headers module instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import zlib


# ── StepResult — oracle return shape ───────────────────────────

@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ── GTP-U layer defs (for OUTPUT construction; mirror custom_headers.py) ─

def _gtpu_layers():
    from scapy.packet import Packet, bind_layers
    from scapy.fields import BitField, ByteField, ShortField, IntField, XByteField
    from scapy.all import UDP, IP

    if "GTPU" in globals():
        return globals()["GTPU"], globals()["GTPUOpt"], globals()["GTPUPduSession"]

    class GTPU(Packet):
        name = "GTPU"
        fields_desc = [
            BitField("version", 1, 3), BitField("pt", 1, 1), BitField("spare", 0, 1),
            BitField("e", 0, 1), BitField("s", 0, 1), BitField("pn", 0, 1),
            ByteField("msgtype", 255), ShortField("length", 0), IntField("teid", 0),
        ]
        def guess_payload_class(self, payload):
            if self.e or self.s or self.pn:
                return GTPUOpt
            if self.msgtype == 255:
                return IP
            return Packet

    class GTPUOpt(Packet):
        name = "GTPUOpt"
        fields_desc = [ShortField("seqnum", 0), ByteField("npdu", 0),
                       XByteField("next_ext", 0x00)]
        def guess_payload_class(self, payload):
            return GTPUPduSession if self.next_ext == 0x85 else IP

    class GTPUPduSession(Packet):
        name = "GTPUPduSession"
        fields_desc = [
            ByteField("ext_len", 1), BitField("pdu_type", 0, 4), BitField("spare0", 0, 4),
            BitField("ppp", 0, 1), BitField("rqi", 0, 1), BitField("qfi", 0, 6),
            XByteField("next_ext", 0x00),
        ]
        def guess_payload_class(self, payload):
            return GTPUPduSession if self.next_ext == 0x85 else IP

    bind_layers(UDP, GTPU, dport=2152)
    globals().update(GTPU=GTPU, GTPUOpt=GTPUOpt, GTPUPduSession=GTPUPduSession)
    return GTPU, GTPUOpt, GTPUPduSession


# ── Packet-introspection helpers (Scapy + dict tolerant) ────────────────

def _has(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet
    return False


def _field(packet, layer: str, fname: str, default=None, nb: int = 1):
    # scapy getlayer's occurrence index `nb` is 1-based.
    if hasattr(packet, "getlayer"):
        try:
            lay = packet.getlayer(layer, nb)
            if lay is not None:
                return getattr(lay, fname, default)
        except Exception:
            pass
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _inner_ip(packet):
    """Return the inner IP layer of a decap input (the 2nd IP), or None."""
    from scapy.all import IP
    if hasattr(packet, "getlayer"):
        return packet.getlayer(IP, 2)        # 1 = outer, 2 = inner
    return None


def _outer_ip(packet):
    from scapy.all import IP
    if hasattr(packet, "getlayer"):
        return packet.getlayer(IP, 1)
    return None


# ── State lookups ───────────────────────────────────────────────────────

def _port_role(ingress_port: int, state: Dict[str, Any]) -> str:
    if ingress_port in state.get("n3_ports", []):
        return "n3"
    if ingress_port in state.get("n6_ports", []):
        return "n6"
    return "unknown"


def _ul_session(teid: int, state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for e in state.get("ul_session_entries", []):
        if int(e["teid"]) == int(teid):
            return e
    return None


def _dl_bearer(ue_ip: str, state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for e in state.get("dl_bearer_entries", []):
        if e["ue_ip"] == ue_ip:
            return e
    return None


def _n3_nexthop(gnb_ip: str, state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for e in state.get("n3_nexthop_entries", []):
        if e["gnb_ip"] == gnb_ip:
            return e
    return None


def _outer_udp_src(cfg: Dict[str, Any], five_tuple) -> int:
    mode = cfg.get("outer_udp_src_port_mode", "fixed")
    if mode == "fixed":
        return int(cfg.get("outer_udp_src_port_fixed_value", 2152))
    src, dst, proto, l4s, l4d = five_tuple
    payload = f"{src}|{dst}|{proto}|{l4s}|{l4d}".encode()
    algo = cfg.get("hash_algo", "crc16")
    if algo == "crc32":
        h = zlib.crc32(payload) & 0xFFFFFFFF
    elif algo == "xor_fold":
        h = 0
        for b in payload:
            h ^= b
        h = (h * 257) & 0xFFFF
    else:                                                       # crc16
        h = zlib.crc32(payload) & 0xFFFF
    return 49152 + (h % 16384)


# ── step() — oracle interface ──────────────────────────────────

def step(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    cfg = state.get("config", {})
    ns = state                                                  # stateless pattern
    role = _port_role(ingress_port, state)

    if not _has(packet, "Ether"):
        return _drop(ns, "R0: missing Ethernet")
    if not _has(packet, "IP"):
        return _drop(ns, "R0: missing IPv4")
    if role == "unknown":
        return _drop(ns, "R0: ingress port not bound to an N3/N6 role")

    if role == "n3":
        return _uplink(packet, state)
    return _downlink(packet, state)


# ── Uplink decap (R1 / R3 / R4 / R5) ────────────────────────────────────

def _uplink(packet, state: Dict[str, Any]) -> StepResult:
    cfg = state.get("config", {})
    if not _has(packet, "UDP"):
        return _drop(state, "R0: N3 ingress without outer UDP")
    if int(_field(packet, "UDP", "dport", 0)) != int(cfg.get("outer_udp_dst_port", 2152)):
        return _drop(state, "R0: N3 UDP dport != GTP-U port (non-GTP-U transit)")
    if not _has(packet, "GTPU"):
        return _drop(state, "R0: N3 ingress without GTP-U")

    msgtype = int(_field(packet, "GTPU", "msgtype", 255))
    if msgtype == 254:                                          # End Marker
        if cfg.get("end_marker_handling", "drop") == "drop":
            return _drop(state, "R5: End Marker dropped (signalling, not user data)",
                         invariants=[("R5_uplink_end_marker", {"msgtype": 254})])
        # forward_to_n6 is a non-conformant foil — not active at this seed
        return _drop(state, "R5: End Marker (forward_to_n6 not modelled at this seed)")

    if bool(cfg.get("teid_validation_strict", False)):
        version = int(_field(packet, "GTPU", "version", 1))
        pt = int(_field(packet, "GTPU", "pt", 1))
        if version != 1 or pt != 1:
            return _drop(state, "R4: malformed GTP-U header (version/PT) under strict",
                         invariants=[("R4_uplink_malformed_gtpu_drop",
                                      {"version": version, "pt": pt})])

    outer_dst = _field(packet, "IP", "dst", None, nb=1)
    if outer_dst != cfg.get("upf_n3_ip"):
        return _drop(state, "R0/R1: outer IPv4 dst is not this UPF's N3 endpoint")

    teid = int(_field(packet, "GTPU", "teid", 0))
    sess = _ul_session(teid, state)
    if sess is None:
        return _drop(state, "R3: unknown TEID",
                     invariants=[("R3_uplink_unknown_teid_drop", {"teid": teid})])

    inner = _inner_ip(packet)
    if inner is None:
        return _drop(state, "R1: GTP-U payload missing inner IPv4 T-PDU")

    from scapy.all import Ether
    out = Ether(src=sess["n6_src_mac"], dst=sess["n6_dst_mac"]) / inner

    return StepResult(
        output_packets={int(sess["n6_egress_port"]): [out]},
        new_state=state,
        decision="forward",
        invariant_log=[
            ("R1_uplink_decap", {"teid": teid, "egress_port": int(sess["n6_egress_port"])}),
            ("teid_decap_routing_correctness", {"teid": teid}),
            ("inner_payload_persistence", {"inner_dst": getattr(inner, "dst", None)}),
        ],
    )


# ── Downlink encap (R2 / R6 / R7) ───────────────────────────────────────

def _downlink(packet, state: Dict[str, Any]) -> StepResult:
    cfg = state.get("config", {})
    if _has(packet, "GTPU"):
        return _drop(state, "R0: N6 ingress already tunnelled")

    ue_ip = _field(packet, "IP", "dst", None, nb=1)
    bearer = _dl_bearer(ue_ip, state)
    if bearer is None:
        return _drop(state, "R6: no UE bearer for destination",
                     invariants=[("R6_downlink_unknown_ue_drop", {"ue_ip": ue_ip})])

    nh = _n3_nexthop(bearer["gnb_ip"], state)
    if nh is None:
        return _drop(state, "R2: gNB underlay nexthop unresolved")

    inner = _outer_ip(packet)                                   # the lone IP = T-PDU
    inner_bytes = len(bytes(inner)) if inner is not None else 0

    ext_on = cfg.get("gtpu_ext_header_handling", "none") == "pdu_session_container"
    if cfg.get("mtu_enforcement", "ignore") == "strict_drop_oversize":
        overhead = 14 + 20 + 8 + 8 + (8 if ext_on else 0)
        if inner_bytes + overhead > int(cfg.get("outer_mtu", 1500)):
            return _drop(state, "R7: encap oversize under strict_drop_oversize",
                         invariants=[("R7_downlink_oversize_drop", {})])

    from scapy.all import Ether, IP, UDP
    GTPU, GTPUOpt, GTPUPduSession = _gtpu_layers()

    inner_proto = int(getattr(inner, "proto", 0) or 0)
    inner_l4s = int(_field(packet, "TCP", "sport", None) or _field(packet, "UDP", "sport", 0) or 0)
    inner_l4d = int(_field(packet, "TCP", "dport", None) or _field(packet, "UDP", "dport", 0) or 0)
    outer_udp_src = _outer_udp_src(
        cfg, (getattr(inner, "src", ""), ue_ip, inner_proto, inner_l4s, inner_l4d))

    dscp = 0
    if cfg.get("dscp_copy_policy", "none") == "copy_inner_to_outer":
        dscp = (int(getattr(inner, "tos", 0) or 0)) >> 2
    tos = (dscp << 2)

    # GTP-U Length = octets after the first 8 mandatory octets
    gtpu_length = inner_bytes + (8 if ext_on else 0)
    qfi = int(bearer.get("qfi", 0)) if cfg.get("qfi_policy", "none") == "set_from_bearer" else 0

    gtpu = GTPU(version=1, pt=1, e=1 if ext_on else 0, msgtype=255,
                teid=int(bearer["egress_teid"]), length=gtpu_length)
    if ext_on:
        chain = (gtpu / GTPUOpt(seqnum=0, npdu=0, next_ext=0x85)
                 / GTPUPduSession(ext_len=1, pdu_type=0, qfi=qfi, next_ext=0x00) / inner)
    else:
        chain = gtpu / inner

    out = (Ether(src=nh["outer_src_mac"], dst=nh["outer_dst_mac"], type=0x0800)
           / IP(src=cfg.get("upf_n3_ip"), dst=bearer["gnb_ip"], ttl=64, proto=17,
                tos=tos, flags="DF")
           / UDP(sport=outer_udp_src, dport=int(cfg.get("outer_udp_dst_port", 2152)), chksum=0)
           / chain)

    return StepResult(
        output_packets={int(nh["n3_egress_port"]): [out]},
        new_state=state,
        decision="forward",
        invariant_log=[
            ("R2_downlink_encap", {"teid": int(bearer["egress_teid"]),
                                   "egress_port": int(nh["n3_egress_port"])}),
            ("outer_header_field_completeness", {"outer_src": cfg.get("upf_n3_ip"),
                                                 "outer_dst": bearer["gnb_ip"]}),
            ("gtpu_length_field_correct", {"length": gtpu_length}),
            ("gtpu_header_wellformed_on_tx", {"version": 1, "pt": 1, "msgtype": 255}),
            ("qfi_set_on_tx", {"qfi": qfi}) if ext_on else ("encap", {}),
        ],
    )


# ── helpers ──────────────────────────────────────────────────────────────

def _drop(state, reason, invariants=None) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=(invariants or []) + [("drop_reason", reason)])


def reset():
    return None
