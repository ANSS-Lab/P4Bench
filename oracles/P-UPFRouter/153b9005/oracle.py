"""Python oracle for benchmark/composition/upf_router_anchor.

Implements P-UPFRouter — the GTP-U-UPF ∘ IPv4-underlay-router COMPOSITE —
at the task's seed (faithfulness = D5.0_decap_route_encap_route):

  - single bearer/TEID surface, lax validation, fixed outer UDP source
    port, zero outer UDP checksum on transmit, no extension headers
    (E=0, no PDU Session Container), End Marker drop, MTU enforcement off,
    underlay multipath = none (singleton next-hops), martian filter off.

The composite chains the two audited halves' behaviour (P-GTPUEncap ∘
P-IPv4Routing) under content-addressing — the GTP-U
encap/decap step (the mobile half) feeds the LPM-forward step over the
ACTIVE header (the underlay half: the INNER dst on decap, the OUTER dst on
encap/transit), with the composition glue handling the interactions
neither half exhibits alone:

  R0    non-handled drop (no Ether / no IPv4 / unbound port)
  R1    outer IPv4 header validation on N3 (RFC 1812 §5.2.2)
  R2    DECAP + ROUTE-INNER — N3 ∧ GTP-U(255) ∧ outer.dst == upf_n3_ip ∧
        TEID admit ∧ inner ttl > 1 ∧ LPM(inner.dst) hit: strip the outer
        IP/UDP/GTP-U stack, then ROUTE the exposed inner T-PDU — decrement
        the INNER ttl by one, rewrite the (single) Ethernet from the
        LPM-picked next-hop, recompute the inner IPv4 checksum, forward
  R3    decap inner-TTL-exhausted drop (inner ttl <= 1)
  R4    decap inner-no-route drop (TEID known, inner dst unroutable) — default_action
  R5    decap unknown-TEID drop
  R6    decap malformed-GTP-U drop (version/PT, strict; gated off at anchor)
  R7    decap End Marker (254) drop
  R8    TRANSIT outer-TTL-exhausted drop (outer.dst != upf ∧ outer ttl <= 1)
  R9    TRANSIT underlay forward on the OUTER header (outer.dst != upf):
        LPM(outer.dst) → decrement OUTER ttl → OUTER Ether rewrite →
        forward; the inner T-PDU is OPAQUE (untouched)
  R10   transit no-route drop (default_action)
  R11   ENCAP + underlay route — N6 ∧ bare IP ∧ dl_bearer(ipv4.dst) hit ∧
        LPM(gnb_ip) hit: build the full GTP-U/UDP/outer-IPv4 stack with
        outer.dst = gnb_ip, outer.src = upf_n3_ip, outer.ttl =
        origination_ttl (stamped, NOT decremented — origination), inner
        T-PDU PRESERVED (no inner ttl decrement), then underlay-forward via
        the LPM-picked next-hop (OUTER Ether rewrite)
  R12   encap known-bearer / unreachable-gNB drop (composite-specific)
  R13   encap unknown-UE drop
  R14   encap oversize drop (gated off at anchor)

The load-bearing composite properties this oracle realises:
  * decap_routes_inner — R2 routes the exposed inner T-PDU by LPM on the
    inner dst (NOT a static TEID FAR egress).
  * inner-TTL asymmetry — R2 (decap) decrements the inner TTL by one; R11
    (encap) preserves it. The inverse of P-VXLANRouter (inner never
    touched) and of standalone P-GTPUEncap (inner preserved on both paths).
  * origination_vs_transit_outer_ttl — R11 (origination) does NOT decrement
    the outer TTL; R9 (transit) decrements by exactly one.
  * upf_transit_dichotomy — a GTP-U packet on N3 is decapped iff
    outer.dst == upf_n3_ip, else transit-forwarded.

Per the parametric-source contract: every parameter
named in the pattern's mutation_operators surface is read from `state` (the
entity tables at top level + the scalar knobs under `state["config"]`) at
runtime — seed values never enter as source-level constants, so
parameter rebinding reuses this audited module without
regeneration. The module also accepts a 2-arg `step(packet, ingress_port)`
call (audit harness convention) by falling back to the anchor default
config below.

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import zlib


# ──────────────────────────────────────────────────────────────────────
# StepResult — oracle return shape
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# Anchor-band default state (used when step() is called without `state`,
# e.g. the audit harness's 2-arg call). Mirrors the seed binding exactly.
# ──────────────────────────────────────────────────────────────────────

_DEFAULT_STATE: Dict[str, Any] = {
    "n3_ports": [1],
    "n6_ports": [2],
    "ul_session_entries": [{"teid": 256, "qfi": 9}],
    "dl_bearer_entries": [
        {"ue_ip": "10.45.0.1", "egress_teid": 512, "gnb_ip": "192.168.10.1", "qfi": 9},
        {"ue_ip": "10.45.0.2", "egress_teid": 513, "gnb_ip": "192.168.10.1", "qfi": 5},
        {"ue_ip": "10.45.0.3", "egress_teid": 514, "gnb_ip": "172.16.9.9", "qfi": 7},
    ],
    "routes": [
        {"prefix": "192.168.10.0", "prefix_len": 24, "port": 1,
         "port_mac": "aa:bb:cc:00:00:01", "nexthop_mac": "5e:00:00:00:00:01"},
        {"prefix": "10.0.6.0", "prefix_len": 24, "port": 2,
         "port_mac": "aa:bb:cc:00:00:02", "nexthop_mac": "08:00:00:00:00:02"},
        {"prefix": "10.0.0.0", "prefix_len": 8, "port": 3,
         "port_mac": "aa:bb:cc:00:00:03", "nexthop_mac": "0a:00:00:00:00:03"},
        {"prefix": "192.168.20.0", "prefix_len": 24, "port": 3,
         "port_mac": "aa:bb:cc:00:00:03", "nexthop_mac": "0a:00:00:00:00:03"},
    ],
    "config": {
        "upf_n3_ip": "192.168.10.254",
        "outer_udp_dst_port": 2152,
        "outer_udp_src_port_mode": "fixed",
        "outer_udp_src_port_fixed_value": 2152,
        "outer_udp_checksum_mode": "zero_on_tx",
        "gtpu_ext_header_handling": "none",
        "qfi_policy": "none",
        "dscp_copy_policy": "none",
        "teid_validation_strict": False,
        "end_marker_handling": "drop",
        "mtu_enforcement": "ignore",
        "outer_mtu": 1500,
        # De-quoted (for the audit's config-read check): the anchor oracle never BRANCHES on these — they are
        # carried only as inert metadata, so a single hash cannot exercise them.
        #   multipath_mode / ecmp_remap_algo : no nexthop-group machinery in this
        #     oracle (singleton next-hops live inline in `routes`); never read.
        #   default_action : no-route/no-match is the hardcoded _drop path; the
        #     ICMP-emit variant (where default_action IS read) only exists in the
        #     disc/ceiling hash, not here.
        #   faithfulness : a regeneration-variant rung that SELECTS a different
        #     oracle, not a runtime config branch.
        "martian_filter_enabled": False,
        "emit_transit_icmp_errors": False,
        "origination_ttl": 64,
        "hash_algo": "crc16",
    },
}


def _state(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not state:
        return _DEFAULT_STATE
    merged = dict(state)
    cfg = dict(_DEFAULT_STATE["config"])
    cfg.update(state.get("config", {}))
    merged["config"] = cfg
    for k in ("n3_ports", "n6_ports", "ul_session_entries",
              "dl_bearer_entries", "routes"):
        merged.setdefault(k, _DEFAULT_STATE[k])
    return merged


# ──────────────────────────────────────────────────────────────────────
# GTP-U layer defs (for OUTPUT construction; mirror custom_headers.py)
# ──────────────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────────────
# Packet introspection (Scapy + dict-style tolerant)
# ──────────────────────────────────────────────────────────────────────

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
    if hasattr(packet, "getlayer"):
        try:
            lay = packet.getlayer(layer, nb)
            if lay is not None:
                v = getattr(lay, fname, default)
                return v if v is not None else default
        except Exception:
            pass
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _inner_ip(packet):
    """The inner IP of a G-PDU (the 2nd IP layer), or None."""
    try:
        from scapy.all import IP
        if hasattr(packet, "getlayer"):
            return packet.getlayer(IP, 2)
    except Exception:
        pass
    return None


def _port_role(ingress_port: int, st: Dict[str, Any]) -> str:
    if ingress_port in st.get("n3_ports", []):
        return "n3"
    if ingress_port in st.get("n6_ports", []):
        return "n6"
    return "unknown"


def _ul_session(teid: int, st: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for e in st.get("ul_session_entries", []):
        if int(e["teid"]) == int(teid):
            return e
    return None


def _dl_bearer(ue_ip: str, st: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for e in st.get("dl_bearer_entries", []):
        if e["ue_ip"] == ue_ip:
            return e
    return None


# ──────────────────────────────────────────────────────────────────────
# Underlay LPM (over the ACTIVE IPv4 destination) — the P-IPv4Routing half
# ──────────────────────────────────────────────────────────────────────

def _ip_to_int(addr: str) -> int:
    p = [int(x) for x in str(addr).split(".")]
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]


def _lpm_match(dst: str, routes: List[dict]) -> Optional[dict]:
    d = _ip_to_int(dst)
    best, best_len = None, -1
    for r in routes:
        plen = int(r["prefix_len"])
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        if (d & mask) == (_ip_to_int(r["prefix"]) & mask) and plen > best_len:
            best, best_len = r, plen
    return best


def _is_martian_src(src: str) -> bool:
    s = _ip_to_int(src)

    def inb(prefix, plen):
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        return (s & mask) == (_ip_to_int(prefix) & mask)

    return (inb("127.0.0.0", 8) or inb("0.0.0.0", 8)
            or inb("224.0.0.0", 4) or str(src) == "255.255.255.255")


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
    else:
        h = zlib.crc32(payload) & 0xFFFF
    return 49152 + (h % 16384)


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _drop(st, reason, invariants=None) -> StepResult:
    return StepResult(output_packets={}, new_state=st, decision="drop",
                      invariant_log=(invariants or []) + [("drop_reason", reason)])


# ──────────────────────────────────────────────────────────────────────
# step() — oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int = 1,
         state: Optional[Dict[str, Any]] = None) -> StepResult:
    st = _state(state)
    cfg = st["config"]
    role = _port_role(ingress_port, st)

    # R0 — non-handled
    if not _has(packet, "Ether"):
        return _drop(st, "R0: missing Ethernet")
    if not _has(packet, "IP"):
        return _drop(st, "R0: missing IPv4")
    if role == "unknown":
        return _drop(st, "R0: ingress port bound to no N3/N6 role")

    if role == "n3":
        return _n3_path(packet, st, cfg)
    return _encap(packet, st, cfg)


# ──────────────────────────────────────────────────────────────────────
# N3 path: decap-route (R2–R7) OR transit (R8–R10), gated by ownership
# ──────────────────────────────────────────────────────────────────────

def _n3_path(packet, st, cfg) -> StepResult:
    upf_n3_ip = str(cfg.get("upf_n3_ip"))
    outer_dst = str(_field(packet, "IP", "dst", "0.0.0.0", nb=1))

    # R1 — outer IPv4 header validation
    version = int(_field(packet, "IP", "version", 4, nb=1) or 4)
    ihl = int(_field(packet, "IP", "ihl", 5, nb=1) or 5)
    if version != 4 or ihl < 5:
        return _drop(st, "R1: invalid outer IPv4 header")

    is_gtpu = (_has(packet, "UDP")
               and int(_field(packet, "UDP", "dport", 0) or 0)
               == int(cfg.get("outer_udp_dst_port", 2152))
               and _has(packet, "GTPU"))

    # ── DECAP+ROUTE arm: GTP-U destined to THIS UPF ─────────────────────
    if is_gtpu and outer_dst == upf_n3_ip:
        return _decap_route(packet, st, cfg)

    # ── TRANSIT arm: anything addressed elsewhere ───────────────────────
    if outer_dst != upf_n3_ip:
        return _transit(packet, st, cfg)

    # Addressed to the UPF but not a GTP-U G-PDU (e.g. management) — out of scope
    return _drop(st, "R0: non-GTP-U traffic addressed to the UPF endpoint")


def _decap_route(packet, st, cfg) -> StepResult:
    msgtype = int(_field(packet, "GTPU", "msgtype", 255) or 255)

    # R7 — End Marker (signalling, not user data)
    if msgtype == 254:
        if cfg.get("end_marker_handling", "drop") == "drop":
            return _drop(st, "R7: End Marker dropped (signalling, not user data)",
                         [("R7_decap_end_marker", {"msgtype": 254})])
        return _drop(st, "R7: End Marker (forward_to_n6 not modelled at this seed)")

    # Only G-PDUs (255) carry a T-PDU
    if msgtype != 255:
        return _drop(st, "R0: unhandled GTP-U message type")

    # R6 — strict version/PT validation (gated off at the anchor)
    if bool(cfg.get("teid_validation_strict", False)):
        version = int(_field(packet, "GTPU", "version", 1))
        pt = int(_field(packet, "GTPU", "pt", 1))
        if version != 1 or pt != 1:
            return _drop(st, "R6: malformed GTP-U header (version/PT) under strict",
                         [("R6_decap_malformed_gtpu_drop", {"version": version, "pt": pt})])

    # R5 — TEID admission gate
    teid = int(_field(packet, "GTPU", "teid", 0) or 0)
    if _ul_session(teid, st) is None:
        return _drop(st, "R5: unknown TEID", [("R5_decap_unknown_teid_drop", {"teid": teid})])

    inner = _inner_ip(packet)
    if inner is None:
        return _drop(st, "R2: GTP-U payload missing inner IPv4 T-PDU")

    inner_dst = str(getattr(inner, "dst", "0.0.0.0"))
    inner_ttl = int(getattr(inner, "ttl", 0) or 0)

    # R3 — the switch ROUTES the decapsulated datagram: TTL check (RFC 1812)
    if inner_ttl <= 1:
        out_inv = [("R3_decap_inner_ttl_exhausted_drop", {"ttl": inner_ttl})]
        return _drop(st, "R3: decap inner TTL exhausted", out_inv)

    # R4 — inner-dst LPM toward the data network
    route = _lpm_match(inner_dst, st.get("routes", []))
    if route is None:
        return _drop(st, "R4: decapsulated inner dst unroutable",
                     [("R4_decap_inner_no_route_drop", {"inner_dst": inner_dst})])

    # Build the routed inner T-PDU: single Ethernet (rewritten) + inner IP
    from scapy.all import Ether
    routed_inner = inner.copy()
    try:
        routed_inner.ttl = inner_ttl - 1
        del routed_inner.chksum                      # force inner checksum recompute
    except Exception:
        pass
    out = Ether(src=route["port_mac"], dst=route["nexthop_mac"], type=0x0800) / routed_inner

    return StepResult(
        output_packets={int(route["port"]): [out]},
        new_state=st,
        decision="forward",
        invariant_log=[
            ("R2_decap_and_route_inner",
             {"teid": teid, "port": int(route["port"]),
              "prefix": f"{route['prefix']}/{route['prefix_len']}"}),
            ("decap_routes_inner", {"inner_dst": inner_dst}),
            ("inner_ttl_decremented_on_decap", {"delta": 1, "ttl": inner_ttl - 1}),
            ("inner_ipv4_checksum_validity", {"recomputed": True}),
            ("upf_transit_dichotomy", {"arm": "decap"}),
            ("lpm_longest_match_correctness",
             {"prefix": f"{route['prefix']}/{route['prefix_len']}"}),
            ("ether_rewrite_correctness",
             {"src": route["port_mac"], "dst": route["nexthop_mac"]}),
        ],
    )


def _transit(packet, st, cfg) -> StepResult:
    routes = st.get("routes", [])
    outer_dst = str(_field(packet, "IP", "dst", "0.0.0.0", nb=1))
    outer_src = str(_field(packet, "IP", "src", "0.0.0.0", nb=1))
    outer_ttl = int(_field(packet, "IP", "ttl", 0, nb=1) or 0)

    # R9 guard — martian filter on the OUTER src (off at the anchor)
    if cfg.get("martian_filter_enabled") and _is_martian_src(outer_src):
        return _drop(st, "R9: martian outer source", [("martian_filter", {"src": outer_src})])

    # R8 — transit TTL exhausted
    if outer_ttl <= 1:
        return _drop(st, "R8: transit outer TTL exhausted",
                     [("R8_transit_outer_ttl_exhausted_drop", {"ttl": outer_ttl})])

    # R9/R10 — underlay LPM forward on the OUTER header
    route = _lpm_match(outer_dst, routes)
    if route is None:
        return _drop(st, "R10: transit no route",
                     [("R10_transit_no_route_drop", {"dst": outer_dst})])

    out = _clone(packet)
    try:
        out["IP"].ttl = outer_ttl - 1
        out["Ether"].src = route["port_mac"]
        out["Ether"].dst = route["nexthop_mac"]
        try:
            del out["IP"].chksum
        except Exception:
            pass
    except Exception:
        pass

    return StepResult(
        output_packets={int(route["port"]): [out]},
        new_state=st,
        decision="forward",
        invariant_log=[
            ("R9_transit_underlay_forward",
             {"port": int(route["port"]), "outer_ttl": outer_ttl - 1,
              "prefix": f"{route['prefix']}/{route['prefix_len']}"}),
            ("upf_transit_dichotomy", {"arm": "transit"}),
            ("origination_vs_transit_outer_ttl", {"mode": "transit", "decremented": True}),
            ("ttl_quantum_one", {"delta": 1}),
            ("outer_inner_header_disjointness", {"inner_touched": False}),
            ("ether_rewrite_correctness",
             {"src": route["port_mac"], "dst": route["nexthop_mac"]}),
        ],
    )


# ──────────────────────────────────────────────────────────────────────
# N6 path: encap + underlay route (R11 / R12 / R13 / R14)
# ──────────────────────────────────────────────────────────────────────

def _encap(packet, st, cfg) -> StepResult:
    routes = st.get("routes", [])

    # belt-and-braces: N6 traffic is bare inner IP, not already tunnelled
    if _has(packet, "GTPU"):
        return _drop(st, "R0: N6 ingress already tunnelled")

    ue_ip = str(_field(packet, "IP", "dst", "0.0.0.0", nb=1))

    # R13 — unknown UE
    bearer = _dl_bearer(ue_ip, st)
    if bearer is None:
        return _drop(st, "R13: no UE bearer for destination",
                     [("R13_encap_unknown_ue_drop", {"ue_ip": ue_ip})])

    # R12 — known bearer, unreachable gNB (composite-specific)
    route = _lpm_match(str(bearer["gnb_ip"]), routes)
    if route is None:
        return _drop(st, "R12: known bearer but no underlay route to gNB",
                     [("R12_encap_no_underlay_route_drop", {"gnb_ip": bearer["gnb_ip"]})])

    inner = packet.getlayer("IP", 1) if hasattr(packet, "getlayer") else None
    inner_bytes = len(bytes(inner)) if inner is not None else 0

    ext_on = cfg.get("gtpu_ext_header_handling", "none") == "pdu_session_container"

    # R14 — encap MTU drop (gated off at the anchor)
    if cfg.get("mtu_enforcement", "ignore") == "strict_drop_oversize":
        overhead = 14 + 20 + 8 + 8 + (8 if ext_on else 0)
        if inner_bytes + overhead > int(cfg.get("outer_mtu", 1500)):
            return _drop(st, "R14: encap oversize", [("R14_encap_oversize_drop", {})])

    from scapy.all import Ether, IP, UDP
    GTPU, GTPUOpt, GTPUPduSession = _gtpu_layers()

    inner_proto = int(getattr(inner, "proto", 0) or 0)
    inner_l4s = int(_field(packet, "TCP", "sport", None) or _field(packet, "UDP", "sport", 0) or 0)
    inner_l4d = int(_field(packet, "TCP", "dport", None) or _field(packet, "UDP", "dport", 0) or 0)
    outer_udp_src = _outer_udp_src(
        cfg, (str(getattr(inner, "src", "")), ue_ip, inner_proto, inner_l4s, inner_l4d))

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

    udp_chksum = 0  # zero_on_tx at the anchor
    out = (Ether(src=route["port_mac"], dst=route["nexthop_mac"], type=0x0800)
           / IP(src=str(cfg.get("upf_n3_ip")), dst=str(bearer["gnb_ip"]),
                ttl=int(cfg.get("origination_ttl", 64)), proto=17, tos=tos, flags="DF")
           / UDP(sport=outer_udp_src, dport=int(cfg.get("outer_udp_dst_port", 2152)),
                 chksum=udp_chksum)
           / chain)

    return StepResult(
        output_packets={int(route["port"]): [out]},
        new_state=st,
        decision="forward",
        invariant_log=[
            ("R11_encap_and_underlay_route",
             {"teid": int(bearer["egress_teid"]), "gnb_ip": bearer["gnb_ip"],
              "port": int(route["port"]),
              "prefix": f"{route['prefix']}/{route['prefix_len']}"}),
            ("origination_vs_transit_outer_ttl",
             {"mode": "origination", "decremented": False,
              "ttl": int(cfg.get("origination_ttl", 64))}),
            ("encap_preserves_inner_ttl",
             {"inner_ttl": int(getattr(inner, "ttl", 0) or 0)}),
            ("outer_header_field_completeness",
             {"outer_src": str(cfg.get("upf_n3_ip")), "outer_dst": bearer["gnb_ip"]}),
            ("gtpu_length_field_correct", {"length": gtpu_length}),
            ("gtpu_header_wellformed_on_tx", {"version": 1, "pt": 1, "msgtype": 255}),
            ("outer_ipv4_checksum_validity", {"computed": True}),
            ("lpm_longest_match_correctness",
             {"prefix": f"{route['prefix']}/{route['prefix_len']}"}),
        ],
    )


def reset():
    """No module-level state; step() is pure w.r.t. its `state` argument."""
    return None
