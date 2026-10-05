"""Python oracle for benchmark/composition/vxlan_router_anchor.

Implements P-VXLANRouter — the VXLAN VTEP ∘ IPv4 underlay-router COMPOSITE —
at the task's seed (faithfulness = D5.0_static_encap_route):

  - single VNI, lax flags, fixed outer UDP source port, zero outer UDP
    checksum on transmit, BUM = drop, MTU enforcement off, underlay
    multipath = none (singleton next-hops), martian filter off.

The composite chains the two audited halves' behaviour (P-VXLANTunnel ∘
P-IPv4Routing) under content-addressing — the encap/decap
step (the overlay half) feeds the LPM-forward step over the OUTER header
(the underlay half), with the composition glue handling the three
interactions neither half exhibits alone:

  R0   non-routable drop (no Ethernet / no IPv4)
  R1   outer IPv4 header validation on uplink (RFC 1812 §5.2.2)
  R2   DECAP — uplink ∧ VXLAN ∧ outer.dst == local_vtep_ip ∧ flag check
        (lax→accept) ∧ (vni, inner_dmac) ∈ local FIB ∧ VNI isolation
        (off at anchor): strip outer, deliver inner to the access port
  R3   decap strict-flag malformed drop (gated off at anchor)
  R4   decap unknown (VNI, inner_dmac) drop
  R5   TRANSIT TTL-exhausted drop (uplink ∧ outer.dst ≠ local ∧ ttl ≤ 1)
  R6   TRANSIT underlay forward on the OUTER header (uplink ∧ outer.dst ≠
        local): LPM(outer.dst) → decrement OUTER ttl by one → OUTER Ether
        rewrite → forward; the inner frame is OPAQUE (untouched)
  R7   transit no-route drop (default_action)
  R8   ENCAP + underlay route — access ∧ (vni, inner_dmac) ∈ remote FIB ∧
        LPM(remote_vtep_ip) hit: build the full outer stack with
        outer.dst = remote_vtep_ip, outer.src = local_vtep_ip, outer.ttl =
        origination_ttl (stamped, NOT decremented — origination), then
        underlay-forward via the LPM-picked next-hop (OUTER Ether rewrite)
  R9a  encap BUM drop (remote FIB miss, bum_handling == drop)
  R10  encap known-overlay / unreachable-underlay drop (remote FIB hit but
        no underlay route to the remote VTEP) — composite-specific
  R11  encap oversize drop (gated off at anchor)

The three load-bearing composite properties this oracle realises:
  * outer_inner_header_disjointness — R6/R8 touch only the OUTER IPv4;
    the inner frame is preserved byte-for-byte.
  * vtep_transit_dichotomy — a VXLAN packet on uplink is decapped iff
    outer.dst == local_vtep_ip, else transit-forwarded.
  * origination_vs_transit_ttl — R8 (origination) does NOT decrement the
    outer TTL; R6 (transit) decrements by exactly one.

Per the parametric-source contract: every parameter
named in the pattern's mutation_operators surface is read from `state`
(the entity tables at top level + the scalar knobs under `state["config"]`)
at runtime — seed values never enter as source-level constants, so
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
    "access_port_bindings": [{"port": 1, "access_vni": 100}],
    "uplink_ports": [2, 3],
    "vni_mac_remote_fib_entries": [
        {"vni": 100, "inner_dmac": "00:00:00:00:0a:0a", "remote_vtep_ip": "192.168.0.2"},
        {"vni": 100, "inner_dmac": "00:00:00:00:0b:0b", "remote_vtep_ip": "172.16.9.9"},
    ],
    "vni_mac_local_fib_entries": [
        {"vni": 100, "inner_dmac": "00:00:00:00:01:05", "access_egress_port": 1},
    ],
    "routes": [
        {"prefix": "192.168.0.2", "prefix_len": 32, "port": 2,
         "port_mac": "02:00:00:00:00:02", "nexthop_mac": "0a:00:00:00:00:02"},
        {"prefix": "10.10.0.0", "prefix_len": 16, "port": 2,
         "port_mac": "02:00:00:00:00:02", "nexthop_mac": "0a:00:00:00:00:02"},
        {"prefix": "10.10.5.0", "prefix_len": 24, "port": 3,
         "port_mac": "02:00:00:00:00:03", "nexthop_mac": "0a:00:00:00:00:03"},
    ],
    "config": {
        "local_vtep_ip": "192.168.0.1",
        "outer_udp_dst_port": 4789,
        "outer_udp_src_port_mode": "fixed",
        "outer_udp_src_port_fixed_value": 49152,
        # outer_udp_checksum_mode DE-QUOTED: this anchor hash always emits a
        # zero outer-UDP checksum on tx (UDP(..., chksum=0) in _build_encap_scapy)
        # and never verifies on rx, so the knob is inert on this hash — it is a
        # regeneration-variant (a checksum-verifying variant regenerates the
        # oracle), not a config-read parameter. Not stored as a config key.
        "verify_outer_udp_checksum_on_rx": False,
        "flag_strictness": "lax",
        "vni_isolation_strict": False,
        "bum_handling": "drop",
        "mtu_enforcement": "ignore",
        "outer_mtu": 1500,
        "hash_algo": "crc16",
        "origination_ttl": 64,
        # multipath_mode DE-QUOTED: this anchor hash uses singleton next-hops
        # (_lpm_match returns one route; no ECMP fan-out), so the knob is inert
        # on this hash — a multipath variant regenerates the oracle. Not a
        # config-read parameter here; not stored as a config key.
        "martian_filter_enabled": False,
        # default_action DE-QUOTED: the R7 transit-no-route arm and the encap
        # miss arms unconditionally drop on this anchor hash (no programmable
        # default-forward/punt path), so the knob is inert — a non-drop default
        # regenerates the oracle. Not a config-read parameter here.
        # faithfulness DE-QUOTED: the D-rung faithfulness selector chooses which
        # behavioural variant to instantiate (it regenerates a different oracle),
        # not a value read at runtime. Not stored as a config key.
    },
}


def _state(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not state:
        return _DEFAULT_STATE
    # Merge config so missing scalar knobs fall back to anchor defaults.
    merged = dict(state)
    cfg = dict(_DEFAULT_STATE["config"])
    cfg.update(state.get("config", {}))
    merged["config"] = cfg
    for k in ("access_port_bindings", "uplink_ports",
              "vni_mac_remote_fib_entries", "vni_mac_local_fib_entries", "routes"):
        merged.setdefault(k, _DEFAULT_STATE[k])
    return merged


# ──────────────────────────────────────────────────────────────────────
# Packet introspection (Scapy + dict-style tolerant)
# ──────────────────────────────────────────────────────────────────────

def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        v = getattr(packet[layer], fname, default)
        return v if v is not None else default
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _ingress_role(ingress_port: int, st: Dict[str, Any]) -> Tuple[str, Optional[int]]:
    for e in st.get("access_port_bindings", []):
        if e["port"] == ingress_port:
            return "access", e["access_vni"]
    if ingress_port in st.get("uplink_ports", []):
        return "uplink", None
    return "unknown", None


def _remote_fib_lookup(vni: int, dmac: str, st: Dict[str, Any]) -> Optional[str]:
    for e in st.get("vni_mac_remote_fib_entries", []):
        if e["vni"] == vni and e["inner_dmac"].lower() == str(dmac).lower():
            return e["remote_vtep_ip"]
    return None


def _local_fib_lookup(vni: int, dmac: str, st: Dict[str, Any]) -> Optional[int]:
    for e in st.get("vni_mac_local_fib_entries", []):
        if e["vni"] == vni and e["inner_dmac"].lower() == str(dmac).lower():
            return e["access_egress_port"]
    return None


def _access_vni_of_port(port: int, st: Dict[str, Any]) -> Optional[int]:
    for e in st.get("access_port_bindings", []):
        if e["port"] == port:
            return e["access_vni"]
    return None


# ──────────────────────────────────────────────────────────────────────
# Underlay LPM (over the OUTER IPv4 destination) — the P-IPv4Routing half
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


# ──────────────────────────────────────────────────────────────────────
# Outer-source-port hashing (hash_algo / outer_udp_src_port_mode knobs)
# ──────────────────────────────────────────────────────────────────────

def _outer_udp_src_port(cfg: Dict[str, Any],
                        inner_5tuple: Tuple[str, str, int, int, int]) -> int:
    import zlib
    mode = cfg.get("outer_udp_src_port_mode", "fixed")
    if mode == "fixed":
        return int(cfg.get("outer_udp_src_port_fixed_value", 49152))
    src_ip, dst_ip, proto, l4s, l4d = inner_5tuple
    if mode == "hash_inner_3tuple":
        payload = f"{src_ip}|{dst_ip}|{proto}".encode()
    else:
        payload = f"{src_ip}|{dst_ip}|{proto}|{l4s}|{l4d}".encode()
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


# ──────────────────────────────────────────────────────────────────────
# Scapy packet helpers
# ──────────────────────────────────────────────────────────────────────

def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _build_encap_scapy(inner_pkt, vni, outer_src_mac, outer_dst_mac,
                       outer_src_ip, outer_dst_ip, outer_ttl,
                       outer_udp_src, outer_udp_dst):
    from scapy.all import Ether, IP, UDP
    from scapy.layers.vxlan import VXLAN
    outer = (
        Ether(src=outer_src_mac, dst=outer_dst_mac, type=0x0800)
        / IP(src=outer_src_ip, dst=outer_dst_ip, ttl=outer_ttl,
             proto=17, flags="DF")
        / UDP(sport=outer_udp_src, dport=outer_udp_dst, chksum=0)
        / VXLAN(flags=0x08, vni=vni, reserved1=0, reserved2=0)
    )
    return outer / inner_pkt


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
    role, access_vni = _ingress_role(ingress_port, st)

    # R0 — non-routable
    if not _has_layer(packet, "Ether"):
        return _drop(st, "R0: missing Ethernet")
    if role == "unknown":
        return _drop(st, "R0: ingress port bound to no role")
    if not _has_layer(packet, "IP"):
        return _drop(st, "R0: no IPv4")

    if role == "uplink":
        return _uplink(packet, ingress_port, st, cfg)
    return _encap(packet, ingress_port, access_vni, st, cfg)


# ──────────────────────────────────────────────────────────────────────
# Uplink path: decap (R2/R3/R4) OR transit (R5/R6/R7), gated by ownership
# ──────────────────────────────────────────────────────────────────────

def _uplink(packet, ingress_port, st, cfg) -> StepResult:
    local_vtep_ip = str(cfg.get("local_vtep_ip"))
    outer_dst = str(_field(packet, "IP", "dst", "0.0.0.0"))

    # R1 — outer IPv4 header validation
    version = int(_field(packet, "IP", "version", 4) or 4)
    ihl = int(_field(packet, "IP", "ihl", 5) or 5)
    if version != 4 or ihl < 5:
        return _drop(st, "R1: invalid outer IPv4 header")

    is_vxlan = (_has_layer(packet, "UDP")
                and int(_field(packet, "UDP", "dport", 0) or 0)
                == int(cfg.get("outer_udp_dst_port", 4789))
                and _has_layer(packet, "VXLAN"))

    # ── DECAP arm: VXLAN destined to THIS VTEP ──────────────────────────
    if is_vxlan and outer_dst == local_vtep_ip:
        return _decap(packet, st, cfg)

    # ── TRANSIT arm: anything else on the uplink ────────────────────────
    return _transit(packet, ingress_port, st, cfg)


def _decap(packet, st, cfg) -> StepResult:
    vxlan_flags = int(_field(packet, "VXLAN", "flags", 0) or 0)
    vxlan_r1 = int(_field(packet, "VXLAN", "reserved1", 0) or 0)
    vxlan_r2 = int(_field(packet, "VXLAN", "reserved2", 0) or 0)
    vni = int(_field(packet, "VXLAN", "vni", 0) or 0)

    # R3 — strict flag validation (gated off at the anchor)
    if cfg.get("flag_strictness", "lax") == "strict":
        i_set = (vxlan_flags & 0x08) != 0
        if (not i_set) or (vxlan_flags & 0xF7) != 0 or vxlan_r1 != 0 or vxlan_r2 != 0:
            return _drop(st, "R3: strict flag/reserved validation failed",
                         [("R3_decap_malformed_drop", {"flags": vxlan_flags})])

    # inner Ethernet dst
    inner_dmac = None
    inner_pkt = None
    try:
        from scapy.layers.vxlan import VXLAN
        if hasattr(packet, "haslayer") and packet.haslayer(VXLAN):
            inner_pkt = packet[VXLAN].payload
            inner_dmac = getattr(inner_pkt, "dst", None)
    except Exception:
        pass
    if inner_dmac is None and isinstance(packet, dict):
        inner_dmac = (packet.get("InnerEther") or {}).get("dst")
    if inner_dmac is None:
        return _drop(st, "R4: VXLAN payload missing inner Ethernet")

    # R4 — local-delivery lookup
    access_port = _local_fib_lookup(vni, inner_dmac, st)
    if access_port is None:
        return _drop(st, "R4: unknown (VNI, inner_dmac) on decap",
                     [("R4_decap_unknown_vni_drop", {"vni": vni, "dmac": inner_dmac})])

    # R2 — strict VNI isolation egress recheck (off at the anchor)
    if bool(cfg.get("vni_isolation_strict", False)):
        if _access_vni_of_port(access_port, st) != vni:
            return _drop(st, "R2: vni_isolation_strict egress mismatch",
                         [("vni_isolation", {"vni": vni, "egress_port": access_port})])

    return StepResult(
        output_packets={access_port: [inner_pkt if inner_pkt is not None else packet]},
        new_state=st,
        decision="forward",
        invariant_log=[
            ("R2_decap_path", {"egress_port": access_port, "vni": vni}),
            ("vtep_transit_dichotomy", {"arm": "decap"}),
            ("inner_payload_persistence", {"inner_dmac": inner_dmac}),
        ],
    )


def _transit(packet, ingress_port, st, cfg) -> StepResult:
    routes = st.get("routes", [])
    outer_dst = str(_field(packet, "IP", "dst", "0.0.0.0"))
    outer_src = str(_field(packet, "IP", "src", "0.0.0.0"))
    outer_ttl = int(_field(packet, "IP", "ttl", 0) or 0)

    if outer_dst == "255.255.255.255":
        return _drop(st, "R-bcast: limited broadcast outer dst")

    # R6 guard — martian filter on the OUTER src
    if cfg.get("martian_filter_enabled") and _is_martian_src(outer_src):
        return _drop(st, "R6: martian outer source",
                     [("martian_filter", {"src": outer_src})])

    # R5 — transit TTL exhausted
    if outer_ttl <= 1:
        return _drop(st, "R5: transit TTL exhausted",
                     [("R5_transit_ttl_exhausted_drop", {"ttl": outer_ttl})])

    # R6/R7 — underlay LPM forward on the OUTER header
    route = _lpm_match(outer_dst, routes)
    if route is None:
        return _drop(st, "R7: transit no route", [("R7_transit_no_route_drop",
                                                   {"dst": outer_dst})])

    out = _clone(packet)
    # decrement OUTER ttl by one; rewrite OUTER Ether; inner untouched
    try:
        out["IP"].ttl = outer_ttl - 1
        out["Ether"].src = route["port_mac"]
        out["Ether"].dst = route["nexthop_mac"]
        # force checksum recompute by clearing the cached value
        try:
            del out["IP"].chksum
        except Exception:
            pass
    except Exception:
        if isinstance(out, dict):
            out.setdefault("IP", {})["ttl"] = outer_ttl - 1
            out.setdefault("Ether", {})["src"] = route["port_mac"]
            out.setdefault("Ether", {})["dst"] = route["nexthop_mac"]

    return StepResult(
        output_packets={int(route["port"]): [out]},
        new_state=st,
        decision="forward",
        invariant_log=[
            ("R6_transit_underlay_forward",
             {"port": int(route["port"]), "outer_ttl": outer_ttl - 1,
              "prefix": f"{route['prefix']}/{route['prefix_len']}"}),
            ("vtep_transit_dichotomy", {"arm": "transit"}),
            ("origination_vs_transit_ttl", {"mode": "transit", "decremented": True}),
            ("ttl_quantum_one_transit", {"delta": 1}),
            ("outer_inner_header_disjointness", {"inner_touched": False}),
            ("ether_rewrite_correctness",
             {"src": route["port_mac"], "dst": route["nexthop_mac"]}),
        ],
    )


# ──────────────────────────────────────────────────────────────────────
# Access path: encap + underlay route (R8 / R9a / R10 / R11)
# ──────────────────────────────────────────────────────────────────────

def _encap(packet, ingress_port, access_vni, st, cfg) -> StepResult:
    routes = st.get("routes", [])
    inner_dmac = _field(packet, "Ether", "dst", None)
    if inner_dmac is None:
        return _drop(st, "R8: missing inner Ethernet dst")

    # R8/R9a — remote-MAC FIB lookup
    remote_vtep_ip = _remote_fib_lookup(access_vni, inner_dmac, st)
    if remote_vtep_ip is None:
        if cfg.get("bum_handling", "drop") == "drop":
            return _drop(st, "R9a: BUM under drop mode",
                         [("R9a_encap_bum_drop", {"vni": access_vni, "dmac": inner_dmac})])
        return _drop(st, "R9: non-drop BUM mode not active at anchor")

    # R10 — known overlay, unreachable underlay (composite-specific)
    route = _lpm_match(remote_vtep_ip, routes)
    if route is None:
        return _drop(st, "R10: known remote VTEP but no underlay route",
                     [("R10_encap_no_underlay_route_drop",
                       {"remote_vtep_ip": remote_vtep_ip})])

    # R11 — encap-side MTU drop (gated off at anchor)
    if cfg.get("mtu_enforcement", "ignore") == "strict_drop_oversize":
        overhead = 14 + 20 + 8 + 8
        try:
            inner_len = len(bytes(packet))
        except Exception:
            inner_len = 0
        if inner_len + overhead > int(cfg.get("outer_mtu", 1500)):
            return _drop(st, "R11: encap oversize",
                         [("no_vtep_fragmentation", {"size": inner_len + overhead})])

    # outer UDP source port (fixed at anchor)
    inner_src_ip = _field(packet, "IP", "src", "")
    inner_dst_ip = _field(packet, "IP", "dst", "")
    inner_proto = int(_field(packet, "IP", "proto", 0) or 0)
    l4s = int(_field(packet, "TCP", "sport", None) or _field(packet, "UDP", "sport", 0) or 0)
    l4d = int(_field(packet, "TCP", "dport", None) or _field(packet, "UDP", "dport", 0) or 0)
    outer_udp_src = _outer_udp_src_port(
        cfg, (inner_src_ip or "", inner_dst_ip or "", inner_proto, l4s, l4d))

    origination_ttl = int(cfg.get("origination_ttl", 64))

    try:
        outer_pkt = _build_encap_scapy(
            packet, vni=access_vni,
            outer_src_mac=route["port_mac"],
            outer_dst_mac=route["nexthop_mac"],
            outer_src_ip=str(cfg.get("local_vtep_ip")),
            outer_dst_ip=remote_vtep_ip,
            outer_ttl=origination_ttl,
            outer_udp_src=outer_udp_src,
            outer_udp_dst=int(cfg.get("outer_udp_dst_port", 4789)),
        )
    except Exception as e:
        outer_pkt = {
            "OuterEther": {"src": route["port_mac"], "dst": route["nexthop_mac"],
                           "type": 0x0800},
            "OuterIP": {"src": str(cfg.get("local_vtep_ip")), "dst": remote_vtep_ip,
                        "ttl": origination_ttl, "proto": 17},
            "UDP": {"sport": outer_udp_src,
                    "dport": int(cfg.get("outer_udp_dst_port", 4789)), "chksum": 0},
            "VXLAN": {"flags": 0x08, "vni": access_vni, "reserved1": 0, "reserved2": 0},
            "Inner": packet, "_synth_error": str(e),
        }

    return StepResult(
        output_packets={int(route["port"]): [outer_pkt]},
        new_state=st,
        decision="forward",
        invariant_log=[
            ("R8_encap_and_underlay_route",
             {"vni": access_vni, "remote_vtep_ip": remote_vtep_ip,
              "port": int(route["port"]),
              "prefix": f"{route['prefix']}/{route['prefix_len']}"}),
            ("origination_vs_transit_ttl",
             {"mode": "origination", "decremented": False, "ttl": origination_ttl}),
            ("outer_header_field_completeness",
             {"outer_src_ip": str(cfg.get("local_vtep_ip")),
              "outer_dst_ip": remote_vtep_ip, "vni": access_vni}),
            ("outer_ipv4_checksum_validity", {"computed": True}),
            ("vxlan_i_flag_set_on_tx", {"i_flag": 1}),
            ("lpm_longest_match_correctness",
             {"prefix": f"{route['prefix']}/{route['prefix_len']}"}),
        ],
    )


def reset():
    """No module-level state; step() is pure w.r.t. its `state` argument."""
    return None
