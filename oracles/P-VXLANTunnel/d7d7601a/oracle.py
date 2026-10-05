"""Python oracle for benchmark/redesign/vxlan_vtep_disc.

Implements P-VXLANTunnel's rule sequence under the
task's seed:

  - R0      non-routable drop (no IPv4 / no UDP on uplink)
  - R1      decap path  (uplink + valid VXLAN + flag check + VNI lookup
                          + strict VNI isolation egress recheck)
  - R2      encap path  (access + inner Ethernet + (vni, dmac) lookup
                          + underlay nexthop + outer-header per-field stamp)
  - R3      decap strict-flag malformed drop
  - R4      decap unknown (VNI, inner_dmac) drop
  - R5a     encap BUM drop (bum_handling == drop)
  - R5b     encap BUM head-end replication (gated; not active at this seed)
  - R5c     encap BUM ingress multicast group (gated; not active at this seed)
  - R6      encap oversize drop (gated; not active at this seed —
                                  mtu_enforcement == ignore)

Per the parametric-source contract: every parameter
named in the pattern's `mutation_operators` surface is read from `state`
at runtime (specifically from `state["config"]` and the four entity-
population tables under `state[<table_name>]`). Seed values never enter
the module as source-level constants — this is what lets parameter
rebinding reuse the same audited oracle.

step() signature is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult

The packet representation tolerates both Scapy packets (engine-side
evaluation) and dict-shaped layers (audit-side canonical examples).
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
# Packet-introspection helpers (Scapy + dict-style tolerant)
# ──────────────────────────────────────────────────────────────────────

def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet or name in packet.get("_layers", {})
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        return getattr(packet[layer], fname, default)
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _ingress_port_role(ingress_port: int, state: Dict[str, Any]) -> Tuple[str, Optional[int]]:
    """Resolve the ingress port's role and access_vni from state-bound
    `access_port_bindings` and `uplink_ports`. Returns ('access', vni),
    ('uplink', None), or ('unknown', None)."""
    for entry in state.get("access_port_bindings", []):
        if entry["port"] == ingress_port:
            return "access", entry["access_vni"]
    if ingress_port in state.get("uplink_ports", []):
        return "uplink", None
    return "unknown", None


def _vni_mac_remote_lookup(vni: int, inner_dmac: str, state: Dict[str, Any]) -> Optional[str]:
    for e in state.get("vni_mac_remote_fib_entries", []):
        if e["vni"] == vni and e["inner_dmac"].lower() == inner_dmac.lower():
            return e["remote_vtep_ip"]
    return None


def _vni_mac_local_lookup(vni: int, inner_dmac: str, state: Dict[str, Any]) -> Optional[int]:
    for e in state.get("vni_mac_local_fib_entries", []):
        if e["vni"] == vni and e["inner_dmac"].lower() == inner_dmac.lower():
            return e["access_egress_port"]
    return None


def _access_vni_of_port(port: int, state: Dict[str, Any]) -> Optional[int]:
    for e in state.get("access_port_bindings", []):
        if e["port"] == port:
            return e["access_vni"]
    return None


def _underlay_lookup(remote_vtep_ip: str, state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for e in state.get("underlay_fib_entries", []):
        if e["remote_vtep_ip"] == remote_vtep_ip:
            return e
    return None


# ──────────────────────────────────────────────────────────────────────
# Outer-source-port hashing (hash_algo parameter)
# ──────────────────────────────────────────────────────────────────────

def _outer_udp_src_port(state: Dict[str, Any], inner_5tuple: Tuple[str, str, int, int, int]) -> int:
    """Derive the outer UDP source port from the inner 5-tuple per the
    `outer_udp_src_port_mode` and `hash_algo` parameters.

    Returns an int in [49152, 65535] per RFC 7348 §5 RECOMMENDED range
    when `outer_udp_src_port_mode` ∈ {hash_inner_3tuple, hash_inner_5tuple};
    returns the fixed value otherwise.
    """
    cfg = state.get("config", {})
    mode = cfg.get("outer_udp_src_port_mode", "fixed")
    if mode == "fixed":
        return int(cfg.get("outer_udp_src_port_fixed_value", 49152))
    src_ip, dst_ip, proto, l4_src, l4_dst = inner_5tuple
    if mode == "hash_inner_3tuple":
        payload = f"{src_ip}|{dst_ip}|{proto}".encode()
    else:                                                       # hash_inner_5tuple
        payload = f"{src_ip}|{dst_ip}|{proto}|{l4_src}|{l4_dst}".encode()
    algo = cfg.get("hash_algo", "crc16")
    if algo == "crc32":
        h = zlib.crc32(payload) & 0xFFFFFFFF
    elif algo == "xor_fold":
        h = 0
        for b in payload:
            h ^= b
        h = (h * 257) & 0xFFFF                                  # spread the low-entropy XOR result
    else:                                                       # crc16 (default; RFC 7348 §5 example)
        h = zlib.crc32(payload) & 0xFFFF
    return 49152 + (h % 16384)


# ──────────────────────────────────────────────────────────────────────
# Scapy-aware packet construction for outputs
# ──────────────────────────────────────────────────────────────────────

def _build_encap_output_scapy(inner_pkt, vni: int, outer_src_mac: str,
                              outer_dst_mac: str, outer_src_ip: str,
                              outer_dst_ip: str, outer_udp_src: int,
                              outer_udp_dst: int) -> Any:
    """Wrap a Scapy inner packet in outer Ether/IP/UDP/VXLAN per RFC 7348 §5."""
    from scapy.all import Ether, IP, UDP
    from scapy.layers.vxlan import VXLAN

    outer = (
        Ether(src=outer_src_mac, dst=outer_dst_mac)
        / IP(src=outer_src_ip, dst=outer_dst_ip, ttl=64, flags="DF")
        / UDP(sport=outer_udp_src, dport=outer_udp_dst, chksum=0)
        / VXLAN(flags=0x08, vni=vni, reserved1=0, reserved2=0)
    )
    return outer / inner_pkt


def _strip_outer_scapy(packet) -> Any:
    """Return the inner-Ethernet-onwards portion of a VXLAN-encapped Scapy packet."""
    from scapy.layers.vxlan import VXLAN
    # The VXLAN layer's payload is the inner Ethernet.
    if packet.haslayer(VXLAN):
        inner = packet[VXLAN].payload
        return inner
    return packet


# ──────────────────────────────────────────────────────────────────────
# step() — oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    """Execute one packet step under the VXLAN VTEP rule sequence.

    state shape (seeded by the harness from the seed at task init):
      - access_port_bindings:        list of {port, access_vni}
      - uplink_ports:                list of port-int
      - vni_mac_remote_fib_entries:  list of {vni, inner_dmac, remote_vtep_ip}
      - vni_mac_local_fib_entries:   list of {vni, inner_dmac, access_egress_port}
      - underlay_fib_entries:        list of {remote_vtep_ip, uplink_egress_port,
                                              outer_dst_mac, outer_src_mac}
      - config:                      dict carrying the scalar seed parameters
                                     (local_vtep_ip, flag_strictness,
                                      vni_isolation_strict, bum_handling,
                                      mtu_enforcement, outer_mtu, hash_algo,
                                      outer_udp_dst_port, outer_udp_src_port_mode,
                                      outer_udp_src_port_fixed_value,
                                      outer_udp_checksum_mode,
                                      verify_outer_udp_checksum_on_rx,
                                      faithfulness, workload_skew)
    """
    cfg = state.get("config", {})
    new_state = state                                           # stateless pattern

    role, port_access_vni = _ingress_port_role(ingress_port, state)

    # ──────────────────────────────────────────────────────────────────
    # R0 — non-routable drop (no Ethernet, no IPv4, or no UDP on uplink)
    # ──────────────────────────────────────────────────────────────────
    if not _has_layer(packet, "Ether"):
        return _drop(new_state, "R0: missing Ethernet")
    if role == "unknown":
        return _drop(new_state, "R0: ingress port not bound to any role")

    if role == "uplink":
        # Uplink ingress → expect outer IPv4 + UDP + VXLAN
        if not _has_layer(packet, "IP") or not _has_layer(packet, "UDP"):
            return _drop(new_state, "R0: uplink ingress without outer IP+UDP")
        udp_dport = _field(packet, "UDP", "dport", 0)
        outer_udp_dst_port = int(cfg.get("outer_udp_dst_port", 4789))
        if udp_dport != outer_udp_dst_port:
            return _drop(new_state, "R0: uplink UDP dst != configured VXLAN port")
        if not _has_layer(packet, "VXLAN"):
            return _drop(new_state, "R0: uplink ingress without VXLAN layer")
        return _decap(packet, ingress_port, new_state)

    # role == "access" — encap path
    if not _has_layer(packet, "IP"):
        # The pattern's R2 guards on inner IPv4 presence; non-IPv4 access
        # frames are out of scope and drop.
        return _drop(new_state, "R0: access ingress without inner IPv4")
    return _encap(packet, ingress_port, port_access_vni, new_state)


# ──────────────────────────────────────────────────────────────────────
# Decap path (R1 / R3 / R4)
# ──────────────────────────────────────────────────────────────────────

def _decap(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    cfg = state.get("config", {})
    flag_strictness = cfg.get("flag_strictness", "strict")
    vni_isolation_strict = bool(cfg.get("vni_isolation_strict", True))
    verify_chksum = bool(cfg.get("verify_outer_udp_checksum_on_rx", False))

    vxlan_flags = _field(packet, "VXLAN", "flags", 0)
    vxlan_reserved1 = _field(packet, "VXLAN", "reserved1", 0)   # Scapy field for 24-bit reserved
    vxlan_reserved2 = _field(packet, "VXLAN", "reserved2", 0)   # Scapy field for 8-bit reserved
    vxlan_vni = _field(packet, "VXLAN", "vni", 0)

    # R3 — strict-flag validation
    if flag_strictness == "strict":
        i_flag_set = (int(vxlan_flags) & 0x08) != 0
        reserved_flag_bits = int(vxlan_flags) & 0xF7
        if (not i_flag_set
                or reserved_flag_bits != 0
                or int(vxlan_reserved1 or 0) != 0
                or int(vxlan_reserved2 or 0) != 0):
            return _drop(state, "R3: strict flag/reserved-bits validation failed",
                         invariants=[("R3_decap_malformed_drop", {"flags": int(vxlan_flags)})])

    # Optional outer-UDP-checksum verification
    if verify_chksum:
        udp_chksum = _field(packet, "UDP", "chksum", 0) or 0
        if udp_chksum != 0:
            # Per RFC 7348 §5, on non-zero chksum we MAY verify. This
            # oracle treats any non-zero as a mismatch by default
            # (the harness does not currently compute the correct
            # multi-layer UDP checksum).
            return _drop(state, "R3/verify: outer UDP checksum non-zero "
                                "and verification-on-rx is enabled")

    # Inner Ethernet must be present after VXLAN
    inner_eth_dst = None
    inner_eth_src = None
    try:
        from scapy.layers.vxlan import VXLAN
        if hasattr(packet, "haslayer") and packet.haslayer(VXLAN):
            inner = packet[VXLAN].payload
            inner_eth_dst = getattr(inner, "dst", None)
            inner_eth_src = getattr(inner, "src", None)
    except Exception:
        pass
    if inner_eth_dst is None:
        # dict-shaped fallback: look for a nested 'InnerEther' or second 'Ether'
        if isinstance(packet, dict):
            inner_eth_dst = (packet.get("InnerEther") or {}).get("dst")
            inner_eth_src = (packet.get("InnerEther") or {}).get("src")
    if inner_eth_dst is None:
        return _drop(state, "R4: VXLAN payload missing inner Ethernet")

    # R4 / R1 — local-delivery table lookup
    access_port = _vni_mac_local_lookup(int(vxlan_vni), inner_eth_dst, state)
    if access_port is None:
        return _drop(state, "R4: unknown (VNI, inner_dmac) on decap",
                     invariants=[("R4_decap_unknown_vni_drop",
                                  {"vni": int(vxlan_vni), "dmac": inner_eth_dst})])

    # R1 strict VNI isolation egress recheck
    if vni_isolation_strict:
        egress_access_vni = _access_vni_of_port(access_port, state)
        if egress_access_vni != int(vxlan_vni):
            return _drop(state, "R1: vni_isolation_strict — egress port's access_vni "
                                "does not match received VNI",
                         invariants=[("vni_isolation",
                                      {"vni": int(vxlan_vni),
                                       "egress_port": access_port,
                                       "egress_access_vni": egress_access_vni})])

    # Strip outer headers and forward
    try:
        inner_pkt = _strip_outer_scapy(packet)
    except Exception:
        inner_pkt = packet                                      # dict-shaped: caller handles

    return StepResult(
        output_packets={access_port: [inner_pkt]},
        new_state=state,
        decision="forward",
        invariant_log=[
            ("R1_decap_path", {"egress_port": access_port,
                               "vni": int(vxlan_vni)}),
            ("vni_isolation", {"vni": int(vxlan_vni), "egress_port": access_port}),
            ("inner_payload_persistence",
             {"inner_dmac": inner_eth_dst, "inner_src": inner_eth_src}),
        ],
    )


# ──────────────────────────────────────────────────────────────────────
# Encap path (R2 / R5a / R5b / R5c / R6)
# ──────────────────────────────────────────────────────────────────────

def _encap(packet, ingress_port: int, access_vni: int,
           state: Dict[str, Any]) -> StepResult:
    cfg = state.get("config", {})

    inner_dmac = _field(packet, "Ether", "dst", None)
    inner_smac = _field(packet, "Ether", "src", None)
    inner_src_ip = _field(packet, "IP", "src", None)
    inner_dst_ip = _field(packet, "IP", "dst", None)
    inner_proto = int(_field(packet, "IP", "proto", 0) or 0)
    # Best-effort L4 port extraction (uniform across TCP/UDP for hashing)
    inner_l4_src = (_field(packet, "TCP", "sport", None)
                    or _field(packet, "UDP", "sport", 0))
    inner_l4_dst = (_field(packet, "TCP", "dport", None)
                    or _field(packet, "UDP", "dport", 0))
    inner_l4_src = int(inner_l4_src or 0)
    inner_l4_dst = int(inner_l4_dst or 0)

    if inner_dmac is None:
        return _drop(state, "R2: missing inner Ethernet dst")

    # R2/R5 — remote-MAC FIB lookup
    remote_vtep_ip = _vni_mac_remote_lookup(access_vni, inner_dmac, state)
    if remote_vtep_ip is None:
        # BUM handling
        bum_mode = cfg.get("bum_handling", "drop")
        if bum_mode == "drop":
            return _drop(state, "R5a: BUM under drop mode",
                         invariants=[("R5a_encap_bum_drop",
                                      {"vni": access_vni, "dmac": inner_dmac})])
        elif bum_mode == "head_end_replication":
            return _bum_replicate(packet, access_vni, state, inner_src_ip,
                                  inner_dst_ip, inner_proto,
                                  inner_l4_src, inner_l4_dst)
        elif bum_mode == "ingress_multicast_group":
            # Multicast forwarding (group resolution not modelled at this seed)
            return _drop(state, "R5c: ingress_multicast_group not configured at this seed")
        else:
            return _drop(state, f"R5: unknown bum_handling mode {bum_mode!r}")

    # R6 — encap-side MTU drop (gated by mtu_enforcement)
    mtu_enforcement = cfg.get("mtu_enforcement", "ignore")
    if mtu_enforcement == "strict_drop_oversize":
        encap_overhead = 14 + 20 + 8 + 8                        # outer Eth + IP + UDP + VXLAN
        try:
            inner_len = len(bytes(packet))
        except Exception:
            inner_len = 0
        if inner_len + encap_overhead > int(cfg.get("outer_mtu", 1500)):
            return _drop(state, "R6: encap path oversize under strict_drop_oversize",
                         invariants=[("no_vtep_fragmentation",
                                      {"size": inner_len + encap_overhead,
                                       "mtu": int(cfg.get("outer_mtu", 1500))})])

    # Underlay nexthop resolution
    underlay = _underlay_lookup(remote_vtep_ip, state)
    if underlay is None:
        return _drop(state, "R2: underlay nexthop unresolved for remote VTEP")

    # Outer UDP source port
    outer_udp_src = _outer_udp_src_port(
        state, (inner_src_ip or "", inner_dst_ip or "", inner_proto,
                inner_l4_src, inner_l4_dst))

    # Build outer-wrapped output
    try:
        outer_pkt = _build_encap_output_scapy(
            packet,
            vni=access_vni,
            outer_src_mac=underlay["outer_src_mac"],
            outer_dst_mac=underlay["outer_dst_mac"],
            outer_src_ip=str(cfg.get("local_vtep_ip", "0.0.0.0")),
            outer_dst_ip=remote_vtep_ip,
            outer_udp_src=outer_udp_src,
            outer_udp_dst=int(cfg.get("outer_udp_dst_port", 4789)),
        )
    except Exception as e:                                       # dict-shaped fallback
        outer_pkt = {
            "OuterEther": {"src": underlay["outer_src_mac"],
                           "dst": underlay["outer_dst_mac"],
                           "type": 0x0800},
            "OuterIP": {"src": str(cfg.get("local_vtep_ip", "0.0.0.0")),
                        "dst": remote_vtep_ip, "ttl": 64, "proto": 17},
            "UDP": {"sport": outer_udp_src,
                    "dport": int(cfg.get("outer_udp_dst_port", 4789)),
                    "chksum": 0},
            "VXLAN": {"flags": 0x08, "vni": access_vni,
                      "reserved1": 0, "reserved2": 0},
            "Inner": packet,
            "_synth_error": str(e),
        }

    return StepResult(
        output_packets={underlay["uplink_egress_port"]: [outer_pkt]},
        new_state=state,
        decision="forward",
        invariant_log=[
            ("R2_encap_path",
             {"vni": access_vni,
              "remote_vtep_ip": remote_vtep_ip,
              "egress_port": underlay["uplink_egress_port"]}),
            ("outer_header_field_completeness",
             {"outer_src_ip": str(cfg.get("local_vtep_ip")),
              "outer_dst_ip": remote_vtep_ip,
              "outer_udp_src": outer_udp_src,
              "outer_udp_dst": int(cfg.get("outer_udp_dst_port", 4789)),
              "vni": access_vni}),
            ("outer_ipv4_checksum_validity", {"computed": True}),
            ("vxlan_i_flag_set_on_tx", {"i_flag": 1}),
        ],
    )


def _bum_replicate(packet, access_vni: int, state: Dict[str, Any],
                   src_ip: Optional[str], dst_ip: Optional[str],
                   proto: int, l4_src: int, l4_dst: int) -> StepResult:
    """R5b — head-end replication. One outer-encapsulated copy per remote
    VTEP listed in `bum_replication_targets`."""
    cfg = state.get("config", {})
    targets = cfg.get("bum_replication_targets", []) or []
    if not targets:
        return _drop(state, "R5b: head_end_replication selected but targets list empty")

    outputs: Dict[int, List[Any]] = {}
    inv_log: List[Tuple[str, Any]] = []
    outer_udp_dst = int(cfg.get("outer_udp_dst_port", 4789))
    outer_src_ip = str(cfg.get("local_vtep_ip", "0.0.0.0"))

    for remote_vtep_ip in targets:
        underlay = _underlay_lookup(remote_vtep_ip, state)
        if underlay is None:
            continue
        outer_udp_src = _outer_udp_src_port(
            state, (src_ip or "", dst_ip or "", proto, l4_src, l4_dst))
        try:
            outer_pkt = _build_encap_output_scapy(
                packet, vni=access_vni,
                outer_src_mac=underlay["outer_src_mac"],
                outer_dst_mac=underlay["outer_dst_mac"],
                outer_src_ip=outer_src_ip,
                outer_dst_ip=remote_vtep_ip,
                outer_udp_src=outer_udp_src,
                outer_udp_dst=outer_udp_dst,
            )
        except Exception:
            continue
        outputs.setdefault(underlay["uplink_egress_port"], []).append(outer_pkt)
        inv_log.append(("R5b_encap_bum_replicate",
                        {"remote_vtep_ip": remote_vtep_ip,
                         "egress_port": underlay["uplink_egress_port"]}))

    if not outputs:
        return _drop(state, "R5b: no replication target resolvable in underlay_fib")

    return StepResult(
        output_packets=outputs,
        new_state=state,
        decision="forward",
        invariant_log=inv_log,
    )


# ──────────────────────────────────────────────────────────────────────
# drop helper
# ──────────────────────────────────────────────────────────────────────

def _drop(state: Dict[str, Any], reason: str,
          invariants: Optional[List[Tuple[str, Any]]] = None) -> StepResult:
    return StepResult(
        output_packets={},
        new_state=state,
        decision="drop",
        invariant_log=(invariants or []) + [("drop_reason", reason)],
    )


# ──────────────────────────────────────────────────────────────────────
# reset() — for OracleSynth.load()
# ──────────────────────────────────────────────────────────────────────

def reset():
    """No module-level state; step() is pure w.r.t. its `state` argument."""
    return None
