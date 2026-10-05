"""Composed oracle for P-LBFailover (Stateful L4 Load Balancer ∘
Primary/Backup Fast-Reroute).

    step(scapy_pkt, ingress_port, state) -> StepResult        [STATEFUL]

Pipeline (first-match over the pattern's R0..R4):

  R0  ¬header_present(ipv4)                                    → drop
  R1  dst ≠ vip ∨ ¬header_present(tcp)                         → drop
  R2  cascaded ∧ pinned-backend primary down ∧ backup down     → drop
  R3  new flow  → pin backend (assign) + DNAT + FRR demux fwd
  R4  existing  → follow pinned backend + DNAT + FRR demux fwd

The LB pin (R3/R4) selects a backend, DNATs hdr.ipv4.dst to it, and the
FRR demux — keyed on the POST-DNAT backend address — picks the backend's
primary egress port (and primary_mac) when that port is up, else the
backup port (and backup_mac). Backend selection is liveness-INDEPENDENT:
a flow whose pinned backend's primary is down still goes to that backend
via its backup port (failover_does_not_rebalance); the DNAT'd destination
is identical on the primary and backup paths (backend_pin_survives_failover).

L2 rewrite convention (inherited from P-PURRFastReroute's FRR stage, which
owns L2 in this composition): hdr.ethernet.src ← prior hdr.ethernet.dst,
hdr.ethernet.dst ← the chosen path's next-hop MAC (primary_mac | backup_mac).
Only the IPv4 DESTINATION is rewritten (DNAT); the IPv4 source is preserved
(src_addr_preservation). TTL convention: gate ttl > 0 — ttl == 0 drops,
ttl == 1 forwards with egress ttl == 0 (decrement once, never twice).

PARAMETRIC-SOURCE CONTRACT. Every mutable knob is read
from the runtime `state` dict — never baked as a module-level constant. The
seed's values enter only at evaluation time via step()'s `state` argument.
State keys consumed:

  vip                  : str
  backends             : list[str]   (ordered; round_robin = selector mod len)
  assign               : 'round_robin' | 'hash_5tuple' | 'consistent_hash'
  flow_table_capacity  : int | 'unbounded'
  eviction_policy      : 'none' | 'FIFO_collision_displace' | 'LRU'
  persistence_strict   : bool
  frr_groups           : dict[backend_ip -> {primary_port, backup_port,
                                             primary_mac, backup_mac}]
  port_down            : iterable[int]
  cascaded_backup      : bool
  ttl_decrement_strict : bool

The per-flow binding table and the round-robin selector are the only MUTABLE
runtime state; they live module-level and are cleared by reset() (the engine /
test generator calls reset() before replaying each test's prior_inputs).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── mutable runtime state (cleared by reset) ────────────────────────────────
_SELECTOR: int = 0
_BINDINGS: "dict[tuple, str]" = {}


def reset() -> None:
    """Clear the per-flow bindings and the round-robin selector. Called once
    per test before replaying that test's prior_inputs + input packet."""
    global _SELECTOR, _BINDINGS
    _SELECTOR = 0
    _BINDINGS = {}


# ── result ──────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    reason: str
    output_port: Optional[int] = None
    dnat_dst: Optional[str] = None          # the pinned backend IP (DNAT target)
    backend_ip: Optional[str] = None
    next_hop_mac_dst: Optional[str] = None  # primary_mac | backup_mac
    next_hop_mac_src: Optional[str] = None  # prior ethernet.dst
    ttl_decrement: int = 0
    new_flow: Optional[bool] = None
    path: Optional[str] = None              # 'primary' | 'backup'
    invariant_log: list = field(default_factory=list)

    @property
    def decision(self) -> str:              # for the oracle audit's comparison
        return "forward" if self.admitted else "drop"


# ── helpers ───────────────────────────────────────────────────────────────--

def _fnv1a32(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _pick_backend(flow_key, backends, assign) -> tuple[str, bool]:
    """Return (backend_ip, advanced_selector?) for a NEW flow."""
    global _SELECTOR
    n = len(backends)
    if assign == "round_robin":
        idx = _SELECTOR % n
        _SELECTOR += 1
        return backends[idx], True
    payload = "|".join(str(x) for x in flow_key).encode()
    idx = _fnv1a32(payload) % n
    return backends[idx], False


def _frr_index(frr_groups) -> dict:
    """Normalise frr_groups to a {backend_ip -> entry} dict. Accepts either
    the seed's list[frr_group_entry] (each carrying a `backend` key) or a
    pre-indexed dict."""
    if frr_groups is None:
        return {}
    if isinstance(frr_groups, dict):
        return frr_groups
    out = {}
    for e in frr_groups:
        out[str(e["backend"])] = e
    return out


# ── oracle entry point (step interface) ──────────────────────────

def step(scapy_pkt, ingress_port: int = 1, state: Optional[dict] = None) -> StepResult:
    from scapy.all import IP, TCP

    state = state or {}
    vip          = state.get("vip")
    backends     = list(state.get("backends") or [])
    assign       = state.get("assign", "round_robin")
    frr_groups   = _frr_index(state.get("frr_groups"))
    port_down    = set(int(p) for p in (state.get("port_down") or []))
    cascaded     = bool(state.get("cascaded_backup", False))
    ttl_strict   = bool(state.get("ttl_decrement_strict", True))

    # ── R0: non-IPv4 → drop ─────────────────────────────────────────────────
    if IP not in scapy_pkt:
        return StepResult(False, "R0_non_ipv4_drop")

    ip = scapy_pkt[IP]
    ttl = int(getattr(ip, "ttl", 0))

    # ── R1: not TCP-to-VIP → drop (the LB default-deny gate) ────────────────
    if vip is None or str(ip.dst) != str(vip) or TCP not in scapy_pkt:
        return StepResult(False, "R1_non_vip_or_non_tcp_drop")

    # TTL guard (binding convention: gate ttl > 0). A ttl==0 packet to the VIP
    # drops; this precedes the pin so a dead packet never mutates state.
    if ttl <= 0:
        return StepResult(False, "R1_ttl_exhausted_drop")

    tcp = scapy_pkt[TCP]
    flow_key = (str(ip.src), str(ip.dst), int(tcp.sport), int(tcp.dport), int(ip.proto))

    # ── resolve the pinned backend (existing binding, else select) ──────────
    existing = flow_key in _BINDINGS
    if existing:
        backend = _BINDINGS[flow_key]
        new_flow = False
    else:
        backend, _ = _pick_backend(flow_key, backends, assign)
        new_flow = True

    grp = frr_groups.get(backend)
    if grp is None:
        # Every backend must have an FRR group; a missing group is a seed
        # error, but fail safe (drop, no binding committed).
        return StepResult(False, "drop_no_frr_group_for_backend",
                          backend_ip=backend, new_flow=new_flow)

    primary_port = int(grp["primary_port"])
    backup_port  = int(grp["backup_port"])
    primary_mac  = grp["primary_mac"]
    backup_mac   = grp["backup_mac"]
    primary_down = primary_port in port_down
    backup_down  = backup_port in port_down

    # ── R2: cascaded both-down → drop (no binding committed) ────────────────
    if cascaded and primary_down and backup_down:
        return StepResult(False, "R2_cascaded_double_down_drop",
                          backend_ip=backend, dnat_dst=backend, new_flow=new_flow)

    # commit the binding only on a forwarded packet
    if new_flow:
        _BINDINGS[flow_key] = backend

    # ── FRR demux (R3/R4 forward): primary if up, else backup ───────────────
    if not primary_down:
        out_port, dst_mac, path = primary_port, primary_mac, "primary"
        inv = ("ether_rewrite_correctness_on_primary", {"dst": primary_mac})
    else:
        out_port, dst_mac, path = backup_port, backup_mac, "backup"
        inv = ("ether_rewrite_correctness_on_backup", {"dst": backup_mac})

    prior_dst_mac = str(scapy_pkt["Ether"].dst)
    ttl_delta = 1 if ttl_strict else 0
    log = [
        ("pin_precedes_path", {"frr_keyed_on_backend": backend}),
        ("backend_pin_survives_failover", {"dnat_dst": backend, "path": path}),
        ("failover_does_not_rebalance", {"backend": backend,
                                         "primary_down": primary_down}),
        ("src_addr_preservation", {"src_preserved": True}),
        inv,
        ("ttl_quantum_one", {"decrement": ttl_delta}),
    ]
    return StepResult(
        admitted=True,
        reason=("R3_new_flow_pin_and_forward" if new_flow
                else "R4_existing_flow_forward"),
        output_port=out_port,
        dnat_dst=backend,
        backend_ip=backend,
        next_hop_mac_dst=dst_mac,
        next_hop_mac_src=prior_dst_mac,
        ttl_decrement=ttl_delta,
        new_flow=new_flow,
        path=path,
        invariant_log=log,
    )


# Compatibility alias for callers that use the older name.
def oracle_step(scapy_pkt, ingress_port: int, state: dict) -> StepResult:
    return step(scapy_pkt, ingress_port, state)
