"""Composed oracle for P-ResilientLB (BFD liveness ∘ stateful LB ∘ ring-order
fast reroute) at seed `resilient_lb_anchor-default`.

Implements the single-pass health-checked load balancer in the binding order
BFD-update -> select -> reroute -> route:

  STAGE 1 — BFD liveness update (P-BFDLiveness). A UDP packet to bfd_udp_port
    (3784) arriving on the backend_port, sourced from a backend address,
    updates that backend's liveness bit and is CONSUMED. up=1/down=0 is encoded
    in UDP.sport (sport != 0 => up, sport == 0 => down). decision
    bfd_liveness_update, behavior drop (the BFD packet is terminated).

  STAGE 2 — LB select (P-StatefulLB). A client TCP flow to the virtual_ip
    arriving on the client_port is mapped by a deterministic 5-tuple hash to a
    primary backend index (sum of the 5-tuple integer fields mod hash_modulus).
    If the flow is already pinned and the pinned backend is still up, the pin is
    reused. Otherwise the selector rings forward from the primary index and
    chooses the first LIVE backend in ring order; if no backend is live the
    packet is dropped (all_dead_drop). The chosen index is pinned (install or
    re-pin on failover).

  STAGE 3 — route forward (P-PURRFastReroute / P-IPv4Routing). IP.dst is
    rewritten to the chosen backend address, the packet is routed out the
    backend_port, TTL is decremented once (ttl==0 drops), and Ether.dst is
    rewritten to the chosen next hop.

Load-bearing composite contracts:
  - liveness_gated_selection: a backend whose liveness bit is down is never
    selected; the selector reads the BFD-maintained register first.
  - failover_repin: an established flow whose pinned backend goes down re-pins
    to the next live backend in ring order.
  - all_dead_drop: when no backend is live the client packet is dropped.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant. The liveness/pin tables live on the instance and are cleared
by reset(), so a prior_inputs sequence accumulates state.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
CLIENT_PORT = 1
BACKEND_PORT = 2
VIRTUAL_IP = "10.0.9.9"
BFD_UDP_PORT = 3784
HASH_MODULUS = 3
PIN_CAPACITY = 256
PIN_EVICTION = "none"            # 'none' | 'LRU' | 'FIFO'

# Fixed ring of backends in index order. Each: (backend_ip, egress_port, mac).
BACKEND_POOL = [
    ("10.0.2.11", BACKEND_PORT, "08:00:00:00:02:11"),   # index 0 (B1)
    ("10.0.2.12", BACKEND_PORT, "08:00:00:00:02:12"),   # index 1 (B2)
    ("10.0.2.13", BACKEND_PORT, "08:00:00:00:02:13"),   # index 2 (B3)
]


# ── helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _hash5tuple(src: str, dst: str, proto: int, sport: int, dport: int) -> int:
    """Deterministic, unit-testable: sum of the 5-tuple integer fields."""
    return _ip_to_int(src) + _ip_to_int(dst) + int(proto) + int(sport) + int(dport)


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None
    ttl_decrement: int = 0
    # post-select field values (None == field unchanged from input)
    new_ip_dst: Optional[str] = None
    backend_index: Optional[int] = None
    primary_index: Optional[int] = None
    failover: bool = False
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class ResilientLBSimulator:
    client_port: int = CLIENT_PORT
    backend_port: int = BACKEND_PORT
    virtual_ip: str = VIRTUAL_IP
    bfd_udp_port: int = BFD_UDP_PORT
    hash_modulus: int = HASH_MODULUS
    pin_capacity: int = PIN_CAPACITY
    pin_eviction: str = PIN_EVICTION
    backend_pool: list = field(default_factory=lambda: list(BACKEND_POOL))

    # per-backend liveness: index -> bool (default all up)
    liveness: dict = field(default_factory=dict)
    # per-flow pin: 5-tuple -> backend index
    pins: dict = field(default_factory=dict)
    order: list = field(default_factory=list)

    def __post_init__(self):
        if not self.liveness:
            self.liveness = {i: True for i in range(len(self.backend_pool))}

    def reset(self):
        self.liveness = {i: True for i in range(len(self.backend_pool))}
        self.pins = {}
        self.order = []

    # ── liveness ─────────────────────────────────────────────────────────────
    def _backend_index_by_ip(self, ip: str) -> Optional[int]:
        for i, (bip, _, _) in enumerate(self.backend_pool):
            if bip == ip:
                return i
        return None

    def _ring_select(self, primary: int) -> Optional[int]:
        n = len(self.backend_pool)
        for k in range(n):
            idx = (primary + k) % n
            if self.liveness.get(idx, True):
                return idx
        return None

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, UDP

        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")

        ip = scapy_pkt[IP]
        ttl = int(ip.ttl)
        proto = int(ip.proto)
        if TCP in scapy_pkt:
            sport, dport = int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
        elif UDP in scapy_pkt:
            sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
        else:
            sport, dport = 0, 0

        # STAGE 1 — BFD liveness update (UDP to bfd port, from a backend, on backend_port).
        if (UDP in scapy_pkt and dport == self.bfd_udp_port
                and in_port == self.backend_port):
            bidx = self._backend_index_by_ip(ip.src)
            if bidx is not None:
                up = sport != 0          # sport != 0 => up, sport == 0 => down
                self.liveness[bidx] = up
            return StepResult(False, "bfd_liveness_update",
                              invariant_log=[("liveness_gated_selection",
                                              {"backend": ip.src, "up": sport != 0})])

        # STAGE 2 — LB select for a client flow to the VIP on the client_port.
        if not (in_port == self.client_port and ip.dst == self.virtual_ip):
            # not a client-VIP packet and not a recognised BFD packet -> drop.
            return StepResult(False, "drop_non_ipv4")

        ilog = []
        key = (ip.src, ip.dst, proto, sport, dport)
        primary = _hash5tuple(ip.src, ip.dst, proto, sport, dport) % self.hash_modulus
        ilog.append(("flow_pin", {"primary": primary}))

        failover = False
        if key in self.pins and self.liveness.get(self.pins[key], True):
            chosen = self.pins[key]                      # reuse live pin
            ilog.append(("flow_pin_persistence", {"chosen": chosen}))
        else:
            had_pin = key in self.pins
            chosen = self._ring_select(primary)
            if chosen is None:
                return StepResult(False, "drop_all_backends_down",
                                  primary_index=primary,
                                  invariant_log=ilog + [("all_dead_drop", {})])
            failover = (chosen != primary) or (had_pin and self.pins.get(key) != chosen)
            self.pins[key] = chosen
            ilog.append(("failover_repin" if failover else "flow_pin",
                         {"chosen": chosen}))

        bip, egress, mac = self.backend_pool[chosen]

        # STAGE 3 — route forward on the chosen backend.
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired", backend_index=chosen,
                              primary_index=primary, invariant_log=ilog)
        decision = "forward_lb_failover" if (chosen != primary) else "forward_lb_primary"
        return StepResult(
            True, decision, output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, new_ip_dst=bip, backend_index=chosen,
            primary_index=primary, failover=(chosen != primary),
            invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = ResilientLBSimulator()


# ── PARAMETRIC-SOURCE SHIM ─────────────────
# The module-level step() threads a runtime `state` so every seed-bound knob is
# read from state["config"] at call time rather than a module constant. A 2-arg
# call (no state) falls back to the module default simulator held equal to the
# seed (the oracle audit's smoke path). The simulator — and its mutable per-flow
# accumulators — is persisted in state["_sim"] so a prior_inputs sequence threads
# against one instance. Two siblings with different bindings produce identical
# source; the seed enters here at call time.
import inspect as _inspect


def _sim_from_config(cfg: dict):
    sim_cls = type(_DEFAULT)
    params = _inspect.signature(sim_cls).parameters
    kwargs = {k: cfg[k] for k in cfg if k in params}
    return sim_cls(**kwargs)


def _sim_for(state):
    if state is None:
        return _DEFAULT
    sim = state.get("_sim")
    if sim is None:
        cfg = state.get("config") or {}
        sim = _sim_from_config(cfg) if cfg else type(_DEFAULT)()
        state["_sim"] = sim
    return sim


def step(scapy_pkt, in_port: int = 1, state=None):
    return _sim_for(state).step(scapy_pkt, in_port)


def reset():
    _DEFAULT.reset()
