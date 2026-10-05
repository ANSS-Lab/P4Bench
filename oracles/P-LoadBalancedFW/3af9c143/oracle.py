"""Composed oracle for P-LoadBalancedFW (stateful connection-tracking firewall
∘ stateful service load balancer ∘ LPM forward) at seed `lb_fw_anchor-default`.

Implements the single-pass north-south service pipeline in the binding order
firewall -> LB -> route:

  STAGE 1 — FIREWALL / conntrack (P-StatefulFW). Connection state is keyed on
    the 5-tuple. A new TCP SYN ingressing the client side OPENS a connection
    (state=new). A later packet matching a live forward (client->backend) OR
    reverse (backend->client, swapped tuple) entry is ADMITTED. A packet with
    no live entry that does not itself open one is DROPPED before any LB state
    is touched (no-orphan whitelist / admit_precedes_pin).

  STAGE 2 — LOAD BALANCER (P-StatefulLB). Direction is decided by ingress port:
      client_port  -> if dst == service_vip, choose a backend ONCE by a
        deterministic stable hash of the 5-tuple, PIN it in the conntrack
        entry, and reuse the pin for every later packet of the flow
        (sticky_backend). Rewrite IP.dst -> pinned_backend.
      backend_port -> reverse map: look up the matching tracked connection by
        the swapped 5-tuple; on a hit rewrite IP.src -> service_vip (the client
        always sees the VIP); on a miss DROP (untracked return).

  STAGE 3 — LPM forward (P-IPv4Routing). The fib is consulted on the POST-LB
    IP.dst. No match or ttl==0 drops; otherwise TTL is decremented once,
    Ether.dst is rewritten to the next hop, and the packet egresses.

Load-bearing composite contracts:
  - admit_precedes_pin: a non-admitted connection installs NO LB pin.
  - sticky_backend: every packet of a flow maps to the same pinned backend;
    the backend is chosen once (stable hash) and reused.
  - reverse_path_consistency: a backend reply is reverse-mapped iff a matching
    tracked connection is live; untracked return drops.
  - compound_checksum_validity: one IPv4/L4 checksum recompute covers the LB
    rewrite AND the TTL decrement.

Deterministic backend choice (binding, observable + unit-testable):
    pinned_backend = backend_pool[ stable_hash(5-tuple) % backend_pool_size ]
    stable_hash    = src_int + dst_int + proto + l4_src + l4_dst
where the 5-tuple is the ORIGINAL client->VIP tuple (dst == service_vip on the
first/forward packet). The pin is stored per-connection so reuse is exact.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant. The conntrack table lives on the instance and is cleared by
reset(), so a prior_inputs sequence accumulates connections + pins.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
CLIENT_PORT = 1
BACKEND_PORT = 2
SERVICE_VIP = "10.0.9.9"
BACKEND_POOL = ["10.0.2.11", "10.0.2.12", "10.0.2.13"]
CONNTRACK_CAPACITY = 256
CONNTRACK_EVICTION = "none"        # 'none' | 'LRU' | 'FIFO'
SYN_OPENS_ONLY = True

# LPM forwarding table: (subnet, prefix) -> (egress_port, next_hop_mac).
FIB = [
    (("10.0.1.0", 24), (CLIENT_PORT,  "08:00:00:00:01:01")),   # client hosts
    (("10.0.2.0", 24), (BACKEND_PORT, "08:00:00:00:02:02")),   # backend pool
]

TCP_PROTO = 6


# ── helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _stable_hash(src: str, dst: str, proto: int, sport: int, dport: int) -> int:
    """Deterministic, unit-testable 5-tuple hash: sum of the tuple integers."""
    return _ip_to_int(src) + _ip_to_int(dst) + int(proto) + int(sport) + int(dport)


def _lpm_lookup(dst_ip: str, fib):
    dst = _ip_to_int(dst_ip)
    best, best_len = None, -1
    for (subnet, plen), nh in fib:
        if plen <= best_len:
            continue
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        if (dst & mask) == (_ip_to_int(subnet) & mask):
            best, best_len = nh, plen
    return best


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None
    ttl_decrement: int = 0
    # post-LB field values (None == field unchanged from input)
    new_ip_src: Optional[str] = None
    new_ip_dst: Optional[str] = None
    pinned_backend: Optional[str] = None   # backend chosen/reused for this flow
    fw_verdict: Optional[str] = None       # 'admit' | 'drop'
    lb_direction: Optional[str] = None     # 'forward' | 'reverse' | None
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class LoadBalancedFWSimulator:
    client_port: int = CLIENT_PORT
    backend_port: int = BACKEND_PORT
    service_vip: str = SERVICE_VIP
    backend_pool: list = field(default_factory=lambda: list(BACKEND_POOL))
    conntrack_capacity: int = CONNTRACK_CAPACITY
    conntrack_eviction: str = CONNTRACK_EVICTION
    syn_opens_only: bool = SYN_OPENS_ONLY
    fib: list = field(default_factory=lambda: list(FIB))

    # conntrack: forward key (src,dst,proto,sport,dport) -> {pinned_backend, orig}
    conns: dict = field(default_factory=dict)
    # eviction order (oldest first)
    order: list = field(default_factory=list)

    def reset(self):
        self.conns = {}
        self.order = []

    # ── conntrack ───────────────────────────────────────────────────────────
    def _open(self, key):
        if key in self.conns:
            if key in self.order:
                self.order.remove(key)
            self.order.append(key)
            return
        if len(self.conns) >= self.conntrack_capacity and self.conntrack_eviction in ("LRU", "FIFO"):
            victim = self.order.pop(0)
            self.conns.pop(victim, None)
        self.conns[key] = {"pinned_backend": None}
        self.order.append(key)

    def _pin(self, key, sport, dport, src, dst, proto):
        entry = self.conns[key]
        if entry["pinned_backend"] is None:
            idx = _stable_hash(src, dst, proto, sport, dport) % len(self.backend_pool)
            entry["pinned_backend"] = self.backend_pool[idx]
        return entry["pinned_backend"]

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, UDP

        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")

        ip = scapy_pkt[IP]
        ttl = int(ip.ttl)
        proto = int(ip.proto)
        is_syn = False
        if TCP in scapy_pkt:
            tcp = scapy_pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            is_syn = bool(int(tcp.flags) & 0x02) and not bool(int(tcp.flags) & 0x10)
        elif UDP in scapy_pkt:
            sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
        else:
            sport, dport = 0, 0

        fwd_key = (ip.src, ip.dst, proto, sport, dport)
        # reverse-direction match: a backend reply's swapped tuple equals the
        # forward key with src/dst and sport/dport swapped, AND the forward
        # entry's pinned backend is the reply's source.
        rev_match = None
        for fk, entry in self.conns.items():
            (fsrc, fdst, fproto, fsp, fdp) = fk
            if (fproto == proto and fsrc == ip.dst and fsp == dport
                    and fdp == sport and entry["pinned_backend"] == ip.src):
                rev_match = (fk, entry)
                break

        # STAGE 1 — FIREWALL / conntrack.
        #
        # A new TCP SYN from the client side opens a connection. Any packet
        # matching a live forward (client->VIP) or reverse (backend->client)
        # entry is admitted. The no-orphan whitelist rule is split by direction
        # so the decision codes stay distinct: a CLIENT-side packet with no live
        # connection that does not open one is `drop_no_conntrack`; a
        # BACKEND-side packet with no matching tracked connection is handled by
        # the reverse LB stage as `drop_return_untracked` (reverse_path).
        ilog = []
        opens = (in_port == self.client_port and proto == TCP_PROTO and is_syn
                 and self.syn_opens_only)
        live_fwd = fwd_key in self.conns
        if opens:
            self._open(fwd_key)
        elif in_port == self.client_port and not live_fwd:
            ilog.append(("no_orphan", {"key": fwd_key}))
            return StepResult(False, "drop_no_conntrack", fw_verdict="drop",
                              invariant_log=ilog)
        ilog.append(("admit_precedes_pin", {"verdict": "admit"}))

        # STAGE 2 — LOAD BALANCER.
        new_src = new_dst = None
        pinned = None
        direction = None
        if in_port == self.client_port:
            direction = "forward"
            if ip.dst == self.service_vip:
                pinned = self._pin(fwd_key, sport, dport, ip.src, ip.dst, proto)
                new_dst = pinned
                route_dst = pinned
                ilog.append(("sticky_backend", {"pinned": pinned}))
            else:
                route_dst = ip.dst
        elif in_port == self.backend_port:
            direction = "reverse"
            if rev_match is None:
                ilog.append(("reverse_path_consistency", {"tracked": False}))
                return StepResult(False, "drop_return_untracked", fw_verdict="admit",
                                  lb_direction="reverse", invariant_log=ilog)
            new_src = self.service_vip
            route_dst = ip.dst
            ilog.append(("reverse_path_consistency", {"tracked": True}))
        else:
            route_dst = ip.dst

        # STAGE 3 — LPM forward on the POST-LB dst.
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired", fw_verdict="admit",
                              lb_direction=direction, pinned_backend=pinned,
                              invariant_log=ilog)
        nh = _lpm_lookup(route_dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", fw_verdict="admit",
                              lb_direction=direction, pinned_backend=pinned,
                              invariant_log=ilog)
        egress, mac = nh
        ilog.append(("compound_checksum_validity",
                     {"lb": direction, "ttl_decremented": True}))
        if direction == "forward":
            decision = ("forward_new_pinned"
                        if opens and ip.dst == self.service_vip
                        else "forward_established")
        elif direction == "reverse":
            decision = "forward_return"
        else:
            decision = "forward_transit"
        return StepResult(
            True, decision, output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, new_ip_src=new_src, new_ip_dst=new_dst,
            pinned_backend=pinned, fw_verdict="admit", lb_direction=direction,
            invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = LoadBalancedFWSimulator()


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
