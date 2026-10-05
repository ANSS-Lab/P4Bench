"""Composed oracle for P-SecureRouter (stateless ACL ∘ stateful NAT44 ∘ LPM
forward) at seed `secure_router_anchor-default`.

Implements the single-pass edge-router pipeline in the binding order
ACL → NAT → route:

  STAGE 1 — ACL classification (P-ACL). The original (pre-NAT) 5-tuple is
    matched against a stateless ternary table by descending priority. A deny
    (or a miss under default_acl_action == deny) drops the packet BEFORE any
    NAT state is touched (acl_precedes_nat).

  STAGE 2 — NAT44 (P-NAT44). Direction is decided by ingress port:
      inside_port  -> source-NAT: rewrite IP.src -> nat_pool_ip and L4.src ->
        an allocated pool port; the binding (orig_ip, orig_l4_src, proto) ->
        (pool_port) is installed on first sight and reused thereafter, and the
        reverse mapping (nat_pool_ip, pool_port, proto) -> (orig_ip, orig_port)
        is installed at the same time.
      outside_port -> reverse de-NAT: look up (IP.dst==nat_pool_ip, L4.dst,
        proto) in the reverse table; on a hit rewrite IP.dst/L4.dst back to the
        original inside endpoint; on a miss DROP (unsolicited inbound).

  STAGE 3 — LPM forward (P-IPv4Routing). The fib is consulted on the POST-NAT
    IP.dst. No match or ttl==0 drops; otherwise TTL is decremented once,
    Ether.dst is rewritten to the next hop, and the packet egresses.

Load-bearing composite contracts:
  - acl_precedes_nat: a denied flow installs NO nat binding.
  - reverse_mapping_consistency: inbound is de-NATed iff a matching outbound
    binding is live; unsolicited inbound drops.
  - post_nat_routing: the LPM key is IP.dst AFTER reverse de-NAT.
  - compound_checksum_validity: one IPv4/L4 checksum recompute covers the NAT
    rewrites AND the TTL decrement.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant. The nat tables live on the instance and are cleared by
reset(), so a prior_inputs sequence accumulates bindings.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
INSIDE_PORT = 1
OUTSIDE_PORT = 2
NAT_POOL_IP = "203.0.113.1"
NAT_POOL_PORT_BASE = 20000
NAT_CAPACITY = 256
NAT_EVICTION = "none"            # 'none' | 'LRU' | 'FIFO'
DEFAULT_ACL_ACTION = "permit"

# Stateless ACL: priority + action + ternary src/dst/proto/sport/dport
# (missing field = wildcard). Evaluated on the PRE-NAT tuple.
ACL_RULES = [
    {"priority": 100, "action": "deny", "ipv4_src": "10.0.1.66/32"},   # blocked inside host
]

# LPM forwarding table: (subnet, prefix) -> (egress_port, next_hop_mac).
FIB = [
    (("10.0.1.0", 24),     (INSIDE_PORT,  "08:00:00:00:01:01")),   # inside hosts
    (("198.51.100.0", 24), (OUTSIDE_PORT, "08:00:00:00:02:02")),   # external dst
]


# ── helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _ipv4_match(addr: str, cidr: Optional[str]) -> bool:
    if cidr is None:
        return True
    if "/" in cidr:
        net, n = cidr.split("/"); n = int(n)
    else:
        net, n = cidr, 32
    mask = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0
    return (_ip_to_int(addr) & mask) == (_ip_to_int(net) & mask)


def _eq_or_any(v, c) -> bool:
    return c is None or v == c


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
    # post-NAT field values (None == field unchanged from input)
    new_ip_src: Optional[str] = None
    new_ip_dst: Optional[str] = None
    new_l4_src: Optional[int] = None
    new_l4_dst: Optional[int] = None
    nat_direction: Optional[str] = None    # 'outbound' | 'inbound' | None
    acl_verdict: Optional[str] = None      # 'permit' | 'deny'
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class SecureRouterSimulator:
    inside_port: int = INSIDE_PORT
    outside_port: int = OUTSIDE_PORT
    nat_pool_ip: str = NAT_POOL_IP
    nat_pool_port_base: int = NAT_POOL_PORT_BASE
    nat_capacity: int = NAT_CAPACITY
    nat_eviction: str = NAT_EVICTION
    default_acl_action: str = DEFAULT_ACL_ACTION
    acl_rules: list = field(default_factory=lambda: [dict(r) for r in ACL_RULES])
    fib: list = field(default_factory=lambda: list(FIB))

    # forward bindings: (orig_ip, orig_port, proto) -> pool_port
    fwd: dict = field(default_factory=dict)
    # reverse bindings: (pool_port, proto) -> (orig_ip, orig_port)
    rev: dict = field(default_factory=dict)
    # LRU/FIFO order of forward keys (oldest first)
    order: list = field(default_factory=list)

    def reset(self):
        self.fwd = {}
        self.rev = {}
        self.order = []

    # ── ACL ───────────────────────────────────────────────────────────────
    def _acl_verdict(self, l4: dict) -> str:
        best, best_p = None, -1
        for r in self.acl_rules:
            if (_ipv4_match(l4["src"], r.get("ipv4_src"))
                    and _ipv4_match(l4["dst"], r.get("ipv4_dst"))
                    and _eq_or_any(l4["proto"], r.get("proto"))
                    and _eq_or_any(l4["sport"], r.get("sport"))
                    and _eq_or_any(l4["dport"], r.get("dport"))):
                p = int(r["priority"])
                if p > best_p:
                    best, best_p = r, p
        return best["action"] if best is not None else self.default_acl_action

    # ── NAT allocation ──────────────────────────────────────────────────────
    def _allocate(self, key):
        """Return (pool_port, installed_now)."""
        if key in self.fwd:
            # refresh recency
            if key in self.order:
                self.order.remove(key)
            self.order.append(key)
            return self.fwd[key], False
        # evict if at capacity
        if len(self.fwd) >= self.nat_capacity and self.nat_eviction in ("LRU", "FIFO"):
            victim = self.order.pop(0)
            vp = self.fwd.pop(victim)
            self.rev.pop((vp, victim[2]), None)
        port = self.nat_pool_port_base + len(self.fwd)
        self.fwd[key] = port
        self.rev[(port, key[2])] = (key[0], key[1])
        self.order.append(key)
        return port, True

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
        l4 = {"src": ip.src, "dst": ip.dst, "proto": proto,
              "sport": sport, "dport": dport}

        # STAGE 1 — ACL on the PRE-NAT tuple.
        verdict = self._acl_verdict(l4)
        ilog = [("acl_precedes_nat", {"verdict": verdict})]
        if verdict == "deny":
            return StepResult(False, "drop_acl_deny", acl_verdict="deny",
                              invariant_log=ilog)

        # STAGE 2 — NAT.
        new_src = new_dst = None
        new_sport = new_dport = None
        direction = None
        if in_port == self.inside_port:
            direction = "outbound"
            port, _ = self._allocate((ip.src, sport, proto))
            new_src = self.nat_pool_ip
            new_sport = port
            route_dst = ip.dst
            ilog.append(("nat_outbound", {"pool_port": port}))
        elif in_port == self.outside_port:
            direction = "inbound"
            key = (dport, proto)
            if ip.dst != self.nat_pool_ip or key not in self.rev:
                return StepResult(False, "drop_unsolicited_inbound",
                                  acl_verdict=verdict, nat_direction="inbound",
                                  invariant_log=ilog)
            orig_ip, orig_port = self.rev[key]
            new_dst = orig_ip
            new_dport = orig_port
            route_dst = orig_ip
            ilog.append(("reverse_mapping_consistency",
                         {"orig": orig_ip, "orig_port": orig_port}))
        else:
            route_dst = ip.dst

        # STAGE 3 — LPM forward on the POST-NAT dst.
        ilog.append(("post_nat_routing", {"route_dst": route_dst}))
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired", acl_verdict=verdict,
                              nat_direction=direction, invariant_log=ilog)
        nh = _lpm_lookup(route_dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", acl_verdict=verdict,
                              nat_direction=direction, invariant_log=ilog)
        egress, mac = nh
        ilog.append(("compound_checksum_validity",
                     {"nat": direction, "ttl_decremented": True}))
        decision = ("forward_outbound_nat" if direction == "outbound"
                    else "forward_inbound_denat" if direction == "inbound"
                    else "forward_transit")
        return StepResult(
            True, decision, output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, new_ip_src=new_src, new_ip_dst=new_dst,
            new_l4_src=new_sport, new_l4_dst=new_dport,
            nat_direction=direction, acl_verdict=verdict, invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = SecureRouterSimulator()


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
