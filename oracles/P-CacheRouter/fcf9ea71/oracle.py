"""Composed oracle for P-CacheRouter (stateless ACL ∘ NetCache KV-cache ∘ LPM
forward) at seed `cache_router_anchor-default`.

Implements the in-switch key-value cache pipeline in the binding order
ACL → cache → route:

  STAGE 1 — ACL classification (P-ACL). The request 5-tuple is matched against
    a stateless ternary table by descending priority. A deny (or a miss under
    default_acl_action == deny) drops the packet BEFORE the cache is consulted
    or mutated (acl_precedes_cache) — a deny neither serves a value nor
    invalidates a key.

  STAGE 2 — KV cache (P-NetCacheKV). Request type is decided by UDP.dport:
      read_dport (7777) -> READ. The cache key is the low byte of UDP.sport
        (key = UDP.sport & 0xFF). On a HIT (key present and valid) the switch
        synthesises the reply IN PLACE: swap IP.src/IP.dst, swap
        UDP.sport/UDP.dport, encode the 16-bit cached value into IP.id, and
        egress on the INGRESS (client) port (hit_served_locally — the store
        never sees the request). On a MISS, fall through to the forwarder.
      write_dport (7778) -> WRITE. Invalidate the cached value for the key
        (write_invalidation_coherence — a later read of that key MISSES), then
        fall through to the forwarder (write-through).
      anything else -> ordinary IPv4 packet; fall through to the forwarder.

  STAGE 3 — LPM forward (P-IPv4Routing). For everything not served from cache,
    the fib is consulted on IP.dst. No match or ttl==0 drops; otherwise TTL is
    decremented once, Ether.dst is rewritten to the next hop, and the packet
    egresses toward the store.

Load-bearing composite contracts:
  - acl_precedes_cache: a denied request neither serves nor invalidates.
  - hit_served_locally: a cached read egresses the ingress (client) port.
  - write_invalidation_coherence: a write invalidates the key so the next read
    of it MISSES and is routed to the store (visible only across write->read).
  - read_reply_endpoint_swap: a hit reply has IP src/dst and UDP sport/dport
    swapped relative to the request, value in IP.id.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant. The cache valid-bits live on the instance and are reset by
reset(), so a prior_inputs sequence accumulates invalidations.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
CLIENT_PORT = 1
STORE_PORT = 2
READ_DPORT = 7777
WRITE_DPORT = 7778
DEFAULT_ACL_ACTION = "permit"

# Preloaded KV cache: key (UDP.sport low byte) -> 16-bit value.
CACHE_ENTRIES = {
    0x10: 4242,
    0x20: 0xBEEF,
}

# Stateless ACL: priority + action + ternary src/dst/proto/sport/dport
# (missing field = wildcard). Evaluated on the request tuple.
ACL_RULES = [
    {"priority": 100, "action": "deny", "ipv4_src": "10.0.1.66/32"},   # blocked client
]

# LPM forwarding table: (subnet, prefix) -> (egress_port, next_hop_mac).
FIB = [
    (("10.0.1.0", 24), (CLIENT_PORT, "08:00:00:00:01:01")),   # clients
    (("10.0.2.0", 24), (STORE_PORT, "08:00:00:00:02:02")),    # store
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
    # post-pipeline field values (None == field unchanged from input)
    new_ip_src: Optional[str] = None
    new_ip_dst: Optional[str] = None
    new_l4_src: Optional[int] = None
    new_l4_dst: Optional[int] = None
    new_ip_id: Optional[int] = None        # cached value encoded on a hit reply
    request_type: Optional[str] = None     # 'read' | 'write' | 'other' | None
    acl_verdict: Optional[str] = None      # 'permit' | 'deny'
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class CacheRouterSimulator:
    client_port: int = CLIENT_PORT
    store_port: int = STORE_PORT
    read_dport: int = READ_DPORT
    write_dport: int = WRITE_DPORT
    default_acl_action: str = DEFAULT_ACL_ACTION
    cache_entries: dict = field(default_factory=lambda: dict(CACHE_ENTRIES))
    acl_rules: list = field(default_factory=lambda: [dict(r) for r in ACL_RULES])
    fib: list = field(default_factory=lambda: list(FIB))

    # per-key validity (a write-through invalidates a key for later reads)
    invalidated: set = field(default_factory=set)

    def reset(self):
        self.invalidated = set()

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

    def _cached(self, key: int) -> bool:
        return key in self.cache_entries and key not in self.invalidated

    # ── routing helper ──────────────────────────────────────────────────────
    def _route(self, route_dst, ttl, verdict, req_type, decision):
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired", acl_verdict=verdict,
                              request_type=req_type)
        nh = _lpm_lookup(route_dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", acl_verdict=verdict,
                              request_type=req_type)
        egress, mac = nh
        return StepResult(
            True, decision, output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, acl_verdict=verdict, request_type=req_type)

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

        # STAGE 1 — ACL on the request tuple.
        verdict = self._acl_verdict(l4)
        ilog = [("acl_precedes_cache", {"verdict": verdict})]
        if verdict == "deny":
            return StepResult(False, "drop_acl_deny", acl_verdict="deny",
                              invariant_log=ilog)

        is_udp = UDP in scapy_pkt
        key = sport & 0xFF

        # STAGE 2 — KV cache dispatch by UDP dport.
        if is_udp and dport == self.read_dport:
            req_type = "read"
            if self._cached(key):
                # HIT — serve locally on the ingress port, swap endpoints.
                value = int(self.cache_entries[key]) & 0xFFFF
                ilog.append(("hit_served_locally", {"key": key, "value": value}))
                ilog.append(("read_reply_endpoint_swap", {}))
                return StepResult(
                    True, "cache_hit_reply", output_port=in_port,
                    ttl_decrement=0,
                    new_ip_src=ip.dst, new_ip_dst=ip.src,
                    new_l4_src=dport, new_l4_dst=sport,
                    new_ip_id=value, request_type=req_type,
                    acl_verdict=verdict, invariant_log=ilog)
            # MISS — fall through to the forwarder.
            ilog.append(("cache_miss_route", {"key": key}))
            return self._route(ip.dst, ttl, verdict, req_type, "forward_cache_miss")

        if is_udp and dport == self.write_dport:
            req_type = "write"
            # WRITE-THROUGH — invalidate the key, then forward to the store.
            self.invalidated.add(key)
            ilog.append(("write_invalidation_coherence", {"key": key}))
            return self._route(ip.dst, ttl, verdict, req_type, "forward_write_invalidate")

        # ordinary IPv4 packet (neither read nor write) — route.
        req_type = "other"
        return self._route(ip.dst, ttl, verdict, req_type, "forward_transit")

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit (2-arg smoke path).
_DEFAULT = CacheRouterSimulator()


def _sim_from_config(cfg: dict) -> "CacheRouterSimulator":
    """Build a simulator from a threaded seed config. Every knob is read from
    `cfg` with the seed-bound module default as fallback, so the seed enters
    here at call time and never as the authoritative source-level constant
    (parametric-source contract). A parameter rebind that changes
    read_dport / write_dport / cache_entries / acl_rules / fib / ports moves the
    materialised expectations without regenerating this oracle."""
    ce = cfg.get("cache_entries")
    if isinstance(ce, list):                     # seed shape: [{key, value}, ...]
        ce = {int(e["key"]): int(e["value"]) for e in ce}
    elif isinstance(ce, dict):
        ce = {int(k): int(v) for k, v in ce.items()}
    else:
        ce = dict(CACHE_ENTRIES)

    fib = cfg.get("fib")
    if fib is None:
        # Derive the FIB from the seed's client/store subnets + ports when given,
        # else fall back to the baked FIB.
        client_subnet = cfg.get("client_subnet")
        store_subnet = cfg.get("store_subnet")
        cport = int(cfg.get("client_port", CLIENT_PORT))
        sport = int(cfg.get("store_port", STORE_PORT))
        if client_subnet and store_subnet:
            cnet, cplen = client_subnet.split("/")
            snet, splen = store_subnet.split("/")
            fib = [((cnet, int(cplen)), (cport, "08:00:00:00:01:01")),
                   ((snet, int(splen)), (sport, "08:00:00:00:02:02"))]
        else:
            fib = list(FIB)

    return CacheRouterSimulator(
        client_port=int(cfg.get("client_port", CLIENT_PORT)),
        store_port=int(cfg.get("store_port", STORE_PORT)),
        read_dport=int(cfg.get("read_dport", READ_DPORT)),
        write_dport=int(cfg.get("write_dport", WRITE_DPORT)),
        default_acl_action=cfg.get("default_acl_action", DEFAULT_ACL_ACTION),
        cache_entries=ce,
        acl_rules=[dict(r) for r in (cfg["acl_rules"] if "acl_rules" in cfg
                                     else ACL_RULES)],
        fib=fib,
    )


def _sim_for(state: Optional[dict]) -> "CacheRouterSimulator":
    """Resolve the simulator for this call. With a threaded `state` carrying a
    `config`, build (once) a seed-configured simulator and persist it in
    `state['_sim']` so a prior_inputs sequence accumulates invalidations against
    the same instance. With no state (2-arg audit smoke path) use the module
    default held equal to this seed."""
    if state is None:
        return _DEFAULT
    sim = state.get("_sim")
    if sim is None:
        cfg = state.get("config") or {}
        sim = _sim_from_config(cfg) if cfg else CacheRouterSimulator()
        state["_sim"] = sim
    return sim


def step(scapy_pkt, in_port: int = 1, state: Optional[dict] = None):
    return _sim_for(state).step(scapy_pkt, in_port)


def reset():
    _DEFAULT.reset()
