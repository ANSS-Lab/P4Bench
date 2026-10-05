"""Python oracle for benchmark/redesign/ipv4_routing_anchor.

Implements P-IPv4Routing's rule sequence under the
task's seed (D5.0_static_fib single-next-hop forwarder):

  - R0  non-IPv4 drop
  - R1  invalid IPv4 header drop (version≠4, IHL<5, totalLen<header)
  - R2  TTL-exhausted drop  (gate `ttl > 0`: ttl==0 drops, ttl==1 forwards
        to egress ttl==0 — the basic_ipv4_forwarding tutorial convention
        that the `fwd_ttl_one` test pins, and that
        an anchor instance must subsume)
  - R3  LPM-hit forward: longest-prefix route → set egress port, rewrite
        Ether.src ← egress port MAC, Ether.dst ← next-hop MAC, decrement
        TTL by exactly one; IP src/dst preserved
  - R4  no-route → default_action (drop at this seed)
  - R5  limited-broadcast dst (255.255.255.255) → drop
  - R6  martian-source drop (gated off — martian_filter_enabled=false)
  - R7  directed-broadcast dst (all-ones host of a configured subnet) → drop

Per the parametric-source contract: routes,
multipath_mode, martian_filter_enabled, default_action, etc. are read from
`state["config"]` at runtime, never baked as source-level constants — this
is what lets parameter rebinding reuse the same audited
oracle across mutated instances (e.g. ECMP / martian / scaled-FIB siblings).

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ── Default config mirrors the anchor seed; overridden by state["config"]. ──
_DEFAULT_CONFIG = {
    "routes": [
        {"prefix": "10.0.1.0", "prefix_len": 24, "port": 1,
         "port_mac": "08:00:00:00:01:00", "nexthop_mac": "08:00:00:00:01:01"},
        {"prefix": "10.0.2.0", "prefix_len": 24, "port": 2,
         "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        {"prefix": "10.0.3.0", "prefix_len": 24, "port": 3,
         "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
        {"prefix": "10.0.2.7", "prefix_len": 32, "port": 3,
         "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    ],
    "multipath_mode": "none",
    "martian_filter_enabled": False,
    "emit_icmp_errors": False,
    "default_action": "drop",
}


def _config(state: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


# ── Packet introspection (Scapy + dict-style tolerant) ──────────────────────

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


def _has_ipv4(packet) -> bool:
    return _has_layer(packet, "IP") or _has_layer(packet, "ipv4")


def _ip(packet, fname, default=None):
    v = _field(packet, "IP", fname, None)
    if v is None:
        v = _field(packet, "ipv4", fname, None)
    return default if v is None else v


# ── Address helpers ─────────────────────────────────────────────────────────

def _ip_to_int(addr: str) -> int:
    parts = [int(x) for x in str(addr).split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _lpm_match(dst: str, routes: List[dict]) -> Optional[dict]:
    """Return the route with the longest prefix covering dst, or None."""
    d = _ip_to_int(dst)
    best = None
    best_len = -1
    for r in routes:
        plen = int(r["prefix_len"])
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        if (d & mask) == (_ip_to_int(r["prefix"]) & mask):
            if plen > best_len:
                best, best_len = r, plen
    return best


def _is_directed_broadcast(dst: str, routes: List[dict]) -> bool:
    """True when dst is the all-ones host address of a configured subnet
    (prefix_len < 32)."""
    d = _ip_to_int(dst)
    for r in routes:
        plen = int(r["prefix_len"])
        if plen >= 32 or plen == 0:
            continue
        net = _ip_to_int(r["prefix"]) & (((1 << plen) - 1) << (32 - plen))
        bcast = net | ((1 << (32 - plen)) - 1)
        if d == bcast:
            return True
    return False


def _is_martian_src(src: str) -> bool:
    s = _ip_to_int(src)
    def inb(prefix, plen):
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        return (s & mask) == (_ip_to_int(prefix) & mask)
    return (inb("127.0.0.0", 8) or inb("0.0.0.0", 8)
            or inb("224.0.0.0", 4) or src == "255.255.255.255")


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _set(packet, layer, fname, value):
    if isinstance(packet, dict):
        packet.setdefault(layer, {})[fname] = value
        return
    try:
        setattr(packet[layer], fname, value)
    except Exception:
        pass


def _drop(state, reason) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


# ── step() — oracle interface ───────────────────────────────────────────────

def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)
    routes = cfg["routes"]

    # R0 — non-IPv4 drop
    if not _has_ipv4(packet):
        return _drop(new_state, "R0_non_ipv4")

    # R1 — invalid IPv4 header (only checks fields when explicitly present)
    version = _ip(packet, "version", 4)
    ihl = _ip(packet, "ihl", 5)
    total_len = _ip(packet, "len", None)
    if int(version) != 4 or int(ihl) < 5:
        return _drop(new_state, "R1_invalid_header")
    if total_len is not None and int(total_len) < int(ihl) * 4:
        return _drop(new_state, "R1_total_length")

    ttl = int(_ip(packet, "ttl", 0))
    src = _ip(packet, "src", "0.0.0.0")
    dst = _ip(packet, "dst", "0.0.0.0")

    # R2 — TTL exhausted (gate ttl > 0; ttl==1 forwards to egress 0)
    if ttl <= 0:
        return _drop(new_state, "R2_ttl_exhausted")

    # R5 — limited-broadcast destination
    if dst == "255.255.255.255":
        return _drop(new_state, "R5_limited_broadcast")

    # R6 — martian source (gated)
    if cfg.get("martian_filter_enabled") and _is_martian_src(src):
        return _drop(new_state, "R6_martian_src")

    # R7 — directed-broadcast destination
    if _is_directed_broadcast(dst, routes):
        return _drop(new_state, "R7_directed_broadcast")

    # R3 / R4 — LPM lookup
    route = _lpm_match(dst, routes)
    if route is None:
        return _drop(new_state, "R4_no_route")

    # R3 — forward (singleton next-hop at multipath_mode == none → i = 0)
    out = _clone(packet)
    _set(out, "Ether", "src", route["port_mac"])
    _set(out, "Ether", "dst", route["nexthop_mac"])
    if isinstance(out, dict):
        out.setdefault("IP", {})["ttl"] = ttl - 1
        out["IP"]["chksum"] = None        # RFC 1812 §5.2.2.5: recompute hdr checksum on egress (TTL changed)
    else:
        try:
            out["IP"].ttl = ttl - 1
            out["IP"].chksum = None        # force scapy to recompute the IPv4 header checksum
        except Exception:
            pass
    return StepResult(
        output_packets={int(route["port"]): [out]},
        new_state=new_state,
        decision="forward",
        invariant_log=[("R3_forward",
                        {"port": int(route["port"]),
                         "ether_src": route["port_mac"],
                         "ether_dst": route["nexthop_mac"],
                         "ttl": ttl - 1,
                         "prefix": f"{route['prefix']}/{route['prefix_len']}"})],
    )
