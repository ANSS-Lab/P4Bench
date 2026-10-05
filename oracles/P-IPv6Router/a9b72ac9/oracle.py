"""Per-task oracle for benchmark/scale_up/ipv6_router_anchor (P-IPv6Router).

Implements the IPv6 unicast-forwarding rule sequence under
the canonical D5.0 single-next-hop static-FIB seed:

  - R0  non-IPv6 drop
  - R1  hop-limit-exhausted drop (gate hopLimit > 1: hlim ∈ {0,1} drops; a
        transit router cannot forward a packet that would decrement to 0,
        RFC 8200 §3)
  - R4  link-local destination (fe80::/10) drop      (gated)
  - R5  multicast destination (ff00::/8) drop         (gated)
  - R2  LPM-hit forward: longest-prefix route → egress port, Ether.src ←
        egress port MAC, Ether.dst ← next-hop MAC, decrement hopLimit by one;
        IPv6 src/dst preserved; NO header checksum (IPv6 has none)
  - R3  no route → drop (default_action)

Per the parametric-source contract: routes, multipath_mode,
filter_link_local, filter_multicast, default_action are read from
state["config"] at runtime, never baked as source-level constants — this lets
parameter rebinding reuse the same audited oracle.

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ── Default config mirrors the canonical seed; overridden by state["config"]. ─
_DEFAULT_CONFIG = {
    "routes": [
        {"prefix": "2001:db8:1::", "prefix_len": 64, "port": 1,
         "port_mac": "08:00:00:00:01:00", "nexthop_mac": "08:00:00:00:01:01"},
        {"prefix": "2001:db8:2::", "prefix_len": 64, "port": 2,
         "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        {"prefix": "2001:db8:3::", "prefix_len": 64, "port": 3,
         "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
        {"prefix": "2001:db8:2:0:0:0:0:7", "prefix_len": 128, "port": 3,
         "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    ],
    "multipath_mode": "none",
    "filter_link_local": True,
    "filter_multicast": True,
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


def _has_ipv6(packet) -> bool:
    return _has_layer(packet, "IPv6") or _has_layer(packet, "ipv6")


def _ip6(packet, fname, default=None):
    v = _field(packet, "IPv6", fname, None)
    if v is None:
        v = _field(packet, "ipv6", fname, None)
    return default if v is None else v


# ── Address helpers (128-bit) ───────────────────────────────────────────────

def _addr_int(addr: str) -> int:
    return int(ipaddress.IPv6Address(str(addr)))


def _in_prefix(addr: str, prefix: str, plen: int) -> bool:
    a = _addr_int(addr)
    p = _addr_int(prefix)
    if plen == 0:
        return True
    mask = ((1 << plen) - 1) << (128 - plen)
    return (a & mask) == (p & mask)


def _lpm_match(dst: str, routes: List[dict]) -> Optional[dict]:
    d = _addr_int(dst)
    best, best_len = None, -1
    for r in routes:
        plen = int(r["prefix_len"])
        if plen == 0:
            mask = 0
        else:
            mask = ((1 << plen) - 1) << (128 - plen)
        if (d & mask) == (_addr_int(r["prefix"]) & mask) and plen > best_len:
            best, best_len = r, plen
    return best


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

    # R0 — non-IPv6 drop
    if not _has_ipv6(packet):
        return _drop(new_state, "R0_non_ipv6")

    hlim = int(_ip6(packet, "hlim", 0))
    dst = str(_ip6(packet, "dst", "::"))

    # R1 — hop-limit exhausted (gate hopLimit > 1)
    if hlim <= 1:
        return _drop(new_state, "R1_hoplimit_exhausted")

    # R4 — link-local destination (gated)
    if cfg.get("filter_link_local") and _in_prefix(dst, "fe80::", 10):
        return _drop(new_state, "R4_link_local")

    # R5 — multicast destination (gated)
    if cfg.get("filter_multicast") and _in_prefix(dst, "ff00::", 8):
        return _drop(new_state, "R5_multicast")

    # R2 / R3 — LPM lookup
    route = _lpm_match(dst, routes)
    if route is None:
        return _drop(new_state, "R3_no_route")

    # R2 — forward (singleton next-hop at multipath_mode == none → i = 0)
    out = _clone(packet)
    _set(out, "Ether", "src", route["port_mac"])
    _set(out, "Ether", "dst", route["nexthop_mac"])
    if isinstance(out, dict):
        out.setdefault("IPv6", {})["hlim"] = hlim - 1
    else:
        try:
            out["IPv6"].hlim = hlim - 1
        except Exception:
            pass
    return StepResult(
        output_packets={int(route["port"]): [out]},
        new_state=new_state,
        decision="forward",
        invariant_log=[("R2_forward",
                        {"port": int(route["port"]),
                         "ether_src": route["port_mac"],
                         "ether_dst": route["nexthop_mac"],
                         "hlim": hlim - 1,
                         "prefix": f"{route['prefix']}/{route['prefix_len']}"})],
    )
