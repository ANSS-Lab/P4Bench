"""Per-task oracle for benchmark/redesign/icmp_error_gen_anchor (P-ICMPErrorGen).

IPv4 forwarder with ICMP Time-Exceeded origination on TTL expiry.

  - R0  non-IPv4 drop
  - R1  live TTL (>1) + route → normal forward (TTL--, L2 rewrite)
  - R2  TTL ≤ 1 (and not already an ICMP error) → originate ICMP Time Exceeded
        (type 11, code 0): ip.src=router_ip, ip.dst=orig.src, routed to the
        source via the FIB; original dropped
  - R3  live TTL, no route → drop

Config read from state["config"]. Entry point: step(packet, ingress_port, state).
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


_DEFAULT_CONFIG = {
    "router_ip": "10.0.0.254",
    "routes": [
        {"prefix": "10.0.5.0", "prefix_len": 24, "port": 2,
         "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        {"prefix": "10.0.6.0", "prefix_len": 24, "port": 3,
         "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    ],
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _ip_to_int(a):
    p = [int(x) for x in str(a).split(".")]
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]


def _lpm(dst, routes):
    d = _ip_to_int(dst)
    best, bl = None, -1
    for r in routes:
        pl = int(r["prefix_len"])
        mask = ((1 << pl) - 1) << (32 - pl) if pl else 0
        if (d & mask) == (_ip_to_int(r["prefix"]) & mask) and pl > bl:
            best, bl = r, pl
    return best


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    from scapy.all import Ether, IP, ICMP, Raw
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)
    routes = cfg["routes"]

    if not packet.haslayer(IP):
        return _drop(new_state, "R0_non_ipv4")

    ip = packet.getlayer(IP)
    ttl = int(ip.ttl)
    src = str(ip.src)
    dst = str(ip.dst)
    is_icmp_err = packet.haslayer(ICMP) and int(getattr(packet.getlayer(ICMP), "type", -1)) in (3, 11)

    if ttl > 1:
        route = _lpm(dst, routes)
        if route is None:
            return _drop(new_state, "R3_no_route")
        out = packet.copy()
        out[Ether].src = route["port_mac"]
        out[Ether].dst = route["nexthop_mac"]
        out[IP].ttl = ttl - 1
        return StepResult(output_packets={int(route["port"]): [out]}, new_state=new_state,
                          decision="forward", invariant_log=[("R1_forward", {"port": int(route["port"])})])

    # R2 — TTL expired → originate ICMP Time Exceeded toward the source
    if is_icmp_err:
        return _drop(new_state, "R2_no_icmp_to_icmp")
    route = _lpm(src, routes)               # route the error back to the source
    if route is None:
        return _drop(new_state, "R2_source_unreachable")
    quote = bytes(ip)[:28]                   # original IP header + 8 bytes
    err = (Ether(src=route["port_mac"], dst=route["nexthop_mac"]) /
           IP(src=str(cfg["router_ip"]), dst=src, proto=1, ttl=64) /
           ICMP(type=11, code=0) / Raw(load=quote))
    return StepResult(output_packets={int(route["port"]): [err]}, new_state=new_state,
                      decision="forward",
                      invariant_log=[("R2_icmp_time_exceeded",
                                      {"port": int(route["port"]), "dst": src, "src": cfg["router_ip"]})])
