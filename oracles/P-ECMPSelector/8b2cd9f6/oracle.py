"""Per-task oracle for benchmark/redesign/ecmp_selector_anchor.

P-ECMPSelector under the canonical seed: an RFC 2992 equal-cost multipath
(ECMP) next-hop selector. STATELESS: for each routed IPv4 packet, longest-
prefix-match the destination to an ECMP group of N equal-cost next-hop ports,
then select ONE member by a hash over the flow 5-tuple (the v1model
`action_selector` construct). All packets of a flow select the SAME member
(consistency); distinct flows spread across the group (distribution).

  R0  no IPv4 / no route   -> default_action (drop, or forward to default_port)
  R1  dst in an ECMP group -> forward to hash(5-tuple) % |members| member port

Grading note (verifier): a real submission's selector hash is internal to
BMv2 and NOT predictable here, so the runtime tests grade the RFC 2992
*properties* behaviourally — `ecmp_consistent` (a same-flow burst lands wholly
on one member ∈ the group) and `ecmp_distributes` (distinct flows spread across
≥2 members) — NOT a specific member. This oracle therefore exposes BOTH:
  - `ecmp_members`: the full member-port list of the matched group (what
    test generation bakes into the `output_ports` of the ecmp_* expected blocks), and
  - `output_port`: a DETERMINISTIC representative member (this oracle's own
    stable hash) so the oracle audit has a comparable scalar. The oracle's hash
    need not match BMv2's — runtime grading never compares against it.

Config (routes / default_action / default_port) is read from state["config"]
(parametric-source contract).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    output_port: Optional[int] = None
    ecmp_members: Optional[List[int]] = None
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


_DEFAULT_CONFIG = {
    # One route: dst 10.0.2.0/24 -> 3 equal-cost next-hops on ports 2,3,4.
    "routes": [
        {"dst_net": "10.0.2.0", "prefix_len": 24, "members": [2, 3, 4]},
    ],
    "default_action": "drop",        # drop | forward_default_class
    "default_port": 5,
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(x) for x in str(ip).split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _l4_ports(packet):
    if getattr(packet, "haslayer", lambda x: False)("TCP"):
        t = packet["TCP"]
        return int(getattr(t, "sport", 0)), int(getattr(t, "dport", 0))
    if getattr(packet, "haslayer", lambda x: False)("UDP"):
        u = packet["UDP"]
        return int(getattr(u, "sport", 0)), int(getattr(u, "dport", 0))
    return 0, 0


def _flow_hash(packet) -> int:
    """Deterministic stable hash over the 5-tuple (no Python hash randomisation).
    Representative only — BMv2's selector hash differs and is not compared."""
    ip = packet["IP"]
    sport, dport = _l4_ports(packet)
    key = (str(getattr(ip, "src", "")), str(getattr(ip, "dst", "")),
           int(getattr(ip, "proto", 0)), sport, dport)
    h = 2166136261
    for part in key:
        for ch in str(part):
            h = ((h ^ ord(ch)) * 16777619) & 0xFFFFFFFF
    return h


def _lpm(cfg, dst_int):
    """Longest-prefix-match dst against the routes; return the matched route."""
    best, best_len = None, -1
    for r in cfg.get("routes", []):
        plen = int(r["prefix_len"])
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        if (dst_int & mask) == (_ip_to_int(r["dst_net"]) & mask) and plen > best_len:
            best, best_len = r, plen
    return best


def _default(cfg, state, packet, reason):
    if cfg.get("default_action") == "forward_default_class":
        port = int(cfg.get("default_port", 0))
        return StepResult(output_packets={port: [packet.copy()]}, new_state=state,
                          decision="forward", output_port=port,
                          invariant_log=[("default", {"port": port, "why": reason})])
    return StepResult(new_state=state, decision="drop", output_port=None,
                      invariant_log=[("default", {"action": "drop", "why": reason})])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)          # stateless

    if not getattr(packet, "haslayer", lambda x: False)("IP"):
        return _default(cfg, new_state, packet, "no_ipv4")

    dst_int = _ip_to_int(getattr(packet["IP"], "dst", "0.0.0.0"))
    route = _lpm(cfg, dst_int)
    if route is None:
        return _default(cfg, new_state, packet, "no_route")

    members = [int(p) for p in route["members"]]
    idx = _flow_hash(packet) % len(members)
    port = members[idx]
    out = packet.copy()
    return StepResult(output_packets={port: [out]}, new_state=new_state,
                      decision="forward", output_port=port, ecmp_members=members,
                      invariant_log=[("ecmp", {"members": members, "selected": port})])
