"""Per-task oracle for benchmark/relocate/srv6_endpoint_anchor (P-SRv6Endpoint).

SRv6 segment-endpoint node implementing the End behaviour (RFC 8986 §4.1)
under the canonical D.end seed.

  - R0  non-IPv6 / no SRH → drop
  - R1  IPv6 DA not a local SID → drop
  - R2  Segments Left == 0 → drop (end of path / out of scope in this task)
  - R3  End: decrement Segments Left, set IPv6 DA = Segment List[new SL],
        decrement Hop Limit, forward via the FIB on the new DA

Config read from state["config"]. Entry point: step(packet, ingress_port, state).
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


_DEFAULT_CONFIG = {
    "local_sids": ["2001:db8:a::1"],
    "fib": {
        "2001:db8:a::2": {"port": 2, "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        "2001:db8:a::3": {"port": 3, "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    },
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _norm6(a):
    return str(ipaddress.IPv6Address(str(a)))


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrSegmentRouting as SRH
    from scapy.all import Ether
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)
    fib = {_norm6(k): v for k, v in cfg["fib"].items()}
    local = {_norm6(s) for s in cfg["local_sids"]}

    if not packet.haslayer(IPv6):
        return _drop(new_state, "R0_non_ipv6")
    if not packet.haslayer(SRH):
        return _drop(new_state, "R0_no_srh")

    ip6 = packet.getlayer(IPv6)
    srh = packet.getlayer(SRH)
    if _norm6(ip6.dst) not in local:
        return _drop(new_state, "R1_not_local_sid")
    segleft = int(srh.segleft)
    if segleft == 0:
        return _drop(new_state, "R2_segleft_zero")

    new_sl = segleft - 1
    addrs = [str(a) for a in srh.addresses]
    if new_sl < 0 or new_sl >= len(addrs):
        return _drop(new_state, "R3_bad_index")
    new_da = _norm6(addrs[new_sl])
    entry = fib.get(new_da)
    if entry is None:
        return _drop(new_state, "R3_no_route")

    out = packet.copy()
    out.getlayer(SRH).segleft = new_sl
    out.getlayer(IPv6).dst = new_da
    out.getlayer(IPv6).hlim = int(ip6.hlim) - 1
    out[Ether].src = entry["port_mac"]
    out[Ether].dst = entry["nexthop_mac"]
    return StepResult(output_packets={int(entry["port"]): [out]}, new_state=new_state,
                      decision="forward",
                      invariant_log=[("R3_end", {"port": int(entry["port"]),
                                                 "new_da": new_da, "new_segleft": new_sl})])
