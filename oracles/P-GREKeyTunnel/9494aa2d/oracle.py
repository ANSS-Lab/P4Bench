"""Per-task oracle for benchmark/relocate/gre_key_tunnel_anchor (P-GREKeyTunnel).

GRE keyed-tunnel decapsulation endpoint under the canonical D13.0_decap_only
seed.

  - R0  not IPv4/proto-47 to the local endpoint → drop
  - R1  no GRE Key, or Key not in the tunnel table → drop
  - R2  decap: strip outer IPv4 + GRE, forward the inner IPv4 out the tunnel
        port with the Ethernet rewrite; inner unchanged

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
    "local_vtep_ip": "10.200.0.1",
    "tunnels": {
        0x1001: {"port": 2, "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        0x1002: {"port": 3, "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    },
    "require_key": True,
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    cfg["tunnels"] = {int(k): v for k, v in cfg["tunnels"].items()}
    return cfg


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    from scapy.all import Ether, IP, GRE
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)

    if not packet.haslayer(IP):
        return _drop(new_state, "R0_non_ipv4")
    outer = packet.getlayer(IP)  # first IP = outer
    if int(outer.proto) != 47 or str(outer.dst) != str(cfg["local_vtep_ip"]):
        return _drop(new_state, "R0_not_gre_to_vtep")
    if not packet.haslayer(GRE):
        return _drop(new_state, "R0_no_gre")

    gre = packet.getlayer(GRE)
    key_present = int(getattr(gre, "key_present", 0)) == 1
    key = int(getattr(gre, "key", 0)) if key_present else None
    if cfg.get("require_key") and not key_present:
        return _drop(new_state, "R1_no_key")
    tun = cfg["tunnels"].get(key)
    if tun is None:
        return _drop(new_state, "R1_unknown_key")

    inner = gre.payload  # inner IPv4 packet
    if not isinstance(inner, IP) and not (hasattr(inner, "haslayer") and inner.haslayer(IP)):
        return _drop(new_state, "R2_no_inner_ip")

    out = Ether(src=tun["port_mac"], dst=tun["nexthop_mac"]) / inner.copy()
    port = int(tun["port"])
    return StepResult(output_packets={port: [out]}, new_state=new_state,
                      decision="forward",
                      invariant_log=[("R2_decap", {"key": key, "port": port})])
