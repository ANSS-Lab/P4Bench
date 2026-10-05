"""Per-task oracle for benchmark/scale_up/l2_learning_bridge_anchor.

Self-learning Ethernet bridge under the canonical D9.0_learn_flood seed.

  - R1  learn src MAC → ingress port (every frame)
  - R2  known unicast dst → forward to the learned port (filtered if == ingress)
  - R3  broadcast or unknown unicast → flood to member ports \ {ingress}

The MAC table persists in state["mac_table"] across warm-up prior_inputs.
Entry point: step(packet, ingress_port, state).
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


_DEFAULT_CONFIG = {"member_ports": [1, 2, 3]}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _norm(m):
    return str(m).lower()


def _is_broadcast(mac):
    return _norm(mac) == "ff:ff:ff:ff:ff:ff"


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    from scapy.all import Ether
    state = state or {}
    cfg = _config(state)
    members = [int(p) for p in cfg["member_ports"]]
    table = dict(state.get("mac_table", {}))
    new_state = dict(state)

    if not packet.haslayer(Ether):
        new_state["mac_table"] = table
        return StepResult(output_packets={}, new_state=new_state, decision="drop",
                          invariant_log=[("drop", "non_ethernet")])

    src = _norm(packet[Ether].src)
    dst = _norm(packet[Ether].dst)

    # R1 — learn
    table[src] = int(ingress_port)
    new_state["mac_table"] = table

    # R2 — known unicast
    if not _is_broadcast(dst) and dst in table:
        port = int(table[dst])
        if port == int(ingress_port):
            return StepResult(output_packets={}, new_state=new_state, decision="drop",
                              invariant_log=[("R2_filter_same_port", {"port": port})])
        return StepResult(output_packets={port: [packet.copy()]}, new_state=new_state,
                          decision="forward", invariant_log=[("R2_forward", {"port": port})])

    # R3 — flood (broadcast or unknown unicast)
    flood_ports = [p for p in members if p != int(ingress_port)]
    outs = {p: [packet.copy()] for p in flood_ports}
    return StepResult(output_packets=outs, new_state=new_state, decision="multicast",
                      invariant_log=[("R3_flood", {"ports": flood_ports})])
