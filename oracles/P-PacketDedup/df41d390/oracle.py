"""Per-task oracle for benchmark/scale_up/packet_dedup_anchor.

P-PacketDedup under the canonical D8.0_exact_set seed: an exact seen-set keyed
on (ipv4.src, ipv4.dst, ipv4.id). First occurrence forwards out forward_port;
any later packet with the same key drops.

  - R0  non-IPv4 drop
  - R1  key already seen → drop (duplicate/replay)
  - R2  first seen → record key, forward

The seen-set lives in state and persists across step() calls (warm-up
prior_inputs accumulate it). Entry point: step(packet, ingress_port, state).
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


_DEFAULT_CONFIG = {"forward_port": 2}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _has_ip(packet) -> bool:
    return bool(getattr(packet, "haslayer", lambda x: False)("IP"))


def _f(packet, layer, name, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        v = getattr(packet[layer], name, default)
        return v if v is not None else default
    return default


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    # seen-set persists in state; copy so we don't mutate caller's dict in place
    seen = list(state.get("seen", []))
    new_state = dict(state)

    if not _has_ip(packet):
        new_state["seen"] = seen
        return StepResult(output_packets={}, new_state=new_state, decision="drop",
                          invariant_log=[("drop", "R0_non_ipv4")])

    key = (str(_f(packet, "IP", "src", "0.0.0.0")),
           str(_f(packet, "IP", "dst", "0.0.0.0")),
           int(_f(packet, "IP", "id", 0)))

    if key in seen:
        new_state["seen"] = seen
        return StepResult(output_packets={}, new_state=new_state, decision="drop",
                          invariant_log=[("R1_duplicate", {"key": key})])

    seen.append(key)
    new_state["seen"] = seen
    out = packet.copy()
    port = int(cfg["forward_port"])
    return StepResult(output_packets={port: [out]}, new_state=new_state,
                      decision="forward", invariant_log=[("R2_first_seen", {"key": key, "port": port})])
