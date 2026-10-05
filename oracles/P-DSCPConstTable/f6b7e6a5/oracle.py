"""Per-task oracle for benchmark/redesign/dscp_const_table_anchor.

P-DSCPConstTable under the canonical seed: a STATELESS DiffServ
Behaviour-Aggregate (BA) classifier (RFC 2475 §1.2). Reads the 6-bit DSCP from
the IPv4 DS field (top 6 bits of the TOS octet; the low 2 CU/ECN bits are
IGNORED, RFC 2474 §3), maps the codepoint through a FIXED codepoint->class map
to a PHB class, and forwards the packet UNCHANGED out that class's egress port.

  R0  no IPv4 header              -> default_action (forward default class / drop)
  R1  DSCP in the map             -> forward out the mapped class port (unchanged)
  R2  DSCP not in the map         -> default_action

Config (dscp_class_map / default_action / default_class_port) is read from
state["config"] (parametric-source contract). The StepResult
exposes `output_port` so the oracle audit grades the class assignment directly.
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
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


_DEFAULT_CONFIG = {
    # Canonical: EF->p2, AF11->p3, BE->p4; default class = p4.
    "dscp_class_map": {46: 2, 10: 3, 0: 4},
    "default_action": "forward_default_class",    # forward_default_class | deny
    "default_class_port": 4,
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    # YAML may hand string keys; normalise the map to int->int.
    cfg["dscp_class_map"] = {int(k): int(v) for k, v in cfg["dscp_class_map"].items()}
    return cfg


def _has_ip(packet) -> bool:
    return bool(getattr(packet, "haslayer", lambda x: False)("IP"))


def _dscp(packet) -> int:
    tos = int(getattr(packet["IP"], "tos", 0))
    return (tos >> 2) & 0x3F          # top 6 bits; CU/ECN (low 2) ignored


def _default(cfg, state, packet, reason):
    if cfg.get("default_action") == "deny":
        return StepResult(new_state=state, decision="drop", output_port=None,
                          invariant_log=[("default", {"action": "deny", "why": reason})])
    port = int(cfg.get("default_class_port", 0))
    return StepResult(output_packets={port: [packet.copy()]}, new_state=state,
                      decision="forward", output_port=port,
                      invariant_log=[("default", {"action": "forward_default_class",
                                                   "port": port, "why": reason})])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)          # stateless

    if not _has_ip(packet):          # R0
        return _default(cfg, new_state, packet, "no_ipv4")

    dscp = _dscp(packet)
    cmap = cfg["dscp_class_map"]
    if dscp not in cmap:             # R2
        return _default(cfg, new_state, packet, "unmapped_codepoint")

    port = int(cmap[dscp])           # R1
    return StepResult(output_packets={port: [packet.copy()]}, new_state=new_state,
                      decision="forward", output_port=port,
                      invariant_log=[("classify", {"dscp": dscp, "class_port": port})])
