"""Per-task oracle for benchmark/scale_up/diffserv_classifier_anchor.

P-DiffServClassifier under the canonical D6.0_be_ef_af seed: multi-field
classify → DSCP remark (preserving ECN) → forward.

  - R0  non-IPv4 drop
  - R2  MF-match → set DSCP to the class codepoint (preserve ECN), L2 rewrite,
        forward to the class port
  - R3  unmatched → Best-Effort default (DSCP default_dscp), forward to default

The DS field is the IPv4 TOS byte: DSCP = tos>>2, ECN = tos & 3. Config is read
from state["config"] (parametric-source contract). Entry point: step(packet, ingress_port, state).
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
    "class_rules": [
        {"dst": "10.0.2.2", "proto": 17, "dport": 5060, "dscp": 46,
         "port": 2, "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        {"dst": "10.0.3.3", "proto": 6, "dport": 80, "dscp": 26,
         "port": 3, "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    ],
    "default_dscp": 0,
    "default_port": 2,
    "preserve_ecn": True,
}


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


def _l4(packet):
    proto = int(_f(packet, "IP", "proto", 0))
    dport = None
    if packet.haslayer("TCP"):
        dport = int(_f(packet, "TCP", "dport", 0))
    elif packet.haslayer("UDP"):
        dport = int(_f(packet, "UDP", "dport", 0))
    return proto, dport


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)

    if not _has_ip(packet):
        return _drop(new_state, "R0_non_ipv4")

    dst = str(_f(packet, "IP", "dst", "0.0.0.0"))
    tos = int(_f(packet, "IP", "tos", 0))
    ecn = tos & 0x3
    proto, dport = _l4(packet)

    match = None
    for r in cfg["class_rules"]:
        if str(r["dst"]) == dst and int(r["proto"]) == proto and int(r["dport"]) == dport:
            match = r
            break

    out = packet.copy()
    if match is not None:
        dscp = int(match["dscp"])
        new_tos = (dscp << 2) | (ecn if cfg.get("preserve_ecn") else 0)
        out["IP"].tos = new_tos
        out["Ether"].src = match["port_mac"]
        out["Ether"].dst = match["nexthop_mac"]
        port = int(match["port"])
        log = ("R2_classify", {"dscp": dscp, "port": port, "tos": new_tos})
    else:
        dscp = int(cfg["default_dscp"])
        new_tos = (dscp << 2) | (ecn if cfg.get("preserve_ecn") else 0)
        out["IP"].tos = new_tos
        port = int(cfg["default_port"])
        log = ("R3_default_be", {"dscp": dscp, "port": port, "tos": new_tos})

    return StepResult(output_packets={port: [out]}, new_state=new_state,
                      decision="forward", invariant_log=[log])
