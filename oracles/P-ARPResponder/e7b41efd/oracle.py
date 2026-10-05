"""Per-task oracle for benchmark/redesign/arp_responder_anchor (P-ARPResponder).

Data-plane proxy-ARP responder under the canonical D.table_proxy seed.

  - R0  non-ARP or non-request (op != 1) → drop
  - R1  request for a known target IP, from a known requester → ORIGINATE an
        ARP reply (op 2, resolved MAC) toward the requester via the L2 FIB
  - R2  request for an unknown target IP → drop

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
    "arp_table": {
        "10.0.0.100": "aa:bb:cc:00:00:01",
        "10.0.0.200": "aa:bb:cc:00:00:02",
    },
    "l2_fib": {
        "00:00:00:00:00:0b": 2,
        "00:00:00:00:00:0c": 3,
    },
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    cfg["arp_table"] = {str(k): str(v).lower() for k, v in cfg["arp_table"].items()}
    cfg["l2_fib"] = {str(k).lower(): int(v) for k, v in cfg["l2_fib"].items()}
    return cfg


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    from scapy.all import Ether, ARP
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)

    if not packet.haslayer(ARP):
        return _drop(new_state, "R0_non_arp")
    arp = packet.getlayer(ARP)
    if int(arp.op) != 1:
        return _drop(new_state, "R0_not_request")

    target_ip = str(arp.pdst)
    requester_mac = str(arp.hwsrc).lower()
    requester_ip = str(arp.psrc)

    resolved = cfg["arp_table"].get(target_ip)
    if resolved is None:
        return _drop(new_state, "R2_unknown_target")
    egress = cfg["l2_fib"].get(requester_mac)
    if egress is None:
        return _drop(new_state, "R1_unknown_requester")

    reply = (Ether(src=resolved, dst=requester_mac) /
             ARP(op=2, hwsrc=resolved, psrc=target_ip,
                 hwdst=requester_mac, pdst=requester_ip))
    return StepResult(output_packets={int(egress): [reply]}, new_state=new_state,
                      decision="forward",
                      invariant_log=[("R1_arp_reply", {"port": int(egress),
                                                       "resolved": resolved, "target_ip": target_ip})])
