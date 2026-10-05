"""Per-task oracle for benchmark/redesign/vlan_bridge_anchor (P-VLANBridge).

802.1Q VLAN bridge under the canonical D9.0_static_fib seed: access/trunk port
roles, PVID ingress association, per-VLAN L2 FIB, ingress tag push (to trunk)
/ egress tag pop (to access), VLAN isolation, unknown-unicast drop.

  - R0   access port + tagged frame       → drop
  - R0b  trunk port + untagged frame       → drop
  - R2   trunk + VID not in allowed set    → drop
  - R3   per-VLAN FIB hit                   → push/pop tag per egress role, forward
  - R4   FIB miss (unknown unicast)         → drop (canonical)

Config read from state["config"]. Entry point: step(packet, ingress_port, state).

vlan_fib shape tolerance: each FIB entry's
egress port is read via `_entry_port`, which accepts BOTH the seed field
spelling `egress_port` AND the canonical/default spelling `port`. Reading
`entry["port"]` only would make threading the seed's
`{vlan, dst_mac, egress_port}` vlan_fib raise KeyError('port') and the oracle
silently fall back to _DEFAULT_CONFIG — a source-baked vlan_fib that any
vlan_fib-rebinding sibling would keep. The vlan_fib is genuinely read from
state["config"].
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
    "port_roles": {
        1: {"role": "access", "pvid": 10},
        2: {"role": "access", "pvid": 20},
        3: {"role": "trunk", "vlans": [10, 20]},
        4: {"role": "trunk", "vlans": [10, 20]},
    },
    "vlan_fib": [
        {"vlan": 10, "dst_mac": "00:00:00:00:00:0a", "port": 1},
        {"vlan": 10, "dst_mac": "00:00:00:00:00:0c", "port": 4},
        {"vlan": 20, "dst_mac": "00:00:00:00:00:0d", "port": 4},
    ],
    "unknown_unicast_policy": "drop",
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    cfg["port_roles"] = {int(k): v for k, v in cfg["port_roles"].items()}
    return cfg


def _entry_port(entry) -> int:
    """Egress port of one vlan_fib entry, tolerant of both field spellings:
    `egress_port` (the seed FIB-family shape) and `port` (the canonical /
    module-default shape). This is what makes the oracle config-RESPONSIVE to a
    rebound vlan_fib instead of raising KeyError('port') and falling back to
    the source-baked _DEFAULT_CONFIG."""
    p = entry.get("egress_port", entry.get("port"))
    if p is None:
        raise KeyError(
            "vlan_fib entry has neither 'egress_port' nor 'port': "
            f"{entry!r}"
        )
    return int(p)


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def _norm_mac(m):
    return str(m).lower()


def _strip_tag(pkt):
    from scapy.all import Ether, Dot1Q
    inner = pkt[Dot1Q].payload
    eth = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=pkt[Dot1Q].type)
    return eth / inner


def _ensure_tag(pkt, vlan):
    from scapy.all import Ether, Dot1Q
    if pkt.haslayer(Dot1Q):
        out = pkt.copy()
        out[Dot1Q].vlan = vlan
        return out
    eth = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=0x8100)
    return eth / Dot1Q(vlan=vlan, type=pkt[Ether].type) / pkt[Ether].payload


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    from scapy.all import Ether, Dot1Q
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)

    if not packet.haslayer(Ether):
        return _drop(new_state, "R0_non_ethernet")

    role_spec = cfg["port_roles"].get(int(ingress_port))
    if role_spec is None:
        return _drop(new_state, "no_port_role")
    role = role_spec["role"]
    tagged = packet.haslayer(Dot1Q)

    # R0 / R0b — role/tag mismatch
    if role == "access" and tagged:
        return _drop(new_state, "R0_access_tagged")
    if role == "trunk" and not tagged:
        return _drop(new_state, "R0b_trunk_untagged")

    # R1 — resolve VLAN
    if role == "access":
        vlan = int(role_spec["pvid"])
    else:
        vlan = int(packet[Dot1Q].vlan)
        # R2 — trunk VLAN membership
        if vlan not in [int(v) for v in role_spec.get("vlans", [])]:
            return _drop(new_state, "R2_vlan_not_allowed")

    dst_mac = _norm_mac(packet[Ether].dst)

    # R3 / R4 — per-VLAN FIB
    entry = next((e for e in cfg["vlan_fib"]
                  if int(e["vlan"]) == vlan and _norm_mac(e["dst_mac"]) == dst_mac), None)
    if entry is None:
        if cfg.get("unknown_unicast_policy") == "drop":
            return _drop(new_state, "R4_unknown_unicast")
        # flood: to all other member ports (mutation; not exercised at canonical)
        members = [p for p, rs in cfg["port_roles"].items()
                   if p != int(ingress_port) and (
                       (rs["role"] == "access" and int(rs["pvid"]) == vlan) or
                       (rs["role"] == "trunk" and vlan in [int(v) for v in rs.get("vlans", [])]))]
        outs = {}
        for p in members:
            erole = cfg["port_roles"][p]["role"]
            outs[p] = [_ensure_tag(packet, vlan) if erole == "trunk" else
                       (_strip_tag(packet) if tagged else packet.copy())]
        return StepResult(output_packets=outs, new_state=new_state, decision="multicast",
                          invariant_log=[("R4_flood", {"vlan": vlan, "ports": members})])

    egress_port = _entry_port(entry)
    egress_role = cfg["port_roles"][egress_port]["role"]
    if egress_role == "trunk":
        out = _ensure_tag(packet, vlan)
    else:
        out = _strip_tag(packet) if tagged else packet.copy()

    return StepResult(output_packets={egress_port: [out]}, new_state=new_state,
                      decision="forward",
                      invariant_log=[("R3_forward", {"vlan": vlan, "port": egress_port,
                                                     "egress_role": egress_role})])
