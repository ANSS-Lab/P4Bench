"""P-RuntimeMeta oracle — in-switch observability / meta-NF (sFlow / SPAN).

Implements the pattern's rule sequence (pattern
patterns/P-RuntimeMeta/pattern.yaml):

  R0  non-IPv4 / unparseable                         -> drop
  R1  monitored ∧ mon-rule(mirror) ∧ sample-selected -> count + MIRROR(collector) + forward
  R2  monitored ∧ mon-rule (count-only or unsampled) -> count + forward (no mirror)
  R3  unmonitored, or monitored-but-unruled, FIB hit -> forward (no count, no mirror)
  R4  FIB miss ∧ default_action == forward_flood     -> flood to host ports (collector excluded)
  R5  FIB miss ∧ default_action == drop              -> drop

Parametric-source contract: every mutation-surface parameter
(sampling_policy, sample_rate, hash_algo, mon_match_fields, counter_granularity,
default_action, mirror_truncation, ...) is read from the runtime `state` dict.
Seed VALUES never enter as source-level constants; when `state` is None (the
audit drives step with no state) a documented default config — the
runtime_meta_anchor topology — is used so the canonical examples are
reproducible.

OBSERVABILITY GAP (the pattern's signature caveat): the per-rule counters are
control-plane-read and never appear in a packet, so they are tracked in
`new_state` for structural checks only and do NOT affect the returned
output_ports. The gradable surface is the mirror copy + the
non-destructive forward + the no-leak / flood behaviour.

step(packet, ingress_port, state) -> StepResult.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── StepResult — compatible with the oracle audit (_compare reads .decision /
#    .output_port) and with the test generator (reads .output_ports / .mirrored).
@dataclass
class StepResult:
    decision: str = "drop"                       # "forward" | "drop"
    output_port: Optional[int] = None            # primary forward egress (single-port + audit)
    output_ports: List[int] = field(default_factory=list)  # ALL egress incl. mirror copy / flood set
    mirrored: bool = False                        # a collector copy was produced
    collector_port: Optional[int] = None
    new_state: Dict[str, Any] = field(default_factory=dict)
    invariant_log: List[Any] = field(default_factory=list)


# ── Default config (audit / no-state path) — the runtime_meta_anchor seed. ──
def _default_config() -> Dict[str, Any]:
    return {
        "monitored_ports": [1, 2],
        "collector_port": 3,
        "l2_fib": {
            "08:00:00:00:01:01": 1,
            "08:00:00:00:02:02": 2,
            "08:00:00:00:03:03": 3,
            "08:00:00:00:04:04": 4,
            "08:00:00:00:05:05": 5,
        },
        "mon_rules": [                    # ipv4_dst_only key at D5.0
            {"ipv4_dst": "10.0.0.5", "should_mirror": True},
            {"ipv4_dst": "10.0.0.2", "should_mirror": False},
        ],
        "mon_match_fields": "ipv4_dst_only",
        "counter_granularity": "packets_only",
        "sampling_policy": "mirror_all",
        "sample_rate": 1,
        "hash_algo": "crc16",
        "default_action": "forward_flood",
        "mirror_truncation": "full",
    }


# ── Packet introspection (string-name based; tolerant of scapy + dict). ─────
def _has(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    return isinstance(packet, dict) and name in packet


def _f(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        return getattr(packet[layer], fname, default)
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _mon_key(packet, mon_match_fields: str):
    """Derive the monitor-table lookup key per ${mon_match_fields}.

    Only ipv4_dst_only is exercised at the anchor; five_tuple / five_tuple_plus
    are implemented for the mutation siblings that reuse this oracle."""
    ip_dst = _f(packet, "IP", "dst")
    if mon_match_fields == "ipv4_dst_only":
        return ("ipv4_dst", ip_dst)
    proto = _f(packet, "IP", "proto")
    sport = _f(packet, "TCP", "sport", _f(packet, "UDP", "sport"))
    dport = _f(packet, "TCP", "dport", _f(packet, "UDP", "dport"))
    base = (_f(packet, "IP", "src"), ip_dst, proto, sport, dport)
    if mon_match_fields == "five_tuple_plus":
        return base + (_f(packet, "Dot1Q", "vlan"), _f(packet, "IP", "tos"))
    return base


def _rule_key(entry: Dict[str, Any], mon_match_fields: str):
    if mon_match_fields == "ipv4_dst_only":
        return ("ipv4_dst", entry.get("ipv4_dst"))
    base = (entry.get("ipv4_src"), entry.get("ipv4_dst"), entry.get("ipv4_proto"),
            entry.get("l4_src"), entry.get("l4_dst"))
    if mon_match_fields == "five_tuple_plus":
        return base + (entry.get("vlan"), entry.get("dscp"))
    return base


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def _sample_selected(packet, cfg, rule_skip_state: Dict[str, int], key) -> bool:
    """Whether this matched mirror-rule packet is selected for the mirror."""
    policy = cfg.get("sampling_policy", "mirror_all")
    n = max(1, int(cfg.get("sample_rate", 1)))
    if policy == "mirror_all" or n == 1:
        return True
    if policy == "hash_5tuple_1_in_n":
        tup = (_f(packet, "IP", "src"), _f(packet, "IP", "dst"),
               _f(packet, "IP", "proto"),
               _f(packet, "TCP", "sport", _f(packet, "UDP", "sport")),
               _f(packet, "TCP", "dport", _f(packet, "UDP", "dport")))
        return _crc16(repr(tup).encode()) % n == 0
    if policy == "deterministic_count_1_in_n":
        # inc-then-check: every Nth matched packet is selected (skip = 0 mirrors).
        skip = rule_skip_state.get(repr(key), 0)
        selected = (skip + 1) % n == 0
        rule_skip_state[repr(key)] = (skip + 1) % n
        return selected
    return True


# ── step ────────────────────────────────────────────────────────────────────
def step(packet, ingress_port: int, state: Optional[Dict[str, Any]] = None) -> StepResult:
    cfg = state if state is not None else _default_config()
    ingress_port = int(ingress_port)

    # Mutable cross-packet state the oracle threads (counters + skip phase).
    counters: Dict[str, Dict[str, int]] = cfg.setdefault("_counters", {})
    skip_state: Dict[str, int] = cfg.setdefault("_skip_state", {})

    collector = int(cfg["collector_port"])
    monitored = set(int(p) for p in cfg["monitored_ports"])
    fib = cfg["l2_fib"]
    mmf = cfg.get("mon_match_fields", "ipv4_dst_only")

    # R0 — non-IPv4 / unparseable.
    if not _has(packet, "Ether") or not _has(packet, "IP"):
        return StepResult(decision="drop", new_state=cfg,
                          invariant_log=[("R0_unparseable_drop", {})])

    eth_dst = _f(packet, "Ether", "dst")
    egress = fib.get(eth_dst)

    # FIB lookup determines the forward target for every forwarded path.
    if egress is None:
        # R4 / R5 — FIB miss.
        if cfg.get("default_action", "forward_flood") == "drop":
            return StepResult(decision="drop", new_state=cfg,
                              invariant_log=[("R5_fib_miss_drop", {})])
        # Flood to all known host egress ports, minus ingress, minus collector.
        flood = sorted({int(p) for p in fib.values()} - {collector, ingress_port})
        return StepResult(decision="forward", output_port=(flood[0] if flood else None),
                          output_ports=flood, new_state=cfg,
                          invariant_log=[("R4_fib_miss_flood", {"ports": flood})])
    egress = int(egress)

    # Monitor-table lookup (ipv4_dst_only at the anchor).
    key = _mon_key(packet, mmf)
    rule = None
    for e in cfg["mon_rules"]:
        if _rule_key(e, mmf) == key:
            rule = e
            break

    if ingress_port in monitored and rule is not None:
        # Counters increment on EVERY matched packet (sampling gates only mirror).
        c = counters.setdefault(repr(key), {"pkts": 0, "bytes": 0})
        c["pkts"] += 1
        c["bytes"] += int(_f(packet, "IP", "len", 0) or 0)

        if rule.get("should_mirror") and _sample_selected(packet, cfg, skip_state, key):
            # R1 — mirror: original to egress + copy to collector (non-destructive).
            return StepResult(
                decision="forward", output_port=egress,
                output_ports=[egress, collector], mirrored=True,
                collector_port=collector, new_state=cfg,
                invariant_log=[("R1_monitored_mirror_and_forward",
                                {"egress": egress, "collector": collector}),
                               ("forward_unmodified_under_mirror", {}),
                               ("conditional_clone_only_on_sampled_path", {"mirror": True})],
            )
        # R2 — count-only / unsampled: forward, no collector copy.
        return StepResult(
            decision="forward", output_port=egress, output_ports=[egress],
            mirrored=False, new_state=cfg,
            invariant_log=[("R2_monitored_count_only", {"egress": egress}),
                           ("conditional_clone_only_on_sampled_path", {"mirror": False})],
        )

    # R3 — unmonitored ingress, or monitored-but-unruled: plain forward.
    return StepResult(
        decision="forward", output_port=egress, output_ports=[egress],
        mirrored=False, new_state=cfg,
        invariant_log=[("R3_unmonitored_or_unruled_forward", {"egress": egress})],
    )


def reset():
    """No persistent module state to reset (state is threaded through cfg)."""
    return None
