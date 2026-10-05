"""Per-task oracle for benchmark/scale_up/three_color_marker_anchor.

P-ThreeColorMarker under the canonical D5.1_per_packet_quantum seed: a
deterministic RFC 2698 two-rate three-color marker (trTCM).

Two token buckets are held in runtime state, shared across the metered IPv4
stream (aggregate scope; per_flow keys a bucket array by a hash of the 5-tuple):

    meter = {"tp": <peak tokens, <= pbs>, "tc": <committed tokens, <= cbs>}

initialised full (tp=pbs, tc=cbs, RFC 2698 §3). On each IPv4 packet of size B
bytes (B = the IP layer length when token_unit=bytes, else 1):

  R1  replenish BOTH buckets by a per-packet quantum, SATURATING at the maxima
        tp = min(pbs, tp + peak_quantum)         # |+| saturate
        tc = min(cbs, tc + committed_quantum)    # |+| saturate
  R2  RED     if tp - B < 0  (color-aware: or pre-colored red)
                -> mark red_dscp; DO NOT touch either bucket; drop or forward
  R3  YELLOW  elif tc - B < 0 (color-aware: or pre-colored yellow)
                -> mark yellow_dscp; tp = max(0, tp - B)   # |-| saturate
  R4  GREEN   else
                -> mark green_dscp; tp = max(0, tp - B); tc = max(0, tc - B)

The color is written to the IPv4 DS field (DSCP = top 6 bits of the TOS byte),
preserving the low 2 ECN bits. This is NOT the BMv2 meter extern (wall-clock,
ungradable under --use-files): replenishment is a per-packet quantum, a
discretisation RFC 2698 §3 explicitly permits ("the actual implementation of a
Meter doesn't need to be modeled according to the above formal specification").

Config is read from state["config"] (parametric-source contract);
seed values enter only at evaluation time. Entry point: step(packet, ingress_port, state).
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
    "mode": "color_blind",          # color_blind | color_aware
    "peak_quantum": 1500,           # PIR, discretised: tokens added to P per packet
    "committed_quantum": 600,       # CIR, discretised: tokens added to C per packet
    "pbs": 6000,                    # Peak Burst Size = P bucket maximum (bytes)
    "cbs": 3000,                    # Committed Burst Size = C bucket maximum (bytes)
    "token_unit": "bytes",          # bytes (B = IP length) | packets (B = 1)
    "meter_scope": "aggregate",     # aggregate | per_flow
    "meter_capacity": 1,            # bucket pairs when per_flow
    "green_dscp": 10,               # AF11
    "yellow_dscp": 12,              # AF12
    "red_dscp": 14,                 # AF13
    "red_action": "remark",         # remark (forward with red codepoint) | drop
    "egress_port": 2,
}

def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _has_ip(packet) -> bool:
    return bool(getattr(packet, "haslayer", lambda x: False)("IP"))


def _ip_len(packet) -> int:
    """B in bytes = the IP layer length (IP header + payload), RFC 2698 §2:
    'bytes of IP packets ... includes the IP header, but not link headers'."""
    ip = packet["IP"]
    ln = getattr(ip, "len", None)
    if ln:
        return int(ln)
    return len(bytes(ip))      # scapy rebuilds + fills length


def _l4_ports(packet):
    sport = dport = 0
    if packet.haslayer("TCP"):
        sport = int(getattr(packet["TCP"], "sport", 0))
        dport = int(getattr(packet["TCP"], "dport", 0))
    elif packet.haslayer("UDP"):
        sport = int(getattr(packet["UDP"], "sport", 0))
        dport = int(getattr(packet["UDP"], "dport", 0))
    return sport, dport


def _meter_index(packet, cfg) -> int:
    if cfg.get("meter_scope") != "per_flow":
        return 0
    ip = packet["IP"]
    sport, dport = _l4_ports(packet)
    key = (str(getattr(ip, "src", "")), str(getattr(ip, "dst", "")),
           int(getattr(ip, "proto", 0)), sport, dport)
    # deterministic, stable across runs (no Python hash randomisation)
    h = 0
    for part in key:
        for ch in str(part):
            h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return h % max(1, int(cfg.get("meter_capacity", 1)))


def _precolor(tos, cfg):
    """Color-aware: read the incoming DS field; map a known codepoint to a color."""
    dscp = (int(tos) >> 2) & 0x3F
    if dscp == int(cfg["red_dscp"]):
        return "red"
    if dscp == int(cfg["yellow_dscp"]):
        return "yellow"
    return "green"   # green codepoint or anything else treated as green-eligible


def _drop(state, reason, log_extra=None):
    log = [("drop", reason)]
    if log_extra:
        log.append(log_extra)
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=log)


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)
    meters = dict(new_state.get("meters", {}))   # index -> {"tp","tc"}

    if not _has_ip(packet):
        new_state["meters"] = meters
        return _drop(new_state, "R0_non_ipv4")

    pbs = int(cfg["pbs"]); cbs = int(cfg["cbs"])
    idx = _meter_index(packet, cfg)
    m = dict(meters.get(idx, {"tp": pbs, "tc": cbs}))   # buckets start full
    tp = int(m["tp"]); tc = int(m["tc"])

    # R1: saturating replenishment (the |+| contract) — refill precedes the test.
    tp = min(pbs, tp + int(cfg["peak_quantum"]))
    tc = min(cbs, tc + int(cfg["committed_quantum"]))

    B = _ip_len(packet) if cfg.get("token_unit") == "bytes" else 1

    tos = int(getattr(packet["IP"], "tos", 0))
    ecn = tos & 0x3

    # Metering decision. Color-aware mode (RFC 2698 §3) ORs the incoming
    # pre-color into each test, so a pre-colored packet is only ever downgraded,
    # never improved. The canonical seed is color_blind, so `pre` is "green"
    # (no constraint) and this reduces to the plain two-bucket test.
    color_aware = cfg.get("mode") == "color_aware"
    pre = _precolor(tos, cfg) if color_aware else "green"

    if (color_aware and pre == "red") or (tp - B < 0):
        color = "red"                     # RED consumes NOTHING
    elif (color_aware and pre == "yellow") or (tc - B < 0):
        color = "yellow"
        tp = max(0, tp - B)               # |-| saturate; YELLOW consumes peak only
    else:
        color = "green"
        tp = max(0, tp - B)               # |-| saturate
        tc = max(0, tc - B)

    dscp = {"green": int(cfg["green_dscp"]),
            "yellow": int(cfg["yellow_dscp"]),
            "red": int(cfg["red_dscp"])}[color]
    new_tos = ((dscp & 0x3F) << 2) | ecn

    meters[idx] = {"tp": int(tp), "tc": int(tc)}
    new_state["meters"] = meters

    log = ("meter", {"index": idx, "color": color, "B": B,
                     "tp": int(tp), "tc": int(tc), "tos": new_tos})

    if color == "red" and cfg.get("red_action") == "drop":
        return _drop(new_state, "R2_red_drop", log)

    out = packet.copy()
    out["IP"].tos = new_tos
    port = int(cfg["egress_port"])
    return StepResult(output_packets={port: [out]}, new_state=new_state,
                      decision="forward", invariant_log=[log])
