"""Per-task oracle for benchmark/scale_up/flow_sampler_anchor (P-FlowSampler).

Implements the deterministic 1-in-N packet-sampling rule sequence
(RFC 3176 / RFC 7014) under the canonical D5.0_count_based
single-global-counter seed:

  - R3  non-IPv4 frame  → forward to its static egress, NOT sampled, counter
        untouched (the sampler observes the IPv4 stream only; RFC 7014 §2
        Observation scope).
  - R1  IPv4 packet     → advance the sampler counter by EXACTLY one, then
        forward the ORIGINAL on its normal egress (RFC 7014 §2 each packet
        enters the Selection Process once; RFC 3176 §2 sampling is
        non-destructive). Forwarding is a plain static-egress copy: no IP /
        Ethernet rewrite, no TTL decrement — the sampler is orthogonal to the
        forwarding policy.
  - R2  sample fire     → ADDITIVELY, when the post-increment counter is an
        exact multiple of N (counter mod N == 0), clone a verbatim COPY of the
        packet to the collector port (RFC 3176 §2 1-in-N copied to the agent;
        RFC 7014 §2.2 systematic count-based selection). The clone is additive;
        the original from R1 is still forwarded. The selector is DETERMINISTIC
        count-based, never random (gradability; see pattern bridging_notes).

Per the parametric-source contract: sample_rate,
sampler_scope, collector_port, sampler_cells, sample_header, and the egress_map
are read from state["config"] at runtime, never baked as source-level
constants — this lets parameter rebinding reuse the same audited oracle. The
seed's values enter only via the initial state at evaluation time.

State threading: the per-scope counter array lives in
state["counters"] (dict cell-index -> int) and the per-scope sample-sequence
array in state["sample_seq"]; both persist across packets when the caller
threads `new_state` back in. There is NO time_tick: the counter advances on
received packets only (v1.0 harness injects no time ticks).

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ── Default config mirrors the canonical seed; overridden by state["config"]. ─
# Every value here is a mutation_operators-touched knob and so is read from
# state["config"] at runtime (parametric-source invariant); the
# defaults are a convenience for direct unit calls only.
_DEFAULT_CONFIG = {
    # Normal (non-destructive) forwarding path. A list of fwd_entry mappings
    # (dst exact -> egress_port); a static default egress is permitted by the
    # pattern. A dict {dst: port} is also accepted for direct unit calls.
    "egress_map": [
        {"dst": "10.0.1.1", "egress_port": 1},
        {"dst": "10.0.2.2", "egress_port": 2},
    ],
    "default_egress": 2,        # static fallback egress for unmatched IPv4 dsts
    "non_ipv4_egress": 2,       # R3 static egress for non-IPv4 frames
    "sample_rate": 4,           # N: clone 1-in-N (counter mod N == 0)
    "collector_port": 3,        # telemetry egress the clone is mirrored to
    "sampler_scope": "global",  # global | per_port | per_flow
    "sampler_cells": 1,         # number of independent counter cells
    "sample_header": "none",    # none | rate_only | rate_seq (clone tag breadth)
    "hash_algo": "crc32",       # per_flow cell-index hash family
}


def _config(state: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


# ── Packet introspection (Scapy + dict-style tolerant) ──────────────────────

def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        v = getattr(packet[layer], fname, default)
        return v if v is not None else default
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _has_ipv4(packet) -> bool:
    return _has_layer(packet, "IP") or _has_layer(packet, "ip")


def _ip(packet, fname, default=None):
    v = _field(packet, "IP", fname, None)
    if v is None:
        v = _field(packet, "ip", fname, None)
    return default if v is None else v


def _l4_ports(packet):
    sport = _field(packet, "TCP", "sport", None)
    dport = _field(packet, "TCP", "dport", None)
    if sport is None:
        sport = _field(packet, "UDP", "sport", None)
        dport = _field(packet, "UDP", "dport", None)
    return sport, dport


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


# ── Scope / cell-index resolution (RFC 7014 §3 per-Observation-Point) ────────

def _cell_index(cfg, ingress_port, packet) -> int:
    scope = cfg["sampler_scope"]
    cells = int(cfg["sampler_cells"])
    if scope == "global":
        return 0
    if scope == "per_port":
        return int(ingress_port) % max(cells, 1)
    if scope == "per_flow":
        sport, dport = _l4_ports(packet)
        key = "{}|{}|{}|{}|{}".format(
            _ip(packet, "src", ""), _ip(packet, "dst", ""),
            _ip(packet, "proto", 0), sport, dport,
        )
        h = zlib.crc32(key.encode()) & 0xFFFFFFFF
        return h % max(cells, 1)
    return 0


def _egress_for(cfg, packet) -> int:
    emap = cfg.get("egress_map") or []
    dst = str(_ip(packet, "dst", ""))
    if isinstance(emap, dict):
        if dst in emap:
            return int(emap[dst])
    else:
        for entry in emap:
            if str(entry.get("dst")) == dst:
                return int(entry.get("egress_port"))
    return int(cfg.get("default_egress", 0))


# ── step() — oracle interface ───────────────────────────────────────────────

def step(packet, ingress_port: int = 1,
         state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)

    new_state = dict(state)
    counters = dict(state.get("counters", {}))
    sample_seq = dict(state.get("sample_seq", {}))

    # ── R3 — non-IPv4 frame: forward to static egress, NOT sampled ──────────
    if not _has_ipv4(packet):
        port = int(cfg.get("non_ipv4_egress", cfg.get("default_egress", 0)))
        out = _clone(packet)
        new_state["counters"] = counters
        new_state["sample_seq"] = sample_seq
        return StepResult(
            output_packets={port: [out]},
            new_state=new_state,
            decision="forward",
            invariant_log=[("R3_non_ipv4_forward", {"port": port, "sampled": False})],
        )

    # ── R1 — advance the sampler counter by EXACTLY one, then forward ───────
    idx = _cell_index(cfg, ingress_port, packet)
    counters[idx] = int(counters.get(idx, 0)) + 1     # counter_quantum_one
    count = counters[idx]
    egress = _egress_for(cfg, packet)

    original = _clone(packet)                          # forward_always (non-destructive)
    outputs: Dict[int, List[Any]] = {egress: [original]}

    inv_log = [
        ("counter_quantum_one", {"cell": idx, "counter": count}),
        ("forward_always", {"port": egress}),
    ]

    # ── R2 — sample fire on every Nth packet (counter mod N == 0) ───────────
    N = int(cfg["sample_rate"])
    collector = int(cfg["collector_port"])
    decision = "forward"
    sampled = (count % N == 0)                          # sample_spacing_correctness
    if sampled:
        clone = _clone(packet)                          # sample_is_copy_not_move
        sample_header = cfg.get("sample_header", "none")
        if sample_header in ("rate_only", "rate_seq"):
            # The clone carries a sample tag (RFC 3176 §5.1). Recorded in the
            # invariant log; the canonical seed uses sample_header == none so
            # the clone is a verbatim copy and no tag is materialised.
            tag = {"sample_rate": N}
            if sample_header == "rate_seq":
                sample_seq[idx] = int(sample_seq.get(idx, 0)) + 1
                tag["sample_seq"] = sample_seq[idx]
            inv_log.append(("sample_tag", {"cell": idx, "tag": tag}))
        outputs.setdefault(collector, []).append(clone)
        decision = "mirror"
        inv_log.append(
            ("sample_spacing_correctness",
             {"cell": idx, "counter": count, "N": N,
              "collector_port": collector, "fired": True}))
    else:
        inv_log.append(
            ("sample_spacing_correctness",
             {"cell": idx, "counter": count, "N": N, "fired": False}))

    new_state["counters"] = counters
    new_state["sample_seq"] = sample_seq
    return StepResult(
        output_packets=outputs,
        new_state=new_state,
        decision=decision,
        invariant_log=inv_log,
    )


def reset():
    """No module-level state — state is threaded explicitly via `state`."""
    return None
