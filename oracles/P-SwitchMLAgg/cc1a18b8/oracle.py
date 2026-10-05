"""Python oracle for benchmark/relocate/switchml_agg_disc.

Implements P-SwitchMLAgg's rule sequence under the
task's seed (the SwitchML strict-barrier model):

  - R0  non-aggregation passthrough (no SwitchML header → L3 forward)
  - R1  duplicate-worker idempotent drop (bitmap_dedup)
  - R2  cross-job slot-collision fallback (eventually_consistent only;
        dormant under the strict seed — collisions are dropped)
  - R3  first contribution → bind/open the slot
  - R4  accumulate a non-final contribution (no emit)
  - R5  completing contribution → fold, multicast the aggregated result
        to the worker group, reset the slot

Per the parametric-source contract: every parameter
named in the pattern's `mutation_operators` surface is read from
`state["config"]` at runtime, never baked as a source-level constant —
this is what lets parameter rebinding reuse this
same audited oracle across mutated instances.

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult

The aggregation slots live in `state["slots"]`, keyed by (job_id, slot_id).
A module-level fallback store backs the 2-arg `step(pkt, port)` calls the
oracle audit harness makes (which does not thread state); the
content-addressed reference and the task's hand-derived `expected:` blocks
are cross-checked by replaying this module with explicit state threading.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────
# StepResult — oracle return shape
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# Module-level fallback store for stateless 2-arg audit calls.
_GLOBAL_STATE: Dict[str, Any] = {}


def reset() -> None:
    """Clear the module-level fallback store (called by the audit harness
    between canonical examples)."""
    _GLOBAL_STATE.clear()


# ──────────────────────────────────────────────────────────────────────
# Packet-introspection helpers (Scapy + dict-style tolerant)
# ──────────────────────────────────────────────────────────────────────

def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet or name in packet.get("_layers", {})
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        v = getattr(packet[layer], fname, default)
        return v if v is not None else default
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _has_switchml(packet) -> bool:
    return _has_layer(packet, "SwitchML") or _has_layer(packet, "switchml")


def _sml(packet, fname: str, default=0) -> int:
    v = _field(packet, "SwitchML", fname, None)
    if v is None:
        v = _field(packet, "switchml", fname, None)
    return default if v is None else int(v)


# ──────────────────────────────────────────────────────────────────────
# Config / state helpers
# ──────────────────────────────────────────────────────────────────────

# Defaults mirror the task's seed; they are overridden by
# state["config"] at runtime so parameter rebinding never edits this file.
_DEFAULT_CONFIG = {
    "n_workers": 2,
    "n_slots": 4,
    # NB: vector_width, loss_tolerance and faithfulness are variant SELECTORS —
    # they pick a behavioural variant (multi-value vector / shadow-copy loss
    # tolerance / faithfulness rung) regenerated as a DIFFERENT oracle, and this
    # scalar D5.0 source never branches on them. They are therefore NOT carried
    # in _DEFAULT_CONFIG (exercised across regeneration, not config injection on
    # this hash). value_width_bits IS read (the integer fold mask), and stays.
    "value_width_bits": 32,
    "aggregation_op": "sum",
    "barrier_policy": "strict",
    "worker_id_collision_handling": "bitmap_dedup",
    "slot_collision_policy": "drop",
    "result_delivery": "multicast_all",
    "worker_ports": [1, 2],
    "result_multicast_group": 1,
    "result_collector_port": 3,
}


def _config(state: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _reduce(op: str, a: int, b: int, width_bits: int) -> int:
    """Lane reduction with exact-integer saturation (no modular wrap)."""
    if op == "max":
        return max(a, b)
    s = a + b                                   # sum
    cap = (1 << width_bits) - 1
    return min(s, cap)                          # saturating add (D5.0 contract)


# ──────────────────────────────────────────────────────────────────────
# step() — the oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    """Execute one packet step under the pattern's rules.

    state["slots"]: dict keyed by "job_id:slot_id" → slot dict with
        {agg, bitmap, count, occupant_job}.
    state["config"]: the parametric knobs from the seed (read every call).
    """
    own_state = state is None
    if own_state:
        state = _GLOBAL_STATE
    cfg = _config(state)

    new_state = dict(state)
    slots: Dict[str, Any] = {k: dict(v) for k, v in state.get("slots", {}).items()}
    new_state["slots"] = slots

    # ── R0 — non-aggregation passthrough ────────────────────────────────
    if not _has_switchml(packet):
        res = _r0_passthrough(packet, ingress_port, cfg, new_state)
        return _finish(res, own_state)

    job_id = _sml(packet, "job_id")
    slot_id = _sml(packet, "slot_id")
    worker_id = _sml(packet, "worker_id")
    val = _sml(packet, "val")
    key = str(slot_id)  # physical aggregation-slot index; occupant_job tracks the holder so R2 cross-job collisions fire
    n_workers = int(cfg["n_workers"])
    width = int(cfg["value_width_bits"])
    slot = slots.get(key)

    # ── R1 — duplicate-worker idempotent drop (bitmap_dedup) ─────────────
    if (slot is not None
            and slot["occupant_job"] == job_id
            and cfg["worker_id_collision_handling"] == "bitmap_dedup"
            and (slot["bitmap"] >> worker_id) & 1):
        return _finish(
            StepResult(output_packets={}, new_state=new_state, decision="drop",
                       invariant_log=[("R1_duplicate_drop",
                                       {"key": key, "worker_id": worker_id})]),
            own_state)

    # ── R2 — cross-job slot collision ────────────────────────────────────
    if slot is not None and slot["occupant_job"] != job_id:
        if (cfg["barrier_policy"] == "eventually_consistent"
                and cfg["slot_collision_policy"] == "server_fallback"):
            collector = int(cfg["result_collector_port"])
            return _finish(
                StepResult(output_packets={collector: [_clone(packet)]},
                           new_state=new_state, decision="forward",
                           invariant_log=[("R2_server_fallback",
                                           {"key": key, "to": collector})]),
                own_state)
        # strict: drop the colliding block; occupant aggregate untouched.
        return _finish(
            StepResult(output_packets={}, new_state=new_state, decision="drop",
                       invariant_log=[("R2_collision_drop", {"key": key})]),
            own_state)

    # ── R3 — first contribution opens the slot ──────────────────────────
    if slot is None:
        slots[key] = {
            "agg": int(val),
            "bitmap": 1 << worker_id,
            "count": 1,
            "occupant_job": job_id,
        }
        # n_workers == 1 completes immediately (single-worker degenerate).
        if n_workers <= 1:
            return _finish(_emit_and_reset(packet, key, slots, cfg, new_state, int(val)),
                           own_state)
        return _finish(
            StepResult(output_packets={}, new_state=new_state, decision="drop",
                       invariant_log=[("R3_first_contribution",
                                       {"key": key, "worker_id": worker_id, "agg": int(val)})]),
            own_state)

    # slot exists, same job, this worker not yet counted
    folded = _reduce(cfg["aggregation_op"], slot["agg"], int(val), width)

    # ── R5 — completing contribution (this is the n_workers-th) ──────────
    if slot["count"] == n_workers - 1:
        return _finish(_emit_and_reset(packet, key, slots, cfg, new_state, folded),
                       own_state)

    # ── R4 — accumulate a non-final contribution ────────────────────────
    slot["agg"] = folded
    slot["bitmap"] |= (1 << worker_id)
    slot["count"] += 1
    slots[key] = slot
    return _finish(
        StepResult(output_packets={}, new_state=new_state, decision="drop",
                   invariant_log=[("R4_accumulate",
                                   {"key": key, "worker_id": worker_id,
                                    "agg": folded, "count": slot["count"]})]),
        own_state)


# ──────────────────────────────────────────────────────────────────────
# Sub-rules / helpers
# ──────────────────────────────────────────────────────────────────────

def _emit_and_reset(packet, key, slots, cfg, new_state, agg_value) -> StepResult:
    """R5 tail: build the aggregated result block, deliver it to the
    worker group, and reset (evict) the slot."""
    result = _clone(packet)
    _set_sml_val(result, agg_value)

    if cfg["result_delivery"] == "unicast_each":
        out = {int(p): [_clone(result)] for p in cfg["worker_ports"]}
    else:                                        # multicast_all
        out = {int(p): [_clone(result)] for p in cfg["worker_ports"]}

    slots.pop(key, None)                         # reset the slot
    return StepResult(
        output_packets=out,
        new_state=new_state,
        decision="forward",
        invariant_log=[("R5_complete_emit_reset",
                        {"key": key, "agg": agg_value,
                         "ports": sorted(int(p) for p in cfg["worker_ports"])})],
    )


def _r0_passthrough(packet, ingress_port, cfg, new_state) -> StepResult:
    """Forward ordinary IPv4 traffic via the harness-installed L3 path.
    Convention for this topology: dst IP → (port, mac). Non-IPv4 with no
    entry is dropped."""
    fwd = cfg.get("non_agg_forward_table", {
        "10.0.1.1": {"port": 1, "mac": "08:00:00:00:01:01"},
        "10.0.2.2": {"port": 2, "mac": "08:00:00:00:02:02"},
        "10.0.3.3": {"port": 3, "mac": "08:00:00:00:03:03"},
    })
    if not _has_layer(packet, "IP"):
        return StepResult(output_packets={}, new_state=new_state, decision="drop",
                          invariant_log=[("R0_non_ipv4_drop", {})])
    dst = _field(packet, "IP", "dst", None)
    entry = fwd.get(dst)
    if entry is None:
        return StepResult(output_packets={}, new_state=new_state, decision="drop",
                          invariant_log=[("R0_no_forward_entry", {"dst": dst})])
    out = _clone(packet)
    _rewrite_eth_dst(out, entry["mac"])
    return StepResult(output_packets={entry["port"]: [out]}, new_state=new_state,
                      decision="forward",
                      invariant_log=[("R0_passthrough", {"port": entry["port"]})])


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _set_sml_val(packet, value):
    if isinstance(packet, dict):
        layer = packet.get("SwitchML") or packet.get("switchml")
        if layer is not None:
            layer["val"] = value
        return
    try:
        packet["SwitchML"].val = value
    except Exception:
        pass


def _rewrite_eth_dst(packet, new_mac):
    if isinstance(packet, dict):
        packet.setdefault("Ether", {})["dst"] = new_mac
        return
    try:
        packet["Ether"].dst = new_mac
    except Exception:
        pass


def _finish(res: StepResult, own_state: bool) -> StepResult:
    """If running off the module-level fallback store (2-arg audit calls),
    commit new_state back so successive calls accumulate."""
    if own_state:
        _GLOBAL_STATE.clear()
        _GLOBAL_STATE.update(res.new_state)
    return res
