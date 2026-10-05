"""Per-task oracle for benchmark/relocate/in_network_sequencer_anchor
(P-InNetworkSequencer).

Implements the in-network ordered-multicast (NOPaxos OUM / Eris) rule sequence.
On the sequenced traffic class the switch read-increments a
per-group monotone counter, stamps the NEW value into the sequence-number
header field (and the group session, when enabled), and multicasts the request
to the replica group so every replica observes one identical request order.
Non-sequenced traffic forwards untouched without consuming a sequence number.

Rule sequence (first-match, declaration order):

  - R_malformed_drop            no sequencing header parsed -> drop
  - R_session_reset             (gated by enable_session_reset & stamp_session)
                                a session-reset control message bumps the
                                group session, restarts its counter at 0, and
                                multicasts the reset (seq_no == 0)
  - R0_non_sequenced_forward    (non_sequenced_policy == forward) out-of-class
                                packet forwards untouched; counter UNCHANGED
  - R_non_sequenced_drop        (non_sequenced_policy == drop) out-of-class
                                packet dropped; counter UNCHANGED
  - R2_sequence_stamp_multicast in-class packet: counter <- counter + 1, stamp
                                seq_no <- counter (and session when enabled),
                                multicast to the replica group

Parametric-source contract: every value a parameter rebind may
touch — sequencing_class (the REQUEST type code), group_id_map (sequencing
group -> replica multicast group), n_groups, non_sequenced_policy,
stamp_session, enable_session_reset, reset_type, seq_width_bits —
is read from state["config"] at runtime, NEVER baked as a source-level
constant. The seed's values enter only via the initial state, so two siblings
of this pattern with different seed bindings produce byte-identical oracle
source and reuse the same audited module.

The monotone counter and session live in state["buckets"] (a per-group dict)
and persist across the packet train threaded by the caller. The harness feeds
only packets (no time_tick): the counter and any session reset are driven
entirely by received packets, never a wall-clock timer.

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
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


# ── Default config mirrors the canonical seed; overridden by state["config"]. ─
# n_groups == 1 (NOPaxos single global sequencer); group 0 multicasts to the
# replica group at mcast_grp 1 (ports {2,3,4}); REQUEST class type code == 1;
# session stamping on; no session-reset rule; 32-bit no-wrap sequence space;
# exact-monotone ordering.
_DEFAULT_CONFIG = {
    "n_groups": 1,
    # control-plane binding: sequencing group_id -> replica multicast group id
    "group_id_map": {0: 1},
    # the replica ports each multicast group fans the request out to
    "replica_ports": {1: [2, 3, 4]},
    "request_type": 1,            # hdr.seq.type value that marks the OUM class
    "reset_type": 2,             # hdr.seq.type value that triggers a session reset
    "non_sequenced_policy": "forward",
    "stamp_session": True,
    "enable_session_reset": False,
    "seq_width_bits": 32,
    "initial_session": 1,        # session/epoch each group starts in
}


def _config(state: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    # group_id_map / replica_ports keys may arrive as strings from YAML/JSON.
    cfg["group_id_map"] = {int(k): int(v) for k, v in cfg["group_id_map"].items()}
    cfg["replica_ports"] = {int(k): [int(p) for p in v]
                            for k, v in cfg["replica_ports"].items()}
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


def _has_seq(packet) -> bool:
    return _has_layer(packet, "Sequencer") or _has_layer(packet, "seq")


def _seq(packet, fname, default=None):
    v = _field(packet, "Sequencer", fname, None)
    if v is None:
        v = _field(packet, "seq", fname, None)
    return default if v is None else v


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _set(packet, layer, fname, value):
    if isinstance(packet, dict):
        packet.setdefault(layer, {})[fname] = value
        return
    # Scapy: write into the parsed custom layer under either resolved name.
    for lname in (layer, "seq"):
        try:
            if packet.haslayer(lname):
                setattr(packet[lname], fname, value)
                return
        except Exception:
            continue
    try:
        setattr(packet[layer], fname, value)
    except Exception:
        pass


def _drop(state, reason) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def _buckets(state: Dict[str, Any]) -> Dict[int, Dict[str, int]]:
    """Per-group monotone counter + session, persisted across the train."""
    return dict(state.get("buckets", {}))


def _bucket(buckets: Dict[int, Dict[str, int]], gid: int, cfg) -> Dict[str, int]:
    b = buckets.get(gid)
    if b is None:
        # Cold start: an untouched counter reads 0 (first stamped value is 1);
        # the group begins in its initial session.
        b = {"counter": 0, "session": int(cfg["initial_session"])}
    return dict(b)


# ── step() — oracle interface ───────────────────────────────────────────────

def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)
    buckets = _buckets(state)

    # R_malformed_drop — no sequencing header parsed.
    if not _has_seq(packet):
        new_state["buckets"] = buckets
        return _drop(new_state, "R_malformed_no_seq_header")

    gid = int(_seq(packet, "group_id", 0))
    ptype = int(_seq(packet, "type", 0))
    seq_mask = (1 << int(cfg["seq_width_bits"])) - 1

    group_map = cfg["group_id_map"]
    mgid = group_map.get(gid)
    out_ports = cfg["replica_ports"].get(mgid, []) if mgid is not None else []

    is_request = (ptype == int(cfg["request_type"]))
    is_reset = (ptype == int(cfg["reset_type"]))

    # R_session_reset — gated by enable_session_reset & stamp_session.
    if cfg["enable_session_reset"] and cfg["stamp_session"] and is_reset:
        b = _bucket(buckets, gid, cfg)
        b["session"] = (b["session"] + 1) & seq_mask
        b["counter"] = 0
        buckets[gid] = b
        new_state["buckets"] = buckets
        out = _clone(packet)
        _set(out, "Sequencer", "session", b["session"])
        _set(out, "Sequencer", "seq_no", b["counter"])  # reset multicast carries seq_no == 0
        return StepResult(
            output_packets={p: [_clone(out)] for p in out_ports},
            new_state=new_state,
            decision="multicast",
            invariant_log=[("R_session_reset",
                            {"group_id": gid, "session": b["session"],
                             "seq_no": b["counter"], "ports": list(out_ports)}),
                           ("session_stamp_stability",
                            {"group_id": gid, "session": b["session"]})],
        )

    # R0 / R_non_sequenced — out-of-class packet (not a REQUEST).
    if not is_request:
        new_state["buckets"] = buckets  # counter MUST NOT advance off-class
        if cfg["non_sequenced_policy"] == "drop":
            return _drop(new_state, "R_non_sequenced_drop")
        # forward untouched (seq_no UNCHANGED — no stamp).
        out = _clone(packet)
        return StepResult(
            output_packets={p: [_clone(out)] for p in out_ports},
            new_state=new_state,
            decision="multicast",
            invariant_log=[("R0_non_sequenced_forward",
                            {"group_id": gid, "ports": list(out_ports)}),
                           ("counter_persistence_off_class",
                            {"group_id": gid,
                             "counter": _bucket(buckets, gid, cfg)["counter"]})],
        )

    # R2_sequence_stamp_multicast — in-class request.
    b = _bucket(buckets, gid, cfg)
    # read-increment-stamp: counter <- counter + 1, stamp the NEW value.
    b["counter"] = (b["counter"] + 1) & seq_mask
    buckets[gid] = b
    new_state["buckets"] = buckets

    out = _clone(packet)
    _set(out, "Sequencer", "seq_no", b["counter"])
    if cfg["stamp_session"]:
        _set(out, "Sequencer", "session", b["session"])

    log = [("R2_sequence_stamp_multicast",
            {"group_id": gid, "seq_no": b["counter"],
             "session": b["session"], "ports": list(out_ports)}),
           ("seq_monotonicity", {"group_id": gid, "seq_no": b["counter"]})]
    if cfg["stamp_session"]:
        log.append(("session_stamp_stability",
                    {"group_id": gid, "session": b["session"]}))
    # per_group_isolation witness (only meaningful when n_groups > 1).
    log.append(("per_group_isolation",
                {"group_id": gid, "counter": b["counter"]}))

    return StepResult(
        output_packets={p: [_clone(out)] for p in out_ports},
        new_state=new_state,
        decision="multicast",
        invariant_log=log,
    )
