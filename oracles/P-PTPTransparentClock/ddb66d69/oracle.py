"""Python oracle for benchmark/redesign/ptp_tc_dispatch_ceiling.

Implements P-PTPTransparentClock's R0 (non-PTP passthrough), R1 (PTP general
non-follow-up passthrough), R2 (one-step in-transit residence correction),
R3 (two-step store) and R4 (two-step Follow_Up apply), PLUS the
flag_dispatched dispatch: when ``step_mode == "flag_dispatched"``
the R2 (in-transit) vs R3 (store) choice is made PER EVENT MESSAGE from the PTP
twoStepFlag (flagField bit 0x0200, IEEE 1588-2008 §13.3.2.6) instead of from a
global config constant — a twoStepFlag-CLEAR event is corrected in transit, a
twoStepFlag-SET event is stored and applied to its Follow_Up. R4 fires for any
Follow_Up with a matching stored entry (follow-ups exist only for two-step
exchanges). This is a STRICT SUPERSET of the 216755ff oracle: for the existing
one_step / two_step seeds it is byte-identical (the dispatch branch is reached
only when step_mode == "flag_dispatched").

Residence model (the P-PTPTransparentClock pattern's post_instantiation_hooks):
BMv2 timestamps are not reproducible across runs, so the oracle reads a
deterministic residence from runtime `state` (``residence_ns``, default 0)
rather than wall-clock. The audit's canonical examples (when authored) drive
this knob at its feasibility-postcondition extremes; the v1.0 evaluation
harness does not yet inject residence, so the residence-magnitude-exact tests
are deferred.

Parametric-source contract: every parameter named in the pattern's
mutation_operators surface is read from `state["config"]` at call time, never
baked as a source-level constant — this is what lets parameter rebinding
reuse this same module across mutated instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────
# StepResult and packet helpers (dict-style for audit, Scapy for the harness)
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# PTP messageType wire encodings (low nibble of byte 0)
SYNC, DELAY_REQ, PDELAY_REQ, PDELAY_RESP = 0x0, 0x1, 0x2, 0x3
FOLLOW_UP, DELAY_RESP, PDELAY_RESP_FOLLOW_UP = 0x8, 0x9, 0xA
ANNOUNCE, SIGNALING, MANAGEMENT = 0xB, 0xC, 0xD

EVENT_TYPES = {SYNC, DELAY_REQ, PDELAY_REQ, PDELAY_RESP}
GENERAL_NON_FOLLOWUP = {DELAY_RESP, ANNOUNCE, SIGNALING, MANAGEMENT}
FOLLOWUP_TYPES = {FOLLOW_UP, PDELAY_RESP_FOLLOW_UP}

PTP_EVENT_PORT = 319
PTP_GENERAL_PORT = 320

# IEEE 1588-2008 §13.3.2.6 twoStepFlag — flagField bit 0x0200 (byte 6 bit 1).
# When step_mode == "flag_dispatched" the per-event correction mechanism is
# selected from this bit: clear → one-step in-transit (R2), set → two-step
# store/apply (R3/R4).
TWO_STEP_FLAG = 0x0200


def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    return name in (packet or {})


def _field(packet, layer: str, field_name: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        return getattr(packet[layer], field_name, default)
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(field_name, default)
    return default


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _set(packet, layer: str, field_name: str, value):
    if isinstance(packet, dict):
        packet.setdefault(layer, {})[field_name] = value
        return
    try:
        setattr(packet[layer], field_name, value)
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────
# Residence / correction arithmetic
# ──────────────────────────────────────────────────────────────────────

def _message_class(mtype: int) -> str:
    """Two-step correlation class: Sync<->Follow_Up, Pdelay_Resp<->Pdelay_Resp_Follow_Up."""
    if mtype in (SYNC, FOLLOW_UP):
        return "sync"
    if mtype in (PDELAY_RESP, PDELAY_RESP_FOLLOW_UP):
        return "pdelay"
    return "other"


def _scaled_correction(residence_ns: int, link_delay_ns: int, mode: str) -> int:
    """Convert measured residence (+ link delay for P2P) to a correctionField
    delta in the units selected by ${correction_field_faithfulness}."""
    total_ns = residence_ns + link_delay_ns
    if mode == "full64_scaled_ns":
        # RFC-faithful: correctionField is in units of 2^-16 ns across 64 bits.
        return (total_ns << 16) & ((1 << 64) - 1)
    # low32_ns: plain nanoseconds in the low 32 bits.
    return total_ns & ((1 << 32) - 1)


def _is_corrected_event(mtype: int, corrected_message_types: str) -> bool:
    if corrected_message_types == "sync_only":
        return mtype == SYNC
    return mtype in EVENT_TYPES


def _domain_admits(packet, config) -> bool:
    if config.get("domain_handling", "single_domain_any") == "single_domain_any":
        return True
    active = config.get("active_domains", [0])
    return _field(packet, "PTP", "domainNumber", 0) in active


# ──────────────────────────────────────────────────────────────────────
# step() — the oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int, state: Optional[Dict[str, Any]] = None) -> StepResult:
    """Execute one packet step under the transparent-clock rules.

    State threading:
      - state["config"]: parametric knobs from the seed (step_mode,
        delay_mechanism, transport, correction_field_faithfulness,
        domain_handling, active_domains, corrected_message_types,
        link_delays, correlation_capacity). Read at every call.
      - state["residence_ns"]: deterministic residence injected by the harness
        (default 0 — see module docstring).
      - state["correlation"]: two-step residence store, keyed by
        (clockIdentity, portNumber, sequenceId, message_class).
      - state["forward_table"]: dst-IP -> {port, mac} downstream forwarding.
    """
    state = state or {}
    new_state = dict(state)
    new_state["correlation"] = dict(state.get("correlation", {}))
    config = state.get("config", {})
    residence_ns = int(state.get("residence_ns", 0))

    # ── Demux: is this a PTP message, and on which transport/port? ─────────
    transport = config.get("transport", "udp_ipv4")
    on_event_port = False
    on_general_port = False
    is_ptp = False
    if transport == "eth_88f7":
        is_ptp = _field(packet, "Ether", "type", None) == 0x88F7
        on_event_port = on_general_port = is_ptp
    else:  # udp_ipv4 / udp_ipv6
        if _has_layer(packet, "UDP"):
            dport = _field(packet, "UDP", "dport", 0)
            on_event_port = dport == PTP_EVENT_PORT
            on_general_port = dport == PTP_GENERAL_PORT
            is_ptp = on_event_port or on_general_port

    # ── R0 — non-PTP passthrough ───────────────────────────────────────────
    if not is_ptp or not _has_layer(packet, "PTP"):
        return _r0_passthrough(packet, ingress_port, new_state)

    mtype = _field(packet, "PTP", "messageType", None)

    # ── R1 — PTP general non-follow-up passthrough (never corrected) ────────
    if mtype in GENERAL_NON_FOLLOWUP:
        return _forward(packet, ingress_port, new_state,
                        ("R1_general_passthrough", {"messageType": mtype}))

    step_mode = config.get("step_mode", "one_step")
    corrected = config.get("corrected_message_types", "sync_only")

    # ── R4 — two-step Follow_Up apply ───────────────────────────────────────
    # Fires for two_step AND flag_dispatched: a Follow_Up exists only for a
    # two-step exchange, so under flag_dispatched it pairs with whatever
    # twoStepFlag-SET event R3 stored. An orphan Follow_Up (no stored entry,
    # e.g. the matching event was flag-clear and corrected in transit) is
    # forwarded unmodified by _r4_followup_apply's miss path.
    if step_mode in ("two_step", "flag_dispatched") and mtype in FOLLOWUP_TYPES:
        return _r4_followup_apply(packet, ingress_port, new_state, config)

    # ── Event messages: R2 (one-step) or R3 (two-step store) ────────────────
    if mtype in EVENT_TYPES:
        if not _is_corrected_event(mtype, corrected):
            # An event message outside the corrected set is forwarded untouched.
            return _forward(packet, ingress_port, new_state,
                            ("event_not_in_corrected_set", {"messageType": mtype}))
        if not _domain_admits(packet, config):
            return _forward(packet, ingress_port, new_state,
                            ("domain_filtered_passthrough", {}))

        link_delay_ns = 0
        if config.get("delay_mechanism", "e2e") == "p2p":
            link_delay_ns = _link_delay_for(config, ingress_port)
        delta = _scaled_correction(residence_ns, link_delay_ns,
                                   config.get("correction_field_faithfulness", "low32_ns"))

        # Resolve the effective per-event mechanism. For one_step / two_step it
        # is the global config constant; for flag_dispatched it is read from the
        # event's own twoStepFlag (the flag_dispatched mutation operator).
        effective = step_mode
        if step_mode == "flag_dispatched":
            flag = int(_field(packet, "PTP", "flagField", 0) or 0)
            effective = "two_step" if (flag & TWO_STEP_FLAG) else "one_step"

        if effective == "one_step":
            return _r2_onestep_correct(packet, ingress_port, new_state, config, delta)
        else:
            return _r3_twostep_store(packet, ingress_port, new_state, config, delta)

    # Anything else (unexpected messageType) — forward unmodified.
    return _forward(packet, ingress_port, new_state,
                    ("unhandled_message_type", {"messageType": mtype}))


# ──────────────────────────────────────────────────────────────────────
# Rule bodies
# ──────────────────────────────────────────────────────────────────────

def _r0_passthrough(packet, ingress_port, state) -> StepResult:
    """Non-PTP frame: hand to the downstream forwarding pipeline."""
    fwd = state.get("forward_table", {
        "10.0.2.2": {"port": 2, "mac": "08:00:00:00:02:02"},
        "10.0.1.1": {"port": 1, "mac": "08:00:00:00:01:01"},
    })
    dst = _field(packet, "IP", "dst", None)
    if dst is None or dst not in fwd:
        return StepResult(output_packets={}, new_state=state, decision="drop",
                          invariant_log=[("R0_no_forward_entry", {"dst": dst})])
    entry = fwd[dst]
    out = _clone(packet)
    _set(out, "Ether", "dst", entry["mac"])
    return StepResult(output_packets={entry["port"]: [out]}, new_state=state,
                      decision="forward",
                      invariant_log=[("R0_passthrough", {"port": entry["port"]})])


def _forward(packet, ingress_port, state, log) -> StepResult:
    """Forward a PTP message via the downstream pipeline, header preserved."""
    fwd = state.get("forward_table", {
        "10.0.2.2": {"port": 2, "mac": "08:00:00:00:02:02"},
        "10.0.1.1": {"port": 1, "mac": "08:00:00:00:01:01"},
    })
    out = _clone(packet)
    dst = _field(packet, "IP", "dst", None)
    port = ingress_port
    if dst in fwd:
        _set(out, "Ether", "dst", fwd[dst]["mac"])
        port = fwd[dst]["port"]
    return StepResult(output_packets={port: [out]}, new_state=state,
                      decision="forward", invariant_log=[log])


def _r2_onestep_correct(packet, ingress_port, state, config, delta) -> StepResult:
    """R2: ADD the scaled residence to the event message's own correctionField
    in transit, clear the reserved bytes, recompute UDP checksum over UDP."""
    out = _clone(packet)
    incoming = int(_field(packet, "PTP", "correctionField", 0) or 0)
    result = (incoming + delta) & ((1 << 64) - 1)
    _set(out, "PTP", "correctionField", result)            # += not = (accumulate)
    _set(out, "PTP", "reserved", 0)                        # IEEE 1588 §11.5.3
    if config.get("transport") in ("udp_ipv4", "udp_ipv6"):
        _set(out, "UDP", "chksum", None)                  # signal recompute on rebuild
    base = _forward(out, ingress_port, state,
                    ("R2_onestep_correct",
                     {"messageType": _field(packet, "PTP", "messageType", None),
                      "incoming": incoming, "delta": delta, "result": result}))
    base.invariant_log.append(
        ("residence_correction_equals_measured", {"delta": delta}))
    base.invariant_log.append(
        ("correction_is_accumulated", {"incoming": incoming, "result": result}))
    return base


def _r3_twostep_store(packet, ingress_port, state, config, delta) -> StepResult:
    """R3: store the residence keyed by (sourcePortIdentity, sequenceId, class)
    and forward the event message UNMODIFIED."""
    key = _correlation_key(packet)
    cap = config.get("correlation_capacity", "unbounded")
    corr = state["correlation"]
    if cap != "unbounded" and key not in corr and len(corr) >= int(cap):
        # Capacity overflow: drop this correlation (its Follow_Up will pass
        # through unmodified via R1 fallthrough). Never apply a stale value.
        log = ("R3_capacity_overflow", {"key": key, "cap": cap})
    else:
        corr[key] = delta
        log = ("R3_store_residence", {"key": key, "delta": delta})
    return _forward(packet, ingress_port, state, log)      # event forwarded verbatim


def _r4_followup_apply(packet, ingress_port, state, config) -> StepResult:
    """R4: add the stored residence to the paired Follow_Up's correctionField,
    clear reserved, recompute checksum, and evict the entry (apply once)."""
    key = _correlation_key(packet)
    corr = state["correlation"]
    if key not in corr:
        # Orphan Follow_Up (lost event / evicted) — forward unmodified.
        return _forward(packet, ingress_port, state,
                        ("R4_orphan_followup", {"key": key}))
    delta = corr.pop(key)                                  # evict: consumed once
    out = _clone(packet)
    incoming = int(_field(packet, "PTP", "correctionField", 0) or 0)
    result = (incoming + delta) & ((1 << 64) - 1)
    _set(out, "PTP", "correctionField", result)
    _set(out, "PTP", "reserved", 0)
    if config.get("transport") in ("udp_ipv4", "udp_ipv6"):
        _set(out, "UDP", "chksum", None)
    return _forward(out, ingress_port, state,
                    ("R4_twostep_apply", {"key": key, "delta": delta, "result": result}))


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _correlation_key(packet):
    return (
        _field(packet, "PTP", "clockIdentity", 0),
        _field(packet, "PTP", "portNumber", 0),
        _field(packet, "PTP", "sequenceId", 0),
        _message_class(_field(packet, "PTP", "messageType", None)),
    )


def _link_delay_for(config, ingress_port) -> int:
    for entry in config.get("link_delays", []):
        if entry.get("ingress_port") == ingress_port:
            return int(entry.get("mean_link_delay", 0))
    return 0
