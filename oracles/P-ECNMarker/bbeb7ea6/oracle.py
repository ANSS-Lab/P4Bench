"""Python oracle for benchmark/scale_up/ecn_marker_disc.

Implements P-ECNMarker's rule sequence under the
task's seed:

  - R0   wrong-port drop
  - R1   non-IPv4 action (drop under non_ipv4_action == drop;
                          passthrough under non_ipv4_action == passthrough)
  - R2   non-eligible-L4 drop (vacuous under eligibility_protocol == any_l4;
                                fires for non-TCP under tcp_only)
  - R3   above-threshold Not-ECT drop (active under not_ect_action == drop)
  - R4   above-threshold ECT mark (ECN ← 0b11, IPv4 checksum recomputed)
  - R5   above-threshold CE preserve (verbatim forward)
  - R6   below-threshold passthrough (verbatim forward)

Per the parametric-source contract: every parameter
named in the pattern's `mutation_operators` surface is read from `state`
at runtime (specifically from `state["config"]`). Seed values never enter
the module as source-level constants — this is what lets parameter
rebinding reuse the same audited oracle.

Synthetic queue-depth convention: the task's seed wires the
depth signal through hdr.ipv4.identification (a 16-bit IPv4 header field
unused by ECN logic). The oracle reads packet.ipv4.id at packet processing
time and uses it as `bucket.depth`. Production seeds would replace this
with std.enq_qdepth / std.deq_qdepth; the contract is the same — depth is
state[config]["queue_depth_signal"]-driven.

step() signature is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
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


def _ipv4_tos(packet) -> int:
    """Return the 8-bit IPv4 ToS / diffserv byte (DSCP<<2 | ECN)."""
    v = _field(packet, "IP", "tos", None)
    if v is None:
        v = _field(packet, "ipv4", "diffserv", None)
    if v is None:
        v = _field(packet, "ipv4", "tos", 0)
    return int(v) & 0xFF


def _ipv4_id(packet) -> int:
    """Return the 16-bit IPv4 identification field; the synthetic-qdepth carrier."""
    v = _field(packet, "IP", "id", None)
    if v is None:
        v = _field(packet, "ipv4", "identification", None)
    if v is None:
        v = _field(packet, "ipv4", "id", 0)
    return int(v) & 0xFFFF


def _ipv4_proto(packet) -> Optional[int]:
    v = _field(packet, "IP", "proto", None)
    if v is None:
        v = _field(packet, "ipv4", "protocol", None)
    return None if v is None else int(v) & 0xFF


def _has_ipv4(packet) -> bool:
    return _has_layer(packet, "IP") or _has_layer(packet, "ipv4")


def _has_eligible_l4(packet, eligibility_protocol: str) -> bool:
    if eligibility_protocol == "any_l4":
        # Vacuously true for any IPv4 packet at the pattern level.
        return _has_ipv4(packet)
    if eligibility_protocol == "tcp_only":
        # TCP only — check protocol field or Scapy layer.
        if _has_layer(packet, "TCP") or _has_layer(packet, "tcp"):
            return True
        return _ipv4_proto(packet) == 6
    return False


# ──────────────────────────────────────────────────────────────────────
# ECN bit-field helpers
# ──────────────────────────────────────────────────────────────────────

ECN_NOT_ECT = 0b00
ECN_ECT_1   = 0b01
ECN_ECT_0   = 0b10
ECN_CE      = 0b11


def _ecn_of_tos(tos: int) -> int:
    return tos & 0b11


def _dscp_of_tos(tos: int) -> int:
    return (tos >> 2) & 0b111111


def _tos_with_ecn(tos: int, new_ecn: int) -> int:
    return ((tos & 0b11111100) | (new_ecn & 0b11)) & 0xFF


# ──────────────────────────────────────────────────────────────────────
# Output packet construction
# ──────────────────────────────────────────────────────────────────────

def _forward_unchanged(packet, egress_port: int) -> StepResult:
    return StepResult(
        output_packets={egress_port: [packet]},
        decision="forward",
        invariant_log=[],
    )


def _forward_marked(packet, egress_port: int) -> StepResult:
    """Forward with ECN bits set to CE; DSCP and other fields preserved.
    Scapy: rewrite IP.tos by bit-replacing the low 2 bits; Scapy recomputes
    chksum on send. Dict path: rewrite the diffserv byte in-place."""
    out = packet
    if hasattr(packet, "haslayer") and packet.haslayer("IP"):
        # Scapy mutation; force checksum recompute by deleting chksum.
        try:
            new_pkt = packet.copy()
            new_pkt["IP"].tos = _tos_with_ecn(int(new_pkt["IP"].tos), ECN_CE)
            try:
                del new_pkt["IP"].chksum
            except Exception:
                pass
            out = new_pkt
        except Exception:
            out = packet
    elif isinstance(packet, dict):
        # Dict-shaped audit input: mirror the IP.tos rewrite into a copy.
        new_pkt = {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
        if "IP" in new_pkt:
            new_pkt["IP"]["tos"] = _tos_with_ecn(int(new_pkt["IP"].get("tos", 0)), ECN_CE)
        elif "ipv4" in new_pkt:
            old = int(new_pkt["ipv4"].get("diffserv", new_pkt["ipv4"].get("tos", 0)))
            new_tos = _tos_with_ecn(old, ECN_CE)
            if "diffserv" in new_pkt["ipv4"]:
                new_pkt["ipv4"]["diffserv"] = new_tos
            else:
                new_pkt["ipv4"]["tos"] = new_tos
        out = new_pkt
    return StepResult(
        output_packets={egress_port: [out]},
        decision="mark_and_forward",
        invariant_log=[("ipv4_checksum_validity_after_mark", "recomputed"),
                       ("dscp_preserved_under_mark", True)],
    )


def _forward_unmarked(packet, egress_port: int) -> StepResult:
    """Forward with ECN bits cleared to ECT(0); DSCP and other fields
    preserved. The relaxed-persistence path (ce_persistence_strict == False):
    an above-threshold CE packet is unmarked back to ECT(0) rather than
    preserved. IPv4 checksum is recomputed because the diffserv byte changed."""
    out = packet
    if hasattr(packet, "haslayer") and packet.haslayer("IP"):
        try:
            new_pkt = packet.copy()
            new_pkt["IP"].tos = _tos_with_ecn(int(new_pkt["IP"].tos), ECN_ECT_0)
            try:
                del new_pkt["IP"].chksum
            except Exception:
                pass
            out = new_pkt
        except Exception:
            out = packet
    elif isinstance(packet, dict):
        new_pkt = {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
        if "IP" in new_pkt:
            new_pkt["IP"]["tos"] = _tos_with_ecn(int(new_pkt["IP"].get("tos", 0)), ECN_ECT_0)
        elif "ipv4" in new_pkt:
            old = int(new_pkt["ipv4"].get("diffserv", new_pkt["ipv4"].get("tos", 0)))
            new_tos = _tos_with_ecn(old, ECN_ECT_0)
            if "diffserv" in new_pkt["ipv4"]:
                new_pkt["ipv4"]["diffserv"] = new_tos
            else:
                new_pkt["ipv4"]["tos"] = new_tos
        out = new_pkt
    return StepResult(
        output_packets={egress_port: [out]},
        decision="unmark_and_forward",
        invariant_log=[("ipv4_checksum_validity_after_mark", "recomputed"),
                       ("dscp_preserved_under_mark", True),
                       ("ce_unmarked_to_ect0_under_relaxed", True)],
    )


def _drop(reason: str) -> StepResult:
    return StepResult(
        output_packets={},
        decision="drop",
        invariant_log=[("drop_reason", reason)],
    )


# ──────────────────────────────────────────────────────────────────────
# step() — canonical oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    """Single-packet step over the seven-rule P-ECNMarker dispatch table.

    All parameters are read from state["config"] at call time — the
    parametric-source contract.
    """
    config = state.get("config", {})

    access_port           = int(config.get("access_port", 1))
    core_port             = int(config.get("core_port", 2))
    marking_threshold_k   = int(config.get("marking_threshold_k", 64))
    marking_mode          = config.get("marking_mode", "single_threshold")
    not_ect_action        = config.get("not_ect_action", "drop")
    ce_persistence_strict = bool(config.get("ce_persistence_strict", True))
    non_ipv4_action       = config.get("non_ipv4_action", "drop")
    eligibility_protocol  = config.get("eligibility_protocol", "any_l4")
    queue_depth_signal    = config.get("queue_depth_signal", "synthetic_qdepth")
    # ── v1.1 multi-priority queue parameters (pattern augmentation) ──
    priority_queue_count  = int(config.get("priority_queue_count", 1))
    priority_classifier   = config.get("priority_classifier", "none")

    # ── R0: wrong-port drop ───────────────────────────────────────────────
    if ingress_port != access_port:
        return _drop("R0_wrong_port")

    # ── R1: non-IPv4 ──────────────────────────────────────────────────────
    if not _has_ipv4(packet):
        if non_ipv4_action == "passthrough":
            return _forward_unchanged(packet, core_port)
        return _drop("R1_non_ipv4")

    # ── R2: non-eligible-L4 (vacuous under any_l4) ─────────────────────────
    if not _has_eligible_l4(packet, eligibility_protocol):
        return _drop("R2_non_eligible_l4")

    # ── Read depth from the configured signal ─────────────────────────────
    # synthetic_qdepth: depth lives in hdr.ipv4.identification.
    # enq_qdepth / deq_qdepth: depth would come from state[config][queue_depth]
    # (the audit harness pre-populates it). Both paths are covered.
    if queue_depth_signal == "synthetic_qdepth":
        depth = _ipv4_id(packet)
    else:
        depth = int(config.get("queue_depth", 0))

    tos = _ipv4_tos(packet)
    ecn = _ecn_of_tos(tos)

    # ── v1.1 priority-class threshold resolution ─────────────────────────
    # Under priority_queue_count==1 (default), the class-aware code path is
    # a no-op: effective_min_th/effective_k collapse to the single-queue
    # values. Under priority_queue_count==2 with priority_classifier ==
    # 'dscp_high_bit', class is derived from the MSB of the DSCP field
    # (equivalently the MSB of the ToS byte, since ECN occupies the low
    # 2 bits and DSCP MSB is ToS bit 7).
    if priority_queue_count > 1 and priority_classifier == "dscp_high_bit":
        priority_class = 1 if (tos & 0x80) else 0
        if priority_class == 0:
            effective_min_th = int(config.get("class_0_min_threshold", 32))
            effective_k      = int(config.get("class_0_marking_threshold_k", 64))
        else:
            effective_min_th = int(config.get("class_1_min_threshold", 16))
            effective_k      = int(config.get("class_1_marking_threshold_k", 32))
    else:
        priority_class = 0
        effective_min_th = int(config.get("min_threshold", 32))
        effective_k      = marking_threshold_k

    above_threshold = depth >= effective_k

    # ── D5.3 collapse: tail_drop_no_mark ──────────────────────────────────
    if marking_mode == "tail_drop_passthrough":
        if above_threshold:
            return _drop("R3_R4_R5_tail_drop_above_threshold")
        return _forward_unchanged(packet, core_port)

    # ── D5.2 RED: probabilistic ramp (deterministic-with-floor at audit) ───
    # Under v1.1 multi-priority queues, the ramp uses effective_min_th and
    # effective_k (class-aware) so a class-1 packet sees the tighter
    # (16, 32) ramp by default while class-0 sees the (32, 64) ramp.
    if marking_mode == "red_proportional":
        p_max = float(config.get("marking_probability_max", 1.0))
        if depth >= effective_k:
            mark_p = p_max
        elif depth >= effective_min_th and effective_k > effective_min_th:
            mark_p = p_max * (depth - effective_min_th) / (effective_k - effective_min_th)
        else:
            mark_p = 0.0
        # Deterministic threshold per the audit harness convention: mark iff
        # rng_uniform_for(packet) < mark_p, with the per-packet rng value
        # supplied via state[config]["rng_value"] (audit) or via a
        # hash(packet) fallback. The task's seed never uses this.
        rng = float(config.get("rng_value", 0.0))
        above_threshold = (rng < mark_p)

    if not above_threshold:
        # ── R6: below-threshold passthrough; CE preserved by virtue of no rewrite
        return _forward_unchanged(packet, core_port)

    # depth >= threshold; dispatch on ECN field
    if ecn == ECN_NOT_ECT:
        # ── R3: Not-ECT on congestion ────────────────────────────────────
        if not_ect_action == "drop":
            return _drop("R3_not_ect_above_threshold")
        # passthrough (relaxed): forward unchanged
        return _forward_unchanged(packet, core_port)

    if ecn == ECN_ECT_0 or ecn == ECN_ECT_1:
        # ── R4: ECT → CE mark + IPv4 checksum recompute ─────────────────
        return _forward_marked(packet, core_port)

    if ecn == ECN_CE:
        # ── R5: above-threshold CE ───────────────────────────────────────
        # Strict (ce_persistence_strict == True): preserve the CE codepoint
        # verbatim (RFC 3168 §6.1.5). Relaxed (ce_persistence_strict == False):
        # unmark CE back to ECT(0) — the enable_ce_persistence_relaxed boundary.
        if ce_persistence_strict:
            return _forward_unchanged(packet, core_port)
        return _forward_unmarked(packet, core_port)

    # Defensive: a 2-bit field has no fifth value. Fall through is dead code.
    return _drop("R_internal_ecn_value_out_of_range")


def reset():
    """No persistent oracle state — the marker is stateless from the
    pattern's perspective; the bucket (queue depth) is read-only and
    supplied per-packet from packet.ipv4.id or state[config]['queue_depth']."""
    return None
