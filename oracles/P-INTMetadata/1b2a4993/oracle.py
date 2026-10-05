"""Pure-Python oracle for P-INTMetadata at the int_metadata_threshold_report seed.

Implements the source+sink single-switch INT-MD pipeline with a threshold-
gated telemetry report. Used at test-generation time
and at audit time to derive expected per-test outputs.

PARAMETRIC-SOURCE CONTRACT.

Every mutable knob is read from runtime `state` — never baked as a
module-level constant. The seed's values enter the module only at
evaluation time, via `step(pkt, ingress_port, state)`. Keys consumed:

  role                       : 'source_and_sink' (this seed) | 'source' | 'sink' | 'transit' | 'multi'
  faithfulness               : 'D5.0_int_md' (this seed) | 'D5.1_int_mx' | 'D5.2_pint_probabilistic'
  metadata_fields            : list[str] — ordered subset of the field-set enum
  max_hop_count              : int (seeds the remaining_hop_count on source push)
  sample_rate                : int (1 = every packet, > 1 = hash-mod sampling)
  bit_width_timestamp        : 32 | 48
  conditional_emit_predicate : 'always' | 'hop_latency_exceeds_threshold'
                             | 'queue_depth_exceeds_threshold' | 'none'
  report_threshold           : int (units depend on the predicate)
  report_port                : int (egress port for telemetry reports)
  switch_id                  : int (this switch's identifier, stamped by source)
  source_port_set            : list[int] (ingress ports that play the source role)
  port_decoder               : list[{cidr, egress_port, host_mac}] — LPM table
  port_macs                  : dict[int → mac] — per-egress switch-side MAC
  collector                  : {ip, mac, port} — telemetry-report destination

Stateless: step() is a pure function of (packet, in_port, state).

Wire-format convention (matches the seed's documentation):

  An INT-bearing packet has its TCP payload prefixed by a 4-byte
  int_shim followed by `length × 32` bytes of int_slot data:
    int_shim (4 B big-endian):
      type=0x01, length, remaining_hop_count, instruction_bitmap
    int_slot (32 B per slot, big-endian):
      switch_id   (4 B uint32)
      ingress_ts  (8 B  — bit<48> value in the low 48 bits)
      egress_ts   (8 B  — bit<48> value in the low 48 bits)
      hop_latency (4 B uint32)
      queue_depth (4 B uint32)

  Detection: the TCP payload's FIRST byte == 0x01.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


SLOT_BYTES = 28  # 4(switch_id)+8(ingress_ts)+8(egress_ts)+4(hop_latency)+4(queue_depth) — matches _encode_slot
SHIM_BYTES = 4
INT_MAGIC = 0x01


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _ipv4_in_cidr(addr: str, cidr: str) -> bool:
    net, plen = cidr.split("/")
    plen = int(plen)
    mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
    return (_ip_to_int(addr) & mask) == (_ip_to_int(net) & mask)


def _port_decoder_lookup(dst_ip: str, port_decoder):
    """LPM lookup. Returns (egress_port, host_mac) or None."""
    best = None
    best_plen = -1
    for entry in port_decoder:
        plen = int(entry["cidr"].split("/")[1])
        if _ipv4_in_cidr(dst_ip, entry["cidr"]) and plen > best_plen:
            best = entry
            best_plen = plen
    if best is None:
        return None
    return best["egress_port"], best["host_mac"]


def _encode_shim(length: int, remaining_hop_count: int, instr_bitmap: int) -> bytes:
    return bytes([INT_MAGIC, length & 0xFF, remaining_hop_count & 0xFF, instr_bitmap & 0xFF])


def _encode_slot(switch_id: int, ingress_ts: int, egress_ts: int,
                 hop_latency: int, queue_depth: int) -> bytes:
    # Each timestamp is bit<48>; encode in 8 bytes big-endian with low-48 carrying the value.
    return (
        switch_id.to_bytes(4, "big")
        + ingress_ts.to_bytes(8, "big")
        + egress_ts.to_bytes(8, "big")
        + hop_latency.to_bytes(4, "big")
        + queue_depth.to_bytes(4, "big")
    )


def _parse_shim(payload: bytes):
    if len(payload) < SHIM_BYTES or payload[0] != INT_MAGIC:
        return None
    return {
        "type": payload[0],
        "length": payload[1],
        "remaining_hop_count": payload[2],
        "instruction_bitmap": payload[3],
    }


def _parse_slots(payload: bytes, n: int):
    slots = []
    off = SHIM_BYTES
    for _ in range(n):
        chunk = payload[off:off + SLOT_BYTES]
        if len(chunk) < SLOT_BYTES:
            break
        slots.append({
            "switch_id":   int.from_bytes(chunk[0:4], "big"),
            "ingress_ts":  int.from_bytes(chunk[4:12], "big"),
            "egress_ts":   int.from_bytes(chunk[12:20], "big"),
            "hop_latency": int.from_bytes(chunk[20:24], "big"),
            "queue_depth": int.from_bytes(chunk[24:28], "big"),
        })
        off += SLOT_BYTES
    return slots, off


def _bitmap_of(metadata_fields):
    # Bits 0..4 for [switch_id, ingress_ts, egress_ts, hop_latency, queue_depth].
    canonical = ["switch_id", "ingress_ts", "egress_ts", "hop_latency", "queue_depth",
                 "queue_id", "egress_tx_util", "ingress_port", "egress_port"]
    bitmap = 0
    for f in metadata_fields:
        if f in canonical:
            bitmap |= (1 << canonical.index(f))
    return bitmap


# ────────────────────────────────────────────────────────────────────────────
# Step result
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    reason: str
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None
    next_hop_mac_src: Optional[str] = None
    ttl_decrement: int = 0
    # The new payload bytes (after R2 push or R3-R7 strip). None means
    # "payload unchanged from input".
    new_payload_bytes: Optional[bytes] = None
    # If non-None, the data plane ALSO emits a separate telemetry-report
    # packet on `extra_emit_port` with `extra_emit_payload` bytes as the
    # UDP payload (dport=4096, sport=0). The harness materialises this
    # as one of the test_case's expected outputs.
    extra_emit_port: Optional[int] = None
    extra_emit_payload: Optional[bytes] = None
    extra_emit_dst_ip: Optional[str] = None
    extra_emit_dst_mac: Optional[str] = None
    extra_emit_src_ip: Optional[str] = None
    extra_emit_src_mac: Optional[str] = None
    invariant_log: list = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Step function
# ────────────────────────────────────────────────────────────────────────────

def step(scapy_pkt, in_port: int, state: dict) -> StepResult:
    """Execute one packet step under the P-INTMetadata rules at this seed."""
    from scapy.all import IP, TCP, UDP, Raw

    port_decoder = state["port_decoder"]
    port_macs = state["port_macs"]
    source_port_set = set(int(p) for p in state["source_port_set"])
    role = state["role"]
    bit_width_ts = int(state["bit_width_timestamp"])
    metadata_fields = state["metadata_fields"]
    max_hop = int(state["max_hop_count"])
    sample_rate = int(state.get("sample_rate", 1))
    predicate = state["conditional_emit_predicate"]
    threshold = int(state["report_threshold"])
    report_port = int(state["report_port"])
    switch_id = int(state["switch_id"])
    collector = state.get("collector", {})

    # ── R8: non-IPv4 — passthrough via port-decoder via dst MAC ────────────
    if IP not in scapy_pkt:
        # No IPv4 to inspect; for harness simplicity, drop. (Real switch
        # would consult an L2 table; the seed's port-decoder is L3-only.)
        return StepResult(False, "drop_non_ipv4",
                          invariant_log=[("payload_preservation", {"branch": "non_ipv4_drop"})])

    ip = scapy_pkt[IP]

    # ── R9: non-TCP IPv4 — port-decoder forward, no INT inspection ─────────
    if TCP not in scapy_pkt:
        found = _port_decoder_lookup(ip.dst, port_decoder)
        if found is None:
            return StepResult(False, "drop_no_port_decoder_match")
        ep, host_mac = found
        return StepResult(
            True, "admit_non_tcp_passthrough",
            output_port=ep,
            next_hop_mac_dst=host_mac,
            next_hop_mac_src=port_macs.get(ep),
            ttl_decrement=1,
        )

    # ── Inspect TCP payload for the INT shim magic ──────────────────────────
    raw_layer = scapy_pkt[TCP].payload
    payload_bytes = bytes(raw_layer) if raw_layer else b""
    shim_present = len(payload_bytes) >= SHIM_BYTES and payload_bytes[0] == INT_MAGIC

    is_source_port = in_port in source_port_set
    is_sink_port = (in_port not in source_port_set) and (in_port != report_port)

    # ── R2 + R3 source path: stamp on non-INT TCP on source ports ──────────
    if role in ("source", "source_and_sink", "multi") and is_source_port and not shim_present:
        # Sampling: every Nth packet is stamped; the rest pass through unchanged.
        if sample_rate > 1:
            # Deterministic sample: hash on (src_ip, dst_ip, sport, dport).
            h = hash((ip.src, ip.dst, int(scapy_pkt[TCP].sport),
                      int(scapy_pkt[TCP].dport))) % sample_rate
            if h != 0:
                # Skip stamping; forward unchanged (R1 in the pattern).
                found = _port_decoder_lookup(ip.dst, port_decoder)
                if found is None:
                    return StepResult(False, "drop_no_port_decoder_match")
                ep, host_mac = found
                return StepResult(
                    True, "admit_source_sample_skip",
                    output_port=ep,
                    next_hop_mac_dst=host_mac,
                    next_hop_mac_src=port_macs.get(ep),
                    ttl_decrement=1,
                    invariant_log=[("sink_strips_shim", {"branch": "source_sample_skip_no_shim_added"})],
                )

        # Construct the metadata slot. Timestamps are synthesised
        # deterministically from the input so the harness can drive
        # the threshold case in the sink direction by controlling
        # the hop_latency seed. The harness's convention:
        #   ingress_ts = state.get("synthetic_ingress_ts", 100_000_000)
        #   egress_ts  = ingress_ts + state.get("synthetic_hop_latency", 50_000)
        ingress_ts = int(state.get("synthetic_ingress_ts", 100_000_000))
        hop_latency = int(state.get("synthetic_hop_latency", 50_000))
        egress_ts = ingress_ts + hop_latency
        queue_depth = int(state.get("synthetic_queue_depth", 0))

        # Bit-width fidelity: if a P4 implementation would truncate, this is where
        # it would silently drop the upper 16 bits. The oracle stamps the
        # full 48-bit value when bit_width_timestamp==48.
        if bit_width_ts == 32:
            ingress_ts = ingress_ts & 0xFFFFFFFF
            egress_ts = egress_ts & 0xFFFFFFFF

        shim = _encode_shim(
            length=1,
            remaining_hop_count=max_hop - 1,
            instr_bitmap=_bitmap_of(metadata_fields),
        )
        slot = _encode_slot(switch_id, ingress_ts, egress_ts, hop_latency, queue_depth)
        new_payload = shim + slot + payload_bytes

        found = _port_decoder_lookup(ip.dst, port_decoder)
        if found is None:
            return StepResult(False, "drop_no_port_decoder_match")
        ep, host_mac = found
        return StepResult(
            True, "admit_source_push",
            output_port=ep,
            next_hop_mac_dst=host_mac,
            next_hop_mac_src=port_macs.get(ep),
            ttl_decrement=1,
            new_payload_bytes=new_payload,
            invariant_log=[
                ("payload_preservation", {"branch": "source_push_prefix_added"}),
                ("hop_count_monotone",   {"remaining_hop_count": max_hop - 1}),
                ("stack_length_matches_metadata_emits", {"length": 1}),
                ("timestamp_bit_width_fidelity", {"bit_width": bit_width_ts}),
            ],
        )

    # ── R3 sink path: shim-present on a sink-role port ──────────────────────
    if role in ("sink", "source_and_sink", "multi") and is_sink_port and shim_present:
        shim = _parse_shim(payload_bytes)
        if shim is None:
            return StepResult(False, "drop_malformed_shim")
        slots, off = _parse_slots(payload_bytes, shim["length"])
        if len(slots) != shim["length"]:
            return StepResult(False, "drop_truncated_stack")

        # Compute the predicate
        if predicate == "always":
            predicate_fires = True
        elif predicate == "hop_latency_exceeds_threshold":
            max_hl = max((s["hop_latency"] for s in slots), default=0)
            predicate_fires = max_hl > threshold
        elif predicate == "queue_depth_exceeds_threshold":
            max_qd = max((s["queue_depth"] for s in slots), default=0)
            predicate_fires = max_qd > threshold
        elif predicate == "none":
            predicate_fires = False
        else:
            predicate_fires = False

        # Strip the shim+stack
        stripped = payload_bytes[off:]

        # Port-decoder lookup for the stripped packet
        found = _port_decoder_lookup(ip.dst, port_decoder)
        if found is None:
            return StepResult(False, "drop_no_port_decoder_match_after_strip")
        ep, host_mac = found

        result = StepResult(
            True, "admit_sink_strip_with_report" if predicate_fires else "admit_sink_strip_only",
            output_port=ep,
            next_hop_mac_dst=host_mac,
            next_hop_mac_src=port_macs.get(ep),
            ttl_decrement=1,
            new_payload_bytes=stripped,
            invariant_log=[
                ("sink_strips_shim", {"is_valid": False}),
                ("payload_preservation", {"branch": "sink_strip"}),
            ],
        )
        if predicate_fires:
            # Telemetry report payload = the harvested int_shim + slots.
            result.extra_emit_port = report_port
            result.extra_emit_payload = payload_bytes[:off]
            result.extra_emit_dst_ip = collector.get("ip")
            result.extra_emit_dst_mac = collector.get("mac")
            result.extra_emit_src_ip = state.get("switch_p9_ip", "10.0.9.1")
            result.extra_emit_src_mac = port_macs.get(report_port)
        return result

    # ── R3 sink-with-no-shim — passthrough ──────────────────────────────────
    if role in ("sink", "source_and_sink", "multi") and is_sink_port and not shim_present:
        found = _port_decoder_lookup(ip.dst, port_decoder)
        if found is None:
            return StepResult(False, "drop_no_port_decoder_match")
        ep, host_mac = found
        return StepResult(
            True, "admit_sink_no_shim_passthrough",
            output_port=ep,
            next_hop_mac_dst=host_mac,
            next_hop_mac_src=port_macs.get(ep),
            ttl_decrement=1,
            invariant_log=[("sink_strips_shim", {"branch": "no_shim_no_strip"})],
        )

    # ── Source port + shim already present: malformed-stamp passthrough ────
    if is_source_port and shim_present:
        found = _port_decoder_lookup(ip.dst, port_decoder)
        if found is None:
            return StepResult(False, "drop_no_port_decoder_match")
        ep, host_mac = found
        return StepResult(
            True, "admit_source_with_existing_shim_passthrough",
            output_port=ep,
            next_hop_mac_dst=host_mac,
            next_hop_mac_src=port_macs.get(ep),
            ttl_decrement=1,
            invariant_log=[("payload_preservation", {"branch": "double_stamp_forbidden_pass"})],
        )

    # Catch-all — should not be reached for the documented input space.
    return StepResult(False, "drop_unmatched_rule")


def reset():
    """No-op: the pattern is stateless."""
    return
