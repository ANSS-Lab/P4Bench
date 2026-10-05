"""Composed oracle for P-TelemetryRouter at the telemetry_router_disc seed.

P-TelemetryRouter = P-INTMetadata (per-hop INT metadata stamping) ∘
P-IPv4Routing (LPM + ECMP unicast forwarder). The composed step() FUSES the
two audited halves: it FIRST resolves the routing decision (RFC 1812 guard
ladder → LPM → ECMP next-hop pick, the P-IPv4Routing/98ffd4ff logic) and ONLY
THEN applies the INT role action (source push / sink strip-report, the
P-INTMetadata/1b2a4993 logic) using the FIB-resolved egress port. This
ordering IS the composition: the stamp READS the routing decision, the TTL
decrement and the source-push length growth fold into one IPv4-checksum
recompute, and a FIB-dropped packet is never stamped.

PARAMETRIC-SOURCE CONTRACT. Every mutable knob is read
from runtime `state` — never baked as a module-level constant. The seed's
values enter only at evaluation time via step(pkt, in_port, state). Keys:

  INT stage:  role, faithfulness, metadata_fields, max_hop_count, sample_rate,
              bit_width_timestamp, conditional_emit_predicate, report_threshold,
              report_port, switch_id, source_port_set, collector, switch_p9_ip
  FIB stage:  routes (list of {prefix, prefix_len, group:[{port, port_mac,
              nexthop_mac}]}), multipath_mode, hash_algo, martian_filter_enabled

Wire-format convention (TCP payload prefix; first byte 0x01 ⇒ INT present):
  int_shim (4 B): type=0x01, length, remaining_hop_count, instruction_bitmap
  int_slot (32 B): switch_id(4) ingress_ts(8, bit<48> low) egress_ts(8)
                   hop_latency(4) queue_depth(4)

Stateless: step() is a pure function of (packet, in_port, state).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


SLOT_BYTES = 28      # switch_id(4) + ingress_ts(8) + egress_ts(8) + hop_latency(4) + queue_depth(4)
SHIM_BYTES = 4
INT_MAGIC = 0x01


# ── address + hash helpers (from P-IPv4Routing/98ffd4ff) ────────────────────

def _ip2i(a: str) -> int:
    q = [int(x) for x in str(a).split(".")]
    return (q[0] << 24) | (q[1] << 16) | (q[2] << 8) | q[3]


def _lpm(dst: str, routes):
    d = _ip2i(dst)
    best, blen = None, -1
    for r in routes:
        plen = int(r["prefix_len"])
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        if (d & mask) == (_ip2i(r["prefix"]) & mask) and plen > blen:
            best, blen = r, plen
    return best


def _dir_bcast(dst: str, routes) -> bool:
    d = _ip2i(dst)
    for r in routes:
        plen = int(r["prefix_len"])
        if 0 < plen < 32:
            net = _ip2i(r["prefix"]) & (((1 << plen) - 1) << (32 - plen))
            if d == net | ((1 << (32 - plen)) - 1):
                return True
    return False


def _martian(src: str) -> bool:
    s = _ip2i(src)

    def inb(p, l):
        m = ((1 << l) - 1) << (32 - l) if l else 0
        return (s & m) == (_ip2i(p) & m)

    return inb("127.0.0.0", 8) or inb("0.0.0.0", 8) or inb("224.0.0.0", 4) or src == "255.255.255.255"


def _crc16_arc(data: bytes) -> int:
    """CRC-16/ARC (poly 0xA001 reflected) — BMv2 HashAlgorithm.crc16."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def _ecmp_index(src, dst, proto, sport, dport, k) -> int:
    blob = b"".join(x.to_bytes(4, "big") for x in (_ip2i(src), _ip2i(dst))) + \
        bytes([proto & 0xFF]) + int(sport).to_bytes(2, "big") + int(dport).to_bytes(2, "big")
    return _crc16_arc(blob) % k


# ── INT wire-format helpers (from P-INTMetadata/1b2a4993) ────────────────────

def _encode_shim(length, remaining_hop_count, instr_bitmap) -> bytes:
    return bytes([INT_MAGIC, length & 0xFF, remaining_hop_count & 0xFF, instr_bitmap & 0xFF])


def _encode_slot(switch_id, ingress_ts, egress_ts, hop_latency, queue_depth) -> bytes:
    return (switch_id.to_bytes(4, "big") + ingress_ts.to_bytes(8, "big")
            + egress_ts.to_bytes(8, "big") + hop_latency.to_bytes(4, "big")
            + queue_depth.to_bytes(4, "big"))


def _parse_shim(payload: bytes):
    if len(payload) < SHIM_BYTES or payload[0] != INT_MAGIC:
        return None
    return {"type": payload[0], "length": payload[1],
            "remaining_hop_count": payload[2], "instruction_bitmap": payload[3]}


def _parse_slots(payload: bytes, n: int):
    slots, off = [], SHIM_BYTES
    for _ in range(n):
        chunk = payload[off:off + SLOT_BYTES]
        if len(chunk) < SLOT_BYTES:
            break
        slots.append({"switch_id": int.from_bytes(chunk[0:4], "big"),
                      "ingress_ts": int.from_bytes(chunk[4:12], "big"),
                      "egress_ts": int.from_bytes(chunk[12:20], "big"),
                      "hop_latency": int.from_bytes(chunk[20:24], "big"),
                      "queue_depth": int.from_bytes(chunk[24:28], "big")})
        off += SLOT_BYTES
    return slots, off


def _bitmap_of(metadata_fields):
    canonical = ["switch_id", "ingress_ts", "egress_ts", "hop_latency", "queue_depth",
                 "queue_id", "egress_tx_util", "ingress_port", "egress_port"]
    bitmap = 0
    for f in metadata_fields:
        if f in canonical:
            bitmap |= (1 << canonical.index(f))
    return bitmap


# ── StepResult (P-INTMetadata shape + ECMP routing facets) ───────────────────

@dataclass
class StepResult:
    admitted: bool
    reason: str
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None
    next_hop_mac_src: Optional[str] = None
    ttl_decrement: int = 0
    new_payload_bytes: Optional[bytes] = None
    # Second output (sink telemetry report) on report_port, if emitted.
    extra_emit_port: Optional[int] = None
    extra_emit_payload: Optional[bytes] = None
    extra_emit_dst_ip: Optional[str] = None
    extra_emit_dst_mac: Optional[str] = None
    extra_emit_src_ip: Optional[str] = None
    extra_emit_src_mac: Optional[str] = None
    # ECMP facets — group port set + chosen index (for behavioural tests).
    ecmp: bool = False
    group_ports: List[int] = field(default_factory=list)
    chosen_index: int = 0
    invariant_log: list = field(default_factory=list)


def _ip_field(scapy_pkt, name, default=None):
    from scapy.all import IP
    if IP in scapy_pkt:
        v = getattr(scapy_pkt[IP], name, default)
        return v if v is not None else default
    return default


# ── step() ───────────────────────────────────────────────────────────────────

def step(scapy_pkt, in_port: int, state: dict) -> StepResult:
    from scapy.all import IP, TCP

    routes = state["routes"]
    multipath_mode = state.get("multipath_mode", "none")
    role = state["role"]
    bit_width_ts = int(state["bit_width_timestamp"])
    metadata_fields = state["metadata_fields"]
    max_hop = int(state["max_hop_count"])
    sample_rate = int(state.get("sample_rate", 1))
    predicate = state["conditional_emit_predicate"]
    threshold = int(state["report_threshold"])
    report_port = int(state["report_port"])
    switch_id = int(state["switch_id"])
    source_port_set = set(int(p) for p in state["source_port_set"])
    collector = state.get("collector", {})

    # ── Routing stage FIRST (RFC 1812 guard ladder) ─────────────────────────
    if IP not in scapy_pkt:
        return StepResult(False, "R0_non_ipv4_drop",
                          invariant_log=[("non_routed_not_stamped", {"branch": "non_ipv4"})])

    ip = scapy_pkt[IP]
    if int(getattr(ip, "version", 4)) != 4 or int(getattr(ip, "ihl", 5) or 5) < 5:
        return StepResult(False, "R1_invalid_header_drop")

    ttl = int(getattr(ip, "ttl", 0))
    src = str(ip.src)
    dst = str(ip.dst)

    if ttl <= 1:                                  # R2: ttl≤1 → drop (forwarding ttl-1 would be 0)
        return StepResult(False, "R2_ttl_exhausted_drop",
                          invariant_log=[("non_routed_not_stamped", {"branch": "ttl_exhausted"})])
    if dst == "255.255.255.255":                  # R3 limited broadcast
        return StepResult(False, "R3_limited_broadcast_drop",
                          invariant_log=[("non_routed_not_stamped", {"branch": "limited_broadcast"})])
    if state.get("martian_filter_enabled") and _martian(src):   # R4 (guard-gated)
        return StepResult(False, "R4_martian_src_drop",
                          invariant_log=[("non_routed_not_stamped", {"branch": "martian"})])
    if _dir_bcast(dst, routes):                   # R6 directed broadcast
        return StepResult(False, "R6_directed_broadcast_drop")

    route = _lpm(dst, routes)                      # R5 no-route → drop
    if route is None:
        return StepResult(False, "R5_no_route_drop",
                          invariant_log=[("non_routed_not_stamped", {"branch": "no_route"})])

    # ── ECMP next-hop selection (post-LPM) ──────────────────────────────────
    group = route["group"]
    if multipath_mode == "none" or len(group) == 1:
        i = 0
    else:
        sport = int(getattr(scapy_pkt[TCP], "sport", 0)) if TCP in scapy_pkt else 0
        dport = int(getattr(scapy_pkt[TCP], "dport", 0)) if TCP in scapy_pkt else 0
        proto = int(getattr(ip, "proto", 6))
        i = _ecmp_index(src, dst, proto, sport, dport, len(group))
    nh = group[i]
    ep = int(nh["port"])
    mac_src = nh["port_mac"]
    mac_dst = nh["nexthop_mac"]
    group_ports = [int(g["port"]) for g in group]
    is_ecmp = (multipath_mode != "none" and len(group) > 1)

    def _routed(reason, new_payload=None, extra=False, slots_payload=None, slots_off=0):
        r = StepResult(
            True, reason, output_port=ep, next_hop_mac_dst=mac_dst,
            next_hop_mac_src=mac_src, ttl_decrement=1, new_payload_bytes=new_payload,
            ecmp=is_ecmp, group_ports=group_ports, chosen_index=i,
            invariant_log=[("stamp_reflects_routing_decision", {"egress_port": ep}),
                           ("ttl_decrement_once_across_stages", {"delta": 1}),
                           ("lpm_longest_match_correctness",
                            {"prefix": f"{route['prefix']}/{route['prefix_len']}"})],
        )
        if extra:
            r.extra_emit_port = report_port
            r.extra_emit_payload = slots_payload[:slots_off]
            r.extra_emit_dst_ip = collector.get("ip")
            r.extra_emit_dst_mac = collector.get("mac")
            r.extra_emit_src_ip = state.get("switch_p9_ip", "10.0.9.1")
            r.extra_emit_src_mac = mac_src
            r.invariant_log.append(("sink_strips_then_routes", {"report_port": report_port}))
        return r

    # ── INT role action SECOND, using the resolved egress ────────────────────
    raw = scapy_pkt[TCP].payload if TCP in scapy_pkt else None
    payload_bytes = bytes(raw) if raw else b""
    shim_present = len(payload_bytes) >= SHIM_BYTES and payload_bytes[0] == INT_MAGIC
    is_source_port = in_port in source_port_set
    is_sink_port = (not is_source_port) and (in_port != report_port)

    # Non-TCP IPv4 → route, no INT inspection.
    if TCP not in scapy_pkt:
        return _routed("admit_non_tcp_route")

    # Source push: plain TCP on a source port.
    if role in ("source", "source_and_sink", "multi") and is_source_port and not shim_present:
        if sample_rate > 1:
            h = _ecmp_index(src, dst, int(getattr(ip, "proto", 6)),
                            int(getattr(scapy_pkt[TCP], "sport", 0)),
                            int(getattr(scapy_pkt[TCP], "dport", 0)), sample_rate)
            if h != 0:                              # R8 sample-skip: route, NO shim added
                return _routed("admit_source_sample_skip")
        ingress_ts = int(state.get("synthetic_ingress_ts", 100_000_000))
        hop_latency = int(state.get("synthetic_hop_latency", 50_000))
        egress_ts = ingress_ts + hop_latency
        queue_depth = int(state.get("synthetic_queue_depth", 0))
        if bit_width_ts == 32:
            ingress_ts &= 0xFFFFFFFF
            egress_ts &= 0xFFFFFFFF
        shim = _encode_shim(1, max_hop - 1, _bitmap_of(metadata_fields))
        slot = _encode_slot(switch_id, ingress_ts, egress_ts, hop_latency, queue_depth)
        return _routed("admit_source_push_and_route", new_payload=shim + slot + payload_bytes)

    # Sink: INT-bearing TCP on a sink (upstream) port.
    if role in ("sink", "source_and_sink", "multi") and is_sink_port and shim_present:
        shim = _parse_shim(payload_bytes)
        if shim is None:
            return StepResult(False, "drop_malformed_shim")
        slots, off = _parse_slots(payload_bytes, shim["length"])
        if len(slots) != shim["length"]:
            return StepResult(False, "drop_truncated_stack")
        if predicate == "always":
            fires = True
        elif predicate == "hop_latency_exceeds_threshold":
            fires = max((s["hop_latency"] for s in slots), default=0) > threshold
        elif predicate == "queue_depth_exceeds_threshold":
            fires = max((s["queue_depth"] for s in slots), default=0) > threshold
        else:
            fires = False
        stripped = payload_bytes[off:]
        return _routed("admit_sink_strip_with_report" if fires else "admit_sink_strip_only",
                       new_payload=stripped, extra=fires,
                       slots_payload=payload_bytes, slots_off=off)

    # Sink with no shim → route unchanged.
    if role in ("sink", "source_and_sink", "multi") and is_sink_port and not shim_present:
        return _routed("admit_sink_no_shim_passthrough")

    # Source port already carrying a shim → route, no re-stamp.
    if is_source_port and shim_present:
        return _routed("admit_source_existing_shim_passthrough")

    return _routed("admit_route_fallthrough")


def reset():
    """No-op: the composition is per-packet stateless."""
    return
