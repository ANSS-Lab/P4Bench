"""Per-task oracle for benchmark/scale_up/retransmit_detect_anchor
(P-RetransmitDetect).

Implements the per-flow TCP retransmission / loss-detection rule sequence
under the canonical seed:

  flow_capacity = unbounded (exact per-flow map)
  seq_faithfulness = D8.0_byte_range
  observable_surface = mark_count_mirror
  count_strictness = false

Rule sequence (first-match, declaration order):

  - R0  non-TCP/IPv4 forward unchanged (transport-assistance, not a filter)
  - R1  TCP control / pure-ACK segment (payload_len == 0) forward unchanged;
        the high-water mark is untouched
  - R2  first data segment of a previously-unseen flow → init the per-flow
        high-water mark to (seq + payload_len) mod 2^32, forward, NOT flagged
  - R3  data segment whose covered byte range is already covered by the flow's
        forwarded byte stream ((seq + len) mod 2^32 ≤ stored mark, mod 2^32
        wrap-tolerant) → RETRANSMISSION: set the detected-marker bit, increment
        the per-flow retransmit counter, mirror a copy to the collector port,
        and STILL forward the data segment. The mark is NOT advanced.
  - R4  data segment whose far edge (seq + len) advances past the mark → update
        the mark to (seq + len) mod 2^32, forward, NOT flagged.

Detection is purely sequence-comparison driven by RECEIVED packets — there is
NO RTO timer and NO time_tick (the harness injects only packets). A segment is a
retransmit the instant its covered range is ≤ the stored high-water mark.

Observable surface (the v1.0 packet-only harness reads these from egress
pcaps):
  - the detected-marker bit, written into the IPv4 DSCP low bit (IP.tos value
    `DSCP_MARK` on a flagged segment; left 0 otherwise);
  - the mirrored copy delivered to `collector_port` in addition to the normal
    forwarded copy on `forward_port` (mark_count_mirror);
  - the per-flow retransmit counter's EFFECT is exposed through the marker /
    mirror firing on exactly the detected segments (the counter value itself is
    internal register state — the verifier reads its effect, not its value).

PARAMETRIC-SOURCE CONTRACT: every mutable knob
(forward_port, collector_port, detect_marker_field, flow_capacity, eviction,
seq_faithfulness, hash_algo, observable_surface, count_strictness) is a
constructor argument with a seed-bound default. step() reads no module-level
mutable constant; the per-flow seq map + retransmit buckets live on the
instance and are cleared by reset(), so a prior_inputs sequence accumulates.
Two siblings of P-RetransmitDetect with different seed values share this
byte-identical oracle source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Protocol / header constants (NOT mutation knobs — locked by the pattern).
ETHERTYPE_IPV4 = 0x0800
IP_PROTO_TCP = 6
U32 = 0xFFFFFFFF

# The DSCP low-bit marker value written into IPv4 TOS on a detected
# retransmission. DSCP occupies the top 6 bits of the 8-bit TOS byte; setting
# the DSCP low bit (bit 2 of the byte, value 0x04) leaves the ECN field (bits
# 0-1) untouched. This is a header *constant*, not a per-seed mutation knob:
# detect_marker_field selects WHICH field; the bit value is fixed.
DSCP_MARK = 0x04


@dataclass
class StepResult:
    # `admitted`/`decision`/`output_port` are the audit-compared attributes
    # (the oracle audit's comparison). For this NF every TCP/IPv4
    # data segment is forwarded; `output_port` is the primary forward port.
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    # Detection signal + observable channel.
    detected: bool = False
    mark: Optional[int] = None              # the high-water mark AFTER this step
    retransmit_cnt: Optional[int] = None    # per-flow counter AFTER this step
    mirror_port: Optional[int] = None       # collector port on a mirrored copy
    tos_out: Optional[int] = None           # egress IPv4 TOS (marker channel)
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


def _seq_leq_mod32(a: int, b: int) -> bool:
    """True iff a <= b in modulo-2^32 sequence space (RFC 1982 / RFC 9293 §3.4).

    Uses signed-difference wrap comparison: a is at-or-behind b when
    (b - a) mod 2^32 lies in [0, 2^31).
    """
    return ((b - a) & U32) < 0x80000000


def _seq_lt_mod32(a: int, b: int) -> bool:
    """True iff a < b in modulo-2^32 sequence space."""
    return a != b and _seq_leq_mod32(a, b)


@dataclass
class RetransmitDetectSimulator:
    # ── parametric-source knobs (seed-bound; never module constants) ────────
    forward_port: int = 2
    collector_port: int = 3
    detect_marker_field: str = "ipv4_dscp_bit"
    flow_capacity: Any = "unbounded"        # "unbounded" or int (hashed cells)
    eviction: str = "none"
    seq_faithfulness: str = "D8.0_byte_range"
    hash_algo: str = "crc32"                # dormant when flow_capacity unbounded
    observable_surface: str = "mark_count_mirror"
    count_strictness: bool = False

    # ── per-flow state (accumulates across step(); cleared by reset()) ──────
    _seq_highwater: Dict[Any, int] = field(default_factory=dict)
    _retransmit_cnt: Dict[Any, int] = field(default_factory=dict)

    def reset(self) -> None:
        self._seq_highwater = {}
        self._retransmit_cnt = {}

    # ── helpers ─────────────────────────────────────────────────────────────

    def _flow_key(self, ip, tcp) -> Any:
        """The 5-tuple flow key, or a hashed-cell index when capacity is finite.

        At the canonical band (flow_capacity == unbounded) this is an exact
        per-flow map. A finite capacity buckets distinct flows into
        ${flow_capacity} cells where collisions alias flows (the LossRadar
        approximate regime); modelled with Python's hash mod capacity so the
        oracle reproduces collision-induced misclassification.
        """
        tup = (ip.src, ip.dst, IP_PROTO_TCP, int(tcp.sport), int(tcp.dport))
        if self.flow_capacity == "unbounded" or self.flow_capacity is None:
            return tup
        cap = int(self.flow_capacity)
        return hash(tup) % cap

    @staticmethod
    def _tcp_payload_len(scapy_pkt, ip, tcp) -> int:
        """TCP payload byte count = ip.totalLen - ihl*4 - dataOffset*4.

        This is exactly how a v1model P4 program derives the data length from the
        header fields, so the oracle and a faithful P4 program agree byte for
        byte. We prefer the header-arithmetic form (driven by IP.len) and fall
        back to the on-wire payload byte count when IP.len is unset.
        """
        from scapy.all import IP as _IP, TCP as _TCP

        # Header-derived length (the faithful P4 computation): IP.len is the
        # IPv4 total length; ihl/dataofs are word counts (×4 bytes).
        try:
            total_len = int(getattr(ip, "len", 0) or 0)
            ihl = int(getattr(ip, "ihl", 5) or 5)
            dataofs = int(getattr(tcp, "dataofs", 5) or 5)
            if total_len > 0:
                derived = total_len - ihl * 4 - dataofs * 4
                if derived >= 0:
                    return derived
        except Exception:
            pass

        # Fall back to the on-wire payload byte count.
        try:
            return len(bytes(tcp.payload))
        except Exception:
            return 0

    def _forward_only(self, decision: str, reason: str) -> StepResult:
        return StepResult(
            admitted=True, decision=decision, output_port=self.forward_port,
            detected=False, tos_out=0,
            invariant_log=[(reason, {"port": self.forward_port})],
        )

    # ── step() — one packet under the rule sequence ─────────────────────────

    def step(self, scapy_pkt, in_port: int = 1) -> StepResult:
        from scapy.all import IP, TCP

        # R0 — non-TCP/IPv4 forwarded unchanged (transport-assistance).
        if IP not in scapy_pkt or scapy_pkt[IP].proto != IP_PROTO_TCP or TCP not in scapy_pkt:
            return StepResult(
                admitted=True, decision="forward_non_tcp",
                output_port=self.forward_port, detected=False, tos_out=0,
                invariant_log=[("R0_non_tcp_forward", {"port": self.forward_port})],
            )

        ip = scapy_pkt[IP]
        tcp = scapy_pkt[TCP]
        payload_len = self._tcp_payload_len(scapy_pkt, ip, tcp)

        # R1 — control / pure-ACK segment (no data bytes): forward, mark intact.
        if payload_len == 0:
            return self._forward_only("forward_control", "R1_non_data_segment_forward")

        key = self._flow_key(ip, tcp)
        seq = int(tcp.seq) & U32
        far = (seq + payload_len) & U32

        # R2 — first data segment of an unseen flow: init the mark, forward.
        if key not in self._seq_highwater:
            self._seq_highwater[key] = far
            self._retransmit_cnt[key] = 0
            return StepResult(
                admitted=True, decision="forward_new", output_port=self.forward_port,
                detected=False, mark=far, retransmit_cnt=0, tos_out=0,
                invariant_log=[("R2_first_segment_init",
                                {"port": self.forward_port, "mark": far})],
            )

        mark = self._seq_highwater[key]

        # Retransmission test (seq_faithfulness ladder).
        if self.seq_faithfulness == "D8.1_bare_seq":
            is_retransmit = _seq_lt_mod32(seq, mark)
        else:  # D8.0_byte_range (canonical)
            is_retransmit = _seq_leq_mod32(far, mark)

        if is_retransmit:
            # R3 — retransmission detected. Set the marker bit, (optionally)
            # increment the per-flow counter, (optionally) mirror to the
            # collector, and STILL forward. The mark is NOT advanced.
            ilog: List[Tuple[str, Any]] = [
                ("R3_retransmission_detected",
                 {"port": self.forward_port, "mark": mark, "far": far}),
                ("retransmit_flag_correctness", {"detected": True}),
                ("highwater_monotone", {"mark_unchanged": mark}),
                ("data_path_preserved", {"forwarded": True}),
            ]
            res = StepResult(
                admitted=True, decision="forward_retransmit",
                output_port=self.forward_port, detected=True, mark=mark,
                tos_out=DSCP_MARK,
                invariant_log=ilog,
            )
            if self.observable_surface in ("mark_and_count", "mark_count_mirror"):
                self._retransmit_cnt[key] = self._retransmit_cnt.get(key, 0) + 1
                res.retransmit_cnt = self._retransmit_cnt[key]
                ilog.append(("retransmit_count_exact",
                             {"cnt": self._retransmit_cnt[key]}))
            if self.observable_surface == "mark_count_mirror":
                res.mirror_port = self.collector_port
                ilog.append(("mirror_no_orphan", {"collector": self.collector_port}))
            return res

        # R4 — in-order / gap-filling advance: raise the mark, forward, no flag.
        self._seq_highwater[key] = far
        return StepResult(
            admitted=True, decision="forward_advance", output_port=self.forward_port,
            detected=False, mark=far, retransmit_cnt=self._retransmit_cnt.get(key, 0),
            tos_out=0,
            invariant_log=[("R4_in_order_advance",
                            {"port": self.forward_port, "mark": far}),
                           ("highwater_monotone", {"mark": far})],
        )


# ── parametric module-level step (parametric-source contract) ──
# The canonical step entrypoint. When `state` carries a `config` dict the
# singleton simulator is (re)built from it so a parameter rebind reconfigures the SAME
# audited module at runtime; otherwise the seed-bound default instance is used.
# A knob absent from config falls back to its constructor (seed) default. This
# top-level `step` is preferred by the oracle loader over the bound class method,
# giving the arity-3 config-capable interface the parametric-source audit
# requires.
_CONFIG_KNOBS = (
    "forward_port", "collector_port", "detect_marker_field", "flow_capacity",
    "eviction", "seq_faithfulness", "hash_algo", "observable_surface",
    "count_strictness",
)


def _sim_from_config(config):
    kwargs = {}
    for knob in _CONFIG_KNOBS:
        if config and knob in config and config[knob] is not None:
            kwargs[knob] = config[knob]
    return RetransmitDetectSimulator(**kwargs)


_DEFAULT = RetransmitDetectSimulator()
_SIM = None
_SIM_CFG = None


def step(scapy_pkt, in_port: int = 1, state=None):
    global _SIM, _SIM_CFG
    if isinstance(state, dict) and isinstance(state.get("config"), dict):
        cfg = state["config"]
        if cfg != _SIM_CFG:
            _SIM = _sim_from_config(cfg)
            _SIM_CFG = dict(cfg)
        return _SIM.step(scapy_pkt, in_port)
    return _DEFAULT.step(scapy_pkt, in_port)


def reset():
    global _SIM, _SIM_CFG
    _DEFAULT.reset()
    _SIM = None
    _SIM_CFG = None
