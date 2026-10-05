"""Python oracle for P-RateFeedback at seed `rate_feedback_anchor-default`.

RCP-style explicit-rate / congestion-feedback stamping (D8 transport-assistance
/ P6 congestion-control-assistance). The switch keeps a per-egress-port
congestion signal (a deterministic packet counter), derives a locally
advertised fair-rate from that signal and the class target_rate, and — for
every packet carrying a feedback header — folds that header's rate field to
the PATH MINIMUM:

    field <- MIN(current_field, switch_advertised_value)

so the most-congested switch on the path wins (RCP §3). The field is rewritten
ONLY when the switch's advertised value is strictly more restrictive (smaller,
under the canonical aggregate_lower_better orientation) than the value already
present; an upstream bottleneck's smaller value survives unchanged
(path_minimum_monotone). Packets with no feedback header transit unmodified
(R0 / default_action).

GRADABILITY SUBSTITUTION (pattern bridging_notes): the congestion signal is a
deterministic per-class PACKET COUNTER, NOT standard_metadata.enq_qdepth — the
latter is ~always 0 and non-deterministic under simple_switch --use-files. The
advertised value is a monotone-decreasing, saturating function of the counter:

    advertised(load) = max(rate_floor, target_rate // (1 + load))

read AFTER the R1 increment for this packet (register read-after-write
ordering, per feedback_field_value_correctness). The window resets the counter
at the aggregation_window boundary (by packet count, not wall clock).

PARAMETRIC-SOURCE CONTRACT: every mutation_operators
knob (target_rate, n_signal_classes, aggregation_window, aggregation_mode,
signal_keying, path_min_strict, aggregate_lower_better, feedback_semantics,
default_action) is a constructor argument, and the per-run instance is built
from the seed `bindings` at evaluation time via `RateFeedbackSimulator
.from_config(config)` (or the module-level `configure(config)` /
`step(pkt, port, state={'config': ...})` path). NO seed value enters this
module as a source-level constant that the running simulator reads: the
dataclass field defaults are only the canonical-seed FALLBACK for a knob the
caller omits, and the process-default `_DEFAULT` is lazily configured from a
seed, never baked at import. Two siblings with different seeds therefore reuse
this same byte-identical module — which is what lets parameter rebinding
reuse the audited oracle without regeneration. A constant-baked variant that
ignored `config` would diverge from the audit's canonical examples at the knob
extremes and be rejected before admission.

FEEDBACK HEADER WIRE FORMAT (deferred to the test generator / custom_headers.py;
the audit builder cannot synthesise it — see canonical_examples.yaml note):
a feedback shim demuxed on UDP dport == FEEDBACK_UDP_PORT carrying a 32-bit
big-endian rate field in the first 4 payload bytes. step() parses it
defensively from the raw UDP payload, so it is agnostic to how the packet was
built (scapy custom layer or raw bytes).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── module-level constants no mutation operator touches ───────────────────────────
FEEDBACK_UDP_PORT = 9999          # UDP dport that demuxes the feedback shim
RATE_FLOOR = 1                    # advertised value saturates here (no underflow)

# Forwarding table: IP.dst /24 prefix -> egress port. The egress port also
# names the congestion-signal class under per_egress_port keying. Protocol
# scaffolding (not a mutation knob), so a module-level constant is fine.
FIB = [
    (("10.0.1.0", 24), 1),
    (("10.0.2.0", 24), 2),
    (("10.0.3.0", 24), 3),
]


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
N_SIGNAL_CLASSES   = 8
TARGET_RATE        = 1000000
AGGREGATION_MODE   = "packet_count"      # packet_count | byte_count | window_aggregate
AGGREGATION_WINDOW = 64
SIGNAL_KEYING      = "per_egress_port"   # per_egress_port | per_dscp_class
PATH_MIN_STRICT    = True
AGGREGATE_LOWER_BETTER = True
FEEDBACK_SEMANTICS = "rcp_rate"          # rcp_rate | xcp_feedback
DEFAULT_ACTION     = "forward"           # forward | drop  (packet w/o feedback header)


# ── helpers ──────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _lpm_lookup(dst_ip: str, fib):
    dst = _ip_to_int(dst_ip)
    best, best_len = None, -1
    for (subnet, plen), egress in fib:
        if plen <= best_len:
            continue
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        if (dst & mask) == (_ip_to_int(subnet) & mask):
            best, best_len = egress, plen
    return best


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    signal_class: Optional[int] = None
    load_count: Optional[int] = None              # post-R1-inc signal for this packet
    advertised_value: Optional[int] = None        # switch's locally advertised value
    feedback_in: Optional[int] = None             # ingress feedback field value
    feedback_out: Optional[int] = None            # egress feedback field value (the stamp)
    field_rewritten: bool = False                 # True iff R2 folded (field changed)
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class RateFeedbackSimulator:
    n_signal_classes: int = N_SIGNAL_CLASSES
    target_rate: int = TARGET_RATE
    aggregation_mode: str = AGGREGATION_MODE
    aggregation_window: int = AGGREGATION_WINDOW
    signal_keying: str = SIGNAL_KEYING
    path_min_strict: bool = PATH_MIN_STRICT
    aggregate_lower_better: bool = AGGREGATE_LOWER_BETTER
    feedback_semantics: str = FEEDBACK_SEMANTICS
    default_action: str = DEFAULT_ACTION
    rate_floor: int = RATE_FLOOR
    fib: list = field(default_factory=lambda: list(FIB))

    # per-class congestion signal: class -> load_count (packets/bytes in window)
    load: dict = field(default_factory=dict)
    # per-class window position (packets seen since last reset)
    wpos: dict = field(default_factory=dict)

    def reset(self):
        self.load = {}
        self.wpos = {}

    # ── class resolution ───────────────────────────────────────────────────
    def _class_of(self, egress: int, dscp: int) -> int:
        if self.signal_keying == "per_dscp_class":
            raw = dscp
        else:                                  # per_egress_port (canonical)
            raw = egress
        # Collapse into the available class table (capacity axis).
        return raw % self.n_signal_classes if self.n_signal_classes else 0

    # ── deterministic congestion signal (R1) ────────────────────────────────
    def _update_signal(self, cls: int, pkt_len: int) -> int:
        """Increment the class signal for this packet, applying the
        aggregation_window boundary reset. Returns the post-increment load."""
        pos = self.wpos.get(cls, 0)
        if pos >= self.aggregation_window:        # window boundary -> reset/decay
            self.load[cls] = 0
            pos = 0
        contribution = pkt_len if self.aggregation_mode == "byte_count" else 1
        self.load[cls] = self.load.get(cls, 0) + contribution
        self.wpos[cls] = pos + 1
        return self.load[cls]

    # ── switch advertised value (monotone-decreasing, saturating) ───────────
    def _advertised(self, load: int) -> int:
        adv = self.target_rate // (1 + load)
        return adv if adv >= self.rate_floor else self.rate_floor

    # ── XCP signed efficiency/fairness feedback (monotone-decreasing) ────────
    def _xcp_signed_feedback(self, load: int) -> int:
        """A SIGNED feedback (XCP §3.2/§4.3): POSITIVE when the link is
        under-utilised (low load), NEGATIVE when congested (high load),
        monotonically decreasing in load. Derived deterministically from the
        same per-class signal and ${target_rate} as the RCP advertised value
        so it is reproducible under --use-files:

            xcp(load) = advertised(load) - target_rate // 2

        At load 0 the advertised value is the full target_rate, so the signed
        feedback is +target_rate//2 (room to grow); as load climbs the
        advertised value collapses toward the floor and the signed feedback
        goes negative (back off). The value is a two's-complement bit<32>."""
        adv = self.target_rate // (1 + load)            # un-floored: signed curve
        return adv - (self.target_rate // 2)

    @staticmethod
    def _to_signed32(v: int) -> int:
        v &= 0xFFFFFFFF
        return v - (1 << 32) if v & 0x80000000 else v

    @staticmethod
    def _to_unsigned32(v: int) -> int:
        return v & 0xFFFFFFFF

    # ── feedback header parse (from raw UDP payload bytes) ───────────────────
    @staticmethod
    def _parse_feedback(scapy_pkt):
        """Return the ingress feedback field value, or None if absent.

        The feedback shim is demuxed on UDP dport == FEEDBACK_UDP_PORT and
        carries a 32-bit big-endian rate in the first 4 payload bytes."""
        from scapy.all import UDP, Raw
        if UDP not in scapy_pkt:
            return None
        udp = scapy_pkt[UDP]
        if int(udp.dport) != FEEDBACK_UDP_PORT:
            return None
        payload = b""
        if Raw in scapy_pkt:
            payload = bytes(scapy_pkt[Raw].load)
        else:
            payload = bytes(udp.payload)
        if len(payload) < 4:
            return None
        return int.from_bytes(payload[:4], "big")

    # ── step ─────────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP

        if IP not in scapy_pkt:
            # non-IPv4 has no forwarding class; transit unmodified per R0.
            return StepResult(False, "drop_non_ipv4")

        ip = scapy_pkt[IP]
        dscp = (int(ip.tos) >> 2) & 0x3F
        egress = _lpm_lookup(ip.dst, self.fib)
        if egress is None:
            return StepResult(False, "drop_no_route")

        fb_in = self._parse_feedback(scapy_pkt)

        # R0 — no feedback header: forward unmodified (default_action).
        if fb_in is None:
            if self.default_action == "drop":
                return StepResult(False, "drop_no_feedback")
            return StepResult(True, "forward_no_feedback", output_port=egress,
                              invariant_log=[("R0_no_feedback_header", {})])

        # R1 — update the deterministic per-class congestion signal.
        cls = self._class_of(egress, dscp)
        pkt_len = len(bytes(scapy_pkt))
        load = self._update_signal(cls, pkt_len)
        ilog = [("signal_persistence_within_window",
                 {"class": cls, "load": load})]

        adv = self._advertised(load)
        ilog.append(("feedback_field_value_correctness",
                     {"advertised": adv, "load": load}))

        # R3 — XCP signed efficiency/fairness fold (xcp_feedback mode only).
        # The field carries a SIGNED 32-bit feedback; the more-restrictive
        # (more-negative) value wins under the same most-bottlenecked-hop-wins
        # rule. In rcp_rate mode (the canonical anchor) this branch is dead and
        # the RCP fold below runs byte-identically.
        if self.feedback_semantics == "xcp_feedback":
            sw_signed = self._xcp_signed_feedback(load)
            in_signed = self._to_signed32(fb_in)
            if self.path_min_strict:
                if sw_signed < in_signed:          # R3: switch more restrictive
                    out_signed = sw_signed
                    rewritten = True
                    decision = "forward_stamp_xcp_feedback"
                    ilog.append(("path_minimum_monotone",
                                 {"in": in_signed, "out": out_signed}))
                else:                              # R4: upstream more negative survives
                    out_signed = in_signed
                    rewritten = False
                    decision = "forward_preserve_upstream"
                    ilog.append(("path_minimum_monotone",
                                 {"in": in_signed, "out": out_signed,
                                  "preserved": True}))
            else:
                out_signed = sw_signed             # relaxed: always overwrite
                rewritten = (out_signed != in_signed)
                decision = "forward_stamp_unconditional"
            fb_out = self._to_unsigned32(out_signed)
            ilog.append(("forwarding_independence", {"egress": egress}))
            return StepResult(
                True, decision, output_port=egress, signal_class=cls,
                load_count=load, advertised_value=sw_signed,
                feedback_in=fb_in, feedback_out=fb_out, field_rewritten=rewritten,
                invariant_log=ilog)

        # R2 / R4 — path-minimum fold (canonical aggregate_lower_better).
        if self.path_min_strict and self.aggregate_lower_better:
            if fb_in > adv:
                fb_out = adv                       # R2: switch is more restrictive
                rewritten = True
                decision = "forward_stamp_path_min"
                ilog.append(("path_minimum_monotone",
                             {"in": fb_in, "out": fb_out}))
            else:
                fb_out = fb_in                     # R4: upstream bottleneck survives
                rewritten = False
                decision = "forward_preserve_upstream"
                ilog.append(("path_minimum_monotone",
                             {"in": fb_in, "out": fb_out, "preserved": True}))
        else:
            # relaxed: always overwrite (advisory monotonicity)
            fb_out = adv
            rewritten = (fb_out != fb_in)
            decision = "forward_stamp_unconditional"

        ilog.append(("forwarding_independence", {"egress": egress}))
        return StepResult(
            True, decision, output_port=egress, signal_class=cls,
            load_count=load, advertised_value=adv,
            feedback_in=fb_in, feedback_out=fb_out, field_rewritten=rewritten,
            invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]

    # ── parametric constructor from a seed `bindings` dict ───────────────────
    @classmethod
    def from_config(cls, config: Optional[dict] = None) -> "RateFeedbackSimulator":
        """Build a simulator from a seed `bindings`-shaped config dict.

        Every mutation_operators knob is read from `config` at runtime; a
        knob absent from `config` falls back to its constructor default
        (the canonical-seed value). This is the parametric-source contract:
        the same audited module serves any seed,
        and parameter rebinding reuses it without regeneration. A constant-baked
        oracle that ignored `config` would diverge from the audit's canonical
        examples at the knob extremes and be rejected at admission.
        """
        config = dict(config or {})
        kwargs = {}
        for knob in ("n_signal_classes", "target_rate", "aggregation_mode",
                     "aggregation_window", "signal_keying", "path_min_strict",
                     "aggregate_lower_better", "feedback_semantics",
                     "default_action", "rate_floor"):
            if knob in config and config[knob] is not None:
                kwargs[knob] = config[knob]
        return cls(**kwargs)


# ── module-level parametric step/reset (parametric-source contract) ─────────
# The process-default instance is configured from a seed `bindings` dict via
# configure(...) — NOT constructed with baked constants here. The oracle audit
# and the test generator both pass the seed in, so no mutation_operators knob
# enters this module as a source-level constant that step() reads.
_DEFAULT: Optional[RateFeedbackSimulator] = None


def configure(config: Optional[dict] = None) -> RateFeedbackSimulator:
    """Set the process-default instance from a seed `bindings`-shaped dict."""
    global _DEFAULT
    _DEFAULT = RateFeedbackSimulator.from_config(config)
    return _DEFAULT


def step(scapy_pkt, in_port: int = 1, state: Optional[dict] = None):
    """Module-level step(). If `state` carries a 'config' dict, a fresh
    simulator is built from it (parametric-source contract); otherwise the
    process default (configure(); else the canonical-seed default) is used."""
    global _DEFAULT
    if state and "config" in state:
        sim = state.setdefault(
            "_sim", RateFeedbackSimulator.from_config(state["config"]))
        return sim.step(scapy_pkt, in_port)
    if _DEFAULT is None:
        _DEFAULT = RateFeedbackSimulator.from_config(None)
    return _DEFAULT.step(scapy_pkt, in_port)


def reset():
    global _DEFAULT
    if _DEFAULT is not None:
        _DEFAULT.reset()
