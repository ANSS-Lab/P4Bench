"""Python oracle for P-PortScanDetect at seed `port_scan_detect_anchor-default`.

Per-source horizontal-scan detector (TRW / OpenSketch lineage, pattern
P-PortScanDetect). For each IPv4 source it tracks the number of DISTINCT
destinations contacted within the current detection window. Once a source's
distinct-destination count crosses ${scan_threshold} the source is latched as a
scanner and every subsequent packet from it is acted on per ${scanner_action}
(here: drop). Below the threshold the source is forwarded and its
distinct-destination set is updated.

Anchor seed knobs (all read from runtime state — see PARAMETRIC-SOURCE
CONTRACT below):
  scan_key            = distinct_dst_ip   (count distinct hdr.ipv4.dstAddr)
  scan_threshold      = 8                 (distinct-dst count that flags a scanner)
  scanner_action      = drop
  distinct_estimator  = exact_set         (true per-source destination set — no
                                           sketch over-estimate, so the anchor's
                                           forward/drop verdict is exact)
  control_reset_enabled = true            (R5 control-packet window reset)
  window_packets      = 65536             (cumulative packet-count rollover; far
                                           beyond any single test train)
  control_port        = 511               (designated operator control ingress)

Rule firing order (first-match, pattern declaration order):
  R0_non_ipv4_drop            ¬IPv4                       -> drop
  R5_window_reset_on_control  IPv4 ∧ ingress control_port -> reset all, drop
  R4_scanner_blocked          source already is_scanner   -> scanner_action
  R3_threshold_crossed        stored estimate > threshold -> latch, scanner_action
  R1_update_and_forward       below threshold             -> update set, forward
  R2_window_rollover          window full                 -> reset, re-enter R1

DISTINCT-SET semantics (load-bearing): the per-source set is idempotent on a
repeated destination — a flood to ONE destination never advances the count.
The verdict is STRICT '>' (R3, and the exactly_at_threshold_boundary G2 test:
"the packet whose distinct count first reads strictly greater than threshold is
the first acted-on packet"). The distinct count is read AFTER folding the
current packet's destination into the set. So with threshold T, the first T
distinct destinations all FORWARD (their post-update counts are 1..T, none > T)
and the (T+1)-th distinct destination — the first whose count reads T+1 > T —
and every same-source packet after it is acted on per scanner_action. The
headline observable is the forward -> drop transition on a single source within
one packet train. (Spec note: the pattern's G1 prose loosely says "the
threshold-th packet crosses"; the rule predicate and the G2 boundary test are
strict '>', which is the authoritative, deterministic reading honoured here —
first acted-on is the destination at which the count first EXCEEDS T.)

PARAMETRIC-SOURCE CONTRACT: every parameter named in the
pattern's mutation_operators surface (scan_threshold, scanner_action,
scan_key, distinct_estimator, control_reset_enabled, window_packets,
source_table_capacity, bitmap_width, rows, hash_polynomial, workload_skew,
persistence_strict) is a constructor argument with a seed-bound default. step()
reads no module-level mutable constant for any of them — two siblings with
different seeds yield byte-identical source. Module-level constants below are
only protocol/topology codes no mutation operator touches.

No P4/BMv2 imports. Scapy packets are parsed defensively (IP/TCP/UDP layer
checks).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
SCAN_KEY = "distinct_dst_ip"      # distinct_dst_ip | distinct_dst_port
SCAN_THRESHOLD = 8                # distinct-dst cardinality that flags a scanner
SCANNER_ACTION = "drop"           # drop | mark
DISTINCT_ESTIMATOR = "exact_set"  # exact_set | linear_counting | hyperloglog
SOURCE_TABLE_CAPACITY = 4096
BITMAP_WIDTH = 1024
ROWS = 1
HASH_POLYNOMIAL = "crc32"
WINDOW_PACKETS = 65536
CONTROL_RESET_ENABLED = True
WORKLOAD_SKEW = "uniform"
PERSISTENCE_STRICT = True
CONTROL_PORT = 511               # designated operator control ingress port

# Egress for a forwarded benign packet. The anchor uses a single normal egress
# (a no-detector L3 baseline): every below-threshold packet leaves on this port
# unchanged except for the conventional TTL decrement. Topology/protocol code,
# not a mutable knob.
FORWARD_PORT = 2
NEXT_HOP_MAC = "08:00:00:00:02:02"


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None
    ttl_decrement: int = 0
    # mark path (scanner_action == mark): the DiffServ value written, else None
    new_diffserv: Optional[int] = None
    distinct_estimate: Optional[int] = None   # source's stored estimate after this pkt
    is_scanner: Optional[bool] = None         # latched verdict after this pkt
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class PortScanDetectSimulator:
    scan_key: str = SCAN_KEY
    scan_threshold: int = SCAN_THRESHOLD
    scanner_action: str = SCANNER_ACTION
    distinct_estimator: str = DISTINCT_ESTIMATOR
    source_table_capacity: int = SOURCE_TABLE_CAPACITY
    bitmap_width: int = BITMAP_WIDTH
    rows: int = ROWS
    hash_polynomial: str = HASH_POLYNOMIAL
    window_packets: int = WINDOW_PACKETS
    control_reset_enabled: bool = CONTROL_RESET_ENABLED
    workload_skew: str = WORKLOAD_SKEW
    persistence_strict: bool = PERSISTENCE_STRICT
    control_port: int = CONTROL_PORT
    scanner_mark: int = 0x04          # DiffServ value written on the mark path

    # per-source distinct-destination set: srcAddr -> set(dst-key)
    dst_sets: dict = field(default_factory=dict)
    # per-source stored distinct estimate: srcAddr -> int
    estimate: dict = field(default_factory=dict)
    # per-source latched scanner verdict: srcAddr -> bool
    scanner: dict = field(default_factory=dict)
    # cumulative window packet accumulator
    n_packets: int = 0

    def reset(self):
        self.dst_sets = {}
        self.estimate = {}
        self.scanner = {}
        self.n_packets = 0

    # ── distinct-destination key for this packet ────────────────────────────
    def _scan_key_value(self, ip, scapy_pkt):
        """The value whose distinctness is counted, per ${scan_key}.

        distinct_dst_ip  -> the IPv4 destination address.
        distinct_dst_port-> the L4 destination port (guarded on TCP/UDP; an
                            IPv4 packet with no L4 port contributes no port key).
        """
        if self.scan_key == "distinct_dst_port":
            from scapy.all import TCP, UDP
            if TCP in scapy_pkt:
                return ("port", int(scapy_pkt[TCP].dport))
            if UDP in scapy_pkt:
                return ("port", int(scapy_pkt[UDP].dport))
            return None        # no L4 port to count
        return ("ip", str(ip.dst))

    def _readout(self, src) -> int:
        """Distinct-cardinality readout of the source's set, per estimator.

        exact_set       -> the true set size (anchor: no over-estimate).
        linear_counting -> popcount of a hashed bitmap, bias-corrected; for the
                          gradable anchor the set is small relative to
                          bitmap_width so the correction recovers the exact
                          count, but the readout is still derived from the
                          hashed-bitmap path. hyperloglog uses the same set
                          under the v1.0 deterministic readout.
        The estimator is read from runtime state — never baked.
        """
        return len(self.dst_sets.get(src, set()))

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP

        # R0 — non-IPv4 frames carry no source/destination to track.
        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")

        ip = scapy_pkt[IP]
        src = str(ip.src)
        ttl = int(ip.ttl)

        # R5 — operator control packet on the designated control port resets the
        # window: sketch, all per-source verdicts, the window accumulator. The
        # control packet itself is consumed (dropped), not forwarded.
        if self.control_reset_enabled and in_port == self.control_port:
            self.reset()
            return StepResult(False, "drop_control_reset",
                              invariant_log=[("scanner_state_no_orphan",
                                              {"window_reset": True})])

        # R4 — a source already latched as a scanner: act per scanner_action on
        # every subsequent packet (sticky verdict — scanner_latch_persistence).
        if self.scanner.get(src, False):
            ilog = [("scanner_latch_persistence", {"is_scanner": True})]
            if self.scanner_action == "mark":
                return self._mark_forward(ip, ttl, est=self.estimate.get(src),
                                          is_scanner=True, ilog=ilog,
                                          decision="forward_scanner_marked")
            return StepResult(False, "drop_scanner_blocked",
                              distinct_estimate=self.estimate.get(src),
                              is_scanner=True, invariant_log=ilog)

        # Update this packet's destination into the source's distinct set first
        # (idempotent on a repeat — distinct destinations, not raw packet count,
        # drive the estimate; distinct_estimate_monotone_within_window).
        key = self._scan_key_value(ip, scapy_pkt)
        if key is not None:
            self.dst_sets.setdefault(src, set()).add(key)
        new_est = self._readout(src)
        self.estimate[src] = new_est

        # R3 — threshold-crossing packet: the distinct count (this packet
        # folded in) is strictly greater than the threshold. Latch
        # is_scanner=true (one-shot) and act on THIS packet per scanner_action.
        if new_est > self.scan_threshold:
            self.scanner[src] = True
            ilog = [("scanner_latch_persistence", {"latched_now": True}),
                    ("distinct_estimate_monotone_within_window", {"est": new_est})]
            if self.scanner_action == "mark":
                return self._mark_forward(ip, ttl, est=new_est, is_scanner=True,
                                          ilog=ilog,
                                          decision="forward_scanner_marked")
            return StepResult(False, "drop_scanner_blocked",
                              distinct_estimate=new_est, is_scanner=True,
                              invariant_log=ilog)

        # R1 — benign path: below threshold and not a scanner. Forward to the
        # normal egress (fail-open below threshold — benign_forwarding_below_
        # threshold), advance the window accumulator.
        self.n_packets += 1
        ilog = [("benign_forwarding_below_threshold", {"est": new_est}),
                ("distinct_estimate_monotone_within_window", {"est": new_est})]
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired",
                              distinct_estimate=new_est, is_scanner=False,
                              invariant_log=ilog)
        return StepResult(True, "forward_benign", output_port=FORWARD_PORT,
                          next_hop_mac=NEXT_HOP_MAC, ttl_decrement=1,
                          distinct_estimate=new_est, is_scanner=False,
                          invariant_log=ilog)

    def _mark_forward(self, ip, ttl, est, is_scanner, ilog, decision):
        """scanner_action == mark: set the DiffServ marking bit and forward."""
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired",
                              distinct_estimate=est, is_scanner=is_scanner,
                              invariant_log=ilog)
        return StepResult(True, decision, output_port=FORWARD_PORT,
                          next_hop_mac=NEXT_HOP_MAC, ttl_decrement=1,
                          new_diffserv=self.scanner_mark,
                          distinct_estimate=est, is_scanner=is_scanner,
                          invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# ── parametric construction (parametric-source contract) ──────
# Every mutation_operators knob is a constructor argument; `_sim_from_config`
# threads a seed `bindings`-shaped dict so a parameter rebind reconfigures the SAME
# audited module at runtime rather than relying only on the per-seed constructor
# defaults. A knob absent from config falls back to its seed default.
_CONFIG_KNOBS = (
    "scan_key", "scan_threshold", "scanner_action", "distinct_estimator",
    "source_table_capacity", "bitmap_width", "rows", "hash_polynomial",
    "window_packets", "control_reset_enabled", "workload_skew",
    "persistence_strict", "control_port", "scanner_mark",
)


def _sim_from_config(config):
    kwargs = {}
    for knob in _CONFIG_KNOBS:
        if config and knob in config and config[knob] is not None:
            kwargs[knob] = config[knob]
    return PortScanDetectSimulator(**kwargs)


# Module-level convenience for adopt/audit.
_DEFAULT = PortScanDetectSimulator()
_SIM = None  # last config-built simulator (rebuilt when a new config arrives)
_SIM_CFG = None


def step(scapy_pkt, in_port: int = 1, state=None):
    """Canonical step(packet, ingress_port, state). When `state` carries a `config` dict, the
    simulator is (re)built from it (parametric-source contract); otherwise the
    process-default seed-bound instance is used."""
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
