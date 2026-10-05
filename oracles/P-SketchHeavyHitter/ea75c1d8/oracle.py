"""Pure-Python mirror of the sketch-based heavy-hitter ingress pipeline.

PARAMETRIC oracle for P-SketchHeavyHitter. Every parameter the pattern's
mutation_operators name (sketch_depth, sketch_width, counter_width_bits,
heavy_threshold, heavy_capacity, heavy_eviction, faithfulness,
forwarding_independence_strict, ...) is read from the constructor `config`
at runtime, never baked as a module-level constant. This is the
parametric-source contract that lets parameter rebinding reuse this same
audited module across seeds.

Two observable regimes, selected by the seed:

  (A) PURE TELEMETRY — `heavy_capacity == 0` (equivalently
      `faithfulness < D5.2_heavy_hitter`). R2/R3 (heavy admission) and R4
      (threshold readout) are DISABLED via their `enforced_when`
      predicates; R5 (universal cascade) is off unless D5.3. Observable
      behaviour reduces to:
        R0 — non-IPv4 frames dropped.
        R1 — every IPv4 packet: per-row sketch increment, then LPM-forward
              using the control-plane IPv4 routing table. The sketch state
              does NOT influence the forwarding verdict
              (forwarding_independence invariant). This is the ANCHOR seed
              (sketch_depth=2, sketch_width=256, heavy_capacity=0,
              faithfulness=D5.0_count_min); the constructor defaults
              reproduce it byte-for-byte, so a default-constructed instance
              (the audit's `cls()` path) is the anchor.

  (B) HEAVY-HITTER DETECTION + DROP POLICY — `heavy_capacity > 0` AND
      `faithfulness >= D5.2_heavy_hitter`. R2 admits a flowkey into the
      bounded heavy `flow` table the first time its Count-Min estimate
      `min_r(bucket[r][h_r(flowkey)])` crosses `heavy_threshold` T. R4's
      readout is `drop`: the over-threshold packet (and every subsequent
      packet of an admitted heavy flow in the same epoch) is DROPPED
      (policed) instead of forwarded. This is the
      `relax_forwarding_independence` lineage (drop-on-threshold
      DDoS-mitigation), so it is gated on
      `forwarding_independence_strict == false`. Light flows whose
      estimate stays below T are forwarded exactly as in regime (A).

The Count-Min estimate is the min-of-rows of the (saturating) counter
matrix. The sketch increment for the current packet happens BEFORE the
estimate is read (R1's `inc` then the R2 threshold test), so the packet
that pushes the estimate to T is itself over-threshold.

R6 (epoch boundary) is silent in the test corpus at every authored seed
because `epoch_packets` is large; the counter is implemented for
completeness but no test exercises it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Anchor-seed defaults — used ONLY as constructor defaults so that a
# default-constructed instance (`cls()`, the audit's resolve-step path)
# reproduces the anchor seed. Every value is overridable via config.
# ---------------------------------------------------------------------------

# Topology: single switch s1 with two ports.
PORT_P1 = 1   # s1.p1 — ingress side (host h1 lives here, 10.0.1.1)
PORT_P2 = 2   # s1.p2 — egress side (host h2 lives here, 10.0.2.2)

# Faithfulness ladder ordering for the `>= D5.2_heavy_hitter` predicate.
_FAITHFULNESS_RANK = {
    "D5.0_count_min": 0,
    "D5.1_count_sketch": 1,
    "D5.2_heavy_hitter": 2,
    "D5.3_universal": 3,
}

# LPM forwarding table. (subnet_ip, prefix_len) -> (egress_port, ether_dst,
# ether_src). Mirrors the control-plane entries verbatim.
_DEFAULT_LPM_TABLE = [
    (("10.0.1.0", 24), (PORT_P1, "08:00:00:00:01:01", "08:00:00:00:00:01")),
    (("10.0.2.0", 24), (PORT_P2, "08:00:00:00:02:02", "08:00:00:00:00:02")),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _row_hash(row_idx: int, srcaddr_int: int, sketch_width: int) -> int:
    """Toy independent hash per row. A real P4 implementation uses crc32 with a per-row
    polynomial; for oracle purposes we only need deterministic independence
    across rows. The test corpus does not probe the hash function itself."""
    # FNV-style mix with a per-row seed.
    seeds = [0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F,
             0x165667B1, 0xD3A2646C, 0xFD7046C5, 0xB55A4F09]
    s = seeds[row_idx % len(seeds)]
    x = (srcaddr_int * 0x01000193) ^ s
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    x = (x * 0x85EBCA6B) & 0xFFFFFFFF
    x = (x ^ (x >> 13)) & 0xFFFFFFFF
    x = (x * 0xC2B2AE35) & 0xFFFFFFFF
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    return x % sketch_width


# ---------------------------------------------------------------------------
# Step result
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    admitted: bool
    # "drop_non_ipv4" | "drop_no_lpm_match" | "drop_heavy_policed" | "forward"
    decision: str
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None
    next_hop_mac_src: Optional[str] = None
    # Side-effect: which (row, column) cells were incremented this step.
    sketch_writes: list = field(default_factory=list)
    # Heavy-hitter telemetry (regime B): the Count-Min estimate read this
    # step, and whether the flow is (now) in the heavy `flow` table.
    cm_estimate: Optional[int] = None
    heavy: bool = False
    reason: str = ""


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------

class SketchHeavyHitterSimulator:
    """Sketch-based heavy-hitter pipeline, parameterised by the seed.

    `bucket` is the R x W counter matrix (sparse, keyed by (row, column)).
    `flow` is the bounded heavy-flowkey table (active only when
    heavy_capacity > 0 and faithfulness >= D5.2_heavy_hitter).
    """

    def __init__(self, **config):
        # Every knob read from config; the defaults reproduce the anchor seed
        # so a default-constructed instance is the anchor (parametric-source
        # contract — no seed value is a source-level constant in a rule body).
        self.sketch_depth = int(config.get("sketch_depth", 2))
        self.sketch_width = int(config.get("sketch_width", 256))
        self.counter_width_bits = int(config.get("counter_width_bits", 32))
        self.heavy_threshold = int(config.get("heavy_threshold", 1000))
        self.heavy_capacity = int(config.get("heavy_capacity", 0))
        self.heavy_eviction = config.get("heavy_eviction", "none")
        self.faithfulness = config.get("faithfulness", "D5.0_count_min")
        self.epoch_packets = int(config.get("epoch_packets", 1_048_576))
        self.forwarding_independence_strict = bool(
            config.get("forwarding_independence_strict", True))
        self.lpm_table = config.get("lpm_table", _DEFAULT_LPM_TABLE)

        self.counter_max = (1 << self.counter_width_bits) - 1

        # Runtime state.
        self.bucket: dict = {}      # (row, col) -> count
        self.flow: dict = {}        # flowkey -> {est_count, order, bucket_class}
        self.n_packets = 0
        self.epoch_id = 0
        self._seq = 0               # FIFO/insertion-order counter for eviction

    # ── enforced_when predicate for the heavy path ─────────────────────────
    def _heavy_enabled(self) -> bool:
        """R2/R3/R4 are enforced iff faithfulness >= D5.2_heavy_hitter AND a
        non-empty heavy table is provisioned. The DROP readout additionally
        relaxes forwarding_independence (drop-on-threshold lineage)."""
        return (
            _FAITHFULNESS_RANK.get(self.faithfulness, 0)
            >= _FAITHFULNESS_RANK["D5.2_heavy_hitter"]
            and self.heavy_capacity > 0
            and not self.forwarding_independence_strict
        )

    def reset(self):
        self.bucket = {}
        self.flow = {}
        self.n_packets = 0
        self.epoch_id = 0
        self._seq = 0

    # ── LPM ─────────────────────────────────────────────────────────────────
    def _lpm_lookup(self, dst_ip: str):
        dst = _ip_to_int(dst_ip)
        best = None
        best_len = -1
        for (subnet_ip, prefix_len), nh in self.lpm_table:
            if prefix_len <= best_len:
                continue
            net = _ip_to_int(subnet_ip)
            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF \
                if prefix_len else 0
            if (dst & mask) == (net & mask):
                best = nh
                best_len = prefix_len
        return best

    # ── R1: sketch increment ────────────────────────────────────────────────
    def _inc_sketch(self, srcaddr_int: int) -> list:
        """R1 right-hand-side: inc(bucket[h_r(flowkey)]) for each row r.
        Returns the list of (row, column) cells touched (saturating)."""
        writes = []
        for r in range(self.sketch_depth):
            col = _row_hash(r, srcaddr_int, self.sketch_width)
            key = (r, col)
            v = self.bucket.get(key, 0)
            if v < self.counter_max:
                self.bucket[key] = v + 1
            writes.append(key)
        return writes

    def _cm_estimate(self, srcaddr_int: int) -> int:
        """Count-Min point query: min over rows of bucket[r][h_r(flowkey)]."""
        est = None
        for r in range(self.sketch_depth):
            col = _row_hash(r, srcaddr_int, self.sketch_width)
            v = self.bucket.get((r, col), 0)
            est = v if est is None else min(est, v)
        return est if est is not None else 0

    # ── R2/R3: bounded heavy-table admission ────────────────────────────────
    def _admit_heavy(self, flowkey, est_count: int) -> bool:
        """Admit flowkey into the bounded heavy `flow` table. Returns True if
        flowkey is heavy AFTER this call (already present, or newly admitted)."""
        if flowkey in self.flow:
            self.flow[flowkey]["est_count"] = est_count
            return True
        if len(self.flow) < self.heavy_capacity:
            self._seq += 1
            self.flow[flowkey] = {"est_count": est_count, "order": self._seq,
                                  "bucket_class": "heavy"}
            return True
        # Table full. replace_min / carry_over_on_evict: displace the smallest
        # est_count entry if the candidate is strictly larger (Space-Saving).
        if self.heavy_eviction in ("replace_min", "carry_over_on_evict"):
            victim = min(self.flow, key=lambda k: self.flow[k]["est_count"])
            if est_count > self.flow[victim]["est_count"]:
                if self.heavy_eviction == "carry_over_on_evict":
                    self.flow[victim]["bucket_class"] = "light"
                else:
                    del self.flow[victim]
                self._seq += 1
                self.flow[flowkey] = {"est_count": est_count,
                                      "order": self._seq,
                                      "bucket_class": "heavy"}
                return True
            return False
        # no_evict / none: table full, candidate not admitted (stays light).
        return False

    # ── the oracle step interface ───────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP

        # R0 — non-IPv4 unconditionally dropped. No sketch update, no
        # forwarding side-effect (forwarding_independence invariant).
        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4", reason="R0 non-ipv4")

        ip = scapy_pkt[IP]
        srcaddr_int = _ip_to_int(ip.src)

        # R1 — sketch increment (always), then the LPM lookup. The increment
        # is committed BEFORE the heavy-threshold test, so the packet that
        # pushes the estimate to T is itself over-threshold.
        sketch_writes = self._inc_sketch(srcaddr_int)
        self.n_packets += 1

        # R2/R3/R4 — heavy admission + DROP readout (regime B only).
        cm_est = None
        heavy = False
        if self._heavy_enabled():
            cm_est = self._cm_estimate(srcaddr_int)
            flowkey = ip.src                       # ${flowkey_fields} = srcAddr
            already_heavy = flowkey in self.flow
            if already_heavy or cm_est >= self.heavy_threshold:
                heavy = self._admit_heavy(flowkey, cm_est)
            if heavy:
                # R4 readout == drop: the over-threshold packet is policed.
                # forwarding_independence is relaxed for this lineage.
                return StepResult(
                    False, "drop_heavy_policed",
                    sketch_writes=sketch_writes, cm_estimate=cm_est,
                    heavy=True,
                    reason="R4 heavy flow policed (estimate >= threshold)")

        # R1 forward — pure function of hdr.ipv4.dstAddr.
        nh = self._lpm_lookup(ip.dst)
        if nh is None:
            # LPM-miss: control-plane default drop. Sketch state stays
            # incremented (R1's inc and forward are independent posts).
            return StepResult(False, "drop_no_lpm_match",
                              sketch_writes=sketch_writes,
                              cm_estimate=cm_est, reason="R1 lpm miss")

        port, eth_dst, eth_src = nh
        return StepResult(True, "forward",
                          output_port=port,
                          next_hop_mac_dst=eth_dst,
                          next_hop_mac_src=eth_src,
                          sketch_writes=sketch_writes,
                          cm_estimate=cm_est, heavy=False,
                          reason="R1 forward")

    def run(self, packets) -> list:
        """Batch-driver: each entry of `packets` is (scapy_pkt, in_port)."""
        return [self.step(p, port) for p, port in packets]


# Module-level convenience wrapper so the audit's `oracle.step(pkt, port)`
# fallback also works against a default (anchor) instance.
_DEFAULT: Optional["SketchHeavyHitterSimulator"] = None


def configure(**config) -> "SketchHeavyHitterSimulator":
    global _DEFAULT
    _DEFAULT = SketchHeavyHitterSimulator(**config)
    return _DEFAULT


def step(scapy_pkt, in_port: int, state: Optional[dict] = None) -> StepResult:
    """Module-level step(). If `state` carries a 'config' dict, a fresh
    simulator is built from it (parametric-source contract); otherwise a
    process-wide default (anchor seed) instance is used."""
    global _DEFAULT
    if state and "config" in state:
        sim = state.setdefault("_sim", SketchHeavyHitterSimulator(**state["config"]))
        return sim.step(scapy_pkt, in_port)
    if _DEFAULT is None:
        _DEFAULT = SketchHeavyHitterSimulator()
    return _DEFAULT.step(scapy_pkt, in_port)
