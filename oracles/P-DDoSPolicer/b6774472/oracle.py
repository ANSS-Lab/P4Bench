"""Composed oracle for P-DDoSPolicer (Sketch heavy-hitter detector ∘
stateless policy gate) at seed `ddos_policer_disc-default`.

Implements the pattern's detect → combine → mitigate ingress pipeline:

  STAGE 1 — heavy-hitter detection (P-SketchHeavyHitter). On every IPv4
    packet, increment the count-min sketch for the source-IP flowkey and read
    the post-inc min-across-rows estimate. A flow is `heavy` when its estimate
    reaches `heavy_threshold` (mitigation_onset == from_crossing_packet, so the
    crossing packet itself is heavy). This stage strictly PRECEDES the verdict
    (detect_before_police).

  STAGE 2 — policy combination + mitigation (P-ACL ∘ the heavy signal). The
    verdict fuses the control-plane static allow/block list with the heavy
    signal under the fixed priority (R1 > R2 > R3/R4 > R5):
      R1  static deny (blocklist)                       -> drop (rate-independent)
      R2  static permit ∧ allowlist_bypass              -> forward unrecolored (exempt)
      R3  heavy ∧ mitigation_action == drop             -> drop
      R4  heavy ∧ mitigation_action == recolor          -> recolor (DSCP) + forward
      R5  otherwise                                     -> forward unchanged

The composition's load-bearing contracts:
  - detect_before_police: the sketch inc + heavy check precede the verdict;
    under from_crossing_packet the crossing packet (estimate == threshold) is
    itself mitigated. The common inc-first-then-check trap across two stages.
  - policy_combination_consistency: the blocklist > allowlist-bypass >
    heavy-mitigate > benign priority; the both-permitted-and-heavy cell
    forwards iff allowlist_bypass.
  - compound_recolor_checksum_validity: the R4 recolor path writes IP.tos
    (DSCP) AND decrements IP.ttl in one pass — a single checksum recompute.
  - no_false_positive_under_collision: the min-across-rows estimate clips a
    single-row adversarial collision, so an innocent low-rate flow that
    collides with a heavy flow in one row is NOT policed.

This module is the concrete realisation of P-SketchHeavyHitter's
`relax_forwarding_independence` augmentation — the sketch DRIVES the verdict
here, so forwarding_independence is deliberately not enforced.

PARAMETRIC-SOURCE CONTRACT. Every mutable knob is a
constructor argument with a seed-bound default (the per-seed content-addressed
copy convention). The seed's values enter only via instantiation; `step()`
reads no module-level mutable constant. The mutable sketch + detected-heavy set
live on the instance and are cleared by `reset()`, so a prior_inputs sequence
accumulates state and a fresh instance (or reset) starts cold.

TTL convention (binding, inherited from the IPv4/AQM anchors): gate ttl > 0.
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
SKETCH_DEPTH = 2                 # count-min rows R (min-across-rows protection)
SKETCH_WIDTH = 64                # count-min width W per row (power of two)
COUNTER_MAX = (1 << 32) - 1      # counter_width_bits == 32, saturating
HEAVY_THRESHOLD = 8              # estimate >= T -> heavy (small, unit-testable)
EPOCH_PACKETS = 4096             # large enough that no test rolls the epoch
ACCESS_PORT = 1
CORE_PORT = 2

# composite knobs (the D5.1 rung)
POLICY_TRIGGER = "static_and_heavy"
ALLOWLIST_BYPASS = True
MITIGATION_ACTION = "recolor"    # 'drop' | 'recolor'
MITIGATION_ONSET = "from_crossing_packet"
SCAVENGER_DSCP = 8               # CS1 — the recolor target (full IP.tos byte)
DEFAULT_ACTION = "permit"        # static-table miss -> fall through to heavy check

# Static allow/block list (control-plane installed). Each rule: priority +
# action + a ternary src/dst/proto/sport/dport spec (missing field = wildcard).
STATIC_RULES = [
    {"priority": 100, "action": "deny",   "ipv4_src": "10.0.1.66/32"},  # blocklist (known bad)
    {"priority": 100, "action": "permit", "ipv4_src": "10.0.1.10/32"},  # allowlist (legit bulk)
]

# LPM forwarding table: (subnet, prefix) -> (egress_port, eth_dst, eth_src).
LPM_TABLE = [
    (("10.0.1.0", 24), (ACCESS_PORT, "08:00:00:00:01:01", "08:00:00:00:00:01")),
    (("10.0.2.0", 24), (CORE_PORT,   "08:00:00:00:02:02", "08:00:00:00:00:02")),
]


# ── Helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _ipv4_match(addr: str, cidr: Optional[str]) -> bool:
    if cidr is None:
        return True
    if "/" in cidr:
        net, n = cidr.split("/"); n = int(n)
    else:
        net, n = cidr, 32
    mask = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0
    return (_ip_to_int(addr) & mask) == (_ip_to_int(net) & mask)


def _eq_or_any(v, c) -> bool:
    return c is None or v == c


def _lpm_lookup(dst_ip: str):
    dst = _ip_to_int(dst_ip)
    best, best_len = None, -1
    for (subnet, plen), nh in LPM_TABLE:
        if plen <= best_len:
            continue
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        if (dst & mask) == (_ip_to_int(subnet) & mask):
            best, best_len = nh, plen
    return best


def _row_hash(row_idx: int, srcaddr_int: int, width: int) -> int:
    """Deterministic per-row independent hash (FNV-style mix with a per-row
    seed). A real P4 implementation uses crc32 with a per-row polynomial; the oracle only
    needs deterministic cross-row independence."""
    seeds = [0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F,
             0x165667B1, 0xD3A2646C, 0xFD7046C5, 0xB55A4F09]
    s = seeds[row_idx % len(seeds)]
    x = (srcaddr_int * 0x01000193) ^ s
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    x = (x * 0x85EBCA6B) & 0xFFFFFFFF
    x = (x ^ (x >> 13)) & 0xFFFFFFFF
    x = (x * 0xC2B2AE35) & 0xFFFFFFFF
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    return x % width


# ── Step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None
    next_hop_mac_src: Optional[str] = None
    ttl_decrement: int = 0
    recolored: bool = False
    new_tos: Optional[int] = None          # IP.tos after recolor (R4)
    est_count: int = 0                     # post-inc min-across-rows estimate
    heavy: bool = False
    static_verdict: Optional[str] = None   # 'deny' | 'permit' | 'mark' | miss->default
    invariant_log: list = field(default_factory=list)


# ── Simulator ─────────────────────────────────────────────────────────────────

@dataclass
class DDoSPolicerSimulator:
    sketch_depth: int = SKETCH_DEPTH
    sketch_width: int = SKETCH_WIDTH
    heavy_threshold: int = HEAVY_THRESHOLD
    epoch_packets: int = EPOCH_PACKETS
    policy_trigger: str = POLICY_TRIGGER
    allowlist_bypass: bool = ALLOWLIST_BYPASS
    mitigation_action: str = MITIGATION_ACTION
    mitigation_onset: str = MITIGATION_ONSET
    scavenger_dscp: int = SCAVENGER_DSCP
    default_action: str = DEFAULT_ACTION
    rules: list = field(default_factory=lambda: [dict(r) for r in STATIC_RULES])

    bucket: dict = field(default_factory=dict)     # (row, col) -> count
    detected_heavy: set = field(default_factory=set)  # set of srcaddr ints
    n_packets: int = 0
    epoch_id: int = 0

    def reset(self):
        self.bucket = {}
        self.detected_heavy = set()
        self.n_packets = 0
        self.epoch_id = 0

    # ── detection half ───────────────────────────────────────────────────────
    def _inc_and_estimate(self, srcaddr_int: int) -> int:
        cells = []
        for r in range(self.sketch_depth):
            col = _row_hash(r, srcaddr_int, self.sketch_width)
            key = (r, col)
            v = self.bucket.get(key, 0)
            if v < COUNTER_MAX:
                v += 1
            self.bucket[key] = v
            cells.append(v)
        return min(cells)               # count-min min-across-rows estimate

    def _maybe_epoch_roll(self):
        self.n_packets += 1
        if self.n_packets >= self.epoch_packets:
            self.bucket = {}
            self.detected_heavy = set()
            self.n_packets = 0
            self.epoch_id += 1

    # ── policy half ──────────────────────────────────────────────────────────
    def _static_match(self, l4: dict):
        """Highest-priority EXPLICIT static-rule action, or None on table miss.
        A miss is resolved against ${default_action} by the caller — an
        explicit allowlist permit is distinct from a default-action permit
        (only the former triggers the R2 bypass)."""
        if self.policy_trigger != "static_and_heavy":
            return None                # heavy_only: static list absent
        best, best_p = None, -1
        for r in self.rules:
            if (_ipv4_match(l4["src"], r.get("ipv4_src"))
                    and _ipv4_match(l4["dst"], r.get("ipv4_dst"))
                    and _eq_or_any(l4["proto"], r.get("proto"))
                    and _eq_or_any(l4["sport"], r.get("sport"))
                    and _eq_or_any(l4["dport"], r.get("dport"))):
                p = int(r["priority"])
                if p > best_p:
                    best, best_p = r, p
        return best["action"] if best is not None else None

    # ── step ───────────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, UDP

        # R0 — non-IPv4 dropped (no count, no verdict).
        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")

        ip = scapy_pkt[IP]
        ttl = int(ip.ttl)
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired")

        srcaddr_int = _ip_to_int(ip.src)
        proto = int(ip.proto)
        if TCP in scapy_pkt:
            sport, dport = int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
        elif UDP in scapy_pkt:
            sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
        else:
            sport, dport = 0, 0
        l4 = {"src": ip.src, "dst": ip.dst, "proto": proto,
              "sport": sport, "dport": dport}

        # STAGE 1 — detect_before_police: inc THEN read the estimate.
        was_member = srcaddr_int in self.detected_heavy
        est = self._inc_and_estimate(srcaddr_int)
        crossed = est >= self.heavy_threshold
        if crossed:
            self.detected_heavy.add(srcaddr_int)
        # heavy(flowkey) per mitigation_onset:
        if self.mitigation_onset == "from_crossing_packet":
            heavy = crossed
        else:                          # from_next_packet: police only prior members
            heavy = was_member
        self._maybe_epoch_roll()

        # STAGE 2 — policy combination (R1 > R2 > R3/R4 > R5).
        matched = self._static_match(l4)                 # explicit action or None
        # Effective static verdict for logging: explicit action, else default.
        sv = matched if matched is not None else (
            self.default_action if self.policy_trigger == "static_and_heavy" else None)
        ilog = [("detect_before_police",
                 {"onset": self.mitigation_onset, "est": est, "heavy": heavy}),
                ("policy_combination_consistency",
                 {"matched": matched, "effective": sv, "heavy": heavy,
                  "allowlist_bypass": self.allowlist_bypass})]

        if self.policy_trigger == "static_and_heavy":
            # R1 — explicit blocklist drops regardless of rate.
            if matched == "deny":
                return StepResult(False, "drop_static_blocklist",
                                  est_count=est, heavy=heavy, static_verdict=sv,
                                  invariant_log=ilog)
            # R2 — EXPLICIT allowlist permit exempts a heavy flow (bypass on).
            if matched == "permit" and self.allowlist_bypass:
                return self._forward(ip, recolor=False, est=est, heavy=heavy,
                                     sv=sv, ilog=ilog,
                                     decision="forward_allowlist_exempt")
            # Table MISS under default-deny drops before the heavy check.
            if matched is None and self.default_action == "deny":
                return StepResult(False, "drop_static_default_deny",
                                  est_count=est, heavy=heavy, static_verdict=sv,
                                  invariant_log=ilog)
            # else (miss+default-permit, or explicit permit w/o bypass, or
            # explicit mark) falls through to the heavy check.

        # R3/R4 — heavy mitigation (unless exempted above).
        if heavy:
            if self.mitigation_action == "drop":
                return StepResult(False, "drop_heavy_mitigation",
                                  est_count=est, heavy=heavy, static_verdict=sv,
                                  invariant_log=ilog)
            # recolor
            ilog.append(("compound_recolor_checksum_validity",
                         {"tos_set": self.scavenger_dscp, "ttl_decremented": True}))
            return self._forward(ip, recolor=True, est=est, heavy=heavy,
                                 sv=sv, ilog=ilog, decision="forward_recolor_heavy")

        # R5 — benign forward.
        return self._forward(ip, recolor=False, est=est, heavy=heavy,
                             sv=sv, ilog=ilog, decision="forward_benign")

    def _forward(self, ip, *, recolor, est, heavy, sv, ilog, decision) -> StepResult:
        nh = _lpm_lookup(ip.dst)
        if nh is None:
            return StepResult(False, "drop_no_lpm_match", est_count=est,
                              heavy=heavy, static_verdict=sv, invariant_log=ilog)
        port, eth_dst, eth_src = nh
        return StepResult(
            True, decision, output_port=port,
            next_hop_mac_dst=eth_dst, next_hop_mac_src=eth_src,
            ttl_decrement=1, recolored=recolor,
            new_tos=self.scavenger_dscp if recolor else None,
            est_count=est, heavy=heavy, static_verdict=sv, invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit: a default instance + bound step.
_DEFAULT = DDoSPolicerSimulator()


# ── PARAMETRIC-SOURCE SHIM ─────────────────
# The module-level step() threads a runtime `state` so every seed-bound knob is
# read from state["config"] at call time rather than a module constant. A 2-arg
# call (no state) falls back to the module default simulator held equal to the
# seed (the oracle audit's smoke path). The simulator — and its mutable per-flow
# accumulators — is persisted in state["_sim"] so a prior_inputs sequence threads
# against one instance. Two siblings with different bindings produce identical
# source; the seed enters here at call time.
import inspect as _inspect


def _sim_from_config(cfg: dict):
    sim_cls = type(_DEFAULT)
    params = _inspect.signature(sim_cls).parameters
    kwargs = {k: cfg[k] for k in cfg if k in params}
    return sim_cls(**kwargs)


def _sim_for(state):
    if state is None:
        return _DEFAULT
    sim = state.get("_sim")
    if sim is None:
        cfg = state.get("config") or {}
        sim = _sim_from_config(cfg) if cfg else type(_DEFAULT)()
        state["_sim"] = sim
    return sim


def step(scapy_pkt, in_port: int = 1, state=None):
    return _sim_for(state).step(scapy_pkt, in_port)


def reset():
    _DEFAULT.reset()
