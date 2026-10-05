"""Composed oracle for P-FairAQMRouter (approximate per-flow fair queueing ∘
ECN AQM marking ∘ LPM forward) at seed `fair_aqm_router_anchor-default`.

Implements the single-pass fair-queue + ECN AQM router in the binding order
route(lookup) → AFQ admit → ECN mark → forward:

  STAGE 1 — LPM forward decision (P-IPv4Routing). The fib is consulted on
    IP.dst. No matching route drops (drop_no_lpm); ttl == 0 drops (drop_ttl).
    The forwarding decision (egress port + next hop) is computed FIRST, but
    the packet is only emitted after it survives the AFQ and ECN stages — the
    egress is gated by the later stages.

  STAGE 2 — Approximate fair queueing (P-ApproxFairQueueing). A per-flow
    (5-tuple) running byte counter accumulates IP.len across the window
    (prior_inputs warm the counter). If the flow's accumulated on-wire bytes
    (INCLUDING this packet) exceed fair_budget, the packet is dropped as over
    its fair share (drop_over_budget). This is the admit-before-mark contract:
    an over-budget flow is dropped BEFORE the ECN stage, never marked.
    Admitted packets advance the per-flow byte counter and the
    admitted-packet count used to model the queue depth.

  STAGE 3 — ECN AQM marking (P-ECNMarker). The simulated enqueue depth is
    modelled as the number of admitted packets in the window (qdepth =
    admitted_packets_in_window, counted AFTER this packet is admitted). If
    qdepth >= mark_threshold_k:
      - ECT packets (IP.tos low 2 bits == 0b01 or 0b10) get CE: the low 2 bits
        are rewritten to 0b11, preserving the high 6 DSCP bits
        (forward_marked_ce).
      - non-ECT packets (low 2 bits == 0b00) cannot be marked and are dropped
        (drop_noecn_congested).
      - CE-already packets (0b11) pass through unchanged (also marked-ce path,
        no rewrite needed — already CE).
    Below threshold every admitted packet forwards unchanged (forward_unmarked).

  STAGE 4 — forward. TTL is decremented once; Ether.dst is rewritten to the
    next hop; the packet egresses. One IPv4 checksum recompute covers the tos
    (ECN bit) rewrite AND the TTL decrement.

Load-bearing composite contracts:
  - admit_before_mark: AFQ drop precedes ECN; an over-budget flow is dropped,
    never marked.
  - ect_gated_marking: only ECT packets get CE; non-ECT over threshold drop.
  - compound_checksum_validity: one IPv4 checksum recompute covers the tos
    (ECN) rewrite AND the TTL decrement.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant. The per-flow byte counters and admitted-packet count live on
the instance and are cleared by reset(), so a prior_inputs sequence accumulates
window state.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
INGRESS_PORT = 1
EGRESS_PORT = 2
FAIR_BUDGET = 3000              # per-flow byte budget within the window
MARK_THRESHOLD_K = 3            # qdepth (admitted packets) >= K -> mark / congest
EGRESS_NH_MAC = "08:00:00:00:02:02"

# LPM forwarding table: (subnet, prefix) -> (egress_port, next_hop_mac).
FIB = [
    (("198.51.100.0", 24), (EGRESS_PORT, EGRESS_NH_MAC)),   # external destinations
]


# ── helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _lpm_lookup(dst_ip: str, fib):
    dst = _ip_to_int(dst_ip)
    best, best_len = None, -1
    for (subnet, plen), nh in fib:
        if plen <= best_len:
            continue
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        if (dst & mask) == (_ip_to_int(subnet) & mask):
            best, best_len = nh, plen
    return best


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None
    ttl_decrement: int = 0
    # post-mark field values (None == field unchanged from input)
    new_tos: Optional[int] = None          # full 8-bit IP.tos after CE mark
    ecn_marked: bool = False               # True iff this packet's ECN was set to CE
    flow_bytes: Optional[int] = None       # cumulative on-wire bytes for the flow (incl. this pkt)
    qdepth: Optional[int] = None           # admitted-packets-in-window after this pkt
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class FairAQMRouterSimulator:
    ingress_port: int = INGRESS_PORT
    egress_port: int = EGRESS_PORT
    fair_budget: int = FAIR_BUDGET
    mark_threshold_k: int = MARK_THRESHOLD_K
    fib: list = field(default_factory=lambda: list(FIB))

    # per-flow (5-tuple) cumulative on-wire bytes within the window
    flow_bytes: dict = field(default_factory=dict)
    # admitted packets in the window (models the simulated queue depth)
    admitted_count: int = 0

    def reset(self):
        self.flow_bytes = {}
        self.admitted_count = 0

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, UDP

        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")

        ip = scapy_pkt[IP]
        ttl = int(ip.ttl)
        proto = int(ip.proto)
        tos = int(ip.tos)
        ecn = tos & 0b11                       # low 2 bits = ECN field
        ip_len = int(ip.len)                   # on-wire IP total length (bytes)
        if TCP in scapy_pkt:
            sport, dport = int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
        elif UDP in scapy_pkt:
            sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
        else:
            sport, dport = 0, 0
        flowkey = (ip.src, ip.dst, proto, sport, dport)

        # STAGE 1 — LPM forward decision on IP.dst.
        ilog = []
        if ttl == 0:
            return StepResult(False, "drop_ttl", invariant_log=ilog)
        nh = _lpm_lookup(ip.dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", invariant_log=ilog)
        egress, mac = nh

        # STAGE 2 — AFQ admission (admit-before-mark). Accumulate this packet's
        # bytes onto the per-flow window counter; over-budget drops here BEFORE
        # the ECN stage.
        accumulated = self.flow_bytes.get(flowkey, 0) + ip_len
        if accumulated > self.fair_budget:
            ilog.append(("admit_before_mark", {"flow_bytes": accumulated,
                                                "budget": self.fair_budget}))
            return StepResult(False, "drop_over_budget", flow_bytes=accumulated,
                              invariant_log=ilog)
        # admit: commit the byte counter and bump the simulated queue depth.
        self.flow_bytes[flowkey] = accumulated
        self.admitted_count += 1
        qdepth = self.admitted_count
        ilog.append(("admit_before_mark", {"flow_bytes": accumulated,
                                            "qdepth": qdepth}))

        # STAGE 3 — ECN AQM marking, gated by qdepth >= K.
        new_tos = None
        marked = False
        if qdepth >= self.mark_threshold_k:
            if ecn == 0b00:
                # non-ECT cannot be marked -> drop under congestion.
                ilog.append(("ect_gated_marking", {"ecn": ecn, "action": "drop"}))
                return StepResult(False, "drop_noecn_congested",
                                  flow_bytes=accumulated, qdepth=qdepth,
                                  invariant_log=ilog)
            if ecn in (0b01, 0b10):
                # ECT -> set CE in the low 2 bits, preserve the high 6 DSCP bits.
                new_tos = (tos & 0b11111100) | 0b11
                marked = True
                ilog.append(("ect_gated_marking", {"ecn": ecn, "action": "mark_ce",
                                                    "new_tos": new_tos}))
            else:
                # ecn == 0b11 (CE already) -> preserve verbatim, still on the
                # marked-ce decision branch (no rewrite needed).
                ilog.append(("ect_gated_marking", {"ecn": ecn, "action": "ce_preserved"}))
            decision = "forward_marked_ce"
        else:
            ilog.append(("ect_gated_marking", {"ecn": ecn, "action": "below_threshold"}))
            decision = "forward_unmarked"

        # STAGE 4 — forward: TTL-1, Ether.dst rewrite, one checksum over tos+TTL.
        ilog.append(("compound_checksum_validity",
                     {"ttl_decremented": True, "tos_rewritten": new_tos is not None}))
        return StepResult(
            True, decision, output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, new_tos=new_tos, ecn_marked=marked,
            flow_bytes=accumulated, qdepth=qdepth, invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = FairAQMRouterSimulator()


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
