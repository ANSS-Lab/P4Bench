"""Parametric oracle for P-AQMFairQueue (Approximate Fair-Queue admission ∘
Queue-depth ECN marking).

Two-stage ingress AQM pipeline:

  STAGE 1 — fairness admission (P-ApproxFairQueueing). Derive
    round_shift = max(0, flow_round - current_round) from a count-min byte
    sketch + a single global byte counter, and DROP the packet when
    round_shift >= window (R3). Strictly PRECEDES the marker.

  STAGE 2 — queue-depth ECN marking (P-ECNMarker), applied ONLY to
    AFQ-admitted packets, keyed on the per-destination synthetic queue depth:
      R4  admitted ∧ depth >= K_eff ∧ Not-ECT (00)  -> tail-drop (not_ect_action)
      R5  admitted ∧ depth >= K_eff ∧ ECT (01/10)   -> mark CE (11), forward
      R6  admitted ∧ depth >= K_eff ∧ CE (11)        -> preserve, forward
      R7  admitted ∧ depth <  K_eff                  -> forward unchanged ECN

PARAMETRIC-SOURCE CONTRACT. Every mutable knob named in the
pattern's `mutation_operators` surface is read from the runtime `state`
argument — specifically from `state["config"]` — at call time, NEVER baked as a
source-level constant. Two siblings of this pattern with different seed bindings
produce BYTE-IDENTICAL oracle source; the seed binds the initial `state`, which
the caller (the test generator / the eval harness) threads in. This is what lets
parameter rebinding reuse the same audited oracle.py and the
same task.yaml test inputs.

`_FALLBACK_CONFIG` is used ONLY when no config is threaded (the oracle audit's
2-arg `step(pkt, port)` smoke path, which carries no per-example config). It is
held equal to the published `aqm_fairqueue_disc` seed so the canonical examples
authored at that seed still pass the 2-arg audit. It is NOT the source of truth
for materialisation — the test generator threads the seed-derived config.

Mutable sketch state (count-min rows + global byte counter) lives in `state`
and is initialised lazily from the config's sketch geometry; a fresh `state`
dict (or `reset()` on the module default) starts cold. A `prior_inputs` byte
burst accumulates the sketch across calls that share the same `state`.

TTL convention (binding, inherited from the AFQ/IPv4 anchors): gate ttl > 0.
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).

StepResult shape is the AQM/AFQ family convention (admitted / decision /
output_port + the per-field transformation carriers round_shift, ecn_out,
ttl_decrement, next_hop_mac_dst) the per-task generator translates into
task.yaml `expected:` blocks; the oracle audit compares on
{admitted, decision, output_port}.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── fixed protocol constants (NOT in mutation_operators — safe as module consts) ──
ECN_NOT_ECT = 0b00
ECN_ECT_1 = 0b01
ECN_ECT_0 = 0b10
ECN_CE = 0b11
PROTO_NUM = {"tcp": 6, "udp": 17}


# ── audit-only fallback config (see module docstring) ───────────────────────
# Held equal to the published aqm_fairqueue_disc seed. Used solely for the 2-arg
# step(pkt, port) audit smoke path; real materialisation threads state["config"].
_FALLBACK_CONFIG: Dict[str, Any] = {
    "window": 8,
    "quantum": 256,
    "fair_share_k": 4,
    "sketch_rows": 2,
    "sketch_width": 64,
    "marking_threshold_k": 64,
    "marking_coupling": "decoupled",
    "coupling_gain": 8,
    "min_threshold": 32,
    "not_ect_action": "drop",
    "account_policy": "account_on_admit",
    "byte_accounting": "on_wire_length",
    "eligibility_protocol": "tcp",
    "non_ipv4_action": "drop",
    "ce_persistence_strict": True,
    "queue_depth_signal": "synthetic_qdepth",
    "access_port": 1,
    "core_port": 2,
    "core_mac": "08:00:00:00:02:01",
    "depth_table": {
        "10.0.2.10": 0,
        "10.0.2.20": 63,
        "10.0.2.30": 64,
        "10.0.2.40": 200,
    },
}


@dataclass
class StepResult:
    admitted: bool
    # reason ∈ {wrong_port, not_ipv4, not_eligible_l4, ttl_exhausted,
    #           out_of_window, not_ect_drop, mark, preserve_ce, passthrough}
    reason: str
    output_port: Optional[int] = None
    round_shift: Optional[int] = None      # stamped into IP.identification on forward
    ecn_out: Optional[int] = None          # egress ECN codepoint on forward
    ttl_decrement: int = 0
    next_hop_mac_dst: Optional[str] = None
    bytes_consumed: int = 0                # bytes added to the sketch this step
    depth_seen: Optional[int] = None
    invariant_log: list = field(default_factory=list)

    @property
    def decision(self) -> str:             # for the oracle audit's comparison
        return "forward" if self.admitted else "drop"


# ── helpers ─────────────────────────────────────────────────────────────────
def _ip_to_int(addr: str) -> int:
    a, b, c, d = (int(x) for x in str(addr).split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _row_hashes(src_int: int, rows: int, width: int) -> List[int]:
    """Per-row count-min indices in [0, width). Row 0 keys on the source's last
    octet; row 1 XOR-folds the 2nd- and 3rd-last octets — the audited two-row
    scheme of the P-ApproxFairQueueing sibling oracle, generalised to `width`.
    Further rows (if sketch_rows > 2) fold higher octet pairs."""
    h0 = (src_int & 0xFF) % width
    if rows == 1:
        return [h0]
    h1 = (((src_int >> 8) & 0xFF) ^ ((src_int >> 16) & 0xFF)) % width
    hs = [h0, h1]
    for r in range(2, rows):
        hs.append((((src_int >> (r * 8)) & 0xFF)
                   ^ ((src_int >> ((r + 1) * 8)) & 0xFF)) % width)
    return hs[:rows]


def _config(state: Optional[dict]) -> Dict[str, Any]:
    """Merge the threaded per-instance config over the audit-only fallback, so
    a caller that omits a knob still runs and a caller that threads the seed
    overrides every knob. The seed enters here, never as a source constant."""
    cfg = dict(_FALLBACK_CONFIG)
    if state:
        cfg.update(state.get("config", {}))
    return cfg


def _ensure_sketch(state: dict, rows: int, width: int) -> None:
    if state.get("sketch") is None:
        state["sketch"] = [[0] * width for _ in range(rows)]
        state["global_bytes"] = 0


def _round_shift(state: dict, cfg: dict, src_int: int) -> Tuple[int, List[int]]:
    rows, width = int(cfg["sketch_rows"]), int(cfg["sketch_width"])
    quantum, fair_k = int(cfg["quantum"]), int(cfg["fair_share_k"])
    idx = _row_hashes(src_int, rows, width)
    sketch = state["sketch"]
    est = min(sketch[r][idx[r]] for r in range(rows))
    current_round = state["global_bytes"] // (quantum * fair_k)
    flow_round = est // quantum
    return max(0, flow_round - current_round), idx


def _effective_threshold(cfg: dict, round_shift: int) -> int:
    if cfg.get("marking_coupling") == "round_coupled":
        return max(int(cfg["min_threshold"]),
                   int(cfg["marking_threshold_k"])
                   - int(cfg["coupling_gain"]) * round_shift)
    return int(cfg["marking_threshold_k"])


def _account(state: dict, idx: List[int], pkt_len: int, rows: int) -> None:
    sketch = state["sketch"]
    for r in range(rows):
        sketch[r][idx[r]] += pkt_len
    state["global_bytes"] += pkt_len


def _pkt_len(scapy_pkt, byte_accounting: str) -> int:
    if byte_accounting == "unit_per_packet":
        return 1
    return len(bytes(scapy_pkt))           # on_wire_length (default)


# ── the composed R0..R7 sequence ─────────────────────────────────────────────
def step(scapy_pkt, ingress_port: int = 1, state: Optional[dict] = None) -> StepResult:
    """One packet step. `state` carries `config` (the seed-bound knobs) and the
    mutable count-min sketch; omit it (2-arg call) to use the module default
    state + fallback config for the oracle audit smoke path."""
    from scapy.all import IP, TCP, UDP

    if state is None:
        state = _DEFAULT_STATE
    cfg = _config(state)
    rows, width = int(cfg["sketch_rows"]), int(cfg["sketch_width"])
    _ensure_sketch(state, rows, width)

    # R0: wrong-port drop
    if ingress_port != int(cfg["access_port"]):
        return StepResult(False, "wrong_port")
    # R1: non-IPv4 action
    if IP not in scapy_pkt:
        if cfg.get("non_ipv4_action") == "drop":
            return StepResult(False, "not_ipv4")
        # passthrough: forward verbatim (no fairness/marking — no L3 fields)
        return StepResult(True, "passthrough", output_port=int(cfg["core_port"]),
                          ttl_decrement=0, next_hop_mac_dst=cfg["core_mac"])

    ip = scapy_pkt[IP]
    ttl = int(getattr(ip, "ttl", 0))
    src, dst = ip.src, ip.dst
    # diffserv byte = DSCP(6) << 2 | ECN(2); scapy IP.tos carries the full byte
    tos = int(getattr(ip, "tos", 0))
    ecn = tos & 0x3

    # R2: TTL exhausted (gate ttl > 0)
    if ttl <= 0:
        return StepResult(False, "ttl_exhausted")

    # R2 (eligibility): non-eligible L4 drop
    elig = cfg.get("eligibility_protocol")
    if elig != "any_l4":
        want = PROTO_NUM.get(elig)
        if want == 6 and TCP not in scapy_pkt:
            return StepResult(False, "not_eligible_l4")
        if want == 17 and UDP not in scapy_pkt:
            return StepResult(False, "not_eligible_l4")

    # ── STAGE 1: fairness admission ──────────────────────────────────────────
    src_int = _ip_to_int(src)
    round_shift, idx = _round_shift(state, cfg, src_int)
    pkt_len = _pkt_len(scapy_pkt, cfg.get("byte_accounting", "on_wire_length"))

    # R3: fairness out-of-window drop — NEVER reaches the marking stage
    if round_shift >= int(cfg["window"]):
        return StepResult(False, "out_of_window", round_shift=round_shift,
                          invariant_log=[("admission_precedes_marking",
                                          {"fairness_dropped": True,
                                           "marking_reached": False}),
                                         ("state_unchanged_on_reject",
                                          {"bytes_consumed": 0})])

    # admitted by fairness. account_on_admit: count BEFORE the marker runs.
    account_policy = cfg.get("account_policy", "account_on_admit")
    accounted = 0
    if account_policy == "account_on_admit":
        _account(state, idx, pkt_len, rows)
        accounted = pkt_len

    # ── STAGE 2: queue-depth ECN marking on the admitted packet ──────────────
    depth = int(cfg["depth_table"].get(dst, 0))
    k_eff = _effective_threshold(cfg, round_shift)
    congested = depth >= k_eff

    if congested and ecn == ECN_NOT_ECT:
        # R4: Not-ECT above threshold — RFC 3168 §6.1.2 tail-drop
        if cfg.get("not_ect_action", "drop") == "drop":
            # account_on_admit: bytes already counted above (and STAY counted).
            return StepResult(
                False, "not_ect_drop", round_shift=round_shift,
                depth_seen=depth, bytes_consumed=accounted,
                invariant_log=[("not_ect_never_marked", {"marked": False}),
                               ("account_reflects_admission_not_delivery",
                                {"policy": account_policy,
                                 "bytes_consumed": accounted})])
        # not_ect_action == passthrough -> fall through to forward (R7-style)

    if account_policy == "account_on_deliver":
        # only delivered packets consume bytes
        _account(state, idx, pkt_len, rows)
        accounted = pkt_len

    # decide egress ECN
    if congested and (ecn == ECN_ECT_1 or ecn == ECN_ECT_0):
        ecn_out = ECN_CE                                # R5: mark ECT -> CE
        reason = "mark"
        log = [("ipv4_checksum_validity_after_admit", {"fields": 3}),
               ("dscp_preserved_under_mark", {"dscp_touched": False})]
    elif congested and ecn == ECN_CE:
        ecn_out = ECN_CE                                # R6: preserve CE
        reason = "preserve_ce"
        log = [("ce_persistence_no_unmark", {"ecn": ECN_CE})]
    else:
        ecn_out = ecn                                   # R7: passthrough (incl. Not-ECT passthrough)
        reason = "passthrough"
        log = [("ce_persistence_no_unmark", {"ecn": ecn}),
               ("not_ect_never_marked", {"marked": False})]

    log.append(("fair_round_gap_bounded", {"round_shift": round_shift}))
    log.append(("ttl_quantum_one", {"decrement": 1}))
    return StepResult(
        True, reason, output_port=int(cfg["core_port"]), round_shift=round_shift,
        ecn_out=ecn_out, ttl_decrement=1, next_hop_mac_dst=cfg["core_mac"],
        bytes_consumed=accounted, depth_seen=depth, invariant_log=log)


# Module-level default state for the 2-arg step(pkt, port) audit smoke path.
# reset() clears it between canonical examples (which are cold single-packet
# cases). Real materialisation passes its own threaded `state`.
_DEFAULT_STATE: Dict[str, Any] = {}


def reset():
    _DEFAULT_STATE.clear()
