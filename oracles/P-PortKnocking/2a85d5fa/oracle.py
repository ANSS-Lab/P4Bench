"""Per-task oracle for benchmark/redesign/port_knocking_anchor (P-PortKnocking).

Port-knocking / Single-Packet-Authorization gate in front of a protected TCP
service. Implements the pattern's first-match rule sequence:

  - R0  ¬header_present(ipv4)                                     → drop
  - R4  service-bound (dst==protected_service ∧ dport==protected_port)
        AND source AUTHORIZED (progress == len(knock_sequence))   → forward
        (reset progress to 0 first IF ¬authorize_persists)
  - R5  service-bound AND source NOT authorized                   → drop (default_action)
  - R1  non-service packet on the EXPECTED next knock port        → progress += 1;
        since_advance = 0; drop (knocks are never forwarded)
  - R3  non-service packet that is a WRONG knock-set port, OR (reset_strict),
        OR (expiry window elapsed)                                → progress = 0;
        since_advance = 0; drop
  - R2  non-service noise (lenient fall-through)                  → since_advance += 1
        (progress untouched); drop

STATEFUL. Per-source knock progress is keyed on hdr.ipv4.src and held in
module-level dicts, cleared by reset(). The test generator (and any harness
replaying prior_inputs) calls reset() once, then step()s each prior_input in
order before the graded packet, threading state across the packet TRAIN.

PARAMETRIC-SOURCE CONTRACT. Every parameter a parameter rebind may
touch — knock_sequence, knock_set, reset_strict, expiry_window,
authorize_persists, protected_service, protected_port, default_action,
state_capacity, eviction_policy — is read from state["config"] at runtime,
NEVER baked as a source-level constant. The seed's *values* enter only at
evaluation time via state["config"]; two siblings with different seeds produce
byte-identical oracle source, so the oracle audit is paid once per pattern and
parameter rebinding reuses this module unchanged.

ALL TIMING IS PACKET-COUNT DRIVEN. The BMv2 --use-files harness injects no
time_tick / wall-clock event (see the pattern's bridging_notes), so the optional knock-state expiry is measured in
intervening non-advancing PACKETS via the per-source since_advance counter,
never in seconds.

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)

    # ── convenience accessors for the test-generation materialiser ────────────────
    @property
    def admitted(self) -> bool:
        return self.decision == "forward"

    @property
    def output_port(self) -> Optional[int]:
        for port in self.output_packets:
            return int(port)
        return None


# ── Module-level MUTABLE runtime state (the only mutable state; reset()-able) ─
# Keyed per source IP, mirroring the pattern's knock_state entity
# (key: hdr.ipv4.src). Config/knobs are NOT here — they arrive via state.
_PROGRESS: Dict[str, int] = {}
_SINCE_ADVANCE: Dict[str, int] = {}
# Insertion order of source keys, for FIFO/LRU eviction under bounded capacity.
_ORDER: List[str] = []


def reset() -> None:
    """Clear per-source knock state. Called once before each test's train."""
    _PROGRESS.clear()
    _SINCE_ADVANCE.clear()
    _ORDER.clear()


# ── Default config mirrors the canonical D5.0 seed; overridden by state. ─────
_DEFAULT_CONFIG = {
    "knock_sequence":    [7000, 8000, 9000],
    "knock_set":         None,            # None → derived as set(knock_sequence)
    "reset_strict":      False,
    "expiry_window":     "unbounded",     # int | "unbounded"
    "authorize_persists": True,
    "protected_service": "10.0.0.100",
    "protected_port":    22,
    "service_egress_port": 2,             # egress for an authorized service packet
    "default_action":    "drop",
    "state_capacity":    "unbounded",     # int | "unbounded"
    "eviction_policy":   "none",          # none | FIFO | LRU
}


def _config(state: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update((state or {}).get("config", {}))
    return cfg


def _knock_set(cfg: Dict[str, Any]) -> set:
    ks = cfg.get("knock_set")
    if ks is None:
        return set(int(p) for p in cfg["knock_sequence"])
    return set(int(p) for p in ks)


def _expiry(cfg: Dict[str, Any]):
    w = cfg.get("expiry_window", "unbounded")
    if w is None or w == "unbounded":
        return None
    return int(w)


def _capacity(cfg: Dict[str, Any]):
    c = cfg.get("state_capacity", "unbounded")
    if c is None or c == "unbounded":
        return None
    return int(c)


# ── Packet introspection (Scapy + dict-style tolerant) ───────────────────────

def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        v = getattr(packet[layer], fname, default)
        return v if v is not None else default
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _has_ipv4(packet) -> bool:
    return _has_layer(packet, "IP") or _has_layer(packet, "ipv4")


def _ip(packet, fname, default=None):
    v = _field(packet, "IP", fname, None)
    if v is None:
        v = _field(packet, "ipv4", fname, None)
    return default if v is None else v


def _l4_dport(packet) -> Optional[int]:
    for layer in ("TCP", "UDP", "tcp", "udp"):
        v = _field(packet, layer, "dport", None)
        if v is not None:
            return int(v)
    return None


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


# ── per-source state bookkeeping with optional bounded-capacity eviction ─────

def _touch(src: str) -> None:
    """Record/refresh src in the insertion/recency order list."""
    if src in _ORDER:
        _ORDER.remove(src)
    _ORDER.append(src)


def _ensure_capacity(cfg: Dict[str, Any], incoming_src: str) -> None:
    """Evict per ${eviction_policy} when a NEW source would exceed capacity.

    An evicted source reverts to progress 0 (its entry is removed; it must
    re-knock). Only enforced when state_capacity is bounded.
    """
    cap = _capacity(cfg)
    if cap is None:
        return
    if incoming_src in _PROGRESS:
        return  # already tracked; no new slot needed
    policy = cfg.get("eviction_policy", "none")
    while len(_PROGRESS) >= cap and _ORDER:
        if policy == "LRU":
            victim = _ORDER.pop(0)        # least-recently-used at head (touch moves to tail)
        else:                              # FIFO (and default when policy unset but bounded)
            victim = _ORDER.pop(0)         # oldest insertion at head
        _PROGRESS.pop(victim, None)
        _SINCE_ADVANCE.pop(victim, None)


def _drop(new_state, log) -> StepResult:
    return StepResult(output_packets={}, new_state=new_state, decision="drop",
                      invariant_log=log)


# ── step() — oracle interface ────────────────────────────────────────────────

def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)

    seq = [int(p) for p in cfg["knock_sequence"]]
    seq_len = len(seq)
    kset = _knock_set(cfg)
    reset_strict = bool(cfg.get("reset_strict", False))
    expiry = _expiry(cfg)
    authorize_persists = bool(cfg.get("authorize_persists", True))
    protected_service = str(cfg["protected_service"])
    protected_port = int(cfg["protected_port"])
    service_egress = int(cfg.get("service_egress_port", 2))

    # R0 — non-IPv4 drop
    if not _has_ipv4(packet):
        return _drop(new_state, [("R0_non_ipv4", {})])

    src = str(_ip(packet, "src", "0.0.0.0"))
    dst = str(_ip(packet, "dst", "0.0.0.0"))
    dport = _l4_dport(packet)

    progress = int(_PROGRESS.get(src, 0))
    is_service = (dst == protected_service) and (dport == protected_port)

    # ── SERVICE gate first (R4 / R5) ───────────────────────────────────────
    if is_service:
        if progress == seq_len and seq_len > 0:
            # R4 — authorized: forward to the protected service.
            if not authorize_persists:
                _PROGRESS[src] = 0           # single-use grant: consume it
                _SINCE_ADVANCE[src] = 0
            out = _clone(packet)
            return StepResult(
                output_packets={service_egress: [out]},
                new_state=new_state,
                decision="forward",
                invariant_log=[("default_deny_protected", {"authorized": True}),
                               ("authorized_grant_persistence",
                                {"src": src, "persists": authorize_persists})],
            )
        # R5 — unauthorized service-bound traffic: default-deny.
        return _drop(new_state,
                     [("default_deny_protected",
                       {"src": src, "progress": progress, "len": seq_len})])

    # ── KNOCK state machine (R1 / R3 / R2) ──────────────────────────────────
    # Candidate knock: non-service IPv4 packet. A new source may need a slot.
    _ensure_capacity(cfg, src)
    progress = int(_PROGRESS.get(src, 0))   # re-read in case eviction removed it
    expected_next = seq[progress] if progress < seq_len else None

    # R1 — advance on the EXPECTED next port.
    if expected_next is not None and dport == expected_next:
        _PROGRESS[src] = progress + 1
        _SINCE_ADVANCE[src] = 0
        _touch(src)
        return _drop(new_state,
                     [("sequence_order_correctness",
                       {"src": src, "progress": progress + 1}),
                      ("per_source_isolation", {"src": src})])

    # R3 — reset: wrong knock-set port, OR strict mode, OR expiry elapsed.
    since = int(_SINCE_ADVANCE.get(src, 0))
    expiry_elapsed = (expiry is not None) and (since >= expiry - 1)
    if (dport in kset) or reset_strict or expiry_elapsed:
        if src in _PROGRESS or progress > 0:
            _PROGRESS[src] = 0
            _SINCE_ADVANCE[src] = 0
            _touch(src)
        log = [("wrong_knock_resets", {"src": src, "dport": dport})]
        if expiry_elapsed:
            log.append(("knock_state_expiry", {"src": src, "since_advance": since}))
        return _drop(new_state, log)

    # R2 — lenient noise: progress intact, only bump since_advance.
    if src in _PROGRESS:
        _SINCE_ADVANCE[src] = since + 1
        _touch(src)
    return _drop(new_state,
                 [("per_source_isolation", {"src": src, "noise": True})])
