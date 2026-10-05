"""Python oracle for P-NetPaxos at seed
`netpaxos_acceptor_anchor-default` (single-slot Paxos ACCEPTOR, accept_predicate
== ge, default field widths).

Implements the pattern's first-match rule sequence
over a Paxos consensus message carried in a custom UDP-payload "paxos" header
(msg_type, inst, rnd, vrnd, vvalue):

  R0  ¬paxos                      -> DROP (out of scope; plain IP/UDP, ARP, ...)
  R1  PHASE_1A ∧ rnd > stored.rnd -> PROMISE: adopt rnd, echo stored (vrnd,
                                     vvalue), FORWARD on promise_egress.
  R2  PHASE_1A ∧ rnd <= stored.rnd-> DROP (stale prepare).
  R3  PHASE_2A ∧ accept_ok        -> ACCEPTED: store (vrnd=r, vvalue=v), bump
                                     rnd to r, echo vrnd=r, FORWARD learner_egress.
  R4  PHASE_2A ∧ ¬accept_ok       -> DROP (stale accept).
  R5  PROMISE | ACCEPTED          -> DROP (acceptor outputs, never inputs).

accept_ok(stored, r, pred): r >= stored under 'ge' (textbook, canonical seed),
r > stored under 'gt' (strict variant).

PARSING. The paxos header is a UDP payload that the oracle audit packet builder
(layers limited to {Ether, IP, TCP, UDP, ICMP, ARP}) cannot synthesise, so the
fields are read defensively from the raw UDP payload bytes when the UDP dest
port is the paxos port. A frame with no paxos payload (the audit's base-layer
frames, ARP, plain IP/UDP) falls through R0 and DROPS — which is exactly the
contract the audit exercises. The paxos-bearing paths (R1..R5) are driven by
the test generator, which builds the paxos header (via the task's Paxos scapy
layer / raw bytes).

PARAMETRIC-SOURCE CONTRACT: every mutable knob the pattern
declares — n_slots, round_width, value_width, round_zero, value_none,
accept_predicate, enforce_round_monotonic — is a constructor argument with a
seed-bound default; step() reads no module-level mutable constant for them.
Two siblings with different seeds yield byte-identical oracle source. The
per-slot register state lives on the instance and is cleared by reset(), so a
prior_inputs sequence accumulates promised/accepted state.

EGRESS OBSERVABILITY. Consensus messages ingress on the proposer-facing port;
PROMISE forwards toward the proposer/coordinator on `promise_egress` and
ACCEPTED toward the learners on `learner_egress`, both distinct from the
ingress port so each forward is observable (egress-on-ingress
rule).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


# ── paxos message-type codes (protocol constants; no mutation operator touches these)
PHASE_1A = 0          # prepare  (proposer -> acceptor)
PHASE_2A = 1          # accept   (proposer -> acceptor)
PROMISE = 2           # acceptor -> proposer  (reply to PHASE_1A)
ACCEPTED = 3          # acceptor -> learner   (reply to PHASE_2A)

# Default UDP port carrying the paxos header (protocol constant, not a mutable knob).
PAXOS_UDP_PORT = 34952

# Header byte layout (big-endian) when round_width==16, value_width==32:
#   msg_type:1  inst:2  rnd:2  vrnd:2  vvalue:4   = 11 bytes.
# Parsing is width-driven from the seed so widen_fields stays parametric.


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
N_SLOTS = 1
ROUND_WIDTH = 16
VALUE_WIDTH = 32
ROUND_ZERO = 0
VALUE_NONE = 0
ACCEPT_PREDICATE = "ge"          # 'ge' (textbook) | 'gt' (strict)
ENFORCE_ROUND_MONOTONIC = False

PROMISE_EGRESS = 2               # toward proposer / coordinator
LEARNER_EGRESS = 3               # toward learners
INGRESS_PORT = 1                 # proposer-facing ingress


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    # observable paxos-header rewrites on a forwarded message (None == field
    # carried verbatim / not applicable on a drop):
    new_msg_type: Optional[int] = None
    new_vrnd: Optional[int] = None
    new_vvalue: Optional[int] = None
    invariant_log: list = field(default_factory=list)


# ── packet introspection (scapy + raw-bytes tolerant) ───────────────────────

def _udp_dport(pkt) -> Optional[int]:
    try:
        from scapy.all import UDP
        if pkt.haslayer(UDP):
            return int(pkt.getlayer(UDP).dport)
    except Exception:
        pass
    return None


def _paxos_fields(pkt, round_width: int, value_width: int) -> Optional[dict]:
    """Return {msg_type, inst, rnd, vrnd, vvalue} parsed from the paxos header,
    or None if the frame carries no paxos payload.

    Prefers a bound `Paxos` scapy layer (test-generator path); falls back to
    parsing the raw UDP payload bytes (defensive)."""
    # 1) bound scapy layer, if the custom_headers module is loaded.
    try:
        if pkt.haslayer("Paxos"):
            lay = pkt.getlayer("Paxos")
            return {
                "msg_type": int(lay.msg_type),
                "inst": int(lay.inst),
                "rnd": int(lay.rnd),
                "vrnd": int(lay.vrnd),
                "vvalue": int(lay.vvalue),
            }
    except Exception:
        pass

    # 2) raw UDP-payload bytes on the paxos port.
    if _udp_dport(pkt) != PAXOS_UDP_PORT:
        return None
    try:
        from scapy.all import UDP, Raw
        udp = pkt.getlayer(UDP)
        payload = bytes(udp.payload) if udp is not None else b""
        if not payload and pkt.haslayer(Raw):
            payload = bytes(pkt.getlayer(Raw).load)
    except Exception:
        return None
    rw = round_width // 8
    vw = value_width // 8
    need = 1 + 2 + rw + rw + vw
    if len(payload) < need:
        return None
    off = 0
    msg_type = payload[off]; off += 1
    inst = int.from_bytes(payload[off:off + 2], "big"); off += 2
    rnd = int.from_bytes(payload[off:off + rw], "big"); off += rw
    vrnd = int.from_bytes(payload[off:off + rw], "big"); off += rw
    vvalue = int.from_bytes(payload[off:off + vw], "big"); off += vw
    return {"msg_type": msg_type, "inst": inst, "rnd": rnd,
            "vrnd": vrnd, "vvalue": vvalue}


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class NetPaxosSimulator:
    n_slots: int = N_SLOTS
    round_width: int = ROUND_WIDTH
    value_width: int = VALUE_WIDTH
    round_zero: int = ROUND_ZERO
    value_none: int = VALUE_NONE
    accept_predicate: str = ACCEPT_PREDICATE
    enforce_round_monotonic: bool = ENFORCE_ROUND_MONOTONIC
    promise_egress: int = PROMISE_EGRESS
    learner_egress: int = LEARNER_EGRESS

    # per-slot register state: inst -> (rnd, vrnd, vvalue)
    slots: Dict[int, Tuple[int, int, int]] = field(default_factory=dict)

    def reset(self):
        self.slots = {}

    def _cell(self, inst: int) -> Tuple[int, int, int]:
        return self.slots.get(inst, (self.round_zero, self.round_zero, self.value_none))

    def _accept_ok(self, stored_rnd: int, r: int) -> bool:
        if self.accept_predicate == "gt":
            return r > stored_rnd
        return r >= stored_rnd          # 'ge', textbook

    def step(self, scapy_pkt, in_port: int) -> StepResult:
        px = _paxos_fields(scapy_pkt, self.round_width, self.value_width)

        # R0 — no paxos header: out of scope, drop.
        if px is None:
            return StepResult(False, "drop_non_paxos",
                              invariant_log=[("R0_non_paxos_drop", {})])

        inst = px["inst"]
        mtype = px["msg_type"]

        # no_orphan_slots: inst must index a live cell in [0, n_slots).
        if inst < 0 or inst >= self.n_slots:
            return StepResult(False, "drop_inst_out_of_range",
                              invariant_log=[("no_orphan_slots", {"inst": inst})])

        stored_rnd, stored_vrnd, stored_vvalue = self._cell(inst)

        # R5 — acceptor outputs received as inputs: drop, no state change.
        if mtype in (PROMISE, ACCEPTED):
            return StepResult(False, "drop_reply_message",
                              invariant_log=[("R5_reply_message_drop", {"msg_type": mtype})])

        # ── PHASE-1A (prepare) ────────────────────────────────────────────
        if mtype == PHASE_1A:
            if px["rnd"] > stored_rnd:
                # R1 — promise: adopt rnd, echo the stored accepted pair.
                self.slots[inst] = (px["rnd"], stored_vrnd, stored_vvalue)
                return StepResult(
                    True, "forward_promise", output_port=self.promise_egress,
                    new_msg_type=PROMISE,
                    new_vrnd=stored_vrnd, new_vvalue=stored_vvalue,
                    invariant_log=[
                        ("R1_phase1a_promise", {"inst": inst, "rnd": px["rnd"]}),
                        ("promise_round_safety", {"rnd": px["rnd"]}),
                        ("accepted_pair_persistence",
                         {"vrnd": stored_vrnd, "vvalue": stored_vvalue}),
                    ])
            # R2 — stale prepare (r <= stored rnd): drop, no state change.
            return StepResult(False, "drop_stale_prepare",
                              invariant_log=[("R2_phase1a_stale_drop",
                                              {"inst": inst, "rnd": px["rnd"]})])

        # ── PHASE-2A (accept) ─────────────────────────────────────────────
        if mtype == PHASE_2A:
            if self._accept_ok(stored_rnd, px["rnd"]):
                # R3 — accept: store (vrnd=r, vvalue=v), bump rnd to r.
                self.slots[inst] = (px["rnd"], px["rnd"], px["vvalue"])
                return StepResult(
                    True, "forward_accepted", output_port=self.learner_egress,
                    new_msg_type=ACCEPTED,
                    new_vrnd=px["rnd"], new_vvalue=px["vvalue"],
                    invariant_log=[
                        ("R3_phase2a_accept", {"inst": inst, "rnd": px["rnd"],
                                               "vvalue": px["vvalue"]}),
                        ("promise_round_safety", {"rnd": px["rnd"]}),
                    ])
            # R4 — stale accept: drop, no state change.
            return StepResult(False, "drop_stale_accept",
                              invariant_log=[("R4_phase2a_stale_drop",
                                              {"inst": inst, "rnd": px["rnd"]})])

        # any other msg_type: out of role, drop.
        return StepResult(False, "drop_non_paxos",
                          invariant_log=[("R0_non_paxos_drop", {"msg_type": mtype})])

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# ── parametric-source config wiring ─────────────────────────────────────────
# The mutable knobs are NetPaxosSimulator constructor args; the module-level
# step() threads them from runtime state["config"] so a seed rebind reuses this
# same source. When no config is supplied the seed-bound defaults
# above apply. The active simulator is rebuilt from config on reset / config
# change and reused across a packet sequence so per-slot register state threads.
# Only knobs the step logic actually branches on are threaded here. A knob like
# enforce_round_monotonic is a forward-declared variant selector that gates a
# stricter sibling regenerated as a different oracle (it has no behavioural
# effect on THIS source), so — like `faithfulness` — it is exercised across
# oracle regeneration, not config-threaded on this hash.
_CONFIG_KEYS = (
    "n_slots", "round_width", "value_width", "round_zero", "value_none",
    "accept_predicate", "promise_egress", "learner_egress",
)


def _hashable(v):
    return tuple(v) if isinstance(v, list) else v


def _simulator_from_config(cfg):
    kwargs = {k: cfg[k] for k in _CONFIG_KEYS if k in (cfg or {})}
    return NetPaxosSimulator(**kwargs)


_ACTIVE = NetPaxosSimulator()
_ACTIVE_CFG = None


def step(scapy_pkt, in_port: int = 1, state=None):
    """Process one packet. `state["config"]` (when present) supplies the
    seed-bound knobs; absent => module defaults. Per-slot state threads on the
    active simulator across a sequence until reset() or a config change."""
    global _ACTIVE, _ACTIVE_CFG
    cfg = (state or {}).get("config") if isinstance(state, dict) else None
    if cfg is not None:
        key = tuple(sorted((k, _hashable(cfg[k])) for k in _CONFIG_KEYS if k in cfg))
        if key != _ACTIVE_CFG:
            _ACTIVE = _simulator_from_config(cfg)
            _ACTIVE_CFG = key
    return _ACTIVE.step(scapy_pkt, in_port)


def reset():
    global _ACTIVE, _ACTIVE_CFG
    _ACTIVE = NetPaxosSimulator()
    _ACTIVE_CFG = None
