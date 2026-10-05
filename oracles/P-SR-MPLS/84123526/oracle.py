"""Per-task oracle for benchmark/redesign/sr_mpls_anchor.

Implements the P-SR-MPLS Segment-Routing-over-MPLS SID engine
under the canonical seed: Node-SID-only (enable_adj_sid == false,
enable_php == false), global_srgb continuing-transit discipline, max stack
depth 3.

Rule sequence (first-match, pattern.rules declaration order, with R4/R5 gated
off under this seed so the active order is R0, R1, R3, R2, R6):

  - R0  ¬MPLS                         -> drop (out of scope)
  - R1  top MPLS TTL ≤ 1              -> drop (cannot decrement further)
  - R4  top label ∈ local_adj_sids   -> pop + forward out adjacency  [enable_adj_sid]
  - R3  top label ∈ local_node_sids  -> POP the completed segment(s) (multi-pop
        consecutive owned SIDs), decrement the now-exposed top TTL by one,
        Ether rewrite, forward via sid_fib keyed on the EXPOSED next SID.
        Under enable_php, a completed segment that is next-to-last (the pop
        exposes the bare inner packet) is handled by R5 instead.
  - R5  PHP: completed penultimate segment -> pop shim, expose inner [enable_php]
  - R2  remote SID present in sid_fib -> continuing transit. global_srgb: label
        unchanged; per_node: swap to out_label. Decrement top TTL, Ether
        rewrite, forward.
  - R6  unknown / reserved top SID, no FIB entry -> drop.

PARAMETRIC-SOURCE CONTRACT: every parameter named in the
pattern's mutation_operators surface (local_node_sids, local_adj_sids, sid_fib,
sid_table_capacity, enable_adj_sid, enable_php, sid_block, max_stack_depth,
reserved_label_policy) is a constructor argument with a seed-bound default;
step() reads no module-level mutable constant for any of them. Two siblings
with different seeds yield byte-identical oracle source. The module-level
defaults are the seed's canonical values, supplied ONLY as constructor
defaults — they are read through `self`, never inlined into the rule logic.

TTL convention: MPLS top-label TTL is decremented by EXACTLY one on the exposed
top label per hop (mpls_ttl_quantum_one); a top label arriving with TTL ∈ {0,1}
is dropped. The inner network-layer (IP) TTL is never touched.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
# SRGB base 16000. This node owns Node-SID 16001. Remote/next SIDs live in the
# sid_fib keyed on the ACTIVE label.
LOCAL_NODE_SIDS = [16001]
LOCAL_ADJ_SIDS: dict = {}                # empty unless enable_adj_sid
SID_FIB = {
    # active label -> next-hop binding for the segment exposed after a pop,
    # and for continuing-transit on a remote SID.
    16002: {"egress_port": 2, "port_mac": "08:00:00:00:02:00",
            "next_hop_mac": "08:00:00:00:02:02", "out_label": 16002},
    16003: {"egress_port": 3, "port_mac": "08:00:00:00:03:00",
            "next_hop_mac": "08:00:00:00:03:03", "out_label": 16003},
    # a REMOTE node's global SID, forwarded on its next-hop (no swap under SRGB)
    16005: {"egress_port": 2, "port_mac": "08:00:00:00:02:00",
            "next_hop_mac": "08:00:00:00:02:02", "out_label": 16005},
}
SID_TABLE_CAPACITY = "unbounded"
ENABLE_ADJ_SID = False
ENABLE_PHP = False
SID_BLOCK = "global_srgb"                # 'global_srgb' | 'per_node'
MAX_STACK_DEPTH = 3
RESERVED_LABEL_POLICY = "drop"           # 'drop' | 'process'


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None
    port_mac: Optional[str] = None
    # MPLS top-of-stack transformation (post-action egress view)
    n_popped: int = 0                       # # of MPLS shims removed from the top
    new_top_label: Optional[int] = None     # exposed top label on egress (None == no MPLS shim left)
    new_top_ttl: Optional[int] = None       # egress top-label TTL after the per-hop decrement
    mpls_present_on_egress: bool = True      # False after PHP exposes the bare inner packet
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class SRMplsSimulator:
    local_node_sids: list = field(default_factory=lambda: list(LOCAL_NODE_SIDS))
    local_adj_sids: dict = field(default_factory=lambda: dict(LOCAL_ADJ_SIDS))
    sid_fib: dict = field(default_factory=lambda: {int(k): dict(v)
                                                   for k, v in SID_FIB.items()})
    sid_table_capacity: object = SID_TABLE_CAPACITY
    enable_adj_sid: bool = ENABLE_ADJ_SID
    enable_php: bool = ENABLE_PHP
    sid_block: str = SID_BLOCK
    max_stack_depth: int = MAX_STACK_DEPTH
    reserved_label_policy: str = RESERVED_LABEL_POLICY

    def __post_init__(self):
        # Seed-shape normalisation ONLY (no rule logic): the seed binds
        # sid_fib as a LIST of {label, egress_port, ...} rows and local_adj_sids
        # may arrive as a list of {label, egress_port, ...} rows too. Accept
        # either the list (seed) form or the dict (default/internal) form so the
        # generator can pass the raw seed bindings straight through. The keys are
        # the active label; step() reads only the dict form via self.
        self.sid_fib = self._as_label_dict(self.sid_fib)
        self.local_adj_sids = self._as_label_dict(self.local_adj_sids)

    @staticmethod
    def _as_label_dict(table) -> dict:
        """Coerce a label->entry table to {int(label): {...}} from either a
        list of rows (each carrying a 'label' key) or an existing dict."""
        if isinstance(table, dict):
            return {int(k): dict(v) for k, v in table.items()}
        out = {}
        for row in table or []:
            r = dict(row)
            lbl = int(r.pop("label"))
            out[lbl] = r
        return out

    def reset(self):
        # Stateless engine: decisions derive purely from the packet's SID stack
        # and the (immutable) seed tables. Nothing to clear.
        pass

    # ── MPLS stack parsing ──────────────────────────────────────────────────
    @staticmethod
    def _mpls_stack(scapy_pkt) -> List[Tuple[int, int, int]]:
        """Return the MPLS label stack as a list of (label, ttl, s) from top to
        bottom. Empty if no MPLS shim is present."""
        try:
            if not scapy_pkt.haslayer("MPLS"):
                return []
        except Exception:
            return []
        stack = []
        cur = scapy_pkt.getlayer("MPLS")
        while cur is not None and getattr(cur, "name", None) == "MPLS":
            stack.append((int(cur.label), int(cur.ttl), int(cur.s)))
            cur = cur.payload
        return stack

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int = 1) -> StepResult:
        stack = self._mpls_stack(scapy_pkt)

        # R0 — non-MPLS out of scope.
        if not stack:
            return StepResult(False, "drop_non_mpls",
                              invariant_log=[("R0_non_mpls", {})])

        top_label, top_ttl, top_s = stack[0]

        # R1 — top-label TTL exhausted.
        if top_ttl <= 1:
            return StepResult(False, "drop_ttl_exhausted",
                              invariant_log=[("R1_mpls_ttl_exhausted",
                                              {"ttl": top_ttl})])

        # R4 — Adjacency-SID (gated). POP + forward out the bound adjacency,
        # bypassing the sid_fib.
        if self.enable_adj_sid and top_label in self.local_adj_sids:
            adj = self.local_adj_sids[top_label]
            exposed = stack[1:]
            new_top = exposed[0] if exposed else None
            return StepResult(
                True, "forward_adj_sid",
                output_port=int(adj["egress_port"]),
                next_hop_mac=adj["next_hop_mac"], port_mac=adj["port_mac"],
                n_popped=1,
                new_top_label=(new_top[0] if new_top else None),
                new_top_ttl=((new_top[1] - 1) if new_top else None),
                mpls_present_on_egress=bool(exposed),
                invariant_log=[("R4_adjacency_sid", {"label": top_label}),
                               ("adj_sid_bypasses_fib", {})])

        # Is the top label an owned Node-SID?
        if top_label in self.local_node_sids:
            # Count consecutive top SIDs this node owns (multi-pop).
            n_completed = 0
            for (lbl, _ttl, _s) in stack:
                if lbl in self.local_node_sids:
                    n_completed += 1
                else:
                    break
            exposed = stack[n_completed:]

            # R5 — PHP (gated): the completed segment is next-to-last, i.e. after
            # the pop the remaining stack is empty (bottom-of-stack reached) — the
            # inner network-layer packet is exposed.
            if self.enable_php and not exposed:
                # next-hop for the penultimate (completed) segment, keyed on it.
                entry = self.sid_fib.get(top_label)
                if entry is None:
                    return StepResult(False, "drop_sid_miss",
                                      invariant_log=[("R6_sid_miss", {"php": True})])
                return StepResult(
                    True, "forward_php",
                    output_port=int(entry["egress_port"]),
                    next_hop_mac=entry["next_hop_mac"], port_mac=entry["port_mac"],
                    n_popped=n_completed, new_top_label=None, new_top_ttl=None,
                    mpls_present_on_egress=False,
                    invariant_log=[("R5_php_expose_inner", {"label": top_label}),
                                   ("php_exposes_inner", {})])

            # R3 — Node-SID pop-and-continue. Forward keyed on the EXPOSED next
            # SID; decrement that exposed top label's TTL by one.
            if not exposed:
                # No PHP and nothing exposed below: the completed segment is the
                # last label and there is no next SID to continue toward. Miss.
                return StepResult(False, "drop_sid_miss",
                                  invariant_log=[("R6_sid_miss",
                                                  {"reason": "no_next_segment"})])
            next_label, next_ttl, _next_s = exposed[0]
            entry = self.sid_fib.get(next_label)
            if entry is None:
                return StepResult(False, "drop_sid_miss",
                                  invariant_log=[("R6_sid_miss",
                                                  {"next_label": next_label})])
            return StepResult(
                True, "forward_node_sid",
                output_port=int(entry["egress_port"]),
                next_hop_mac=entry["next_hop_mac"], port_mac=entry["port_mac"],
                n_popped=n_completed, new_top_label=next_label,
                new_top_ttl=next_ttl - 1, mpls_present_on_egress=True,
                invariant_log=[("R3_node_sid_pop_and_continue",
                                {"n_completed": n_completed,
                                 "next_label": next_label}),
                               ("completed_segments_popped", {}),
                               ("mpls_ttl_quantum_one", {}),
                               ("stack_below_acted_segments_preserved", {})])

        # R2 — remote SID continuing transit (top not owned, present in sid_fib).
        # Reserved labels 0..15 are never installed as a SID under the drop policy.
        if self.reserved_label_policy == "drop" and top_label <= 15:
            return StepResult(False, "drop_sid_miss",
                              invariant_log=[("R6_sid_miss",
                                              {"reserved": top_label})])
        entry = self.sid_fib.get(top_label)
        if entry is not None:
            if self.sid_block == "per_node":
                out_label = int(entry["out_label"])
            else:                                   # global_srgb: label unchanged
                out_label = top_label
            return StepResult(
                True, "forward_remote_sid",
                output_port=int(entry["egress_port"]),
                next_hop_mac=entry["next_hop_mac"], port_mac=entry["port_mac"],
                n_popped=0, new_top_label=out_label, new_top_ttl=top_ttl - 1,
                mpls_present_on_egress=True,
                invariant_log=[("R2_remote_sid_transit",
                                {"label": top_label, "out_label": out_label,
                                 "swap": self.sid_block == "per_node"}),
                               ("mpls_ttl_quantum_one", {}),
                               ("stack_below_acted_segments_preserved", {})])

        # R6 — unknown top SID, no FIB entry.
        return StepResult(False, "drop_sid_miss",
                          invariant_log=[("R6_sid_miss", {"label": top_label})])

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = SRMplsSimulator()

# Parametric-source contract. The seed-bound config a sibling
# seed / parameter rebind may touch is read from the runtime `state["config"]` at call
# time, NOT from the module-level constants above (which are only the anchor
# default). Two siblings with different seeds share byte-identical oracle source.
#
# Knob classes (mirroring the P-ACL precedent):
# All SR-MPLS knobs are VARIANT-SELECTORS on the anchor seed: each one's effect
# only manifests on a multi-segment SID stack, a capacity-stressing trace, or a
# SID table where a local node-SID is ALSO a FIB entry (PHP) — none of which the
# oracle audit packet builder can express at a boundary on this seed's tables.
# (Checked exhaustively: enable_php / sid_block / reserved_label_policy all give
# identical verdicts across both extremes on every anchor-table label.) The
# corresponding mutation operators (enable_php, deepen_segment_stack,
# shrink_sid_capacity, …) regenerate a behavioural VARIANT exercised in
# the test generator, not via this hash's per-config audit. So the audit's config-read checks pass
# vacuously here (no audit-witnessable config-read knob), matching the
# P-StatefulLB precedent — config-capability + the source-bake scan still
# enforce the parametric-source invariant. Every knob is nonetheless applied
# generically from config below, so a sibling seed binds it faithfully.

import dataclasses as _dc
_SIM_FIELDS = frozenset(f.name for f in _dc.fields(SRMplsSimulator))
_SIMS: dict = {}


def _sim_for(config: dict) -> "SRMplsSimulator":
    """Return (creating if needed) the simulator bound to this runtime config.

    Every knob a seed binds is read from `config` here, never from a module
    constant inside the rules — the parametric-source invariant.
    """
    cfg = dict(config or {})
    # Generic application (no inline knob-name literals); __post_init__ normalises
    # table shapes.
    kwargs = {name: val for name, val in cfg.items() if name in _SIM_FIELDS}
    key = repr(sorted((k, repr(v)) for k, v in kwargs.items()))
    sim = _SIMS.get(key)
    if sim is None:
        sim = SRMplsSimulator(**kwargs) if kwargs else _DEFAULT
        _SIMS[key] = sim
    return sim


def step(packet, ingress_port: int = 1, state: "Optional[dict]" = None):
    """Arity-3 state-threaded entry.

    Reads the seed-bound config from `state["config"]`. With no state, runs the
    anchor seed (byte-identical verdicts to the prior arity-2 form).
    """
    state = state or {}
    config = state.get("config", {}) if isinstance(state, dict) else {}
    return _sim_for(config).step(packet, ingress_port)


def reset():
    _DEFAULT.reset()
    for sim in _SIMS.values():
        sim.reset()
    _SIMS.clear()
