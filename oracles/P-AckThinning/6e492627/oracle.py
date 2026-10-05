"""Oracle for P-AckThinning (TCP ACK filtering / thinning, RFC 3135 §2.4.1) at
seed `ack_thinning_anchor-default`.

A TCP performance-enhancing-proxy (PEP) function for bandwidth-asymmetric
links: the reverse path carries a flood of pure-ACKs whose cumulative
acknowledgement is redundant. The proxy maintains, per connection, the highest
cumulative ACK number already FORWARDED and DROPS any pure-ACK whose ack-number
does not advance that watermark, while forwarding every advancing ACK, every
data segment, and every control segment (SYN/FIN/RST).

First-match rule firing (pattern.rules declaration order):

  R0  non-TCP/IPv4              -> forward (out of scope; never thinned)
  R1  TCP with payload_len > 0  -> forward (data; never thinnable)
  R2  payload-empty SYN/FIN/RST -> forward (handshake/teardown preserved)
  R3  pure-ACK, flow unseen     -> bind watermark to ack-no; forward (fail-open)
  R4  pure-ACK, ackNo > w       -> raise watermark; reset dup counter; forward
  R5  pure-ACK, ackNo <= w      -> inc dup counter;
                                   forward if dup_seen <= dup_ack_budget else drop

  A "pure ACK" = TCP, ACK flag set, payload_len == 0, no SYN/FIN/RST.
  payload_len = ipv4.totalLen - ipv4.ihl*4 - tcp.dataOffset*4.

The one-sided correctness contract (no_false_thinning): an ACK that ADVANCES
the cumulative ack (ackNo strictly greater than the stored watermark) is NEVER
dropped. The watermark only ever rises (ack_watermark_monotone) — R5 leaves it
unchanged.

PARAMETRIC-SOURCE CONTRACT: every mutable knob
(thinning_direction, dup_ack_budget, flow_table_capacity, eviction_policy,
faithfulness) is a constructor argument with a seed-bound default; step()
reads no module-level mutable constant for these. Module constants below are
only TCP flag bit positions (protocol codes no operator touches). Two siblings
with different seeds yield byte-identical oracle source. The watermark table
lives on the instance and is cleared by reset(), so a prior_inputs sequence
accumulates per-flow state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── protocol codes (no mutation operator touches these) ─────────────────────
_FLAG_FIN = 0x01
_FLAG_SYN = 0x02
_FLAG_RST = 0x04
_FLAG_ACK = 0x10
_PROTO_TCP = 6


# ── step result ─────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    # watermark state observable after the packet (for test cross-checks)
    watermark: Optional[int] = None
    dup_seen: Optional[int] = None
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class AckThinningSimulator:
    # ── seed-bound, mutable knobs (read from state, never baked) ──────────
    thinning_direction: str = "reverse_only"      # 'reverse_only' | 'bidirectional'
    dup_ack_budget: int = 0                        # forward N non-advancing dups before thinning
    flow_table_capacity: object = "unbounded"      # int or "unbounded"
    eviction_policy: str = "none"                  # 'none' | 'LRU' | 'FIFO'
    faithfulness: str = "D5.0_exact"              # 'D5.0_exact' | 'D5.1_hashed'

    # forwarding decision for any non-thinnable segment (always forward in v1.0)
    forward_port: int = 2

    # ── per-flow state: flow_key -> {watermark, dup_seen} ────────────────────
    table: dict = field(default_factory=dict)
    order: list = field(default_factory=list)     # LRU/FIFO recency (oldest first)

    def reset(self):
        self.table = {}
        self.order = []

    # ── flow key extraction ──────────────────────────────────────────────────
    def _flow_key(self, ip_src, ip_dst, sport, dport):
        """The acknowledgement-direction 4-tuple.

        reverse_only  -> key on the directed 4-tuple as observed (the ACK
                         packets travelling the reverse path).
        bidirectional -> key on a direction-canonical tuple so both halves of
                         a connection share nothing across direction; here we
                         keep the directed tuple per half (the harden operator
                         simply doubles the live keys).
        """
        return (ip_src, ip_dst, sport, dport, self.thinning_direction)

    # ── capacity / eviction ───────────────────────────────────────────────────
    def _touch(self, key):
        if key in self.order:
            self.order.remove(key)
        self.order.append(key)

    def _evict_if_full(self):
        cap = self.flow_table_capacity
        if cap == "unbounded":
            return
        cap = int(cap)
        while len(self.table) >= cap and self.eviction_policy in ("LRU", "FIFO") and self.order:
            victim = self.order.pop(0)
            self.table.pop(victim, None)

    # ── step ──────────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int = 1) -> StepResult:
        from scapy.all import IP, TCP

        fwd_decision = "forward"

        # R0 — non-TCP/IPv4 passes through unmodified (never thinned).
        if IP not in scapy_pkt or int(scapy_pkt[IP].proto) != _PROTO_TCP or TCP not in scapy_pkt:
            return StepResult(True, "forward_non_tcp", output_port=self.forward_port,
                              invariant_log=[("non_ack_pass_through", {"reason": "non_tcp"})])

        ip = scapy_pkt[IP]
        tcp = scapy_pkt[TCP]
        flags = int(tcp.flags)
        payload_len = int(ip.len) - int(ip.ihl) * 4 - int(tcp.dataofs) * 4
        if payload_len < 0:
            payload_len = 0

        is_syn = bool(flags & _FLAG_SYN)
        is_fin = bool(flags & _FLAG_FIN)
        is_rst = bool(flags & _FLAG_RST)
        is_ack = bool(flags & _FLAG_ACK)

        # R1 — a segment carrying payload is never thinnable.
        if payload_len > 0:
            return StepResult(True, "forward_data", output_port=self.forward_port,
                              invariant_log=[("non_ack_pass_through", {"reason": "payload"})])

        # R2 — payload-empty control segment (SYN/FIN/RST) always forwards.
        if is_syn or is_fin or is_rst:
            return StepResult(True, "forward_control", output_port=self.forward_port,
                              invariant_log=[("non_ack_pass_through", {"reason": "control"})])

        # Not a pure ACK (ACK flag clear, no payload, no control) -> forward.
        # e.g. a payload-empty segment with all flags clear is not thinnable
        # (R5 requires the ACK flag set).
        if not is_ack:
            return StepResult(True, "forward_non_ack", output_port=self.forward_port,
                              invariant_log=[("non_ack_pass_through", {"reason": "no_ack_flag"})])

        # ── pure ACK: thinning decision keyed on the per-flow watermark ──────
        ackno = int(tcp.ack)
        key = self._flow_key(ip.src, ip.dst, int(tcp.sport), int(tcp.dport))
        entry = self.table.get(key)

        # R3 — first sight (or evicted): bind watermark, forward (fail-open).
        if entry is None:
            self._evict_if_full()
            self.table[key] = {"watermark": ackno, "dup_seen": 0}
            self._touch(key)
            return StepResult(True, "forward_first_ack", output_port=self.forward_port,
                              watermark=ackno, dup_seen=0,
                              invariant_log=[("ack_watermark_monotone",
                                              {"bind": ackno})])

        w = entry["watermark"]
        # R4 — advancing ACK: raise watermark, reset dup counter, forward.
        if ackno > w:
            entry["watermark"] = ackno
            entry["dup_seen"] = 0
            self._touch(key)
            return StepResult(True, "forward_advancing_ack", output_port=self.forward_port,
                              watermark=ackno, dup_seen=0,
                              invariant_log=[("no_false_thinning",
                                              {"old": w, "new": ackno})])

        # R5 — redundant / stale ACK (ackNo <= watermark): dup-budget gate.
        entry["dup_seen"] += 1
        self._touch(key)
        if entry["dup_seen"] <= int(self.dup_ack_budget):
            return StepResult(True, "forward_dup_within_budget", output_port=self.forward_port,
                              watermark=w, dup_seen=entry["dup_seen"],
                              invariant_log=[("ack_watermark_monotone", {"hold": w})])
        return StepResult(False, "drop_redundant_ack",
                          watermark=w, dup_seen=entry["dup_seen"],
                          invariant_log=[("ack_watermark_monotone", {"hold": w})])

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = AckThinningSimulator()


def _apply_config(sim: "AckThinningSimulator", state) -> None:
    """Thread runtime config (parametric-source contract) onto the
    simulator. Only the knobs this single oracle source BRANCHES on at runtime
    are read here — the dup-ACK budget (R5's forward-vs-drop gate) and the
    egress port. The remaining mutation knobs (thinning_direction,
    flow_table_capacity, eviction_policy, faithfulness) are variant-selectors:
    each selects a structurally different oracle that is REGENERATED, not driven
    by config on this hash, so they are intentionally not read here. Absent keys
    keep the canonical seed default, so the anchor seed's behaviour is unchanged
    while a dup-budget parameter rebind is honoured without regeneration."""
    if not isinstance(state, dict):
        return
    cfg = state.get("config") if isinstance(state.get("config"), dict) else {}
    if "dup_ack_budget" in cfg:
        sim.dup_ack_budget = cfg["dup_ack_budget"]
    if "forward_port" in cfg:
        sim.forward_port = cfg["forward_port"]


def step(scapy_pkt, in_port: int = 1, state=None):
    _apply_config(_DEFAULT, state)
    return _DEFAULT.step(scapy_pkt, in_port)


def reset():
    _DEFAULT.reset()
