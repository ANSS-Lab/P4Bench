"""Composed oracle for P-TelemetryFRR (INT telemetry ∘ LPM forward ∘ PURR
fast-reroute) at seed `telemetry_frr_anchor-default`.

Implements the single-pass telemetry router in the binding order
route/FRR-demux → stamp → forward:

  STAGE 1 — maintenance/liveness (PURR control surface). An IPv4 packet whose
    proto == maintenance_proto is a maintenance frame: it sets the addressed
    next hop's liveness register to down and is CONSUMED (not forwarded). This
    is the in-band way to drive the down state for grading. Liveness defaults to
    primary_initial_state.

  STAGE 2 — LPM forward (P-IPv4Routing). The fib is consulted on IP.dst. Each
    route names a PRIMARY egress port and a pre-installed BACKUP egress port
    plus a next-hop MAC. No match or ttl==0 drops.

  STAGE 3 — FRR demux (PURR). The primary next hop's liveness decides the
    egress: up -> primary_port; down -> backup_port (backup_on_down) or drop
    (drop_on_down).

  STAGE 4 — INT stamp + forward (P9). The ACTUAL chosen egress port is stamped
    into the telemetry field (IP.id, observable). TTL is decremented once,
    Ether.dst is rewritten to the next hop, the packet egresses.

Load-bearing composite contracts:
  - stamp_reflects_reroute: the telemetry value equals the egress R3 chose; a
    rerouted packet stamps the backup port, never the primary.
  - liveness_driven_demux: the same destination egresses primary or backup
    purely by the liveness bit a prior maintenance packet wrote.
  - stamp_after_demux: the stamp is written AFTER the demux selects the egress.
  - compound_checksum_validity: one IPv4 checksum recompute covers the IP.id
    stamp AND the TTL decrement.

PARAMETRIC-SOURCE CONTRACT: every mutation_operators knob is read from RUNTIME state/config at
evaluation time — `step(pkt, in_port, state)` builds a per-call simulator from
`state['config']` (maintenance_proto, telemetry_field_width, reroute_policy,
primary_initial_state, primary_port, backup_port, switch_id) and threads the
liveness register through `state` / `new_state` across the input sequence. The
module-level uppercase names are SEED DEFAULTS only — overridden by any config
key — so parameter rebinding reuses this same audited module without
regeneration. No behaviour-determining value is a source-level constant.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (overridden by state['config'] at runtime) ──────────
INGRESS_PORT = 1
PRIMARY_PORT = 2
BACKUP_PORT = 3
SWITCH_ID = 1
MAINTENANCE_PROTO = 253
TELEMETRY_FIELD_WIDTH = 16
PRIMARY_INITIAL_STATE = "up"        # 'up' | 'down'
REROUTE_POLICY = "backup_on_down"   # 'backup_on_down' | 'drop_on_down'

# LPM forwarding table: (subnet, prefix) ->
#   (next_hop_id, primary_port, backup_port, next_hop_mac).
# next_hop_id keys the liveness register so a maintenance packet to a next hop
# only affects routes that use it. Ports are filled from config per build.


def _default_fib(primary_port, backup_port):
    return [
        (("198.51.100.0", 24), ("NH-A", primary_port, backup_port, "08:00:00:00:02:02")),
        (("203.0.113.0", 24),  ("NH-B", primary_port, backup_port, "08:00:00:00:03:03")),
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
    # post-pipeline field values (None == field unchanged from input)
    new_ip_id: Optional[int] = None        # telemetry stamp (chosen egress port)
    telemetry_egress: Optional[int] = None  # the stamped egress (== output_port on forward)
    telemetry_switch_id: Optional[int] = None  # widen_telemetry_stack reads this
    reroute: Optional[bool] = None          # True if FRR diverted to backup
    liveness_seen: Optional[str] = None     # 'up' | 'down' the demux observed
    new_state: Optional[dict] = None        # liveness threaded forward across the sequence
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class TelemetryFRRSimulator:
    ingress_port: int = INGRESS_PORT
    primary_port: int = PRIMARY_PORT
    backup_port: int = BACKUP_PORT
    switch_id: int = SWITCH_ID
    maintenance_proto: int = MAINTENANCE_PROTO
    telemetry_field_width: int = TELEMETRY_FIELD_WIDTH
    primary_initial_state: str = PRIMARY_INITIAL_STATE
    reroute_policy: str = REROUTE_POLICY
    fib: list = field(default_factory=lambda: _default_fib(PRIMARY_PORT, BACKUP_PORT))

    # per-next-hop liveness: next_hop_id -> 'up' | 'down'
    liveness: dict = field(default_factory=dict)

    def reset(self):
        self.liveness = {}

    def _live(self, nh_id: str) -> str:
        return self.liveness.get(nh_id, self.primary_initial_state)

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP

        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4",
                              new_state={"liveness": dict(self.liveness)})

        ip = scapy_pkt[IP]
        ttl = int(ip.ttl)
        proto = int(ip.proto)

        # STAGE 1 — maintenance / liveness update (PURR control surface).
        if proto == self.maintenance_proto:
            nh = _lpm_lookup(ip.dst, self.fib)
            ilog = [("liveness_driven_demux", {"maintenance_dst": ip.dst})]
            if nh is not None:
                nh_id = nh[0]
                self.liveness[nh_id] = "down"
                ilog.append(("liveness_set_down", {"next_hop": nh_id}))
            # The maintenance packet is consumed (not forwarded). The decision
            # normalises to a DROP behaviour (no egress) for the evaluation
            # engine, while the `liveness_update` semantics live in
            # the invariant_log + the persisted down state.
            return StepResult(False, "drop_liveness_consumed", invariant_log=ilog,
                              new_state={"liveness": dict(self.liveness)})

        # STAGE 2 — LPM forward on IP.dst.
        ilog = []
        if ttl == 0:
            return StepResult(False, "drop_ttl", invariant_log=ilog,
                              new_state={"liveness": dict(self.liveness)})
        nh = _lpm_lookup(ip.dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", invariant_log=ilog,
                              new_state={"liveness": dict(self.liveness)})
        nh_id, prim_port, back_port, mac = nh

        # STAGE 3 — FRR demux on the primary's liveness.
        state = self._live(nh_id)
        ilog.append(("liveness_driven_demux", {"next_hop": nh_id, "state": state}))
        if state == "up":
            egress = prim_port
            rerouted = False
        else:
            if self.reroute_policy == "backup_on_down":
                egress = back_port
                rerouted = True
            else:  # drop_on_down
                return StepResult(False, "drop_primary_down",
                                  liveness_seen=state, invariant_log=ilog,
                                  new_state={"liveness": dict(self.liveness)})

        # STAGE 4 — INT stamp (actual egress) + forward.
        ilog.append(("stamp_after_demux", {"stamp": egress}))
        ilog.append(("stamp_reflects_reroute", {"egress": egress, "rerouted": rerouted}))
        ilog.append(("compound_checksum_validity",
                     {"stamp": True, "ttl_decremented": True}))
        decision = "forward_backup_stamped" if rerouted else "forward_primary_stamped"
        return StepResult(
            True, decision, output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, new_ip_id=egress, telemetry_egress=egress,
            telemetry_switch_id=self.switch_id,
            reroute=rerouted, liveness_seen=state, invariant_log=ilog,
            new_state={"liveness": dict(self.liveness)})

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# ── config-driven construction (parametric-source invariant) ────────────────

def _sim_from_config(cfg: dict) -> "TelemetryFRRSimulator":
    """Build a simulator whose every behaviour-determining knob is read from the
    runtime config dict, falling back to the seed default only when a key is
    absent. This is what makes the oracle config-responsive and keeps
    no seed value authoritative as a source constant."""
    cfg = cfg or {}
    primary_port = int(cfg.get("primary_port", PRIMARY_PORT))
    backup_port = int(cfg.get("backup_port", BACKUP_PORT))
    return TelemetryFRRSimulator(
        ingress_port=int(cfg.get("ingress_port", INGRESS_PORT)),
        primary_port=primary_port,
        backup_port=backup_port,
        switch_id=int(cfg.get("switch_id", SWITCH_ID)),
        maintenance_proto=int(cfg.get("maintenance_proto", MAINTENANCE_PROTO)),
        telemetry_field_width=int(cfg.get("telemetry_field_width", TELEMETRY_FIELD_WIDTH)),
        primary_initial_state=str(cfg.get("primary_initial_state", PRIMARY_INITIAL_STATE)),
        reroute_policy=str(cfg.get("reroute_policy", REROUTE_POLICY)),
        fib=_default_fib(primary_port, backup_port),
    )


# Module-level adapter for adopt/audit.
_DEFAULT = TelemetryFRRSimulator()


def step(scapy_pkt, in_port: int = 1, state=None):
    """Module-level adapter. `state` may carry:
      - state['config'] : {maintenance_proto, telemetry_field_width,
            reroute_policy, primary_initial_state, primary_port, backup_port,
            switch_id, ...} — overrides the seed defaults at runtime so a
            constant-baked oracle is impossible (parametric-source invariant).
      - state['liveness'] : the per-next-hop register threaded across a packet
            sequence (so a prior maintenance packet's down state persists).
    A fresh per-call simulator is built from config; the returned StepResult
    carries new_state['liveness'] so the audit/eval driver threads it forward.
    """
    if isinstance(state, dict):
        cfg = state.get("config", {}) or {}
        sim = _sim_from_config(cfg) if cfg else TelemetryFRRSimulator()
        live = state.get("liveness")
        if isinstance(live, dict):
            sim.liveness = dict(live)
        return sim.step(scapy_pkt, in_port)
    global _DEFAULT
    if not isinstance(_DEFAULT, TelemetryFRRSimulator):
        _DEFAULT = TelemetryFRRSimulator()
    return _DEFAULT.step(scapy_pkt, in_port)


def reset():
    global _DEFAULT
    _DEFAULT = TelemetryFRRSimulator()
