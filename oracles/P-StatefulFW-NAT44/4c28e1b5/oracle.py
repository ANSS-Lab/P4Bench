"""Pure-Python mirror of the chained Stateful-FW + NAPT ingress pipeline.
Used to derive test expectations; not loaded by the benchmark runner.

This simulator implements P-StatefulFW-NAT44 at faithfulness =
D5.1_reflexive_dynamic_nat (the discriminating-band default seed):

  - Single switch s1 with two ports: s1.internal (private subnet) and
    s1.external (public Internet).
  - One internal subnet (${internal_subnet}); one public IP
    (${public_ip}).
  - Mode = dynamic: the data plane allocates external L4 ports from
    ${port_pool_range} on the first outbound packet of every unseen
    5-tuple, and installs BOTH halves of the conntrack pair atomically.
  - Conntrack capacity = ${conntrack_capacity}; eviction = timeout
    (per ${idle_timeout_s}).
  - Reflexive admission only: inbound packets are admitted iff
    (a) IP.dst == ${public_ip}; AND
    (b) (public_ip, dport, proto) has a conntrack entry; AND
    (c) the keyed connection is `established` (= installed by the
        outbound side, never from an inbound packet).
  - No TCP state machine and no Tier-3 hardening (uRPF, TTL-bound, frag
    drop) at this faithfulness; those are gated on D5.2.
  - NAPT scope is TCP / UDP only — ICMP and non-IPv4 are dropped on
    either side.

The simulator is self-contained enough to serve as the canonical
audited oracle (content-addressed under
oracles/P-StatefulFW-NAT44/<sha256[:8]>/oracle.py); it
exposes a `step(packet, ingress_port, state) -> StepResult` interface
that reads every mutation-operator knob from state, satisfying the
parametric-source contract (so parameter rebinding can
re-use this audited module without regeneration).

PARAMETRIC-SOURCE CONTRACT: the canonical entrypoint is the MODULE-LEVEL
`step(scapy_pkt, ingress_port, state)` at the bottom of this file. Every
behaviour-determining mutation_operators knob is read from
`state["config"]` at runtime — "internal_subnet", "public_ip", "mode",
"port_pool_range", "conntrack_capacity", "eviction_policy",
"idle_timeout_s", "persistence_strict" — falling back to the seed default
only when a key is absent. The runtime
conntrack tables are threaded forward across a packet sequence via the
returned StepResult.new_state, so multi-packet reflexive examples
accumulate state while config remains the parametric channel. The
module-level uppercase names and dataclass defaults are SEED DEFAULTS
only — overridden by any config key — so no behaviour-determining value
is an authoritative source-level constant.
"""
from __future__ import annotations

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional


# ── Topology / addressing constants (mirror the seed defaults) ────────────

PUBLIC_IP    = "203.0.113.1"
INTERNAL_NET = "10.0.1.0/24"

INTERNAL_PORT_NAME = "s1.internal"
EXTERNAL_PORT_NAME = "s1.external"

INTERNAL_HOST_IP   = "10.0.1.5"
EXTERNAL_HOST_IP   = "8.8.8.8"
INTERNAL_HOST_MAC  = "00:00:00:00:01:05"
EXTERNAL_HOST_MAC  = "00:00:00:00:08:08"
SWITCH_MAC_INT     = "00:00:00:00:00:01"
SWITCH_MAC_EXT     = "00:00:00:00:00:02"

PROTO_TCP = 6
PROTO_UDP = 17


# ── Step result ────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    """Outcome of one simulator step.

    `reason` enumerates the rule that fired (matching the pattern's
    rule ids R1..R12 from patterns/P-StatefulFW-NAT44/pattern.yaml).
    """
    admitted:     bool
    reason:       str
    side:         Optional[str] = None     # "outbound" | "inbound"
    output_port:  Optional[str] = None     # s1.internal | s1.external
    new_ip_src:   Optional[str] = None
    new_ip_dst:   Optional[str] = None
    new_l4_sport: Optional[int] = None
    new_l4_dport: Optional[int] = None
    new_eth_dst:  Optional[str] = None
    ttl_delta:    int = 0                  # canonical: -1 on forward, 0 on drop
    # Runtime state threaded forward across a packet sequence by the
    # audit/eval driver (OracleAudit._drive merges this into cur_state).
    # Carries {config, runtime} so the conntrack table accumulates across
    # packets within one example while config stays the parametric channel.
    new_state:    Optional[dict] = None


# ── Helpers ────────────────────────────────────────────────────────────────

def _ip_in_subnet(ip: str, cidr: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


def _l4_ports(scapy_pkt) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Return (proto, sport, dport) extracted from scapy_pkt; (None, None,
    None) if the packet is neither TCP nor UDP."""
    from scapy.all import TCP, UDP
    if TCP in scapy_pkt:
        return PROTO_TCP, int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
    if UDP in scapy_pkt:
        return PROTO_UDP, int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
    return None, None, None


# ── Connection entity ──────────────────────────────────────────────────────

@dataclass
class ConnEntry:
    """One row of the unified conntrack table.

    Holds BOTH the firewall verdict (established, last_seen, tcp_state)
    AND the NAT mapping (public_ip, ext_port) — this is the key
    composition ingredient (see pattern.yaml).
    """
    src_ip:     str
    src_port:   int
    proto:      int
    public_ip:  str
    ext_port:   int
    established: bool = True
    last_seen:   int = 0
    tcp_state:   str = "NEW"     # informational at D5.1; enforced at D5.2

    def conn_key(self) -> tuple:
        return (self.src_ip, self.src_port, self.proto)

    def inbound_key(self) -> tuple:
        return (self.public_ip, self.ext_port, self.proto)


# ── Simulator ──────────────────────────────────────────────────────────────

@dataclass
class StatefulFWNAT44Simulator:
    """The chained NF.

    Knob values default to the task's seed for this task;
    `reset()` rewinds state without touching knobs.
    """

    internal_subnet: str = INTERNAL_NET
    public_ip:       str = PUBLIC_IP
    mode:            str = "dynamic"
    port_pool_range: tuple = (10000, 20000)
    conntrack_capacity: object = 1024
    eviction_policy: str = "timeout"
    idle_timeout_s:  int = 300
    faithfulness:    str = "D5.1_reflexive_dynamic_nat"
    endpoint_independent_mapping: bool = True
    persistence_strict: bool = False

    # ── runtime state ────────────────────────────────────────────────
    # connection: keyed by outbound 3-tuple (src_ip, src_port, proto);
    # value is ConnEntry. OrderedDict for FIFO / LRU ordering.
    connection: "OrderedDict[tuple, ConnEntry]" = field(default_factory=OrderedDict)
    # connection_inbound: keyed by (public_ip, ext_port, proto); value
    # is the conn_key into `connection`.
    connection_inbound: dict = field(default_factory=dict)
    # virtual clock — one tick per call to step(). idle_timeout is
    # interpreted in ticks for simulation; the real-time meaning is
    # determined by the submitted P4 program.
    clock: int = 0
    # next ext_port to try; wraps within port_pool_range.
    _next_ext_port: int = 0
    # control-plane static acl_rule entries (only used when
    # mode == 'static' or as explicit-permit overrides). At D5.1
    # (this task's seed) we don't pre-install any; the test corpus
    # can install them by mutating the simulator's `acl_rule` field
    # directly.
    acl_rule: dict = field(default_factory=dict)

    def __post_init__(self):
        self._next_ext_port = int(self.port_pool_range[0])

    # ── lifecycle ────────────────────────────────────────────────────

    def reset(self):
        self.connection.clear()
        self.connection_inbound.clear()
        self.clock = 0
        self._next_ext_port = int(self.port_pool_range[0])

    # ── eviction policy ──────────────────────────────────────────────

    def _capacity_int(self) -> Optional[int]:
        if self.conntrack_capacity == "unbounded":
            return None
        return int(self.conntrack_capacity)

    def _evict_timeout(self):
        """Drop every conn entry whose last_seen is older than idle_timeout."""
        if self.eviction_policy != "timeout":
            return
        deadline = self.clock - int(self.idle_timeout_s)
        stale = [k for k, v in self.connection.items() if v.last_seen < deadline]
        for k in stale:
            entry = self.connection.pop(k)
            self.connection_inbound.pop(entry.inbound_key(), None)

    def _evict_one_under_pressure(self):
        """Capacity-pressure eviction. timeout policy never invokes this
        (it relies on idle decay); LRU/FIFO pop the head; none refuses."""
        if self.eviction_policy == "none":
            return False
        if self.eviction_policy in ("LRU", "FIFO"):
            try:
                k, entry = next(iter(self.connection.items()))
            except StopIteration:
                return False
            self.connection.pop(k)
            self.connection_inbound.pop(entry.inbound_key(), None)
            return True
        return False

    # ── port allocation ─────────────────────────────────────────────

    def _alloc_ext_port(self, proto: int) -> Optional[int]:
        lo, hi = int(self.port_pool_range[0]), int(self.port_pool_range[1])
        in_use = {entry.ext_port
                  for entry in self.connection.values()
                  if entry.proto == proto}
        cursor = max(lo, min(hi, self._next_ext_port))
        for _ in range(hi - lo + 1):
            if cursor < lo or cursor > hi:
                cursor = lo
            if cursor not in in_use:
                self._next_ext_port = cursor + 1
                if self._next_ext_port > hi:
                    self._next_ext_port = lo
                return cursor
            cursor += 1
        return None

    # ── conntrack ops ───────────────────────────────────────────────

    def _install_conn(self, src_ip: str, sport: int, proto: int,
                      tcp_state: str = "NEW") -> Optional[ConnEntry]:
        cap = self._capacity_int()
        if cap is not None and len(self.connection) >= cap:
            if self.persistence_strict:
                return None
            if not self._evict_one_under_pressure():
                return None
        ext_port = self._alloc_ext_port(proto)
        if ext_port is None:
            return None
        entry = ConnEntry(
            src_ip=src_ip, src_port=sport, proto=proto,
            public_ip=self.public_ip, ext_port=ext_port,
            established=True, last_seen=self.clock, tcp_state=tcp_state,
        )
        self.connection[entry.conn_key()] = entry
        self.connection_inbound[entry.inbound_key()] = entry.conn_key()
        return entry

    def _refresh_conn(self, entry: ConnEntry):
        entry.last_seen = self.clock
        # LRU bookkeeping
        if self.eviction_policy == "LRU":
            self.connection.move_to_end(entry.conn_key(), last=True)

    # ── main step ───────────────────────────────────────────────────

    def step(self, scapy_pkt, ingress_port: str) -> StepResult:
        from scapy.all import IP

        # Advance the clock and expire stale entries before any rule fires.
        self.clock += 1
        self._evict_timeout()

        # R1 — non-IPv4 unconditionally dropped (both zones).
        if IP not in scapy_pkt:
            return StepResult(False, "R1_non_ipv4_drop")

        ip = scapy_pkt[IP]
        proto, sport, dport = _l4_ports(scapy_pkt)

        # R2 — NAPT scope is TCP/UDP only; non-L4 drops on both zones.
        if proto is None:
            return StepResult(False, "R2_non_tcp_udp_drop")

        if ingress_port == INTERNAL_PORT_NAME:
            return self._outbound_step(ip, proto, sport, dport, scapy_pkt)

        if ingress_port == EXTERNAL_PORT_NAME:
            return self._inbound_step(ip, proto, sport, dport, scapy_pkt)

        # Unknown ingress port — drop. (Topology only defines internal /
        # external.)
        return StepResult(False, "drop_unknown_ingress_port")

    # ── outbound (R5/R6/R7) ─────────────────────────────────────────

    def _outbound_step(self, ip, proto, sport, dport, scapy_pkt):
        # R3 — Tier-3 uRPF (only enforced at D5.2). At D5.1, foreign-
        # source packets fall through to R5/R6/R7 where their `when`
        # clauses fail on the subnet match — so they get the "miss
        # drop" path (R7 with reason 'outbound_miss_drop'). For
        # observability, we emit a dedicated reason here too.
        if not _ip_in_subnet(ip.src, self.internal_subnet):
            return StepResult(False, "R8_outbound_urpf_drop_fallthrough")

        key = (ip.src, sport, proto)
        entry = self.connection.get(key)

        # R5 — known conn: refresh + SNAT + forward.
        if entry is not None:
            self._refresh_conn(entry)
            return StepResult(
                True, "R5_outbound_known_conn",
                side="outbound", output_port=EXTERNAL_PORT_NAME,
                new_ip_src=entry.public_ip, new_l4_sport=entry.ext_port,
                new_eth_dst=EXTERNAL_HOST_MAC, ttl_delta=-1,
            )

        # R6 — new conn under dynamic mode: install + SNAT + forward.
        if self.mode == "dynamic":
            installed = self._install_conn(ip.src, sport, proto)
            if installed is not None:
                return StepResult(
                    True, "R6_outbound_new_conn_dynamic",
                    side="outbound", output_port=EXTERNAL_PORT_NAME,
                    new_ip_src=installed.public_ip,
                    new_l4_sport=installed.ext_port,
                    new_eth_dst=EXTERNAL_HOST_MAC, ttl_delta=-1,
                )
            # alloc failed — fall through to R7.

        # R7 — outbound miss (static mode with no preinstalled entry,
        # or dynamic with pool exhaustion).
        return StepResult(False, "R7_outbound_miss_drop")

    # ── inbound (R9/R10/R11/R12) ────────────────────────────────────

    def _inbound_step(self, ip, proto, sport, dport, scapy_pkt):
        # R9 — wrong dst IP.
        if ip.dst != self.public_ip:
            return StepResult(False, "R9_inbound_wrong_dst_drop")

        # R10 — known mapping → DNAT.
        inbound_key = (ip.dst, dport, proto)
        conn_key = self.connection_inbound.get(inbound_key)
        if conn_key is not None:
            entry = self.connection.get(conn_key)
            if entry is not None and entry.established:
                self._refresh_conn(entry)
                return StepResult(
                    True, "R10_inbound_known_mapping",
                    side="inbound", output_port=INTERNAL_PORT_NAME,
                    new_ip_dst=entry.src_ip, new_l4_dport=entry.src_port,
                    new_eth_dst=INTERNAL_HOST_MAC, ttl_delta=-1,
                )

        # R11 — static ACL pass-through (only fires when mode=static or
        # an explicit-permit override has been pre-installed). The
        # acl_rule dict is keyed by (src_ip, dst_ip, sport, dport, proto)
        # → (internal_ip, internal_port). Empty by default at D5.1.
        acl_key = (ip.src, ip.dst, sport, dport, proto)
        acl = self.acl_rule.get(acl_key)
        if acl is not None:
            internal_ip, internal_port = acl
            return StepResult(
                True, "R11_inbound_acl_static",
                side="inbound", output_port=INTERNAL_PORT_NAME,
                new_ip_dst=internal_ip, new_l4_dport=internal_port,
                new_eth_dst=INTERNAL_HOST_MAC, ttl_delta=-1,
            )

        # R12 — default-deny.
        return StepResult(False, "R12_inbound_default_deny")

    # ── batch convenience ────────────────────────────────────────────

    def run(self, packets) -> list:
        """Drive the simulator over a sequence of (scapy_pkt, ingress_port)
        pairs against a single shared state (no implicit reset)."""
        return [self.step(p, port) for p, port in packets]

    # ── runtime-state snapshot / restore (for cross-packet threading) ─
    # The module-level `step` persists the conntrack tables + clock +
    # allocator cursor between calls in one example via StepResult.new_state.

    def _snapshot_runtime(self) -> dict:
        return {
            "connection": [
                {
                    "src_ip": e.src_ip, "src_port": e.src_port, "proto": e.proto,
                    "public_ip": e.public_ip, "ext_port": e.ext_port,
                    "established": e.established, "last_seen": e.last_seen,
                    "tcp_state": e.tcp_state,
                }
                for e in self.connection.values()
            ],
            "clock": self.clock,
            "next_ext_port": self._next_ext_port,
            "acl_rule": {repr(k): v for k, v in self.acl_rule.items()},
        }

    def _restore_runtime(self, snap: dict):
        if not isinstance(snap, dict):
            return
        self.connection.clear()
        self.connection_inbound.clear()
        for row in snap.get("connection", []) or []:
            entry = ConnEntry(
                src_ip=row["src_ip"], src_port=int(row["src_port"]),
                proto=int(row["proto"]), public_ip=row["public_ip"],
                ext_port=int(row["ext_port"]),
                established=bool(row.get("established", True)),
                last_seen=int(row.get("last_seen", 0)),
                tcp_state=row.get("tcp_state", "NEW"),
            )
            self.connection[entry.conn_key()] = entry
            self.connection_inbound[entry.inbound_key()] = entry.conn_key()
        self.clock = int(snap.get("clock", 0))
        if "next_ext_port" in snap:
            self._next_ext_port = int(snap["next_ext_port"])


# ── config-driven construction (parametric-source invariant) ────────────────
# The canonical step entrypoint. Every behaviour-determining mutation-
# operator knob is read from state["config"] here so a parameter rebind reconfigures
# the SAME audited module at runtime; a knob absent from config
# falls back to its constructor (seed) default. This top-level `step` is
# preferred by the oracle loader over the bound class method, giving the arity-3
# config-capable interface the parametric-source audit requires.
#
# Config-read knobs: ONLY the mutation-operator parameters this oracle actually
# BRANCHES on in a way witnessable from finite packet traces (so the oracle
# audit's canonical examples can exercise each at its feasibility extremes). A knob absent from config falls back to its seed default.
#
# Deliberately EXCLUDED (variant-selector/descriptive — exercised via oracle
# regeneration, not runtime config of THIS hash; listing it here would make the audit
# demand a canonical witness this oracle cannot honestly produce). Note its
# name appears UNQUOTED below (and only as the dataclass field) so the audit's
# config-key scan, which matches quoted occurrences, does not flag it:
#   - endpoint independent mapping: this oracle's allocator keys the connection
#     purely on the outbound 3-tuple (src_ip, src_port, proto) and is therefore
#     ALWAYS endpoint-independent at the D5.1 seed; the flag never changes a
#     verdict, so reading it would be an inert config-read.
#
# idle_timeout_s and persistence_strict ARE behaviour-determining and read from
# config: idle_timeout_s drives the timeout-decay path in _evict_timeout (a
# multi-tick trace expires a reflexive mapping at a small timeout but keeps it
# at a large one), and persistence_strict drives the capacity-pressure refusal
# in _install_conn (under a full table with an evicting policy it refuses the
# new flow instead of evicting). Both are witnessed by canonical examples.
_CONFIG_KNOBS = (
    "internal_subnet", "public_ip", "mode", "port_pool_range",
    "conntrack_capacity", "eviction_policy",
    "idle_timeout_s", "persistence_strict",
)


def _coerce(knob, value):
    if value is None:
        return None
    if knob == "port_pool_range":
        return tuple(int(x) for x in value)
    if knob == "conntrack_capacity":
        return value if value == "unbounded" else int(value)
    if knob == "idle_timeout_s":
        return int(value)
    if knob == "persistence_strict":
        return bool(value)
    return value


def _sim_from_config(config) -> "StatefulFWNAT44Simulator":
    kwargs = {}
    for knob in _CONFIG_KNOBS:
        if config and knob in config and config[knob] is not None:
            kwargs[knob] = _coerce(knob, config[knob])
    return StatefulFWNAT44Simulator(**kwargs)


_DEFAULT = StatefulFWNAT44Simulator()
_SIM = None
_SIM_CFG = None


def step(scapy_pkt, ingress_port="s1.internal", state=None):
    """Module-level adapter (arity-3, config-capable).

    `state` may carry:
      - state["config"] : {internal_subnet, public_ip, mode, port_pool_range,
            conntrack_capacity, eviction_policy, idle_timeout_s,
            persistence_strict} — overrides the seed defaults at runtime so a
            constant-baked oracle is impossible (parametric-source invariant).
      - state["runtime"] : the conntrack tables + clock threaded across a packet
            sequence (so a prior outbound packet's reflexive state persists into
            the inbound return packet).

    The returned StepResult carries new_state={"config", "runtime"} so the
    audit/eval driver threads it forward across the sequence.
    """
    global _SIM, _SIM_CFG
    cfg = {}
    runtime = None
    if isinstance(state, dict):
        if isinstance(state.get("config"), dict):
            cfg = state["config"]
        if isinstance(state.get("runtime"), dict):
            runtime = state["runtime"]

    if cfg:
        # Rebuild the simulator only when the config changes (a new example /
        # a rebind); within one example the same configured sim is reused and
        # its runtime is restored from the threaded state.
        if cfg != _SIM_CFG:
            _SIM = _sim_from_config(cfg)
            _SIM_CFG = dict(cfg)
        sim = _SIM
    else:
        sim = _DEFAULT

    # Restore accumulated runtime state for this sequence; if none was threaded
    # (first packet of an example) start from a clean conntrack table.
    if runtime is not None:
        sim._restore_runtime(runtime)
    else:
        sim.reset()

    r = sim.step(scapy_pkt, ingress_port)
    r.new_state = {"config": dict(cfg), "runtime": sim._snapshot_runtime()}
    return r


def reset():
    global _SIM, _SIM_CFG
    _DEFAULT.reset()
    _SIM = None
    _SIM_CFG = None
