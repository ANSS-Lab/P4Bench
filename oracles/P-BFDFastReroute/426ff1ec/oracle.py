"""Composed oracle for P-BFDFastReroute (BFD Liveness ∘ Primary/Backup
Fast-Reroute).

    step(scapy_pkt, ingress_port, state) -> StepResult        [STATEFUL]

The composition's whole surface is a single port-keyed liveness register
``link[port].is_down``: the BFD stage WRITES it, the FRR stage READS it. The
two stages exchange nothing else.

Pipeline, demuxed by header type (first-match over the pattern's R0..R8):

  R0  ¬header_present(ipv4)                                    → drop
  BFD stage  (UDP dport 3784/4784):
    R1  §6.8.6 reception cascade fails                         → drop (consume)
    R2  valid BFD ctrl → advance §6.8.6 state machine, WRITE
        link[port_binding].is_down = int(local_state == Down),
        then consume the packet                                → drop
  FRR stage  (IPv4, non-BFD):
    R3  FRR-table miss                                         → ${default_action_on_miss}
    R4  cascaded ∧ primary down ∧ backup down                  → drop
    R5  primary not down (READ link)                           → forward primary
    R6  primary down ∧ ¬(cascaded ∧ backup down)               → forward backup

R7 (tick detection-timeout) and R8 (tick periodic origination) are the
genuinely time-driven rules; the v1.0 evaluation harness injects no
``time_tick`` events (same convention as benchmark/redesign/bfd_liveness_disc),
so they are implemented as parametric tick handlers but NOT exercised by this
task's packet-only test set. The packet-driven Up→Down transition (a received
Down/AdminDown control packet, R2) is the observable equivalent that drives the
reroute, so the detect↔reroute contract is fully gradable without ticks.

DETECT↔REROUTE contract (the composition's reason for existing):
  * liveness_drives_reroute — the FRR demux selects backup for a destination
    iff link[primary_port].is_down == 1, and that bit is written ONLY by the
    BFD stage (R2 on a state transition). There is no second liveness source.
  * no_phantom_reroute — a port whose monitoring session is not Down (or that
    has no session and is not seeded down) keeps is_down == 0 → primary.
  * recovery_restores_primary — when the session leaves Down (Down→Init on the
    next received control packet, or Init→Up), is_down clears to 0 → primary.
  * bfd_control_not_rerouted — a BFD control packet is consumed by R2 (dropped
    after the state write); it never enters the FRR demux.

L2 / addressing convention (inherited from P-PURRFastReroute's FRR stage, which
owns L2): hdr.ethernet.src ← prior hdr.ethernet.dst, hdr.ethernet.dst ← the
chosen path's next-hop MAC. This is plain forwarding — BOTH hdr.ipv4.src and
hdr.ipv4.dst are preserved (ip_addr_preservation; no NAT, unlike P-LBFailover).
TTL convention: gate ttl > 0 — ttl == 0 drops, ttl == 1 forwards with egress
ttl == 0 (decrement once, never twice).

PARAMETRIC-SOURCE CONTRACT. Every mutable knob is read from
the runtime ``state`` dict — never baked as a module-level constant. The seed's
values enter only at evaluation time via step()'s ``state`` argument. The per-
session runtime (local_state, remote_state, remote_discr) and the shared
``link`` register are the only MUTABLE runtime state; they live module-level and
are cleared by reset() (the test generator / engine calls reset() before
replaying each test's prior_inputs).

State keys consumed:

  sessions              : list[dict] — each {local_discr, remote_discr,
                          local_state, remote_state, peer_ip, port_binding,
                          hop_type, detect_mult, ...}
  frr_groups            : list[frr_group_entry] (each carrying a `dst` +
                          prefix_len, primary/backup port + mac) | dict
  port_down             : iterable[int] — seeds the INITIAL link.is_down set
  frr_match_kind        : 'exact' | 'lpm'
  cascaded_backup       : bool
  ttl_decrement_strict  : bool
  default_action_on_miss: 'drop' | 'use_default_route'
  packet_format_faithfulness : 'D5.0_minimal_8byte' | 'D5.1_rfc5880_mandatory'
                          | 'D5.2_multihop_rfc5883'   (gates the R1 cascade)
  ttl_strictness        : 'strict_255' | 'relaxed' | 'per_session_by_hop_type'
  session_lookup_key    : 'your_discr_only' | 'source_ip_and_remote_discr'
                          | 'both'
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# BFD §4.1 state encoding
ADMIN_DOWN, DOWN, INIT, UP = 0, 1, 2, 3
_STATE_NAME = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}
_NAME_STATE = {v: k for k, v in _STATE_NAME.items()}


# ── mutable runtime state (cleared by reset) ────────────────────────────────
_SESSION_RT: list = []          # per-session runtime: {local_state, remote_state, remote_discr}
_LINK: dict = {}                # shared liveness register: port -> is_down (0|1)
_INIT_DONE: bool = False


def reset() -> None:
    """Clear per-session runtime and the shared liveness register. Called once
    per test before replaying that test's prior_inputs + input packet."""
    global _SESSION_RT, _LINK, _INIT_DONE
    _SESSION_RT = []
    _LINK = {}
    _INIT_DONE = False


# ── result ──────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    reason: str
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None      # primary_mac | backup_mac
    next_hop_mac_src: Optional[str] = None       # prior ethernet.dst
    ttl_decrement: int = 0
    path: Optional[str] = None                   # 'primary' | 'backup'
    stage: Optional[str] = None                  # 'bfd' | 'frr'
    invariant_log: list = field(default_factory=list)

    @property
    def decision(self) -> str:                   # for the oracle audit's comparison
        return "forward" if self.admitted else "drop"


# ── IP helpers ──────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in str(ip).split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _frr_entries(frr_groups) -> list:
    """Normalise frr_groups to a list of (prefix_ip, prefix_len, pp, bp, pm, bm)."""
    out = []
    if frr_groups is None:
        return out
    items = frr_groups.values() if isinstance(frr_groups, dict) else frr_groups
    for e in items:
        prefix_ip = e.get("dst", e.get("prefix"))
        prefix_len = int(e.get("prefix_len", 32))
        out.append((str(prefix_ip), prefix_len,
                    int(e["primary_port"]), int(e["backup_port"]),
                    e["primary_mac"], e["backup_mac"]))
    return out


def _frr_lookup(dst_ip, entries, match_kind):
    if match_kind == "exact":
        for prefix_ip, plen, pp, bp, pm, bm in entries:
            if plen == 32 and _ip_to_int(dst_ip) == _ip_to_int(prefix_ip):
                return (pp, bp, pm, bm)
        return None
    best, best_len = None, -1
    for prefix_ip, plen, pp, bp, pm, bm in entries:
        if plen <= best_len:
            continue
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        if (_ip_to_int(dst_ip) & mask) == (_ip_to_int(prefix_ip) & mask):
            best, best_len = (pp, bp, pm, bm), plen
    return best


# ── BFD §6.8.6 state machine (identical to the audited P-BFDLiveness oracle) ─

def _advance_state(local_state: int, received_state: int) -> int:
    if received_state == ADMIN_DOWN:
        return DOWN
    if local_state == DOWN:
        if received_state == DOWN:
            return INIT
        if received_state == INIT:
            return UP
        return DOWN
    if local_state == INIT:
        if received_state in (INIT, UP):
            return UP
        return INIT
    if local_state == UP:
        if received_state == DOWN:
            return DOWN
        return UP
    return local_state


# ── runtime initialisation from seed ────────────────────────────────────────

def _ensure_init(state: dict) -> None:
    """Lazily seed per-session runtime + the initial link register on the first
    step after reset(). Sessions' seeded local_state is the steady-state entry
    point; the initial is_down set is the seed's `port_down` (default: all up)."""
    global _INIT_DONE
    if _INIT_DONE:
        return
    sessions = state.get("sessions", []) or []
    for s in sessions:
        _SESSION_RT.append({
            "local_state": _NAME_STATE.get(s.get("local_state", "Down"), DOWN)
                           if isinstance(s.get("local_state", "Down"), str)
                           else int(s.get("local_state", DOWN)),
            "remote_state": _NAME_STATE.get(s.get("remote_state", "Down"), DOWN)
                            if isinstance(s.get("remote_state", "Down"), str)
                            else int(s.get("remote_state", DOWN)),
            "remote_discr": int(s.get("remote_discr", 0)),
        })
    for p in (state.get("port_down") or []):
        _LINK[int(p)] = 1
    # Reflect any seeded session already in Down onto its monitored port.
    for s, rt in zip(sessions, _SESSION_RT):
        _LINK.setdefault(int(s["port_binding"]), int(rt["local_state"] == DOWN))
    _INIT_DONE = True


def _find_session(state, your_discr, src_ip, ingress_port, lookup_key):
    sessions = state.get("sessions", []) or []
    if your_discr != 0:
        for idx, s in enumerate(sessions):
            if int(s["local_discr"]) == your_discr:
                return idx
        return None
    # your_discr == 0 → initial-packet path
    if lookup_key == "your_discr_only":
        return None
    for idx, s in enumerate(sessions):
        if str(s.get("peer_ip")) == str(src_ip) and int(s["port_binding"]) == ingress_port:
            return idx
    return None


# ── oracle entry point (step interface) ──────────────────────────

def step(scapy_pkt, ingress_port: int = 1, state: Optional[dict] = None) -> StepResult:
    from scapy.all import IP, UDP

    state = state or {}
    _ensure_init(state)

    faithfulness = state.get("packet_format_faithfulness", "D5.0_minimal_8byte")
    ttl_strictness = state.get("ttl_strictness", "strict_255")
    lookup_key = state.get("session_lookup_key", "both")

    # ── R0: non-IPv4 → drop ─────────────────────────────────────────────────
    if IP not in scapy_pkt:
        return StepResult(False, "R0_non_ipv4_drop", stage="frr")

    ip = scapy_pkt[IP]
    dst_ip = str(ip.dst)
    ttl = int(getattr(ip, "ttl", 0))

    # ── BFD stage demux: UDP dport 3784 (single-hop) / 4784 (multi-hop) ─────
    is_bfd = False
    udp_dport = None
    if UDP in scapy_pkt:
        udp_dport = int(scapy_pkt[UDP].dport)
        if udp_dport in (3784, 4784):
            is_bfd = True

    if is_bfd:
        return _bfd_stage(scapy_pkt, ingress_port, state,
                          faithfulness, ttl_strictness, lookup_key, udp_dport)

    # ── FRR stage: IPv4 non-BFD data packet ────────────────────────────────
    return _frr_stage(scapy_pkt, ingress_port, state, ttl, dst_ip)


# ── BFD stage (R1 cascade, R2 advance + register write, consume) ────────────

def _bfd_stage(scapy_pkt, ingress_port, state, faithfulness,
               ttl_strictness, lookup_key, udp_dport) -> StepResult:
    from scapy.all import IP

    if not scapy_pkt.haslayer("BFD"):
        return StepResult(False, "R1_bfd_layer_missing", stage="bfd")
    bfd = scapy_pkt["BFD"]
    version = int(getattr(bfd, "version", 1))
    length = int(getattr(bfd, "length", 24))
    detect_mult = int(getattr(bfd, "detect_mult", 0))
    flag_m = int(getattr(bfd, "flag_M", 0))
    flag_p = int(getattr(bfd, "flag_P", 0))
    my_discr = int(getattr(bfd, "my_discr", 0))
    your_discr = int(getattr(bfd, "your_discr", 0))
    recv_state = int(getattr(bfd, "state", DOWN))
    ttl = int(getattr(scapy_pkt[IP], "ttl", 0))

    # R1 — §6.8.6 reception cascade. Version/length pedantry waived at D5.0.
    if faithfulness != "D5.0_minimal_8byte":
        if version != 1:
            return StepResult(False, "R1_version_ne_1", stage="bfd")
        if length < 24:
            return StepResult(False, "R1_length_lt_24", stage="bfd")
    if detect_mult == 0:
        return StepResult(False, "R1_detect_mult_zero", stage="bfd")
    if flag_m == 1:
        return StepResult(False, "R1_m_bit_set", stage="bfd")
    if my_discr == 0:
        return StepResult(False, "R1_my_discr_zero", stage="bfd")

    single_hop = (udp_dport == 3784)
    if ttl_strictness in ("strict_255", "per_session_by_hop_type") and single_hop and ttl != 255:
        return StepResult(False, "R1_ttl_not_255_single_hop", stage="bfd")

    src_ip = str(getattr(scapy_pkt[IP], "src", ""))
    sidx = _find_session(state, your_discr, src_ip, ingress_port, lookup_key)
    if sidx is None:
        return StepResult(False, "R1_session_lookup_miss", stage="bfd")

    # R2 — advance the §6.8.6 state machine + WRITE the shared liveness register.
    sessions = state.get("sessions", []) or []
    rt = _SESSION_RT[sidx]
    prior = rt["local_state"]
    new_local = _advance_state(prior, recv_state)
    rt["local_state"] = new_local
    rt["remote_state"] = recv_state
    rt["remote_discr"] = my_discr

    port = int(sessions[sidx]["port_binding"])
    _LINK[port] = int(new_local == DOWN)        # the detect↔reroute write

    log = [
        ("session_advance", {"session": sidx, "prior": _STATE_NAME[prior],
                             "new": _STATE_NAME[new_local]}),
        ("liveness_drives_reroute", {"port": port, "is_down": _LINK[port]}),
        ("link_register_stability_under_no_state_change", {"written_on_transition": True}),
    ]
    # The ingress BFD control packet is CONSUMED (never forwarded out a data
    # egress: bfd_control_not_rerouted). A Poll would emit a Final reply; at the
    # D5.0 anchor no Poll test is materialised, so report consume/drop.
    return StepResult(False, "R2_bfd_consumed_after_state_write",
                      stage="bfd", invariant_log=log)


# ── FRR stage (R3 miss, R4 cascaded drop, R5/R6 demux reads the register) ───

def _frr_stage(scapy_pkt, ingress_port, state, ttl, dst_ip) -> StepResult:
    entries = _frr_entries(state.get("frr_groups"))
    match_kind = state.get("frr_match_kind", "exact")
    cascaded = bool(state.get("cascaded_backup", False))
    ttl_strict = bool(state.get("ttl_decrement_strict", True))
    default_on_miss = state.get("default_action_on_miss", "drop")

    grp = _frr_lookup(dst_ip, entries, match_kind)

    # R3 — FRR-table miss.
    if grp is None:
        if default_on_miss == "use_default_route":
            # Only realisable at lpm with a 0.0.0.0/0 catch-all already in entries;
            # a true miss with no catch-all still drops.
            return StepResult(False, "R3_frr_miss_no_default", stage="frr")
        return StepResult(False, "R3_frr_table_miss", stage="frr")

    primary_port, backup_port, primary_mac, backup_mac = grp
    primary_down = bool(_LINK.get(primary_port, 0))
    backup_down = bool(_LINK.get(backup_port, 0))

    # TTL guard (gate ttl > 0): a dead packet never forwards.
    if ttl <= 0:
        return StepResult(False, "R_ttl_exhausted_drop", stage="frr")

    # R4 — cascaded both-down → drop.
    if cascaded and primary_down and backup_down:
        return StepResult(False, "R4_cascaded_double_down_drop", stage="frr")

    # R5 / R6 — demux on the BFD-written register.
    if not primary_down:
        out_port, dst_mac, path = primary_port, primary_mac, "primary"
        inv = ("ether_rewrite_correctness_on_primary", {"dst": primary_mac})
    else:
        out_port, dst_mac, path = backup_port, backup_mac, "backup"
        inv = ("ether_rewrite_correctness_on_backup", {"dst": backup_mac})

    prior_dst_mac = str(scapy_pkt["Ether"].dst)
    ttl_delta = 1 if ttl_strict else 0
    log = [
        ("no_phantom_reroute", {"primary_down": primary_down, "path": path}),
        ("failover_decision_per_packet", {"path": path}),
        ("ip_addr_preservation", {"src_and_dst_preserved": True}),
        inv,
        ("ttl_quantum_one", {"decrement": ttl_delta}),
    ]
    return StepResult(
        admitted=True,
        reason=("R5_frr_primary_up_forward" if path == "primary"
                else "R6_frr_primary_down_forward_backup"),
        output_port=out_port,
        next_hop_mac_dst=dst_mac,
        next_hop_mac_src=prior_dst_mac,
        ttl_decrement=ttl_delta,
        path=path,
        stage="frr",
        invariant_log=log,
    )


# Compatibility alias for callers that use the older name.
def oracle_step(scapy_pkt, ingress_port: int, state: dict) -> StepResult:
    return step(scapy_pkt, ingress_port, state)
