"""Python oracle for benchmark/redesign/bfd_liveness_disc.

Implements P-BFDLiveness's R0 (non-BFD passthrough), R1 (§6.8.6 reception
cascade discard), R2 (state-machine advance + Poll/Final response), and
R5 (echo reflection — dormant in this task since echo_enabled=false in
the seed). R3 (detection-time expiry) and R4 (periodic origination) are
implemented as parametric tick handlers but NOT exercised by this task's
test set — the v1.0 evaluation harness does not inject `time_tick`
events; that is deferred to a follow-up release.

Parametric-source contract: every parameter named in the pattern's
mutation_operators surface is read from `state` at runtime, never
baked as a source-level constant — this is what lets parameter
rebinding reuse this same module across mutated instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────
# StepResult and a tiny ScapyPacket shim
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# BFD state-machine state enum (matches the §4.1 wire encoding)
ADMIN_DOWN, DOWN, INIT, UP = 0, 1, 2, 3
_STATE_NAME = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _has_layer(packet, name: str) -> bool:
    """Robust haslayer that works for plain dicts (oracle audit) and Scapy."""
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    return name in (packet or {})


def _field(packet, layer: str, field_name: str, default=None):
    """Read a field from either Scapy packet or dict-style audit input."""
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        return getattr(packet[layer], field_name, default)
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(field_name, default)
    return default


def _initial_sessions_from_state(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull session bindings from state (seeded by the harness at task init).

    The pattern's parametric-source contract requires every
    mutation-operator-named parameter to be read from `state`, never baked.
    """
    return state.get("sessions", [])


def _find_session_by_your_discr(state: Dict[str, Any], your_discr: int) -> Optional[int]:
    for idx, sess in enumerate(state.get("sessions", [])):
        if sess["local_discr"] == your_discr:
            return idx
    return None


def _find_session_by_peer_ip_port(state: Dict[str, Any], src_ip: str, ingress_port: int) -> Optional[int]:
    for idx, sess in enumerate(state.get("sessions", [])):
        if sess["peer_ip"] == src_ip and sess["port_binding"] == ingress_port:
            return idx
    return None


def _advance_state(local_state: int, received_state: int) -> int:
    """RFC 5880 §6.8.6 state-machine table."""
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
    return local_state                                          # AdminDown handled by harness


# ──────────────────────────────────────────────────────────────────────
# step() — the oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    """Execute one packet step under the pattern's rules.

    State threading:
      - state["sessions"]: list of session dicts (seeded at task init).
      - state["session_runtime"]: per-session runtime mutable fields —
        local_state, remote_state, remote_discr, last_rx_ts. Indexed
        by session list position.
      - state["config"]: parametric knobs from the seed
        (packet_format_faithfulness, ttl_strictness, session_lookup_key,
        echo_enabled, etc.). Read at every call — never closed over.
    """
    new_state = dict(state)                                     # shallow copy
    new_state["session_runtime"] = list(state.get("session_runtime", []))
    config = state.get("config", {})

    # Ensure per-session runtime is initialised
    sessions = state.get("sessions", [])
    while len(new_state["session_runtime"]) < len(sessions):
        s = sessions[len(new_state["session_runtime"])]
        new_state["session_runtime"].append({
            "local_state": _name_to_state(s.get("local_state", "Down")),
            "remote_state": _name_to_state(s.get("remote_state", "Down")),
            "remote_discr": s.get("remote_discr", 0),
            "last_rx_ts": 0,
            "last_tx_ts": 0,
        })

    # ──────────────────────────────────────────────────────────────────
    # R0 — non-BFD passthrough
    # ──────────────────────────────────────────────────────────────────
    is_bfd_control_dst = False
    if _has_layer(packet, "UDP"):
        dport = _field(packet, "UDP", "dport", 0)
        if dport in (3784, 4784):
            is_bfd_control_dst = True
        elif dport == 3785 and config.get("echo_enabled", False):
            return _r5_echo_reflection(packet, ingress_port, new_state)

    if not is_bfd_control_dst:
        # Non-BFD passthrough: forward via the harness-installed downstream
        # forwarding table. For h1↔h2 ICMP/IP traffic, the convention is to
        # set egress = the peer's port and rewrite dst-MAC to the peer's MAC.
        return _r0_passthrough_forward(packet, ingress_port, new_state)

    # ──────────────────────────────────────────────────────────────────
    # R1 — §6.8.6 reception cascade
    # ──────────────────────────────────────────────────────────────────
    if not _has_layer(packet, "BFD"):
        return _drop(new_state, "R1: BFD layer missing")

    version = _field(packet, "BFD", "version", 0)
    length = _field(packet, "BFD", "length", 0)
    detect_mult = _field(packet, "BFD", "detect_mult", 0)
    flag_m = _field(packet, "BFD", "flag_M", 0)
    flag_p = _field(packet, "BFD", "flag_P", 0)
    my_discr = _field(packet, "BFD", "my_discr", 0)
    your_discr = _field(packet, "BFD", "your_discr", 0)
    recv_state = _field(packet, "BFD", "state", DOWN)
    ttl = _field(packet, "IP", "ttl", 0)
    udp_dport = _field(packet, "UDP", "dport", 0)

    faithfulness = config.get("packet_format_faithfulness", "D5.1_rfc5880_mandatory")
    ttl_strictness = config.get("ttl_strictness", "strict_255")

    # Version / length checks apply at D5.1+
    if faithfulness != "D5.0_minimal_8byte":
        if version != 1:
            return _drop(new_state, "R1: version != 1")
        if length < 24:
            return _drop(new_state, "R1: length < 24")

    if detect_mult == 0:
        return _drop(new_state, "R1: detect_mult == 0")
    if flag_m == 1:
        return _drop(new_state, "R1: M bit set")
    if my_discr == 0:
        return _drop(new_state, "R1: my_discr == 0")

    # TTL=255 single-hop check
    is_single_hop_port = (udp_dport == 3784)
    if ttl_strictness == "strict_255" and is_single_hop_port and ttl != 255:
        return _drop(new_state, "R1: TTL != 255 on single-hop")
    if ttl_strictness == "per_session_by_hop_type" and is_single_hop_port and ttl != 255:
        return _drop(new_state, "R1: TTL != 255 on single-hop session")

    # Session lookup — primary by Your Discriminator
    session_idx: Optional[int] = None
    if your_discr != 0:
        session_idx = _find_session_by_your_discr(state, your_discr)
        if session_idx is None:
            return _drop(new_state, "R1: your_discr != 0 with no session")
    else:
        # your_discr == 0 → initial-packet path
        lookup_mode = config.get("session_lookup_key", "both")
        if lookup_mode == "your_discr_only":
            return _drop(new_state, "R1: your_discr == 0 with strict your_discr_only")
        src_ip = _field(packet, "IP", "src", None)
        session_idx = _find_session_by_peer_ip_port(state, src_ip, ingress_port)
        if session_idx is None:
            return _drop(new_state, "R1: your_discr == 0 with no (peer_ip, port) match")

    # ──────────────────────────────────────────────────────────────────
    # R2 — state-machine advance + Poll/Final
    # ──────────────────────────────────────────────────────────────────
    runtime = new_state["session_runtime"][session_idx]
    prior_local_state = runtime["local_state"]
    new_local_state = _advance_state(prior_local_state, recv_state)

    runtime["local_state"] = new_local_state
    runtime["remote_state"] = recv_state
    runtime["remote_discr"] = my_discr
    runtime["last_rx_ts"] = state.get("now_us", 0)

    log = [
        ("session_advance", {
            "session_idx": session_idx,
            "prior": _STATE_NAME[prior_local_state],
            "new": _STATE_NAME[new_local_state],
            "trigger": _STATE_NAME[recv_state],
        }),
    ]

    # Liveness export (P-PURRFastReroute pairing) — gated by config
    if config.get("liveness_export") in ("link_register", "both"):
        link = new_state.setdefault("link", {})
        sess = state["sessions"][session_idx]
        link[sess["port_binding"]] = {"is_down": int(new_local_state == DOWN)}

    # Poll/Final reply
    out_packets: Dict[int, List[Any]] = {}
    if flag_p == 1:
        sess = state["sessions"][session_idx]
        reply = _build_final_reply(packet, sess, runtime, recv_state=new_local_state)
        out_packets[ingress_port] = [reply]
        return StepResult(
            output_packets=out_packets,
            new_state=new_state,
            decision="forward",
            invariant_log=log,
        )

    # No Poll → ingress BFD packet is consumed
    return StepResult(
        output_packets={},
        new_state=new_state,
        decision="drop",
        invariant_log=log,
    )


# ──────────────────────────────────────────────────────────────────────
# Sub-rules
# ──────────────────────────────────────────────────────────────────────

def _drop(state, reason: str) -> StepResult:
    return StepResult(
        output_packets={},
        new_state=state,
        decision="drop",
        invariant_log=[("R1_drop", reason)],
    )


def _r0_passthrough_forward(packet, ingress_port: int, state) -> StepResult:
    """Pass through non-BFD traffic to the harness-installed downstream
    forwarding pipeline. Convention for this 2-host topology: a packet
    with IPv4.dst == h_other's IP is forwarded out h_other's port with
    Ether.dst rewritten to h_other's MAC."""
    fwd_table = state.get("config", {}).get("non_bfd_forward_table", {
        "10.0.2.2": {"port": 2, "mac": "08:00:00:00:02:02"},
        "10.0.1.1": {"port": 1, "mac": "08:00:00:00:01:01"},
    })
    if not _has_layer(packet, "IP"):
        return _drop(state, "R0: non-IPv4 not in forwarding table")
    dst = _field(packet, "IP", "dst", None)
    if dst not in fwd_table:
        return _drop(state, "R0: no forwarding entry")
    entry = fwd_table[dst]
    rewritten = _rewrite_eth_dst(packet, entry["mac"])
    return StepResult(
        output_packets={entry["port"]: [rewritten]},
        new_state=state,
        decision="forward",
        invariant_log=[("R0_passthrough", {"port": entry["port"], "dst_mac": entry["mac"]})],
    )


def _r5_echo_reflection(packet, ingress_port, state) -> StepResult:
    """Echo packet at UDP dst 3785 — bounce back unmodified after IP swap."""
    out = _swap_ip_endpoints(packet)
    return StepResult(
        output_packets={ingress_port: [out]},
        new_state=state,
        decision="forward",
        invariant_log=[("R5_echo_reflection", {"port": ingress_port})],
    )


def _build_final_reply(received_pkt, session, runtime, recv_state):
    """Construct a BFD Final-bit reply. The result is a dict shaped to
    match the on-wire fields; the evaluation harness's verifier compares
    field-by-field, so an opaque dict is enough."""
    return {
        "Ether": {
            "src": _peer_mac_at_session_local(session),
            "dst": session.get("peer_mac", "ff:ff:ff:ff:ff:ff"),
        },
        "IP": {
            "src": session["local_ip"],
            "dst": session["peer_ip"],
            "ttl": 255,
            "proto": 17,
        },
        "UDP": {
            "sport": session["local_udp_src_port"],
            "dport": 3784 if session["hop_type"] == "single_hop" else 4784,
        },
        "BFD": {
            "version": 1,
            "diag": runtime.get("local_diag", 0),
            "state": recv_state,
            "flag_P": 0,
            "flag_F": 1,
            "flag_C": 0,
            "flag_A": 0,
            "flag_D": 0,
            "flag_M": 0,
            "detect_mult": session["detect_mult"],
            "length": 24,
            "my_discr": session["local_discr"],
            "your_discr": _field(received_pkt, "BFD", "my_discr", 0),
            "desired_min_tx_interval": session["desired_min_tx_interval"],
            "required_min_rx_interval": session["required_min_rx_interval"],
            "required_min_echo_rx_interval": session.get("required_min_echo_rx_interval", 0),
        },
    }


def _rewrite_eth_dst(packet, new_dst_mac: str):
    """Shallow-copy the packet representation with a new Ether.dst."""
    if isinstance(packet, dict):
        out = {k: dict(v) if isinstance(v, dict) else v for k, v in packet.items()}
        out.setdefault("Ether", {})["dst"] = new_dst_mac
        return out
    # Scapy path
    try:
        cloned = packet.copy()
        cloned["Ether"].dst = new_dst_mac
        return cloned
    except Exception:
        return packet


def _swap_ip_endpoints(packet):
    if isinstance(packet, dict):
        out = {k: dict(v) if isinstance(v, dict) else v for k, v in packet.items()}
        ip = out.setdefault("IP", {})
        ip["src"], ip["dst"] = ip.get("dst"), ip.get("src")
        return out
    try:
        cloned = packet.copy()
        ip = cloned["IP"]
        ip.src, ip.dst = ip.dst, ip.src
        return cloned
    except Exception:
        return packet


def _peer_mac_at_session_local(session):
    """The MAC the switch presents to the peer on this session's local
    interface. The harness's bindings.yaml supplies this; if absent,
    fall back to a deterministic per-port-id MAC."""
    if "local_mac" in session:
        return session["local_mac"]
    pb = session.get("port_binding", 0)
    return f"08:00:00:00:00:{pb:02x}"


def _name_to_state(name) -> int:
    if isinstance(name, int):
        return name
    return {"AdminDown": ADMIN_DOWN, "Down": DOWN, "Init": INIT, "Up": UP}.get(name, DOWN)


# ──────────────────────────────────────────────────────────────────────
# Tick handler — R3/R4. NOT exercised by this task's test set.
# Implemented for content-addressing parity with the pattern;
# v1.1 harness extension will inject `step(packet=None, ingress_port=-1,
# state)` tick events that drive these.
# ──────────────────────────────────────────────────────────────────────

def step_tick(state: Dict[str, Any]) -> StepResult:
    """Tick path — R3 (detection-time check) + R4 (periodic origination)."""
    new_state = dict(state)
    new_state["session_runtime"] = [dict(r) for r in state.get("session_runtime", [])]
    config = state.get("config", {})
    now = state.get("now_us", 0)
    out_packets: Dict[int, List[Any]] = {}
    log: List[Tuple[str, Any]] = []

    for idx, sess in enumerate(state.get("sessions", [])):
        runtime = new_state["session_runtime"][idx]

        # R3 — detection timeout
        if runtime["local_state"] in (INIT, UP):
            detect_window = sess["detect_mult"] * max(
                sess["required_min_rx_interval"],
                sess["desired_min_tx_interval"],
            )
            if now - runtime["last_rx_ts"] > detect_window:
                runtime["local_state"] = DOWN
                runtime["local_diag"] = 1                       # Control Detection Time Expired
                log.append(("R3_detection_timeout", {"session_idx": idx}))
                if config.get("liveness_export") in ("link_register", "both"):
                    link = new_state.setdefault("link", {})
                    link[sess["port_binding"]] = {"is_down": 1}

        # R4 — periodic origination
        if config.get("origination_mode", "generator_entry_table") != "no_origination_sink_only":
            tx_interval = max(
                sess["desired_min_tx_interval"],
                runtime.get("remote_min_rx_interval", 1),
            )
            if now - runtime["last_tx_ts"] >= tx_interval:
                # Skip if passive role and remote_discr still 0
                if not (sess.get("role") == "passive" and runtime["remote_discr"] == 0):
                    probe = _build_periodic_probe(sess, runtime)
                    out_packets.setdefault(sess["port_binding"], []).append(probe)
                    runtime["last_tx_ts"] = now
                    log.append(("R4_emit", {"session_idx": idx}))

    return StepResult(
        output_packets=out_packets,
        new_state=new_state,
        decision="tick",
        invariant_log=log,
    )


def _build_periodic_probe(session, runtime):
    return {
        "Ether": {
            "src": _peer_mac_at_session_local(session),
            "dst": session.get("peer_mac", "ff:ff:ff:ff:ff:ff"),
        },
        "IP": {
            "src": session["local_ip"],
            "dst": session["peer_ip"],
            "ttl": 255,
            "proto": 17,
        },
        "UDP": {
            "sport": session["local_udp_src_port"],
            "dport": 3784 if session["hop_type"] == "single_hop" else 4784,
        },
        "BFD": {
            "version": 1,
            "diag": runtime.get("local_diag", 0),
            "state": runtime["local_state"],
            "flag_P": 0,
            "flag_F": 0,
            "flag_C": 0,
            "flag_A": 0,
            "flag_D": 0,
            "flag_M": 0,
            "detect_mult": session["detect_mult"],
            "length": 24,
            "my_discr": session["local_discr"],
            "your_discr": runtime["remote_discr"],
            "desired_min_tx_interval": session["desired_min_tx_interval"],
            "required_min_rx_interval": session["required_min_rx_interval"],
            "required_min_echo_rx_interval": session.get("required_min_echo_rx_interval", 0),
        },
    }
