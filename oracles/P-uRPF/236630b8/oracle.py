"""Python oracle for benchmark/redesign/urpf_anchor (P-uRPF).

Implements P-uRPF's rule sequence — an ingress anti-spoofing
filter layered in FRONT of an ordinary destination-based IPv4 forwarder
(RFC 3704 BCP 84 / RFC 2827 BCP 38):

  - R0  non-IPv4 drop
  - R1  uRPF DROP (strict / feasible_path): drop unless the longest reverse
        match for hdr.ipv4.src exists AND std.ingress_port ∈ that entry's
        expected-port set. Gated on ${urpf_mode} ∈ {strict, feasible_path}.
        The ${exempt_default_route} caveat makes a default-only (/0) reverse
        match NOT count as verifiable, so such a packet does NOT drop here.
  - R2  uRPF DROP (loose): drop ONLY when hdr.ipv4.src matches NO reverse
        entry (unroutable); the ingress port is NOT examined. Gated on
        ${urpf_mode} == loose. (Same exempt-default caveat.)
  - R3  dst-FIB LPM forward (reached only by uRPF-verified packets): longest
        prefix on hdr.ipv4.dst → egress port; Ether.src ← egress port MAC,
        Ether.dst ← next-hop MAC, decrement TTL by exactly one; IPv4 src/dst
        preserved (uRPF is a filter, not NAT).
  - R4  uRPF-verified but no forward route → ${default_action} (drop).

Per the parametric-source contract: urpf_mode,
reverse_routes, forward_routes, exempt_default_route, and default_action are
read from `state["config"]` at runtime, never baked as source-level constants.
This is what lets parameter rebinding reuse the same
audited oracle across mutated instances — strict / loose / feasible_path all
served by ONE audited module via runtime ${urpf_mode}, the default-route
exemption toggled by runtime ${exempt_default_route}, etc.

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


# ── Default config mirrors the canonical seed; overridden by state["config"]. ──
# CANONICAL: strict single-homed uRPF, no default-route exemption. Reverse FIB
# homes each source prefix on exactly one expected ingress port; the dst-FIB is
# the ordinary forwarder uRPF fronts. NOTHING in mutation_operators is baked —
# urpf_mode / reverse_routes / forward_routes / exempt_default_route /
# default_action all arrive via state["config"] at evaluation time.
_DEFAULT_CONFIG = {
    "urpf_mode": "strict",                       # strict | loose | feasible_path
    "exempt_default_route": False,
    "default_action": "drop",
    # Reverse FIB: source prefix → expected (legitimate) ingress port set.
    "reverse_routes": [
        {"prefix": "10.0.1.0", "prefix_len": 24, "expected_ingress_ports": [1]},
        {"prefix": "10.0.2.0", "prefix_len": 24, "expected_ingress_ports": [2]},
        {"prefix": "10.0.3.0", "prefix_len": 24, "expected_ingress_ports": [3]},
        # Overlapping more-specific reverse prefix homing on a DIFFERENT port
        # than its covering /16 — exercises reverse-LPM longest-match tie-break.
        {"prefix": "10.1.0.0",  "prefix_len": 16, "expected_ingress_ports": [1]},
        {"prefix": "10.1.5.0",  "prefix_len": 24, "expected_ingress_ports": [3]},
    ],
    # Forward FIB: destination prefix → (egress port, port MAC, next-hop MAC).
    "forward_routes": [
        {"prefix": "10.0.1.0", "prefix_len": 24, "port": 1,
         "port_mac": "08:00:00:00:01:00", "nexthop_mac": "08:00:00:00:01:01"},
        {"prefix": "10.0.2.0", "prefix_len": 24, "port": 2,
         "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        {"prefix": "10.0.3.0", "prefix_len": 24, "port": 3,
         "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
        {"prefix": "10.1.0.0", "prefix_len": 16, "port": 3,
         "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    ],
}


def _config(state: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


# ── Packet introspection (Scapy + dict-style tolerant) ──────────────────────

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


# ── Address / LPM helpers ────────────────────────────────────────────────────

def _ip_to_int(addr: str) -> int:
    parts = [int(x) for x in str(addr).split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _mask(plen: int) -> int:
    return ((1 << plen) - 1) << (32 - plen) if plen else 0


def _lpm_match(addr: str, routes: List[dict]) -> Optional[dict]:
    """Return the route entry with the longest prefix covering addr, or None."""
    a = _ip_to_int(addr)
    best, best_len = None, -1
    for r in routes:
        plen = int(r["prefix_len"])
        m = _mask(plen)
        if (a & m) == (_ip_to_int(r["prefix"]) & m) and plen > best_len:
            best, best_len = r, plen
    return best


def _urpf_verified(src: str, ingress_port: int, cfg: Dict[str, Any]) -> bool:
    """The active-mode reverse-path check (pattern.yaml `urpf_verified`).

    strict / feasible_path:
        a reverse entry matches the source  ∧  (not exempt-default-only)
        ∧  ingress_port ∈ the matched entry's expected-port SET
    loose:
        a reverse entry matches the source  ∧  (not exempt-default-only)
        — ingress_port is NOT examined.
    """
    mode = cfg["urpf_mode"]
    rev = _lpm_match(src, cfg["reverse_routes"])
    if rev is None:
        return False                                   # unroutable source

    # ${exempt_default_route} caveat (RFC 3704 §2.2): a source whose ONLY
    # reverse match is the 0.0.0.0/0 default is un-verifiable → treated as PASS
    # (return True regardless of port / mode).
    if cfg.get("exempt_default_route") and int(rev["prefix_len"]) == 0:
        return True

    if mode == "loose":
        return True                                    # routability only

    # strict / feasible_path: ingress port must be in the expected set.
    expected = [int(p) for p in rev["expected_ingress_ports"]]
    return int(ingress_port) in expected


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _set(packet, layer, fname, value):
    if isinstance(packet, dict):
        packet.setdefault(layer, {})[fname] = value
        return
    try:
        setattr(packet[layer], fname, value)
    except Exception:
        pass


def _drop(state, reason) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


# ── step() — oracle interface ───────────────────────────────────────────────

def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)
    mode = cfg["urpf_mode"]

    # R0 — non-IPv4 drop (the filter does not pass unparsed traffic on)
    if not _has_ipv4(packet):
        return _drop(new_state, "R0_non_ipv4")

    src = _ip(packet, "src", "0.0.0.0")
    dst = _ip(packet, "dst", "0.0.0.0")
    ttl = int(_ip(packet, "ttl", 64))

    # ── uRPF verdict gate (R1 strict/feasible | R2 loose), BEFORE the forward.
    # drop_precedes_forward: a spoofed/unroutable packet matches the drop rule
    # first and never reaches the dst-FIB, even if its dst has a valid route.
    verified = _urpf_verified(src, ingress_port, cfg)
    if not verified:
        if mode == "loose":
            return _drop(new_state, "R2_urpf_drop_loose")
        return _drop(new_state, "R1_urpf_drop_strict")

    # ── R3 / R4 — the ordinary destination forward (verified packets only).
    route = _lpm_match(dst, cfg["forward_routes"])
    if route is None:
        # R4 — uRPF-verified but no forward route (ordinary no-route miss,
        # distinct from the anti-spoof drop above).
        return _drop(new_state, "R4_no_forward_route")

    # R3 — forward: Ether rewrite + TTL-1; IPv4 src/dst preserved.
    out = _clone(packet)
    _set(out, "Ether", "src", route["port_mac"])
    _set(out, "Ether", "dst", route["nexthop_mac"])
    if isinstance(out, dict):
        out.setdefault("IP", {})["ttl"] = ttl - 1
    else:
        try:
            out["IP"].ttl = ttl - 1
        except Exception:
            pass
    return StepResult(
        output_packets={int(route["port"]): [out]},
        new_state=new_state,
        decision="forward",
        invariant_log=[("R3_dst_lpm_forward",
                        {"port": int(route["port"]),
                         "ether_src": route["port_mac"],
                         "ether_dst": route["nexthop_mac"],
                         "ttl": ttl - 1,
                         "urpf_mode": mode,
                         "fwd_prefix": f"{route['prefix']}/{route['prefix_len']}"})],
    )
