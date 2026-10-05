"""Python oracle for benchmark/redesign/ipv4_routing_mut2.

P-IPv4Routing under the ECMP harden (multipath_mode == ecmp_hash_5tuple):
the same R0..R7 rule sequence as the anchor, but R3's next-hop selection
is lifted from a singleton (i = 0) to a hash-threshold pick over a
multi-member next-hop group (RFC 2992):

    i = hash(5-tuple) % |group|        (per-flow, stable across volatile fields)

This changes R3's rule SEMANTICS relative to the anchor oracle, so it is a
distinct content-addressed oracle.

The selection here uses CRC-16/ARC over the canonical 5-tuple byte string.
The benchmark's verifier checks the *behavioural* RFC 2992 properties
(flow-consistency, group-membership, hash-distribution) rather than a
specific egress port, so the submission is free to choose its own hash; this
oracle's concrete index is the ground truth only for the oracle audit and
authoring-time checks (flow-consistency and spread), not for the
expected blocks the submission is graded against.

step() is the standard oracle form:  step(packet, ingress_port, state).
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


# A route is {prefix, prefix_len, group:[{port, port_mac, nexthop_mac}, ...]}.
_DEFAULT_CONFIG = {
    "routes": [],
    "multipath_mode": "ecmp_hash_5tuple",
    "martian_filter_enabled": False,
    "emit_icmp_errors": False,
    "default_action": "drop",
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


# ── Packet introspection (Scapy + dict tolerant) ────────────────────────────

def _has_layer(packet, name):
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    return isinstance(packet, dict) and name in packet


def _f(packet, layer, fname, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        v = getattr(packet[layer], fname, default)
        return v if v is not None else default
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _has_ipv4(p):
    return _has_layer(p, "IP") or _has_layer(p, "ipv4")


def _ip(p, fn, d=None):
    v = _f(p, "IP", fn, None)
    if v is None:
        v = _f(p, "ipv4", fn, None)
    return d if v is None else v


def _l4_ports(p):
    """(sport, dport) from TCP/UDP, or (0, 0)."""
    for layer in ("TCP", "UDP"):
        if _has_layer(p, layer):
            return int(_f(p, layer, "sport", 0)), int(_f(p, layer, "dport", 0))
    return 0, 0


# ── Address + hash helpers ──────────────────────────────────────────────────

def _ip2i(a):
    q = [int(x) for x in str(a).split(".")]
    return (q[0] << 24) | (q[1] << 16) | (q[2] << 8) | q[3]


def _lpm(dst, routes):
    d = _ip2i(dst)
    best, blen = None, -1
    for r in routes:
        plen = int(r["prefix_len"])
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        if (d & mask) == (_ip2i(r["prefix"]) & mask) and plen > blen:
            best, blen = r, plen
    return best


def _dir_bcast(dst, routes):
    d = _ip2i(dst)
    for r in routes:
        plen = int(r["prefix_len"])
        if 0 < plen < 32:
            net = _ip2i(r["prefix"]) & (((1 << plen) - 1) << (32 - plen))
            if d == net | ((1 << (32 - plen)) - 1):
                return True
    return False


def _martian(src):
    s = _ip2i(src)
    def inb(p, l):
        m = ((1 << l) - 1) << (32 - l) if l else 0
        return (s & m) == (_ip2i(p) & m)
    return inb("127.0.0.0", 8) or inb("0.0.0.0", 8) or inb("224.0.0.0", 4) or src == "255.255.255.255"


def _crc16_arc(data: bytes) -> int:
    """CRC-16/ARC (poly 0xA001 reflected, init 0x0000) — BMv2 HashAlgorithm.crc16."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def _ecmp_index(src, dst, proto, sport, dport, k):
    """Hash-threshold pick over a k-member group, keyed on the stable 5-tuple."""
    blob = b"".join(x.to_bytes(4, "big") for x in (_ip2i(src), _ip2i(dst))) + \
        bytes([proto & 0xFF]) + sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
    return _crc16_arc(blob) % k


def _clone(p):
    if isinstance(p, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in p.items()}
    try:
        return p.copy()
    except Exception:
        return p


def _set(p, layer, fn, val):
    if isinstance(p, dict):
        p.setdefault(layer, {})[fn] = val
    else:
        try:
            setattr(p[layer], fn, val)
        except Exception:
            pass


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


# ── step() ───────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    ns = dict(state)
    routes = cfg["routes"]

    if not _has_ipv4(packet):
        return _drop(ns, "R0_non_ipv4")

    if int(_ip(packet, "version", 4)) != 4 or int(_ip(packet, "ihl", 5)) < 5:
        return _drop(ns, "R1_invalid_header")
    tl = _ip(packet, "len", None)
    if tl is not None and int(tl) < int(_ip(packet, "ihl", 5)) * 4:
        return _drop(ns, "R1_total_length")

    ttl = int(_ip(packet, "ttl", 0))
    src = _ip(packet, "src", "0.0.0.0")
    dst = _ip(packet, "dst", "0.0.0.0")

    if ttl <= 0:
        return _drop(ns, "R2_ttl_exhausted")
    if dst == "255.255.255.255":
        return _drop(ns, "R5_limited_broadcast")
    if cfg.get("martian_filter_enabled") and _martian(src):
        return _drop(ns, "R6_martian_src")
    if _dir_bcast(dst, routes):
        return _drop(ns, "R7_directed_broadcast")

    route = _lpm(dst, routes)
    if route is None:
        return _drop(ns, "R4_no_route")

    group = route["group"]
    if cfg["multipath_mode"] == "none" or len(group) == 1:
        i = 0
    else:
        sport, dport = _l4_ports(packet)
        proto = int(_ip(packet, "proto", 6))
        i = _ecmp_index(src, dst, proto, sport, dport, len(group))
    nh = group[i]

    out = _clone(packet)
    _set(out, "Ether", "src", nh["port_mac"])
    _set(out, "Ether", "dst", nh["nexthop_mac"])
    if isinstance(out, dict):
        out.setdefault("IP", {})["ttl"] = ttl - 1
        out["IP"]["chksum"] = None        # RFC 1812 §5.2.2.5: recompute hdr checksum on egress (TTL changed)
    else:
        try:
            out["IP"].ttl = ttl - 1
            out["IP"].chksum = None        # force scapy to recompute the IPv4 header checksum
        except Exception:
            pass
    return StepResult(
        output_packets={int(nh["port"]): [out]},
        new_state=ns,
        decision="forward",
        invariant_log=[("R3_forward_ecmp",
                        {"port": int(nh["port"]), "group_size": len(group), "index": i,
                         "prefix": f"{route['prefix']}/{route['prefix_len']}"})],
    )
