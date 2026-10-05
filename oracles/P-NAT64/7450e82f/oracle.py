"""Per-task oracle for benchmark/scale_up/nat64_anchor (P-NAT64).

Stateful NAT64 (RFC 6146 + RFC 6052) translating between IPv6-only clients and
IPv4-only servers, in the canonical D5.0 static-binding seed:

  - R0  neither IP family present (ARP / raw frame)          -> drop
  - R1  v6->v4 hit: ingress(client_port), IPv6 src in v6_client_subnet,
        IPv6 dst in the well-known prefix, AND a control-plane binding exists
        for (v6 src, l4 sport, nextHdr).  HEADER-FAMILY SWAP: the IPv6 header
        is replaced by a freshly built IPv4 header.  IPv4 dst = the 32 bits
        embedded in the v6 dst (RFC 6052 /96 extraction); IPv4 src = the
        allocated v4_base; L4 sport = the bound v4_src_port; TTL = hopLimit-1;
        IPv4 + L4 checksums recomputed; forward(server_port).
  - R3  v6->v4 miss (no binding under static mode, or v6 dst NOT in the
        well-known prefix, or src outside the client subnet)  -> drop
  - R4  v4->v6 hit: ingress(server_port), IPv4 dst == v4_base, AND a binding
        exists for (v4_base, l4 dport, proto).  Reverse HEADER-FAMILY SWAP:
        the IPv4 header is replaced by a freshly built IPv6 header.  IPv6 dst =
        the bound original v6 client address; L4 dport = the bound original v6
        client port; IPv6 src = embed_v4(IPv4 src, wkp); hopLimit = ttl-1; L4
        checksum recomputed (IPv6 has no header checksum); forward(client_port).
  - R5  v4->v6 miss (dst != v4_base, or no binding)            -> drop

Parametric-source contract: every parameter the
pattern's mutation_operators may touch -- the well-known prefix, the v4 base
address, the v6 client subnet, the binding set, the L4 class set, and the
checksum-strictness flag -- is read from state["config"] at runtime, never
baked as a source-level constant.  This lets a parameter rebind (different
seed bindings) reuse this same audited module byte-for-byte.

Dynamic allocation (R2) and teardown eviction (R6) are implemented but DORMANT
under the canonical static seed (mode == static, eviction_policy == none):

  - R2  v6->v4 miss under ${mode} == dynamic: on the first packet of an unseen
        flow the data plane ALLOCATES a v4 L4 port from ${v4_pool_range} (the
        lowest free port, deterministic), installs BOTH binding halves into
        state["bindings"] (pair_symmetry), and translates exactly as R1.  If the
        pool is exhausted (every port in range live, or binding_capacity hit) ->
        drop (folds into R3).  Under ${mode} == static R2 NEVER fires: a binding
        miss falls straight through to R3_v6_to_v4_miss_static, byte-identical to
        the static-only oracle.
  - R6  teardown eviction (${eviction_policy} == teardown): a TCP FIN/RST on an
        established v6->v4 flow evicts BOTH binding halves from state["bindings"]
        (returning the v4 port to the pool) AND still translates+forwards the
        FIN/RST packet in the same pass.  Dormant under eviction_policy == none.

Eviction is packet-driven only (no wall-clock tick): the canonical static seed
sets eviction_policy == none, so no binding is ever evicted here.

PARAMETRIC-SOURCE INVARIANT: mode, v4_pool_range,
binding_capacity, and eviction_policy are all read from state["config"] at
runtime, never baked as source constants.  The dynamic branch keys entirely off
those runtime values, so the SAME audited module serves the static anchor, the
dynamic hard sibling, and any parameter rebind without source-level change.  At the
static anchor seed the dynamic/eviction branches are unreachable, so the anchor's
expected outputs are identical to the static-only predecessor (a933cd1f).

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ── Protocol-number maps (NOT mutation-operator knobs — fixed constants) ─────
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1          # ICMPv4
NEXTHDR_TCP = 6
NEXTHDR_UDP = 17
NEXTHDR_ICMPV6 = 58

# IANA proto (v4) <-> v6 nextHdr.  ICMP is its own class across families.
_V4_OF_NEXTHDR = {NEXTHDR_TCP: PROTO_TCP, NEXTHDR_UDP: PROTO_UDP,
                  NEXTHDR_ICMPV6: PROTO_ICMP}
_NEXTHDR_OF_V4 = {PROTO_TCP: NEXTHDR_TCP, PROTO_UDP: NEXTHDR_UDP,
                  PROTO_ICMP: NEXTHDR_ICMPV6}

# Port-name convention for this instance's two-sided topology.  These are the
# topology's port *names*; the integer they resolve to is read from the
# config's port map so a reseed can relocate the ports.
_CLIENT_PORT_NAME = "s1.client"   # IPv6-facing -> port int 1
_SERVER_PORT_NAME = "s1.server"   # IPv4-facing -> port int 2


# ── Default config mirrors the canonical seed; overridden by state["config"]. ─
# Everything here is a mutation-operator surface and is read at runtime; the
# defaults exist only so the oracle is runnable stand-alone (e.g. audit smoke).
_DEFAULT_CONFIG = {
    "wkp": "64:ff9b::/96",
    "v4_base": "203.0.113.10",
    "v6_client_subnet": "2001:db8:64::/64",
    "mode": "static",
    "eviction_policy": "none",
    "checksum_strict": True,
    "l4_classes": ["tcp", "udp"],
    "client_port": 1,
    "server_port": 2,
    # Dynamic-allocation surface (dormant under mode == static).  Read at
    # runtime; never baked.  v4_pool_range is the inclusive [low, high] band of
    # allocatable IPv4 L4 ports; binding_capacity caps live binding pairs.
    "v4_pool_range": [10000, 65535],
    "binding_capacity": "unbounded",
    # Static control-plane binding pairs.  Each entry is one BIB/session pair:
    #   v6_src, v6_src_port, nextHdr  (the IPv6 transport tuple)
    #     <->  v4_base, v4_src_port, proto  (the allocated IPv4 transport tuple)
    # The v4 dst is NOT stored — it is derived from the v6 dst at translation
    # time via RFC 6052 extraction.
    "bindings": [
        {"v6_src": "2001:db8:64::a", "v6_port": 5000, "nexthdr": NEXTHDR_UDP,
         "v4_port": 14000},
        {"v6_src": "2001:db8:64::a", "v6_port": 6000, "nexthdr": NEXTHDR_TCP,
         "v4_port": 15000},
        {"v6_src": "2001:db8:64::a", "v6_port": 7000, "nexthdr": NEXTHDR_UDP,
         "v4_port": 16000},
        {"v6_src": "2001:db8:64::b", "v6_port": 5000, "nexthdr": NEXTHDR_TCP,
         "v4_port": 17000},
    ],
}


def _config(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    state = state or {}
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    # The live binding set may be threaded through state["bindings"] (so an
    # eviction sibling can mutate it across packets); fall back to the config.
    if "bindings" in state:
        cfg["bindings"] = state["bindings"]
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


def _has_ipv6(packet) -> bool:
    return _has_layer(packet, "IPv6") or _has_layer(packet, "ipv6")


def _has_ipv4(packet) -> bool:
    return _has_layer(packet, "IP") or _has_layer(packet, "ipv4")


def _ip6(packet, fname, default=None):
    v = _field(packet, "IPv6", fname, None)
    if v is None:
        v = _field(packet, "ipv6", fname, None)
    return default if v is None else v


def _ip4(packet, fname, default=None):
    v = _field(packet, "IP", fname, None)
    if v is None:
        v = _field(packet, "ipv4", fname, None)
    return default if v is None else v


def _l4_ports(packet):
    """Return (sport, dport, nextHdr/proto-class-token) for the upper layer."""
    if _has_layer(packet, "TCP") or _has_layer(packet, "tcp"):
        sp = _field(packet, "TCP", "sport", None)
        dp = _field(packet, "TCP", "dport", None)
        if sp is None:
            sp = _field(packet, "tcp", "sport", None)
            dp = _field(packet, "tcp", "dport", None)
        return sp, dp, "tcp"
    if _has_layer(packet, "UDP") or _has_layer(packet, "udp"):
        sp = _field(packet, "UDP", "sport", None)
        dp = _field(packet, "UDP", "dport", None)
        if sp is None:
            sp = _field(packet, "udp", "sport", None)
            dp = _field(packet, "udp", "dport", None)
        return sp, dp, "udp"
    return None, None, None


def _tcp_teardown(packet) -> bool:
    """True iff the packet is TCP with FIN or RST set (R6 eviction trigger)."""
    if not (_has_layer(packet, "TCP") or _has_layer(packet, "tcp")):
        return False
    flags = _field(packet, "TCP", "flags", None)
    if flags is None:
        flags = _field(packet, "tcp", "flags", None)
    if flags is None:
        return False
    # Scapy exposes .flags as a FlagValue (int-like, str-coercible) or an int.
    try:
        fset = set(str(flags))
        if "F" in fset or "R" in fset:
            return True
    except Exception:
        pass
    try:
        fi = int(flags)
        return bool(fi & 0x01) or bool(fi & 0x04)   # FIN=0x01, RST=0x04
    except Exception:
        return False


def _l4_class_of_nexthdr(nh: int) -> Optional[str]:
    if nh == NEXTHDR_TCP:
        return "tcp"
    if nh == NEXTHDR_UDP:
        return "udp"
    if nh == NEXTHDR_ICMPV6:
        return "icmp"
    return None


def _l4_class_of_proto(p: int) -> Optional[str]:
    if p == PROTO_TCP:
        return "tcp"
    if p == PROTO_UDP:
        return "udp"
    if p == PROTO_ICMP:
        return "icmp"
    return None


# ── Address helpers ──────────────────────────────────────────────────────────

def _v6_int(addr: str) -> int:
    return int(ipaddress.IPv6Address(str(addr)))


def _in_v6_prefix(addr: str, cidr: str) -> bool:
    net = ipaddress.ip_network(str(cidr), strict=False)
    return ipaddress.IPv6Address(str(addr)) in net


def _extract_v4(v6_dst: str, wkp_cidr: str) -> str:
    """RFC 6052 §2.2 at /96: the embedded IPv4 address is the last 32 bits."""
    low32 = _v6_int(v6_dst) & 0xFFFFFFFF
    return str(ipaddress.IPv4Address(low32))


def _embed_v4(v4_addr: str, wkp_cidr: str) -> str:
    """RFC 6052 §2.4 at /96: prefix[127:32] ++ the 32-bit IPv4 address."""
    net = ipaddress.ip_network(str(wkp_cidr), strict=False)
    prefix_int = int(net.network_address) & ~0xFFFFFFFF
    return str(ipaddress.IPv6Address(prefix_int | int(ipaddress.IPv4Address(str(v4_addr)))))


# ── Binding lookups (read from runtime state, never baked) ───────────────────

def _bind_outbound(cfg, v6_src, v6_port, nexthdr):
    """v6->v4 (BIB) lookup: keyed by (IPv6 src, L4 sport, nextHdr)."""
    for b in cfg["bindings"]:
        if (str(b["v6_src"]) == str(v6_src)
                and int(b["v6_port"]) == int(v6_port)
                and int(b["nexthdr"]) == int(nexthdr)):
            return b
    return None


def _bind_inbound(cfg, v4_dst, v4_dport, proto):
    """v4->v6 reverse lookup: keyed by (allocated v4 addr, L4 dport, proto)."""
    if str(v4_dst) != str(cfg["v4_base"]):
        return None
    nexthdr = _NEXTHDR_OF_V4.get(int(proto))
    if nexthdr is None:
        return None
    for b in cfg["bindings"]:
        if (int(b["v4_port"]) == int(v4_dport)
                and int(b["nexthdr"]) == nexthdr):
            return b
    return None


# ── Dynamic allocation (R2) — pool/capacity read from runtime config ─────────

def _pool_range(cfg) -> Tuple[int, int]:
    """[low, high] inclusive band of allocatable IPv4 L4 ports under dynamic mode."""
    rng = cfg.get("v4_pool_range", [10000, 65535])
    low, high = int(rng[0]), int(rng[1])
    return low, high


def _capacity(cfg) -> Optional[int]:
    """Max live binding pairs, or None when unbounded."""
    cap = cfg.get("binding_capacity", "unbounded")
    if cap is None or cap == "unbounded":
        return None
    return int(cap)


def _alloc_v4_port(cfg) -> Optional[int]:
    """Pick the lowest free IPv4 L4 port in ${v4_pool_range} not already live.

    Deterministic (lowest-free) so the oracle's allocation is reproducible.
    Returns None when the pool is exhausted (every in-range port is live) — the
    caller then folds the flow into R3 (pool-exhaustion drop)."""
    low, high = _pool_range(cfg)
    live = {int(b["v4_port"]) for b in cfg["bindings"]}
    for p in range(low, high + 1):
        if p not in live:
            return p
    return None


def _drop(state, reason) -> StepResult:
    return StepResult(output_packets={}, new_state=dict(state or {}),
                      decision="drop", invariant_log=[("drop", reason)])


def _resolve_ingress(ingress_port, cfg):
    """Normalise the ingress port to 'client' | 'server' | None."""
    client = cfg.get("client_port", 1)
    server = cfg.get("server_port", 2)
    if ingress_port in (_CLIENT_PORT_NAME, client, str(client)):
        return "client"
    if ingress_port in (_SERVER_PORT_NAME, server, str(server)):
        return "server"
    return None


# ── step() — oracle interface ───────────────────────────────────────────────

def step(packet, ingress_port=1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)

    side = _resolve_ingress(ingress_port, cfg)

    # R0 — neither IP family present (ARP / raw frame) -> drop.
    if not _has_ipv6(packet) and not _has_ipv4(packet):
        return _drop(new_state, "R0_out_of_scope")

    # ── v6 -> v4 direction (ingress on the client/IPv6 side) ─────────────────
    if side == "client" and _has_ipv6(packet):
        v6_src = str(_ip6(packet, "src", "::"))
        v6_dst = str(_ip6(packet, "dst", "::"))
        hlim = int(_ip6(packet, "hlim", 0))
        sport, dport, l4cls = _l4_ports(packet)
        nh = int(_ip6(packet, "nh", 0))
        if l4cls is None:
            # Derive nextHdr class from the IPv6 next-header field.
            l4cls = _l4_class_of_nexthdr(nh)

        # R3 gate: source outside the served client subnet, or destination not
        # in the well-known prefix -> not a translation candidate -> drop.
        if not _in_v6_prefix(v6_src, cfg["v6_client_subnet"]):
            return _drop(new_state, "R3_src_not_client")
        if not _in_v6_prefix(v6_dst, cfg["wkp"]):
            return _drop(new_state, "R3_dst_not_wkp")
        if l4cls is not None and l4cls not in cfg.get("l4_classes", []):
            return _drop(new_state, "R3_l4_class_unhandled")

        # nextHdr token: prefer the parsed L4 layer, else the IPv6 nh field.
        nexthdr = {"tcp": NEXTHDR_TCP, "udp": NEXTHDR_UDP,
                   "icmp": NEXTHDR_ICMPV6}.get(l4cls, nh)

        rule = "R1_v6_to_v4_hit"
        b = _bind_outbound(cfg, v6_src, sport, nexthdr)
        if b is None:
            # No pre-installed / live binding for this flow.
            if str(cfg.get("mode", "static")) == "dynamic":
                # R2 — data-plane allocation from the v4 pool.  pair_symmetry:
                # both binding halves are installed atomically into new_state.
                cap = _capacity(cfg)
                if cap is not None and len(cfg["bindings"]) >= cap:
                    # Binding table full -> no allocation -> R3 drop.
                    return _drop(new_state, "R3_v6_to_v4_capacity_full")
                v4_sport_alloc = _alloc_v4_port(cfg)
                if v4_sport_alloc is None:
                    # v4 pool exhausted -> R3 drop.
                    return _drop(new_state, "R3_v6_to_v4_pool_exhausted")
                b = {"v6_src": str(v6_src), "v6_port": int(sport),
                     "nexthdr": int(nexthdr), "v4_port": int(v4_sport_alloc)}
                # Thread the new live binding set through new_state so that
                # subsequent packets in the same input sequence (the reverse
                # v4->v6, a second flow, a teardown) observe it.
                live = list(cfg["bindings"]) + [b]
                new_state["bindings"] = live
                cfg = dict(cfg)
                cfg["bindings"] = live
                rule = "R2_v6_to_v4_alloc_dynamic"
            else:
                # R3 — static miss (no pre-installed binding) -> drop.
                return _drop(new_state, "R3_v6_to_v4_miss_static")

        # R1/R2 — HEADER-FAMILY SWAP: emit an IPv4 packet.
        v4_dst = _extract_v4(v6_dst, cfg["wkp"])
        v4_src = str(cfg["v4_base"])
        v4_sport = int(b["v4_port"])
        proto = _V4_OF_NEXTHDR.get(nexthdr, PROTO_UDP)
        out = _build_v4_output(packet, l4cls, v4_src, v4_dst, v4_sport,
                               proto, ttl=max(0, hlim - 1))
        ilog = [(rule, {
            "egress_family": "ipv4",
            "ip_src": v4_src, "ip_dst": v4_dst,
            "l4_sport": v4_sport, "ttl": max(0, hlim - 1),
            "proto": proto, "checksum_recompute": bool(cfg.get("checksum_strict")),
        })]

        # R6 — teardown eviction (packet-driven): a TCP FIN/RST on an established
        # flow tears down BOTH binding halves AFTER the packet is translated and
        # forwarded in this same pass.  Dormant unless eviction_policy==teardown.
        if (str(cfg.get("eviction_policy", "none")) == "teardown"
                and _tcp_teardown(packet)):
            remaining = [x for x in cfg["bindings"]
                         if not (str(x["v6_src"]) == str(v6_src)
                                 and int(x["v6_port"]) == int(sport)
                                 and int(x["nexthdr"]) == int(nexthdr))]
            new_state["bindings"] = remaining
            ilog.append(("R6_teardown_evict",
                         {"v6_src": str(v6_src), "v6_port": int(sport),
                          "v4_port": v4_sport, "freed": True}))

        return StepResult(output_packets={int(cfg.get("server_port", 2)): [out]},
                          new_state=new_state, decision="forward",
                          invariant_log=ilog)

    # ── v4 -> v6 direction (ingress on the server/IPv4 side) ─────────────────
    if side == "server" and _has_ipv4(packet):
        v4_dst = str(_ip4(packet, "dst", "0.0.0.0"))
        v4_src = str(_ip4(packet, "src", "0.0.0.0"))
        ttl = int(_ip4(packet, "ttl", 0))
        proto = int(_ip4(packet, "proto", 0))
        sport, dport, l4cls = _l4_ports(packet)

        # R5 — wrong-target or no-binding -> drop (fail-closed).
        if v4_dst != str(cfg["v4_base"]):
            return _drop(new_state, "R5_v4_wrong_dst")
        b = _bind_inbound(cfg, v4_dst, dport, proto)
        if b is None:
            return _drop(new_state, "R5_v4_to_v6_miss")

        # R4 — reverse HEADER-FAMILY SWAP: emit an IPv6 packet.
        v6_dst = str(b["v6_src"])              # restore original v6 client addr
        v6_dport = int(b["v6_port"])           # restore original v6 client port
        v6_src = _embed_v4(v4_src, cfg["wkp"])  # synthesised v6 src under wkp
        out = _build_v6_output(packet, l4cls, v6_src, v6_dst, v6_dport,
                               hlim=max(0, ttl - 1))
        ilog = [("R4_v4_to_v6_hit", {
            "egress_family": "ipv6",
            "ip6_src": v6_src, "ip6_dst": v6_dst,
            "l4_dport": v6_dport, "hlim": max(0, ttl - 1),
        })]
        return StepResult(output_packets={int(cfg.get("client_port", 1)): [out]},
                          new_state=new_state, decision="forward",
                          invariant_log=ilog)

    # Anything else (wrong-side family, unknown ingress) -> drop.
    return _drop(new_state, "R3_R5_default_drop")


# ── Output packet builders (Scapy when available; dict fallback) ─────────────

def _build_v4_output(in_pkt, l4cls, v4_src, v4_dst, v4_sport, proto, ttl):
    """Rebuild the L2 frame with a fresh IPv4 header replacing the IPv6 one.
    The L4 payload bytes are carried over; checksums are left for Scapy to
    recompute on rebuild (= a faithful recompute, RFC 6146 §3.5)."""
    try:
        from scapy.all import Ether, IP, TCP, UDP
        eth_src = _field(in_pkt, "Ether", "src", "00:00:00:00:00:00")
        eth_dst = _field(in_pkt, "Ether", "dst", "00:00:00:00:00:00")
        ip = IP(src=v4_src, dst=v4_dst, ttl=int(ttl), proto=int(proto))
        if l4cls == "tcp":
            sp = _field(in_pkt, "TCP", "sport", 0)
            dp = _field(in_pkt, "TCP", "dport", 0)
            flags = _field(in_pkt, "TCP", "flags", 0)
            l4 = TCP(sport=int(v4_sport), dport=int(dp), flags=flags)
        elif l4cls == "udp":
            dp = _field(in_pkt, "UDP", "dport", 0)
            l4 = UDP(sport=int(v4_sport), dport=int(dp))
        else:
            l4 = None
        eth = Ether(src=eth_src, dst=eth_dst, type=0x0800)
        pkt = eth / ip if l4 is None else eth / ip / l4
        # Force checksum/length recompute by round-tripping the bytes.
        return Ether(bytes(pkt))
    except Exception:
        return {
            "Ether": {"type": 0x0800},
            "IP": {"src": v4_src, "dst": v4_dst, "ttl": int(ttl), "proto": int(proto)},
            "L4": {"sport": int(v4_sport)},
        }


def _build_v6_output(in_pkt, l4cls, v6_src, v6_dst, v6_dport, hlim):
    """Rebuild the L2 frame with a fresh IPv6 header replacing the IPv4 one."""
    try:
        from scapy.all import Ether, TCP, UDP
        from scapy.layers.inet6 import IPv6
        eth_src = _field(in_pkt, "Ether", "src", "00:00:00:00:00:00")
        eth_dst = _field(in_pkt, "Ether", "dst", "00:00:00:00:00:00")
        ip6 = IPv6(src=v6_src, dst=v6_dst, hlim=int(hlim))
        if l4cls == "tcp":
            sp = _field(in_pkt, "TCP", "sport", 0)
            flags = _field(in_pkt, "TCP", "flags", 0)
            l4 = TCP(sport=int(sp), dport=int(v6_dport), flags=flags)
        elif l4cls == "udp":
            sp = _field(in_pkt, "UDP", "sport", 0)
            l4 = UDP(sport=int(sp), dport=int(v6_dport))
        else:
            l4 = None
        eth = Ether(src=eth_src, dst=eth_dst, type=0x86DD)
        pkt = eth / ip6 if l4 is None else eth / ip6 / l4
        return Ether(bytes(pkt))
    except Exception:
        return {
            "Ether": {"type": 0x86DD},
            "IPv6": {"src": v6_src, "dst": v6_dst, "hlim": int(hlim)},
            "L4": {"dport": int(v6_dport)},
        }


# ── Dynamic-extreme self-test (oracle-audit coverage the IPv4-only audit runner can
#    not reach) ─────────────────────────────────────────────────────────────
#
# The oracle audit harness
# builds inputs only from {Ether, IP, TCP, UDP, ICMP, ARP} and threads NO
# runtime state, so it cannot drive the v6->v4 direction (IPv6 input) nor the
# DYNAMIC-ALLOCATION extreme (mode==dynamic, which needs an IPv6 first packet
# AND cross-packet binding state).  This `_selftest` exercises R2 at the
# v4_pool_range extremes — lowest-free allocation and pool-exhaustion drop —
# plus the reverse v4->v6 path for a dynamically-allocated binding and R6
# teardown eviction, with mode/v4_pool_range/binding_capacity/eviction_policy
# read from runtime state (the parametric-source invariant).  Run directly:
#     python3 oracle.py        (or simulator.py)

def _selftest() -> int:  # pragma: no cover - audit/dev convenience only
    from scapy.all import Ether, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    def v6(src, dst, hlim, l4, sp, dp, flags=None):
        L = (UDP(sport=sp, dport=dp) if l4 == "udp"
             else TCP(sport=sp, dport=dp, flags=flags or "S"))
        return Ether(bytes(Ether(src="08:00:00:00:01:01",
                                 dst="08:00:00:00:01:00")
                           / IPv6(src=src, dst=dst, hlim=hlim) / L))

    def v4(src, dst, ttl, l4, sp, dp, flags=None):
        L = (UDP(sport=sp, dport=dp) if l4 == "udp"
             else TCP(sport=sp, dport=dp, flags=flags or "A"))
        return Ether(bytes(Ether(src="08:00:00:00:02:02",
                                 dst="08:00:00:00:02:00")
                           / IP(src=src, dst=dst, ttl=ttl) / L))

    def base_cfg(**over):
        c = {"wkp": "64:ff9b::/96", "v4_base": "203.0.113.10",
             "v6_client_subnet": "2001:db8:64::/64", "mode": "dynamic",
             "eviction_policy": "none", "checksum_strict": True,
             "l4_classes": ["tcp", "udp"], "client_port": 1, "server_port": 2,
             "v4_pool_range": [14000, 14002], "binding_capacity": "unbounded",
             "bindings": []}
        c.update(over)
        return c

    def thread(st, r, cfg):
        st = dict(r.new_state)
        cfg = dict(cfg)
        cfg["bindings"] = st.get("bindings", cfg["bindings"])
        st["config"] = cfg
        return st, cfg

    failures = []

    # 1) R2 dynamic allocation at the pool extremes: 3 distinct flows take the
    #    3 lowest-free ports; the 4th NEW flow exhausts the pool -> drop.
    cfg = base_cfg()
    st = {"config": cfg, "bindings": []}
    allocated = []
    for sp in (5000, 6000, 7000):
        r = step(v6("2001:db8:64::a", "64:ff9b::203.0.113.9", 64, "udp", sp, 53),
                 "s1.client", st)
        if r.decision != "forward":
            failures.append(f"R2 alloc sp={sp} expected forward got {r.decision}")
        else:
            allocated.append(int(list(r.output_packets.values())[0][0]["UDP"].sport))
        st, cfg = thread(st, r, cfg)
    if allocated != [14000, 14001, 14002]:
        failures.append(f"R2 lowest-free alloc expected [14000,14001,14002] got {allocated}")
    r = step(v6("2001:db8:64::a", "64:ff9b::203.0.113.9", 64, "udp", 8000, 53),
             "s1.client", st)
    if r.decision != "drop":
        failures.append(f"R3 pool-exhaust expected drop got {r.decision}")

    # 2) reverse v4->v6 for a dynamically-allocated binding restores the client.
    r = step(v4("203.0.113.9", "203.0.113.10", 64, "udp", 53, 14000),
             "s1.server", st)
    if r.decision != "forward":
        failures.append(f"R4 reverse expected forward got {r.decision}")
    else:
        o = list(r.output_packets.values())[0][0]
        if str(o["IPv6"].dst) != "2001:db8:64::a" or int(o["UDP"].dport) != 5000:
            failures.append(f"R4 reverse restored wrong client {o['IPv6'].dst}:{o['UDP'].dport}")

    # 3) R6 teardown eviction: alloc a TCP flow, then FIN -> translate+evict.
    cfg = base_cfg(eviction_policy="teardown", v4_pool_range=[15000, 15001])
    st = {"config": cfg, "bindings": []}
    r = step(v6("2001:db8:64::a", "64:ff9b::203.0.113.9", 64, "tcp", 6000, 80, "S"),
             "s1.client", st)
    st, cfg = thread(st, r, cfg)
    n_before = len(st["bindings"])
    r = step(v6("2001:db8:64::a", "64:ff9b::203.0.113.9", 64, "tcp", 6000, 80, "FA"),
             "s1.client", st)
    n_after = len(r.new_state.get("bindings", []))
    if r.decision != "forward":
        failures.append(f"R6 teardown expected forward got {r.decision}")
    if not (n_before == 1 and n_after == 0):
        failures.append(f"R6 teardown expected 1->0 bindings got {n_before}->{n_after}")

    # 4) FAITHFULNESS: under mode==static a binding miss drops (R3 static), the
    #    dynamic branch stays dormant.
    scfg = base_cfg(mode="static", v4_pool_range=[10000, 65535],
                    bindings=[{"v6_src": "2001:db8:64::a", "v6_port": 5000,
                               "nexthdr": 17, "v4_port": 14000}])
    sst = {"config": scfg, "bindings": scfg["bindings"]}
    r = step(v6("2001:db8:64::a", "64:ff9b::203.0.113.9", 64, "udp", 9000, 53),
             "s1.client", sst)
    if r.decision != "drop" or r.invariant_log[0][1] != "R3_v6_to_v4_miss_static":
        failures.append(f"static miss expected R3_v6_to_v4_miss_static drop got {r.decision}/{r.invariant_log}")

    if failures:
        print("SELFTEST FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("SELFTEST PASSED: R2 dynamic alloc [14000,14001,14002], pool-exhaust "
          "drop, R4 reverse of dynamic binding, R6 teardown evict 1->0, static "
          "miss dormant->R3.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys as _sys
    _sys.exit(_selftest())
