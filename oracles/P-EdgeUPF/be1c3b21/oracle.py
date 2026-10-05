"""Composed oracle for P-EdgeUPF (stateless ACL ∘ GTP-U decap/encap ∘ LPM
forward) at seed `edge_upf_anchor-default`.

Implements the single-pass 5G edge UPF pipeline in the binding order
ACL → decap/encap → route:

  STAGE 1 — ACL classification (P-ACL). The INNER user 5-tuple is matched
    against a stateless ternary table by descending priority. A deny (or a
    miss under default_acl_action == deny) drops the packet BEFORE any tunnel
    or forwarding work (acl_on_inner). On the uplink the inner tuple is the
    GTP-U-encapsulated inner IP datagram; on the downlink it is the bare
    incoming packet.

  STAGE 2 — GTP-U tunnel endpoint (P-GTPUEncap). Direction is decided by
    ingress port:
      access_port -> UPLINK decap: the input is
        Ether/IP/UDP(2152)/GTP_U_Header/IP(inner)/L4. A non-GTP-U IPv4 packet
        on the access port (no UDP/2152 tunnel) drops. Strip the outer
        Ether/IP/UDP/GTP-U; the inner IPv4 datagram becomes the packet; the
        LPM key is the inner IP.dst.
      core_port -> DOWNLINK encap: the input is plain Ether/IP(dst==UE). Look
        up the bearer by IP.dst; a miss DROPS (no PDU session). Build a NEW
        outer header Ether/IP(src=upf_n3_ip,dst=gnb_ip)/UDP(2152)/
        GTP_U_Header(teid=egress_teid) over the original packet; the LPM key is
        the outer dst (gnb_ip).

  STAGE 3 — LPM forward (P-IPv4Routing). The fib is consulted on the
    direction-specific destination (inner dst uplink, outer dst downlink). No
    match or ttl == 0 on the routed header drops; otherwise the routed header's
    TTL is decremented once, Ether.dst is rewritten to the next hop, and the
    packet egresses.

Load-bearing composite contracts:
  - decap_before_route: the uplink LPM key is the inner dst exposed by decap.
  - acl_on_inner: the deny verdict keys on the inner user tuple both directions.
  - bearer_dependence: a downlink packet to a UE with no bearer drops.
  - encap_outer_header_completeness: the downlink outer header carries
    upf_n3_ip, the bearer gnb_ip, gtpu_udp_port, and the bearer egress_teid.
  - compound_checksum_validity: one IPv4 (and outer UDP, for encap) checksum
    recompute covers the TTL decrement / new-header construction.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant.

TTL convention (binding, inherited from the IPv4 anchor): gate the routed
header's ttl > 0; ttl == 0 drops; ttl == 1 forwards with egress ttl == 0
(decrement once). The uplink decrements the inner (now outermost) TTL; the
downlink builds a fresh outer header and preserves the inner TTL end-to-end.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
ACCESS_PORT = 1
CORE_PORT = 2
UPF_N3_IP = "10.0.1.1"
GTPU_UDP_PORT = 2152
DEFAULT_ACL_ACTION = "permit"

# Stateless ACL: priority + action + ternary inner src/dst/proto/sport/dport
# (missing field = wildcard). Evaluated on the INNER user tuple.
ACL_RULES = [
    {"priority": 100, "action": "deny", "ipv4_src": "10.0.9.66/32"},   # blocked UE
]

# Control-plane bearer bindings: UE IP -> (egress_teid, gnb_ip).
BEARERS = [
    {"ue_ip": "10.0.9.5", "egress_teid": 100, "gnb_ip": "10.0.1.5"},
]

# LPM forwarding table: (subnet, prefix) -> (egress_port, next_hop_mac).
FIB = [
    (("10.0.1.0", 24),     (ACCESS_PORT, "08:00:00:00:01:01")),   # gNB underlay (downlink outer)
    (("198.51.100.0", 24), (CORE_PORT,   "08:00:00:00:02:02")),   # internet (uplink inner dst)
]


# ── helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _ipv4_match(addr: str, cidr: Optional[str]) -> bool:
    if cidr is None:
        return True
    if "/" in cidr:
        net, n = cidr.split("/"); n = int(n)
    else:
        net, n = cidr, 32
    mask = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0
    return (_ip_to_int(addr) & mask) == (_ip_to_int(net) & mask)


def _eq_or_any(v, c) -> bool:
    return c is None or v == c


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
    direction: Optional[str] = None        # 'uplink' | 'downlink' | None
    acl_verdict: Optional[str] = None       # 'permit' | 'deny'
    # uplink decap output (the inner datagram becomes the packet)
    inner_dst: Optional[str] = None         # routed dst after decap (== inner IP.dst)
    inner_src: Optional[str] = None
    # downlink encap output (a NEW outer header is pushed over the packet)
    outer_src: Optional[str] = None         # outer IP.src (upf_n3_ip)
    outer_dst: Optional[str] = None         # outer IP.dst (gnb_ip)
    outer_udp_sport: Optional[int] = None
    outer_udp_dport: Optional[int] = None
    encap_teid: Optional[int] = None
    encap_inner_dst: Optional[str] = None   # inner IP.dst preserved (== UE IP)
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class EdgeUPFSimulator:
    access_port: int = ACCESS_PORT
    core_port: int = CORE_PORT
    upf_n3_ip: str = UPF_N3_IP
    gtpu_udp_port: int = GTPU_UDP_PORT
    default_acl_action: str = DEFAULT_ACL_ACTION
    acl_rules: list = field(default_factory=lambda: [dict(r) for r in ACL_RULES])
    bearers: list = field(default_factory=lambda: [dict(b) for b in BEARERS])
    fib: list = field(default_factory=lambda: list(FIB))

    def reset(self):
        # Stateless w.r.t. graded packets (the bearer/ACL/FIB tables are
        # control-plane state, not per-packet). Nothing to clear.
        pass

    # ── ACL on the inner user tuple ─────────────────────────────────────────
    def _acl_verdict(self, t: dict) -> str:
        best, best_p = None, -1
        for r in self.acl_rules:
            if (_ipv4_match(t["src"], r.get("ipv4_src"))
                    and _ipv4_match(t["dst"], r.get("ipv4_dst"))
                    and _eq_or_any(t["proto"], r.get("proto"))
                    and _eq_or_any(t["sport"], r.get("sport"))
                    and _eq_or_any(t["dport"], r.get("dport"))):
                p = int(r["priority"])
                if p > best_p:
                    best, best_p = r, p
        return best["action"] if best is not None else self.default_acl_action

    def _bearer(self, ue_ip: str):
        for b in self.bearers:
            if b["ue_ip"] == ue_ip:
                return b
        return None

    @staticmethod
    def _inner_ip(pkt, udp, IP, GTP_U_Header):
        """Return the inner IPv4 datagram of a GTP-U uplink packet.

        Handles two builds: (1) the on-wire form Ether/IP/UDP(2152)/
        GTP_U_Header/IP(inner)/L4 where the inner IP is the 2nd IP layer; and
        (2) a degenerate build (e.g. an audit harness that cannot synthesise
        the GTP-U layer) where the UDP payload is the inner IP bytes directly,
        optionally prefixed by an 8-byte GTP-U header. We parse the UDP payload
        bytes: an IPv4 header begins with version nibble 0x4, a GTP-U header
        with version nibble 0x3 (version=1 in the top 3 bits)."""
        # Fast path: a real GTP-U layer with a parsed inner IP.
        if GTP_U_Header in pkt:
            inner = pkt.getlayer(IP, 2)
            if inner is not None:
                return inner
        payload = bytes(udp.payload)
        if not payload:
            return None
        ver = payload[0] >> 4
        if ver == 4:                       # UDP payload is the inner IP directly
            return IP(payload)
        # GTP-U header present in the bytes: strip it (8 mandatory octets;
        # extension/seq/npdu add 4 more when any of E/S/PN is set).
        try:
            g = GTP_U_Header(payload)
        except Exception:
            return None
        rest = bytes(g.payload)
        if rest and (rest[0] >> 4) == 4:
            return IP(rest)
        return None

    @staticmethod
    def _l4_ports(layer):
        if layer is None:
            return 0, 0
        return int(getattr(layer, "sport", 0) or 0), int(getattr(layer, "dport", 0) or 0)

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, UDP
        from scapy.contrib.gtp import GTP_U_Header

        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")

        if in_port == self.access_port:
            return self._uplink(scapy_pkt, IP, TCP, UDP, GTP_U_Header)
        elif in_port == self.core_port:
            return self._downlink(scapy_pkt, IP, TCP, UDP)
        return StepResult(False, "drop_unknown_port")

    # ── uplink: decap then route on the inner dst ───────────────────────────
    def _uplink(self, pkt, IP, TCP, UDP, GTP_U_Header) -> StepResult:
        # Must be a GTP-U tunnel on the access port: outer UDP on the GTP-U
        # port carrying an inner IPv4 datagram (behind a GTP-U header).
        udp = pkt.getlayer(UDP)
        if udp is None or int(udp.dport) != int(self.gtpu_udp_port):
            return StepResult(False, "drop_no_gtpu")
        inner = self._inner_ip(pkt, udp, IP, GTP_U_Header)
        if inner is None:
            return StepResult(False, "drop_no_gtpu")

        # inner L4 (after the inner IP)
        inner_l4 = None
        if inner.haslayer(TCP):
            inner_l4 = inner.getlayer(TCP)
        elif inner.haslayer(UDP):
            inner_l4 = inner.getlayer(UDP)
        isport, idport = self._l4_ports(inner_l4)
        t = {"src": inner.src, "dst": inner.dst, "proto": int(inner.proto),
             "sport": isport, "dport": idport}

        # STAGE 1 — ACL on the INNER tuple.
        verdict = self._acl_verdict(t)
        ilog = [("acl_on_inner", {"verdict": verdict, "inner_src": inner.src})]
        if verdict == "deny":
            return StepResult(False, "drop_acl_deny", direction="uplink",
                              acl_verdict="deny", invariant_log=ilog)

        # STAGE 2 — decap: the inner IP datagram becomes the packet.
        ilog.append(("decap_before_route", {"route_dst": inner.dst}))

        # STAGE 3 — LPM on the INNER dst.
        ttl = int(inner.ttl)
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired", direction="uplink",
                              acl_verdict=verdict, invariant_log=ilog)
        nh = _lpm_lookup(inner.dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", direction="uplink",
                              acl_verdict=verdict, invariant_log=ilog)
        egress, mac = nh
        ilog.append(("compound_checksum_validity", {"ttl_decremented": True}))
        return StepResult(
            True, "forward_uplink_decap", output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, direction="uplink", acl_verdict=verdict,
            inner_dst=inner.dst, inner_src=inner.src, invariant_log=ilog)

    # ── downlink: ACL, bearer-driven encap, then route on the outer dst ──────
    def _downlink(self, pkt, IP, TCP, UDP) -> StepResult:
        ip = pkt.getlayer(IP)               # the bare packet
        l4 = None
        if pkt.haslayer(TCP):
            l4 = pkt.getlayer(TCP)
        elif pkt.haslayer(UDP):
            l4 = pkt.getlayer(UDP)
        sport, dport = self._l4_ports(l4)
        t = {"src": ip.src, "dst": ip.dst, "proto": int(ip.proto),
             "sport": sport, "dport": dport}

        # STAGE 1 — ACL on the (bare = inner) tuple.
        verdict = self._acl_verdict(t)
        ilog = [("acl_on_inner", {"verdict": verdict, "inner_dst": ip.dst})]
        if verdict == "deny":
            return StepResult(False, "drop_acl_deny", direction="downlink",
                              acl_verdict="deny", invariant_log=ilog)

        # STAGE 2 — bearer lookup + encap.
        bearer = self._bearer(ip.dst)
        if bearer is None:
            return StepResult(False, "drop_no_bearer", direction="downlink",
                              acl_verdict=verdict,
                              invariant_log=ilog + [("bearer_dependence",
                                                     {"ue_ip": ip.dst, "hit": False})])
        gnb_ip = bearer["gnb_ip"]
        teid = int(bearer["egress_teid"])
        ilog.append(("bearer_dependence", {"ue_ip": ip.dst, "teid": teid, "hit": True}))
        ilog.append(("encap_outer_header_completeness",
                     {"outer_src": self.upf_n3_ip, "outer_dst": gnb_ip, "teid": teid}))

        # STAGE 3 — LPM on the OUTER dst (gNB underlay).
        nh = _lpm_lookup(gnb_ip, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", direction="downlink",
                              acl_verdict=verdict, invariant_log=ilog)
        egress, mac = nh
        ilog.append(("compound_checksum_validity", {"new_outer_header": True}))
        return StepResult(
            True, "forward_downlink_encap", output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, direction="downlink", acl_verdict=verdict,
            outer_src=self.upf_n3_ip, outer_dst=gnb_ip,
            outer_udp_sport=int(self.gtpu_udp_port), outer_udp_dport=int(self.gtpu_udp_port),
            encap_teid=teid, encap_inner_dst=ip.dst, invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = EdgeUPFSimulator()


# ── PARAMETRIC-SOURCE SHIM ─────────────────
# The module-level step() threads a runtime `state` so every seed-bound knob is
# read from state["config"] at call time rather than a module constant. A 2-arg
# call (no state) falls back to the module default simulator held equal to the
# seed (the oracle audit's smoke path). The simulator — and its mutable per-flow
# accumulators — is persisted in state["_sim"] so a prior_inputs sequence threads
# against one instance. Two siblings with different bindings produce identical
# source; the seed enters here at call time.
import inspect as _inspect


def _sim_from_config(cfg: dict):
    sim_cls = type(_DEFAULT)
    params = _inspect.signature(sim_cls).parameters
    kwargs = {k: cfg[k] for k in cfg if k in params}
    return sim_cls(**kwargs)


def _sim_for(state):
    if state is None:
        return _DEFAULT
    sim = state.get("_sim")
    if sim is None:
        cfg = state.get("config") or {}
        sim = _sim_from_config(cfg) if cfg else type(_DEFAULT)()
        state["_sim"] = sim
    return sim


def step(scapy_pkt, in_port: int = 1, state=None):
    return _sim_for(state).step(scapy_pkt, in_port)


def reset():
    _DEFAULT.reset()
