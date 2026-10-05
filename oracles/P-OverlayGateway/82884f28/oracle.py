"""Composed oracle for P-OverlayGateway (stateless ACL ∘ VXLAN tunnel
encap/decap ∘ LPM underlay forward) at seed `overlay_gateway_anchor-default`.

A VXLAN L3 gateway / VTEP. Port 1 (overlay/tenant side) carries plain inner
Ethernet frames that must be ENCAPped onto the VXLAN underlay; port 2
(underlay side) carries VXLAN-on-the-wire frames that must be DECAPped and
delivered to the tenant. The single ingress pipeline is, in binding order,
ACL → VXLAN encap/decap (by direction) → underlay/inner LPM route:

  STAGE 1 — ACL classification (P-ACL). The ACL keys on the INNER 5-tuple in
    BOTH directions — for the encap direction the inner tuple is the packet
    as received; for the decap direction it is the tuple carried *inside* the
    VXLAN payload (only visible after the outer headers are parsed). A matched
    deny (or a default-deny miss) drops the packet BEFORE any encap/decap or
    routing state is touched (acl_on_inner).

  STAGE 2 — VXLAN encap/decap (P-VXLANTunnel). Direction is decided by ingress
    port:
      tenant_port (encap): the inner frame `Ether/IP/...` is wrapped in
        `Ether/IP(src=local_vtep_ip, dst=remote_vtep_ip)/UDP(dport=4789)/
        VXLAN(vni=tenant_vni)/<inner Ether/IP/...>`. The remote VTEP IP is the
        configured tunnel peer.
      underlay_port (decap): the received frame must be a VXLAN packet whose
        VNI equals the configured tenant_vni (VNI gate — a wrong VNI drops);
        the outer Ether/IP/UDP/VXLAN headers are stripped, leaving the plain
        inner `Ether/IP/...` to be routed.

  STAGE 3 — LPM route (P-IPv4Routing).
      encap direction: the LPM lookup keys on the OUTER dst (the remote VTEP
        IP), egress the underlay_port; the inner header is carried verbatim
        (no inner TTL change).
      decap direction: the LPM lookup keys on the INNER dst (only visible
        after decap — decap_before_route); on a hit the inner IP.ttl is
        decremented once and the packet egresses the tenant_port. No route or
        inner ttl == 0 drops.

Load-bearing composite contracts:
  - acl_on_inner: the ACL verdict keys on the inner 5-tuple in BOTH directions.
  - decap_before_route: the decap-direction LPM key is the INNER dst, which is
    only exposed after the outer/VXLAN headers are stripped.
  - vni_gate: a decap-direction packet whose VNI != tenant_vni drops.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once). On
the encap direction the inner TTL is preserved (the gateway routes on the
outer header, the inner header is opaque payload); on the decap direction the
restored inner header is the routed header and its TTL is decremented once.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
TENANT_PORT = 1          # overlay / tenant side: plain inner frames to encap
UNDERLAY_PORT = 2        # underlay side: VXLAN on the wire to decap
TENANT_VNI = 100
LOCAL_VTEP_IP = "10.0.2.1"        # this gateway's underlay VTEP source IP
REMOTE_VTEP_IP = "10.0.2.9"       # tunnel peer's VTEP address (encap outer dst)
VXLAN_UDP_PORT = 4789
DEFAULT_ACL_ACTION = "permit"

# Stateless ACL: priority + action + ternary src/dst/proto/sport/dport
# (missing field = wildcard). Evaluated on the INNER 5-tuple in both
# directions.
ACL_RULES = [
    {"priority": 100, "action": "deny", "ipv4_src": "192.168.1.66/32"},  # blocked tenant host
]

# LPM forwarding table: (subnet, prefix) -> (egress_port, next_hop_mac).
# The underlay side resolves the remote VTEP; the tenant side resolves inner
# tenant subnets reachable behind this gateway.
FIB = [
    (("10.0.2.0", 24),     (UNDERLAY_PORT, "08:00:00:00:02:02")),   # underlay / remote VTEP
    (("192.168.2.0", 24),  (TENANT_PORT,   "08:00:00:00:01:01")),   # local tenant hosts
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
    direction: Optional[str] = None        # 'encap' | 'decap' | None
    acl_verdict: Optional[str] = None      # 'permit' | 'deny'
    # encap outputs (the outer header this gateway stamps)
    outer_src_ip: Optional[str] = None
    outer_dst_ip: Optional[str] = None
    outer_udp_dport: Optional[int] = None
    vni: Optional[int] = None
    # decap outputs (the restored inner header that is routed)
    inner_ttl_decrement: int = 0
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class OverlayGatewaySimulator:
    tenant_port: int = TENANT_PORT
    underlay_port: int = UNDERLAY_PORT
    tenant_vni: int = TENANT_VNI
    local_vtep_ip: str = LOCAL_VTEP_IP
    remote_vtep_ip: str = REMOTE_VTEP_IP
    vxlan_udp_port: int = VXLAN_UDP_PORT
    default_acl_action: str = DEFAULT_ACL_ACTION
    acl_rules: list = field(default_factory=lambda: [dict(r) for r in ACL_RULES])
    fib: list = field(default_factory=lambda: list(FIB))

    def reset(self):
        # Stateless pattern — no per-flow state accumulates between packets.
        pass

    # ── ACL ───────────────────────────────────────────────────────────────
    def _acl_verdict(self, tup: dict) -> str:
        best, best_p = None, -1
        for r in self.acl_rules:
            if (_ipv4_match(tup["src"], r.get("ipv4_src"))
                    and _ipv4_match(tup["dst"], r.get("ipv4_dst"))
                    and _eq_or_any(tup["proto"], r.get("proto"))
                    and _eq_or_any(tup["sport"], r.get("sport"))
                    and _eq_or_any(tup["dport"], r.get("dport"))):
                p = int(r["priority"])
                if p > best_p:
                    best, best_p = r, p
        return best["action"] if best is not None else self.default_acl_action

    @staticmethod
    def _l4_ports(layer):
        from scapy.all import TCP, UDP
        if layer is not None and TCP in layer:
            return int(layer[TCP].sport), int(layer[TCP].dport)
        if layer is not None and UDP in layer:
            return int(layer[UDP].sport), int(layer[UDP].dport)
        return 0, 0

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, Ether
        try:
            from scapy.layers.vxlan import VXLAN
        except Exception:                                    # pragma: no cover
            VXLAN = None

        if in_port == self.underlay_port:
            return self._decap(scapy_pkt, IP, Ether, VXLAN)
        # default: tenant / encap direction
        return self._encap(scapy_pkt, IP)

    # ── encap (tenant -> underlay) ─────────────────────────────────────────
    def _encap(self, scapy_pkt, IP) -> StepResult:
        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4", direction="encap")
        inner_ip = scapy_pkt[IP]
        proto = int(inner_ip.proto)
        sport, dport = self._l4_ports(inner_ip)
        tup = {"src": inner_ip.src, "dst": inner_ip.dst, "proto": proto,
               "sport": sport, "dport": dport}

        # STAGE 1 — ACL on the inner 5-tuple.
        verdict = self._acl_verdict(tup)
        ilog = [("acl_on_inner", {"dir": "encap", "verdict": verdict})]
        if verdict == "deny":
            return StepResult(False, "drop_acl_deny", direction="encap",
                              acl_verdict="deny", invariant_log=ilog)

        # STAGE 2 — encap: stamp the outer header toward the remote VTEP.
        outer_dst = self.remote_vtep_ip
        ilog.append(("encap_outer", {"outer_src": self.local_vtep_ip,
                                     "outer_dst": outer_dst,
                                     "vni": self.tenant_vni}))

        # STAGE 3 — LPM route on the OUTER dst (the remote VTEP).
        nh = _lpm_lookup(outer_dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", direction="encap",
                              acl_verdict=verdict, invariant_log=ilog)
        egress, mac = nh
        ilog.append(("encap_route_outer", {"route_dst": outer_dst, "egress": egress}))
        return StepResult(
            True, "forward_encap", output_port=egress, next_hop_mac=mac,
            direction="encap", acl_verdict=verdict,
            outer_src_ip=self.local_vtep_ip, outer_dst_ip=outer_dst,
            outer_udp_dport=self.vxlan_udp_port, vni=self.tenant_vni,
            invariant_log=ilog)

    # ── decap (underlay -> tenant) ─────────────────────────────────────────
    def _decap(self, scapy_pkt, IP, Ether, VXLAN) -> StepResult:
        from scapy.all import UDP

        # A non-IPv4 / non-VXLAN underlay frame is out of scope.
        if IP not in scapy_pkt or UDP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4", direction="decap")
        if int(scapy_pkt[UDP].dport) != self.vxlan_udp_port:
            return StepResult(False, "drop_non_ipv4", direction="decap")
        if VXLAN is None or VXLAN not in scapy_pkt:
            return StepResult(False, "drop_bad_vni", direction="decap")

        vx = scapy_pkt[VXLAN]
        vni = int(vx.vni)
        ilog = [("vni_gate", {"vni": vni, "expected": self.tenant_vni})]

        # STAGE 2 (pre) — VNI gate. Wrong VNI drops before anything else.
        if vni != self.tenant_vni:
            return StepResult(False, "drop_bad_vni", direction="decap",
                              vni=vni, invariant_log=ilog)

        # Locate the inner IPv4 (under the inner Ethernet).
        inner = vx.payload                                   # inner Ether
        inner_ip = inner[IP] if (inner is not None and IP in inner) else None
        if inner_ip is None:
            return StepResult(False, "drop_non_ipv4", direction="decap",
                              vni=vni, invariant_log=ilog)
        proto = int(inner_ip.proto)
        sport, dport = self._l4_ports(inner_ip)
        tup = {"src": inner_ip.src, "dst": inner_ip.dst, "proto": proto,
               "sport": sport, "dport": dport}

        # STAGE 1 — ACL on the INNER 5-tuple (visible only after decap parse).
        verdict = self._acl_verdict(tup)
        ilog.append(("acl_on_inner", {"dir": "decap", "verdict": verdict}))
        if verdict == "deny":
            return StepResult(False, "drop_acl_deny", direction="decap",
                              acl_verdict="deny", vni=vni, invariant_log=ilog)

        # STAGE 3 — decap_before_route: LPM on the INNER dst, TTL-1.
        ttl = int(inner_ip.ttl)
        ilog.append(("decap_before_route", {"inner_dst": inner_ip.dst}))
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired", direction="decap",
                              acl_verdict=verdict, vni=vni, invariant_log=ilog)
        nh = _lpm_lookup(inner_ip.dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", direction="decap",
                              acl_verdict=verdict, vni=vni, invariant_log=ilog)
        egress, mac = nh
        return StepResult(
            True, "forward_decap", output_port=egress, next_hop_mac=mac,
            direction="decap", acl_verdict=verdict, vni=vni,
            inner_ttl_decrement=1, invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = OverlayGatewaySimulator()


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
