"""Pure-Python mirror of the STATIC (D5.0) Stateful-FW + NAT44 ingress
pipeline. Used to derive test expectations; not loaded by the benchmark
runner.

This simulator implements P-StatefulFW-NAT44 at faithfulness =
D5.0_static_acl_static_nat (the task's seed):

  - Single switch s1 with two ports: s1.internal (private subnet) and
    s1.external (public Internet).
  - One internal subnet (${internal_subnet}); one public IP
    (${public_ip}).
  - Mode = static: the NAT bindings are NOT allocated by the data plane.
    They are a fixed control-plane policy — a list of bidirectional
    (internal_ip, internal_port, proto) <-> (public_ip, ext_port)
    mappings installed as table entries. There is no per-flow state, no
    port-pool allocation, no hash extern, no conntrack, and no timeout
    eviction. Every verdict is a pure table lookup.
  - Outbound (s1.internal): admit iff the packet is IPv4 + TCP/UDP, its
    source is in ${internal_subnet}, and (src_ip, src_port, proto)
    matches an installed mapping; then SNAT (src_ip -> public_ip,
    src_port -> ext_port), decrement TTL, forward out s1.external. The
    match is destination-independent (endpoint-independent mapping).
  - Inbound (s1.external): admit iff the packet is IPv4 + TCP/UDP, its
    destination is ${public_ip}, and (ext_port, proto) matches an
    installed mapping; then DNAT (dst_ip -> internal_ip, dst_port ->
    internal_port), decrement TTL, forward out s1.internal.
  - Everything else drops: non-IPv4 (R1), non-TCP/UDP (R2), outbound
    foreign-source (R8), outbound no-mapping (R7), inbound wrong-dst
    (R9), inbound no-mapping / default-deny (R12).

Parametric-source contract: the mapping
policy is read from the constructor's `static_mappings` argument (the
seed binding), never baked as a module constant. parameter rebinds that add /
remove mappings reuse this audited module unchanged.
"""
from __future__ import annotations

import ipaddress
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

# Default static NAT policy (the anchor seed). Two bidirectional
# bindings behind the single public IP. Mirrored by the seed's bindings.
DEFAULT_STATIC_MAPPINGS = [
    {"internal_ip": "10.0.1.5", "internal_port": 5000, "proto": PROTO_UDP, "ext_port": 10000},
    {"internal_ip": "10.0.1.5", "internal_port": 6000, "proto": PROTO_TCP, "ext_port": 10001},
]


# ── Step result ────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    """Outcome of one simulator step. `reason` names the rule that fired
    (R1..R12 from patterns/P-StatefulFW-NAT44/pattern.yaml)."""
    admitted:     bool
    reason:       str
    side:         Optional[str] = None     # "outbound" | "inbound"
    output_port:  Optional[str] = None
    new_ip_src:   Optional[str] = None
    new_ip_dst:   Optional[str] = None
    new_l4_sport: Optional[int] = None
    new_l4_dport: Optional[int] = None
    new_eth_dst:  Optional[str] = None
    ttl_delta:    int = 0


# ── Helpers ────────────────────────────────────────────────────────────────

def _ip_in_subnet(ip: str, cidr: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


def _l4_ports(scapy_pkt):
    from scapy.all import TCP, UDP
    if TCP in scapy_pkt:
        return PROTO_TCP, int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
    if UDP in scapy_pkt:
        return PROTO_UDP, int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
    return None, None, None


# ── Simulator ──────────────────────────────────────────────────────────────

@dataclass
class StatefulFWNAT44StaticSimulator:
    """The static (D5.0) chained NF. Stateless: every step is a pure
    lookup against the fixed `static_mappings` policy; `reset()` is a
    no-op kept for interface symmetry with the dynamic simulator."""

    internal_subnet: str = INTERNAL_NET
    public_ip:       str = PUBLIC_IP
    mode:            str = "static"
    faithfulness:    str = "D5.0_static_acl_static_nat"
    static_mappings: list = field(default_factory=lambda: [dict(m) for m in DEFAULT_STATIC_MAPPINGS])

    # derived lookup indexes
    _out_index: dict = field(default_factory=dict, init=False)
    _in_index:  dict = field(default_factory=dict, init=False)

    def __post_init__(self):
        self._build_indexes()

    def _build_indexes(self):
        # outbound: (internal_ip, internal_port, proto) -> (ext_port)
        # inbound:  (ext_port, proto)                   -> (internal_ip, internal_port)
        self._out_index = {}
        self._in_index = {}
        for m in self.static_mappings:
            proto = int(m["proto"])
            self._out_index[(m["internal_ip"], int(m["internal_port"]), proto)] = int(m["ext_port"])
            self._in_index[(int(m["ext_port"]), proto)] = (m["internal_ip"], int(m["internal_port"]))

    def reset(self):
        # stateless — nothing to clear; rebuild indexes in case mappings changed
        self._build_indexes()

    # ── main step ───────────────────────────────────────────────────

    def step(self, scapy_pkt, ingress_port: str) -> StepResult:
        from scapy.all import IP

        # R1 — non-IPv4 unconditionally dropped (both zones).
        if IP not in scapy_pkt:
            return StepResult(False, "R1_non_ipv4_drop")

        ip = scapy_pkt[IP]
        proto, sport, dport = _l4_ports(scapy_pkt)

        # R2 — NAPT scope is TCP/UDP only.
        if proto is None:
            return StepResult(False, "R2_non_tcp_udp_drop")

        if ingress_port == INTERNAL_PORT_NAME:
            return self._outbound_step(ip, proto, sport, dport)
        if ingress_port == EXTERNAL_PORT_NAME:
            return self._inbound_step(ip, proto, sport, dport)
        return StepResult(False, "drop_unknown_ingress_port")

    # ── outbound (R5 static-SNAT / R8 / R7) ─────────────────────────

    def _outbound_step(self, ip, proto, sport, dport):
        # R8 — source must be inside the internal subnet.
        if not _ip_in_subnet(ip.src, self.internal_subnet):
            return StepResult(False, "R8_outbound_foreign_src_drop")

        # R5 — installed static mapping for (src_ip, src_port, proto):
        # SNAT + forward. Destination-independent.
        ext_port = self._out_index.get((ip.src, sport, proto))
        if ext_port is not None:
            return StepResult(
                True, "R5_outbound_static_snat",
                side="outbound", output_port=EXTERNAL_PORT_NAME,
                new_ip_src=self.public_ip, new_l4_sport=ext_port,
                new_eth_dst=EXTERNAL_HOST_MAC, ttl_delta=-1,
            )

        # R7 — no mapping for this outbound triple → drop.
        return StepResult(False, "R7_outbound_no_mapping_drop")

    # ── inbound (R11 static-DNAT / R9 / R12) ────────────────────────

    def _inbound_step(self, ip, proto, sport, dport):
        # R9 — destination must be the public IP.
        if ip.dst != self.public_ip:
            return StepResult(False, "R9_inbound_wrong_dst_drop")

        # R11 — installed static mapping for (ext_port, proto): DNAT.
        target = self._in_index.get((dport, proto))
        if target is not None:
            internal_ip, internal_port = target
            return StepResult(
                True, "R11_inbound_static_dnat",
                side="inbound", output_port=INTERNAL_PORT_NAME,
                new_ip_dst=internal_ip, new_l4_dport=internal_port,
                new_eth_dst=INTERNAL_HOST_MAC, ttl_delta=-1,
            )

        # R12 — default-deny.
        return StepResult(False, "R12_inbound_default_deny")

    # ── batch convenience ────────────────────────────────────────────

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# ── parametric module-level step (parametric-source contract) ──
# The canonical step entrypoint. When `state` carries a `config` dict the
# singleton simulator is (re)built from it so a parameter rebind reconfigures the SAME
# audited module at runtime; otherwise the seed-bound default instance is used.
# A knob absent from config falls back to its constructor (seed) default. This
# top-level `step` is preferred by the oracle loader over the bound class method,
# giving the arity-3 config-capable interface the parametric-source audit
# requires. Only the knobs THIS static simulator branches on are read here; the
# dynamic-NAT knobs (conntrack_capacity, idle_timeout_s, port_pool_range, …) are
# variant-selectors that regenerate the dynamic simulator, not runtime config of
# the static module.
_CONFIG_KNOBS = (
    "internal_subnet", "public_ip", "mode", "faithfulness", "static_mappings",
)


def _sim_from_config(config):
    kwargs = {}
    for knob in _CONFIG_KNOBS:
        if config and knob in config and config[knob] is not None:
            kwargs[knob] = config[knob]
    return StatefulFWNAT44StaticSimulator(**kwargs)


_DEFAULT = StatefulFWNAT44StaticSimulator()
_SIM = None
_SIM_CFG = None


def step(scapy_pkt, ingress_port="s1.p1", state=None):
    global _SIM, _SIM_CFG
    if isinstance(state, dict) and isinstance(state.get("config"), dict):
        cfg = state["config"]
        if cfg != _SIM_CFG:
            _SIM = _sim_from_config(cfg)
            _SIM_CFG = dict(cfg)
        return _SIM.step(scapy_pkt, ingress_port)
    return _DEFAULT.step(scapy_pkt, ingress_port)


def reset():
    global _SIM, _SIM_CFG
    _DEFAULT.reset()
    _SIM = None
    _SIM_CFG = None
