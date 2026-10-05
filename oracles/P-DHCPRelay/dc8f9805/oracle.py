"""Oracle for P-DHCPRelay at seed `dhcp_relay_anchor-default`.

A STATELESS, per-packet DHCP/BOOTP relay agent (RFC 2131 §4.3.2, RFC 1542 §4):

  R0  direction / shape guard. A frame that does not parse as DHCP is out of
      scope; a BOOTREQUEST (op==1) arriving on the server-facing port, and a
      BOOTREPLY (op==2) arriving on an access port, are wrong-direction. All
      drop.
  R1  relay-loop guard. A BOOTREQUEST whose hops field already >= hops_limit
      cannot be relayed one more hop -> drop (pre-increment comparison).
  R2  client->server relay. A BOOTREQUEST on an access port with a configured
      relay interface: stamp giaddr with the relay-interface IP ONLY when it
      arrived 0 (a non-zero upstream giaddr is preserved, RFC 1542 §4),
      increment hops by EXACTLY one, rewrite IP/L2 destination toward the
      configured server (and IP/L2 source to the relay), forward out the
      server port.
  R3  server->client relay. A BOOTREPLY on the server-facing port whose giaddr
      names a configured relay interface: rewrite IP.dst back to giaddr (toward
      the client subnet), rewrite IP/L2 source to the relay, set L2 dst to the
      client next hop, forward out that interface's access port. hops is NOT
      touched on the reply.
  R4  a BOOTREQUEST on an access port with NO relay-interface entry -> drop
      (no giaddr IP to stamp).

DHCP/BOOTP is NOT one of the layers the oracle audit packet builder can build
({Ether,IP,TCP,UDP,ICMP,ARP}). The oracle therefore parses the BOOTP fixed
header out of the RAW bytes of the UDP payload itself, so it works identically
whether the caller built a real DHCP layer (the test generator / the verifier's
custom_headers.py) or only a base UDP frame (the audit harness — which then
yields no DHCP header -> R0 drop). The gradable giaddr/hops transforms and the
multi-server / option82 knobs are exercised by the test generator; the audit
canonical examples cover only the base-layer-expressible contracts.

PARAMETRIC-SOURCE CONTRACT. Every parameter named in
the pattern's mutation_operators surface — the relay/server config tables, the
hops limit, the server-facing port, and the multi_server / option82 / faithful-
ness rungs — is threaded at runtime through ``state["config"]`` (or top-level
``state``) and applied to the ``DHCPRelaySimulator`` constructor; the
module-level ``_DEFAULT_CONFIG`` dict holds only the canonical-seed *defaults*,
overridden whenever config is supplied. No seed value is a module-level source
constant: two siblings with different seeds yield byte-identical oracle source.
The only module-level literals are protocol codes no mutation operator touches (BOOTP
op values, the fixed BOOTP field offsets, the BOOTP UDP ports used solely to
recognise the datagram). ``step`` takes ``state`` (arity 3) so the oracle is
config-capable, not a structurally constant module.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields as _dc_fields
from typing import Any, Dict, Optional


# ── BOOTP/DHCP wire constants no mutation operator touches ──────────────────
BOOTREQUEST = 1
BOOTREPLY = 2

# Fixed-format BOOTP header field byte offsets (RFC 951 / RFC 2131 §2):
#   op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
#   ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128)
_OFF_OP = 0
_OFF_HOPS = 3
_OFF_GIADDR = 24
_BOOTP_FIXED_LEN = 236   # bytes through the end of `file`

# UDP ports DHCP rides on (server 67, client 68); used only to recognise the
# datagram as DHCP, not as a mutation knob.
_DHCP_SERVER_PORT = 67
_DHCP_CLIENT_PORT = 68


# ── canonical-seed DEFAULTS (overridden by runtime state["config"]) ─────────
# Defaults, NOT authoritative: a sibling seed threads its own values through
# state["config"], which the constructor below applies. Kept inside a dict
# (indented) so no seed literal appears on a module-level `NAME = literal` line —
# the parametric-source / source-bake invariant.
_DEFAULT_CONFIG = {
    "server_facing_port": 2,
    "hops_limit": 16,
    "multi_server": False,
    "option82_insert": False,
    "default_action": "drop",
    # Per-access-interface relay config, keyed by ingress port.
    #   giaddr_ip   : IP stamped into giaddr for a request on this port
    #   client_subnet
    #   client_mac  : L2 next hop toward the client on the reply direction
    "relay_interfaces": {
        1: {"giaddr_ip": "10.0.1.1", "client_subnet": "10.0.1.0/24",
            "client_mac": "08:00:00:00:01:0c"},
    },
    # DHCP server target(s), keyed by giaddr_ip (the relay-interface IP).
    #   server_ip / server_mac / server_port : forward-direction rewrite material
    #   relay_src_ip / relay_mac             : relay's own L3/L2 source
    "server_targets": {
        "10.0.1.1": {"server_ip": "192.168.100.10", "server_mac": "08:00:00:00:02:0a",
                     "server_port": 2, "relay_src_ip": "192.168.100.1",
                     "relay_mac": "08:00:00:00:02:01"},
    },
}


# ── helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _int_to_ip(v: int) -> str:
    return ".".join(str((v >> s) & 0xFF) for s in (24, 16, 8, 0))


def _config(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge the canonical defaults with any runtime-threaded config. A sibling
    seed supplies its bindings under state["config"]; the relay/server tables may
    also be threaded at top level (router-style convention)."""
    state = state or {}
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}) or {})
    for key, val in state.items():
        if key != "config":
            cfg[key] = val
    return cfg


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    # per-field transformations on a relayed packet (None == unchanged)
    new_giaddr: Optional[str] = None       # giaddr value on the egress packet
    giaddr_changed: bool = False           # whether R2 stamped giaddr
    hops_out: Optional[int] = None         # hops value on the egress packet
    new_ip_dst: Optional[str] = None
    new_ip_src: Optional[str] = None
    new_eth_dst: Optional[str] = None
    new_eth_src: Optional[str] = None
    option82_present: bool = False
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class DHCPRelaySimulator:
    server_facing_port: int = _DEFAULT_CONFIG["server_facing_port"]
    hops_limit: int = _DEFAULT_CONFIG["hops_limit"]
    multi_server: bool = _DEFAULT_CONFIG["multi_server"]
    option82_insert: bool = _DEFAULT_CONFIG["option82_insert"]
    default_action: str = _DEFAULT_CONFIG["default_action"]
    relay_interfaces: dict = field(
        default_factory=lambda: {k: dict(v)
                                 for k, v in _DEFAULT_CONFIG["relay_interfaces"].items()})
    server_targets: dict = field(
        default_factory=lambda: {k: dict(v)
                                 for k, v in _DEFAULT_CONFIG["server_targets"].items()})

    @classmethod
    def from_config(cls, cfg: Dict[str, Any]) -> "DHCPRelaySimulator":
        """Build a simulator from a runtime config dict, applying only the keys
        that are constructor fields (so an unrelated state key cannot crash it).
        The relay/server tables are normalised: port keys to int, and a list of
        entries (seed-binding shape) to a dict keyed by ingress_port / giaddr_ip."""
        names = {f.name for f in _dc_fields(cls)}
        kw = {k: v for k, v in (cfg or {}).items() if k in names}
        ri = kw.get("relay_interfaces")
        if isinstance(ri, dict):
            kw["relay_interfaces"] = {int(k): dict(v) for k, v in ri.items()}
        elif isinstance(ri, list):
            kw["relay_interfaces"] = {
                int(e["ingress_port"]): {kk: vv for kk, vv in e.items()
                                         if kk != "ingress_port"} for e in ri}
        st = kw.get("server_targets")
        if isinstance(st, list):
            kw["server_targets"] = {e["giaddr_ip"]: dict(e) for e in st}
        return cls(**kw)

    def reset(self):
        # Stateless relay: nothing to clear. Present for the audit harness,
        # which reset()s between canonical examples.
        return

    # ── BOOTP parse out of the UDP payload's raw bytes ──────────────────────
    def _parse_dhcp(self, scapy_pkt):
        """Return (op, hops, giaddr_str, payload_bytes) or None if the frame
        does not carry a DHCP/BOOTP datagram."""
        from scapy.all import IP, UDP

        if IP not in scapy_pkt or UDP not in scapy_pkt:
            return None
        udp = scapy_pkt[UDP]
        # DHCP rides UDP between the bootps/bootpc ports.
        ports = {int(udp.sport), int(udp.dport)}
        if not (ports & {_DHCP_SERVER_PORT, _DHCP_CLIENT_PORT}):
            return None
        payload = bytes(udp.payload)
        if len(payload) < _BOOTP_FIXED_LEN:
            return None
        op = payload[_OFF_OP]
        if op not in (BOOTREQUEST, BOOTREPLY):
            return None
        hops = payload[_OFF_HOPS]
        giaddr = _int_to_ip(int.from_bytes(
            payload[_OFF_GIADDR:_OFF_GIADDR + 4], "big"))
        return op, hops, giaddr, payload

    def _select_target(self, giaddr_ip):
        if self.multi_server:
            return self.server_targets.get(giaddr_ip)
        # single-server: the one configured target
        return next(iter(self.server_targets.values()), None)

    def _iface_by_giaddr(self, giaddr_ip):
        for port, ifc in self.relay_interfaces.items():
            if ifc["giaddr_ip"] == giaddr_ip:
                return port, ifc
        return None, None

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        parsed = self._parse_dhcp(scapy_pkt)

        # R0 — non-DHCP / wrong direction.
        if parsed is None:
            return StepResult(False, "drop_non_dhcp")
        op, hops, giaddr, _payload = parsed
        on_server_port = (in_port == self.server_facing_port)

        if op == BOOTREQUEST and on_server_port:
            return StepResult(False, "drop_wrong_direction_request_on_server")
        if op == BOOTREPLY and not on_server_port:
            return StepResult(False, "drop_wrong_direction_reply_on_access")

        # ── client -> server (BOOTREQUEST on an access port) ────────────────
        if op == BOOTREQUEST:
            ilog = [("hops_quantum_one", {"hops_in": hops})]
            # R1 — relay-loop guard on the PRE-increment value.
            if hops >= self.hops_limit:
                return StepResult(False, "drop_hops_exceeded", invariant_log=ilog)
            iface = self.relay_interfaces.get(in_port)
            # R4 — no relay-interface config on this access port.
            if iface is None:
                return StepResult(False, "drop_unconfigured_iface")
            target = self._select_target(iface["giaddr_ip"])
            if target is None:
                return StepResult(False, "drop_no_server_target")

            # R2 postconditions, in order.
            giaddr_changed = (_ip_to_int(giaddr) == 0)
            new_giaddr = iface["giaddr_ip"] if giaddr_changed else giaddr
            hops_out = hops + 1
            ilog.append(("giaddr_stamp_correctness",
                         {"giaddr_in": giaddr, "giaddr_out": new_giaddr,
                          "stamped": giaddr_changed}))
            ilog.append(("forward_redirect_to_server",
                         {"ip_dst": target["server_ip"],
                          "egress": target["server_port"]}))
            return StepResult(
                True, "relay_request_to_server",
                output_port=target["server_port"],
                new_giaddr=new_giaddr, giaddr_changed=giaddr_changed,
                hops_out=hops_out,
                new_ip_dst=target["server_ip"], new_ip_src=target["relay_src_ip"],
                new_eth_dst=target["server_mac"], new_eth_src=target["relay_mac"],
                option82_present=self.option82_insert,
                invariant_log=ilog)

        # ── server -> client (BOOTREPLY on the server-facing port) ──────────
        # op == BOOTREPLY and on_server_port (guaranteed by R0).
        if _ip_to_int(giaddr) == 0:
            return StepResult(False, "drop_reply_zero_giaddr")
        eport, iface = self._iface_by_giaddr(giaddr)
        target = self._select_target(giaddr)
        if iface is None or target is None:
            return StepResult(False, "drop_reply_unknown_giaddr")

        ilog = [("reply_redirect_to_client",
                 {"ip_dst": giaddr, "egress": eport})]
        return StepResult(
            True, "relay_reply_to_client",
            output_port=eport,
            new_giaddr=giaddr,        # giaddr unchanged on the reply
            giaddr_changed=False,
            hops_out=hops,            # hops NOT touched on the reply
            new_ip_dst=giaddr, new_ip_src=target["relay_src_ip"],
            new_eth_dst=iface["client_mac"], new_eth_src=target["relay_mac"],
            invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level step interface. The simulator is built fresh from the threaded
# config on every call, so the SAME audited source serves every seed
# (parametric-source contract).

def step(scapy_pkt, in_port: int = 1,
         state: Optional[Dict[str, Any]] = None) -> StepResult:
    sim = DHCPRelaySimulator.from_config(_config(state))
    return sim.step(scapy_pkt, in_port)


def reset():
    # Stateless relay: nothing to clear.
    return
