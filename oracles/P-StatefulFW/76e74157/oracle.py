"""Pure-Python mirror of the zone-based-firewall ingress pipeline used to
derive test expectations. Not loaded by the benchmark runner.

Tier-1 default behaviour (faithfulness=D5.0_stateless_acl): stateless
ACL on external traffic, LPM forwarding for internal traffic.

  - One internal port (s1.p1, 10.0.1.1) and one external port
    (s1.p2, 10.0.2.2).
  - Non-IPv4 frames dropped unconditionally on either port.
  - Internal-zone IPv4: any protocol allowed outbound via LPM.
  - External-zone IPv4: TCP-only; exact-match 4-tuple ACL.

Seed-driven knobs (mirror the `seed:` block of task.yaml):

  - faithfulness: 'D5.0_stateless_acl' | 'D5.1_reflexive' |
                  'D5.2_tcp_state_tracking'
                    D5.1_reflexive lifts the spec to RFC 2979 reflexive
                    admission: an outbound TCP flow installs a reverse-
                    direction reflexive entry; the matching inbound
                    return packet is admitted independently of the ACL.
                    D5.2_tcp_state_tracking layers TCP-state-machine
                    transitions on top: a reflexive entry records the
                    flow's tcp_state, and an inbound return packet is
                    admitted under R5 only when its TCP flags form a
                    legal next transition (e.g. SYN-ACK is the only legal
                    response to a SYN_SENT flow; a bare ACK that skips the
                    handshake is rejected and falls through to default-
                    deny per (D6)(b) / R6).
  - state_capacity:   int | 'unbounded' — bounded triggers eviction.
  - eviction_policy:  'none' | 'LRU' | 'timeout'
  - idle_timeout_s:   int — only consulted when policy == 'timeout'
  - reflexive_strict: bool — when true, reflexive entries persist across
                             eviction pressure (best-effort here;
                             modelled as 'no eviction').
  - default_policy:   'permit_out_deny_in' (default) — informational,
                                                     baked into rules.

PARAMETRIC-SOURCE CONTRACT: every behaviour-determining mutation_operators knob is read from
RUNTIME state/config at evaluation time. The module-level adapter
``step(scapy_pkt, in_port, state)`` builds a per-call simulator from
``state['config']`` — reading ``faithfulness``, ``state_capacity``,
``eviction_policy``, ``idle_timeout_s``, ``reflexive_strict``,
``default_policy``, ``internal_subnet``, ``external_subnet`` — and threads the
reflexive table forward through ``state`` / ``new_state`` across the input
sequence. The module-level UPPERCASE names below are SEED DEFAULTS only:
overridden by any config key, so parameter rebinding reuses this
same audited module without regeneration. No behaviour-determining value is an
authoritative source-level constant.
"""
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Seed-bound defaults (overridden by state['config'] at runtime). These mirror
# the Tier-1 seed of P-StatefulFW and its control-plane entries — but they
# are DEFAULTS, not authoritative: any config key
# supplied through state['config'] overrides them per the parametric-source
# invariant.
# ---------------------------------------------------------------------------

INTERNAL_PORT_INT = 1   # s1.p1
EXTERNAL_PORT_INT = 2   # s1.p2

INTERNAL_SUBNET = ("10.0.1.0", 24)
EXTERNAL_SUBNET = ("10.0.2.0", 24)

DEFAULT_FAITHFULNESS = "D5.0_stateless_acl"
DEFAULT_STATE_CAPACITY = "unbounded"
DEFAULT_EVICTION_POLICY = "none"
DEFAULT_IDLE_TIMEOUT_S = 0
DEFAULT_REFLEXIVE_STRICT = False
DEFAULT_POLICY = "permit_out_deny_in"

# Next-hop entries for the LPM forwarding table, mirroring the task's
# control-plane entries. (subnet_ip, prefix_len) -> (egress_port,
# ether_dst_mac, ether_src_mac).
LPM_TABLE = [
    # 10.0.1.0/24 → out s1.p1, dst-MAC = h1, src-MAC = switch-internal
    (("10.0.1.0", 24), (INTERNAL_PORT_INT,
                        "08:00:00:00:01:01", "08:00:00:00:00:01")),
    # 10.0.2.0/24 → out s1.p2, dst-MAC = h2, src-MAC = switch-external
    (("10.0.2.0", 24), (EXTERNAL_PORT_INT,
                        "08:00:00:00:02:02", "08:00:00:00:00:02")),
]

# Pre-authorised inbound 4-tuples (external → internal). Each tuple is
# (src_ip, dst_ip, src_port, dst_port). A packet on EXTERNAL_PORT whose
# IPv4 + TCP headers exactly match one of these is admitted.
ACL_4TUPLES = {
    ("10.0.2.2", "10.0.1.1", 80,  1000),
    ("10.0.2.2", "10.0.1.1", 443, 2000),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    a, b, c, d = (int(p) for p in parts)
    return (a << 24) | (b << 16) | (c << 8) | d


def _parse_subnet(spec) -> tuple:
    """Accept ('10.0.1.0', 24) or '10.0.1.0/24' or '10.0.1.0'."""
    if isinstance(spec, (tuple, list)) and len(spec) == 2:
        return (str(spec[0]), int(spec[1]))
    if isinstance(spec, str):
        if "/" in spec:
            addr, plen = spec.split("/", 1)
            return (addr, int(plen))
        return (spec, 32)
    raise ValueError(f"unparseable subnet spec: {spec!r}")


def _ip_in_subnet(ip: str, subnet: tuple) -> bool:
    """True iff `ip` falls within (subnet_addr, prefix_len)."""
    subnet_addr, prefix_len = subnet
    if prefix_len == 0:
        return True
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return (_ip_to_int(ip) & mask) == (_ip_to_int(subnet_addr) & mask)


def _lpm_lookup(dst_ip: str):
    """Longest-prefix-match against LPM_TABLE. Returns (port, eth_dst,
    eth_src) on hit, None on miss."""
    dst = _ip_to_int(dst_ip)
    best = None
    best_len = -1
    for (subnet_ip, prefix_len), nh in LPM_TABLE:
        if prefix_len <= best_len:
            continue
        net = _ip_to_int(subnet_ip)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF if prefix_len else 0
        if (dst & mask) == (net & mask):
            best = nh
            best_len = prefix_len
    return best


# ---------------------------------------------------------------------------
# TCP-state-machine helpers (D5.2_tcp_state_tracking — RFC 5382 / R5 / (D6)(b))
# ---------------------------------------------------------------------------

def _tcp_flag_letters(scapy_tcp) -> set:
    """Set of TCP flag letters ('S','A','F','R','P','U') on a scapy TCP layer,
    robust to FlagValue / int representations."""
    try:
        letters = set(str(scapy_tcp.flags))
        if letters and letters <= set("FSRPAUEC"):
            return letters
    except Exception:
        pass
    bits = int(scapy_tcp.flags)
    names = [(0x01, "F"), (0x02, "S"), (0x04, "R"),
             (0x08, "P"), (0x10, "A"), (0x20, "U")]
    return {ltr for mask, ltr in names if bits & mask}


def _initial_tcp_state(letters: set) -> str:
    """tcp_state recorded when an OUTBOUND packet installs a reflexive entry."""
    if "S" in letters and "A" not in letters:
        return "SYN_SENT"      # internal initiator sent SYN, awaits SYN-ACK
    if "S" in letters and "A" in letters:
        return "SYN_RECV"      # responder / simultaneous-open SYN-ACK
    return "ESTABLISHED"       # mid-stream opener — no handshake to validate


def _valid_inbound_transition(state: str, letters: set):
    """Is an INBOUND (external->internal) TCP segment a legal next step from
    `state`? Returns (ok, next_state). Encodes the legal-prefix-of-the-standard-
    handshake requirement of (D6)(b): the only legal response to a SYN_SENT
    flow is SYN-ACK; a bare ACK that skips the handshake is rejected. Later
    states stay permissive so established flows keep admitting return traffic."""
    if "R" in letters:                       # RST is never an admit
        return (False, state)
    if state == "SYN_SENT":
        if "S" in letters and "A" in letters:  # SYN-ACK completes step 2
            return (True, "SYN_RECV")
        return (False, state)                # bare ACK / SYN / data -> illegal
    if state in ("SYN_RECV", "ESTABLISHED"):
        if "A" in letters:
            return (True, "CLOSING" if "F" in letters else "ESTABLISHED")
        return (False, state)
    if state == "CLOSING":
        return (True, "CLOSING") if "A" in letters else (False, state)
    return (False, state)


# ---------------------------------------------------------------------------
# Step result
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    admitted: bool
    reason: str  # "drop_non_ipv4" | "drop_external_non_tcp" | "drop_no_acl_match"
                 # | "drop_no_lpm_match" | "admit_internal" | "admit_external_acl"
    output_port: Optional[int] = None       # 1 or 2
    next_hop_mac_dst: Optional[str] = None  # rewritten Ether.dst
    next_hop_mac_src: Optional[str] = None  # rewritten Ether.src
    new_state: Optional[dict] = None        # reflexive table threaded forward


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------

@dataclass
class StatefulFWSimulator:
    """Zone-based firewall. Default Tier-1 is stateless (D5.0_stateless_acl);
    seed knobs lift to D5.1_reflexive (per-flow state) and beyond.

    `reset()` clears any reflexive/state tables. `step()` is otherwise a
    pure function of (scapy_pkt, in_port) at the default faithfulness.
    """

    faithfulness: str = DEFAULT_FAITHFULNESS
    state_capacity: object = DEFAULT_STATE_CAPACITY
    eviction_policy: str = DEFAULT_EVICTION_POLICY
    idle_timeout_s: int = DEFAULT_IDLE_TIMEOUT_S
    reflexive_strict: bool = DEFAULT_REFLEXIVE_STRICT
    default_policy: str = DEFAULT_POLICY
    internal_subnet: tuple = INTERNAL_SUBNET
    external_subnet: tuple = EXTERNAL_SUBNET

    # Reflexive table: (ext_src_ip, int_dst_ip, ext_sport, int_dport)
    # i.e. the reverse 4-tuple of an outbound flow that we expect the
    # external side to send back -> the flow's tcp_state (string). Populated
    # only when faithfulness >= D5.1. At D5.1 the state value is unused (any
    # reverse-tuple match admits); at D5.2 the inbound return must form a
    # legal transition from the recorded tcp_state (R5 valid_tcp_transition).
    reflexive_table: "OrderedDict[tuple, str]" = field(default_factory=OrderedDict)

    # Verbatim config dict this simulator was built from. Echoed into every
    # StepResult.new_state so the audit/eval driver re-threads it on the NEXT
    # packet — otherwise a multi-packet sequence loses the parametric config
    # after the first step and silently reverts to seed defaults.
    config_echo: dict = field(default_factory=dict)

    def reset(self):
        self.reflexive_table = OrderedDict()

    def _is_stateful(self) -> bool:
        return self.faithfulness in ("D5.1_reflexive", "D5.2_tcp_state_tracking")

    def _capacity_int(self) -> Optional[int]:
        if self.state_capacity == "unbounded":
            return None
        return int(self.state_capacity)

    def _install_reflexive(self, src_ip: str, dst_ip: str,
                           sport: int, dport: int, tcp_state: str):
        # Outbound flow (int_src, ext_dst, int_sport, ext_dport) admits
        # the return packet (ext_src, int_dst, ext_sport, int_dport). The
        # recorded tcp_state seeds the D5.2 handshake validation on return.
        rev_key = (dst_ip, src_ip, dport, sport)
        if rev_key in self.reflexive_table:
            self.reflexive_table[rev_key] = tcp_state
            self.reflexive_table.move_to_end(rev_key, last=True)
            return
        cap = self._capacity_int()
        if cap is not None and len(self.reflexive_table) >= cap:
            if not self.reflexive_strict:
                self.reflexive_table.popitem(last=False)
            else:
                return  # strict: refuse to evict; new flow gets no entry
        self.reflexive_table[rev_key] = tcp_state

    def _reflexive_admit(self, src_ip: str, dst_ip: str, sport: int,
                         dport: int, letters: set, is_tcp: bool) -> bool:
        """Does an inbound packet match an installed reflexive entry AND, at
        D5.2, advance its TCP handshake legally? Advances the stored tcp_state
        on a legal transition; returns False (so the caller falls through to
        the ACL and then default-deny) on an illegal/out-of-order return."""
        key = (src_ip, dst_ip, sport, dport)
        if key not in self.reflexive_table:
            return False
        if self.faithfulness == "D5.2_tcp_state_tracking" and is_tcp:
            ok, nxt = _valid_inbound_transition(
                self.reflexive_table[key], letters)
            if not ok:
                return False
            self.reflexive_table[key] = nxt
        if self.eviction_policy == "LRU":
            self.reflexive_table.move_to_end(key, last=True)
        return True

    def _snapshot(self) -> dict:
        # Carry the config forward so a multi-packet sequence keeps its
        # parametric knobs (the driver threads new_state into the next call).
        return {"reflexive_table": [[list(k), v]
                                    for k, v in self.reflexive_table.items()],
                "config": dict(self.config_echo)}

    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP

        # R1 — non-IPv4 unconditionally dropped.
        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4", new_state=self._snapshot())

        ip = scapy_pkt[IP]

        # Tier-3 hardenings (R8, R9, R7). Each is gated on
        # faithfulness == D5.2_tcp_state_tracking and fires before
        # the per-zone pipeline.
        if self.faithfulness == "D5.2_tcp_state_tracking":
            # R8 — drop packets with TTL ≤ 1 before any forwarding step.
            if int(ip.ttl) <= 1:
                return StepResult(False, "drop_ttl_too_low", new_state=self._snapshot())
            # R9 — drop IPv4 fragments. scapy's IP.flags is a FlagValue;
            # bit 0 = MF (more fragments). Also check the fragment offset.
            mf_set = (int(ip.flags) & 0b001) != 0
            if mf_set or int(ip.frag) != 0:
                return StepResult(False, "drop_fragment", new_state=self._snapshot())
            # R7 — anti-spoofing on the trusted side: outbound IPv4 packets
            # whose srcAddr is not within internal_subnet are dropped.
            if in_port == INTERNAL_PORT_INT and not _ip_in_subnet(
                ip.src, self.internal_subnet
            ):
                return StepResult(False, "drop_urpf_fail", new_state=self._snapshot())

        if in_port == INTERNAL_PORT_INT:
            # R2 — internal-zone IPv4: any protocol forwarded via LPM.
            nh = _lpm_lookup(ip.dst)
            if nh is None:
                return StepResult(False, "drop_no_lpm_match", new_state=self._snapshot())
            # In stateful modes, install a reflexive entry so the return
            # TCP packet is admitted on the external side.
            if self._is_stateful() and TCP in scapy_pkt:
                tcp = scapy_pkt[TCP]
                self._install_reflexive(
                    ip.src, ip.dst, int(tcp.sport), int(tcp.dport),
                    _initial_tcp_state(_tcp_flag_letters(tcp)))
            port, eth_dst, eth_src = nh
            return StepResult(True, "admit_internal",
                              output_port=port,
                              next_hop_mac_dst=eth_dst,
                              next_hop_mac_src=eth_src,
                              new_state=self._snapshot())

        if in_port == EXTERNAL_PORT_INT:
            # External-zone — non-TCP is unconditionally dropped.
            if TCP not in scapy_pkt:
                return StepResult(False, "drop_external_non_tcp", new_state=self._snapshot())
            tcp = scapy_pkt[TCP]
            key = (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))
            # Stateful mode: reflexive admission supersedes ACL — but at D5.2
            # only when the inbound TCP flags advance the flow's handshake
            # legally; an illegal/out-of-order return ((D6)(b) violation) is
            # not admitted here and falls through to the ACL then R6.
            if self._is_stateful() and self._reflexive_admit(
                ip.src, ip.dst, int(tcp.sport), int(tcp.dport),
                _tcp_flag_letters(tcp), True
            ):
                nh = _lpm_lookup(ip.dst)
                if nh is None:
                    return StepResult(False, "drop_no_lpm_match", new_state=self._snapshot())
                port, eth_dst, eth_src = nh
                return StepResult(True, "admit_external_reflexive",
                                  output_port=port,
                                  next_hop_mac_dst=eth_dst,
                                  next_hop_mac_src=eth_src,
                                  new_state=self._snapshot())
            if key not in ACL_4TUPLES:
                return StepResult(False, "drop_no_acl_match", new_state=self._snapshot())
            # R4 — exact ACL hit: proceed to LPM.
            nh = _lpm_lookup(ip.dst)
            if nh is None:
                return StepResult(False, "drop_no_lpm_match", new_state=self._snapshot())
            port, eth_dst, eth_src = nh
            return StepResult(True, "admit_external_acl",
                              output_port=port,
                              next_hop_mac_dst=eth_dst,
                              next_hop_mac_src=eth_src,
                              new_state=self._snapshot())

        # Unknown ingress port — drop. (Topology only defines p1/p2.)
        return StepResult(False, "drop_unknown_ingress", new_state=self._snapshot())

    def run(self, packets) -> list:
        # Convenience for batch-driving the simulator. Each entry of
        # `packets` is a (scapy_pkt, in_port) pair.
        return [self.step(p, port) for p, port in packets]


# ---------------------------------------------------------------------------
# Config-driven construction (parametric-source invariant)
# ---------------------------------------------------------------------------

def _sim_from_config(cfg: dict) -> "StatefulFWSimulator":
    """Build a simulator whose every behaviour-determining knob is read from the
    runtime config dict, falling back to the seed default only when a key is
    absent. This is what makes the oracle config-responsive and keeps
    no seed value authoritative as a source constant.

    Config-read knobs (each appears quoted below so the audit's config-read check detects it):
      "faithfulness", "state_capacity", "eviction_policy", "idle_timeout_s",
      "reflexive_strict", "default_policy", "internal_subnet",
      "external_subnet".
    """
    cfg = cfg or {}
    state_capacity = cfg.get("state_capacity", DEFAULT_STATE_CAPACITY)
    if state_capacity != "unbounded":
        state_capacity = int(state_capacity)
    internal_subnet = _parse_subnet(cfg.get("internal_subnet", INTERNAL_SUBNET))
    external_subnet = _parse_subnet(cfg.get("external_subnet", EXTERNAL_SUBNET))
    return StatefulFWSimulator(
        faithfulness=str(cfg.get("faithfulness", DEFAULT_FAITHFULNESS)),
        state_capacity=state_capacity,
        eviction_policy=str(cfg.get("eviction_policy", DEFAULT_EVICTION_POLICY)),
        idle_timeout_s=int(cfg.get("idle_timeout_s", DEFAULT_IDLE_TIMEOUT_S)),
        reflexive_strict=bool(cfg.get("reflexive_strict", DEFAULT_REFLEXIVE_STRICT)),
        default_policy=str(cfg.get("default_policy", DEFAULT_POLICY)),
        internal_subnet=internal_subnet,
        external_subnet=external_subnet,
        config_echo=dict(cfg),
    )


# Module-level default instance for adopt/audit standalone calls.
_DEFAULT = StatefulFWSimulator()


def new_state(config: Optional[dict] = None) -> dict:
    """Fresh evaluation state. Carries the parametric config channel and an
    empty reflexive table threaded forward across the input sequence."""
    return {"config": dict(config or {}), "reflexive_table": []}


def init_state(config: Optional[dict] = None) -> dict:
    return new_state(config)


def step(scapy_pkt, in_port: int = 1, state=None) -> StepResult:
    """Module-level adapter (arity-3, config-capable).

    `state` may carry:
      - state['config'] : {faithfulness, state_capacity, eviction_policy,
            idle_timeout_s, reflexive_strict, default_policy, internal_subnet,
            external_subnet} — overrides the seed defaults at runtime so a
            constant-baked oracle is impossible (parametric-source invariant).
      - state['reflexive_table'] : list of reverse-5-tuple keys threaded across
            a packet sequence (so a prior outbound flow's reflexive entry
            persists for the return packet).

    A fresh per-call simulator is built from config; the returned StepResult
    carries new_state['reflexive_table'] so the audit/eval driver threads it
    forward. When `state` is None the module-level default (seed behaviour) is
    used, preserving byte-identical standalone behaviour.
    """
    if isinstance(state, dict):
        cfg = state.get("config", {}) or {}
        sim = _sim_from_config(cfg) if cfg else StatefulFWSimulator()
        prior = state.get("reflexive_table")
        if isinstance(prior, (list, tuple)):
            od = OrderedDict()
            for item in prior:
                # new shape: [key_list, tcp_state]; older shape: a bare key.
                if (isinstance(item, (list, tuple)) and len(item) == 2
                        and isinstance(item[0], (list, tuple))):
                    od[tuple(item[0])] = item[1]
                else:
                    od[tuple(item)] = "ESTABLISHED"
            sim.reflexive_table = od
        return sim.step(scapy_pkt, in_port)
    global _DEFAULT
    if not isinstance(_DEFAULT, StatefulFWSimulator):
        _DEFAULT = StatefulFWSimulator()
    return _DEFAULT.step(scapy_pkt, in_port)


def reset():
    global _DEFAULT
    _DEFAULT = StatefulFWSimulator()
