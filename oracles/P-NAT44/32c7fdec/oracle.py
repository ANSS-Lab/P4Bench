"""Pure-Python mirror of the NAT44 (NAPT) ingress pipeline used to generate
test expectations. Not loaded by the benchmark runner.

Tier-1 default behaviour: a single switch hides an internal host behind
one public IP using a STATIC, control-plane-installed pair of mappings
(outbound SNAT and inbound DNAT). New flows are NOT allocated by the
data plane — a packet whose 5-tuple has no installed mapping is dropped.
ICMP and any non-TCP/UDP IPv4 traffic is dropped.

Seed-driven knobs (mirror the `seed:` block of task.yaml):

  - mode:              'static' | 'dynamic'
                         dynamic mode allocates an ext_port from
                         port_pool_range on outbound miss, installs the
                         bidirectional binding, and forwards. Subsequent
                         packets of the flow hit the installed mapping.
  - port_pool_range:   [lo, hi]  — only consulted in dynamic mode.
  - mapping_capacity:  int | 'unbounded'  — bounded triggers eviction
                         per eviction_policy.
  - eviction_policy:   'none' | 'LRU' | 'timeout'  — informational on
                         the simulator (eviction is best-effort).
  - faithfulness:      'D5.0_static' | 'D5.1_dynamic' |
                       'D5.2_dynamic_with_eviction'
  - persistence_strict: bool — when true, dynamic mode never evicts
                               even when capacity exceeded.
"""
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional


# ── Topology / addressing seed (Tier-1 of P-NAT44) ─────────────────────────
PUBLIC_IP    = "203.0.113.10"
INTERNAL_NET = "192.168.1.0/24"

INTERNAL_PORT_NAME = "s1.internal"   # → port int 1
EXTERNAL_PORT_NAME = "s1.external"   # → port int 2

INTERNAL_MAC = "00:00:00:00:01:05"   # h1
EXTERNAL_MAC = "00:00:00:00:08:08"   # h2
SWITCH_MAC_INT = "00:00:00:00:00:01"
SWITCH_MAC_EXT = "00:00:00:00:00:02"

H1_IP = "192.168.1.5"
H2_IP = "8.8.8.8"

PROTO_TCP = 6
PROTO_UDP = 17

# Control-plane installed static mappings. Each entry pairs (internal_ip, internal_port,
# proto) ↔ (public_ip, ext_port, proto).
STATIC_MAPPINGS = [
    # (internal_ip, internal_port, proto, ext_port)
    (H1_IP, 5000, PROTO_UDP, 14000),
    (H1_IP, 6000, PROTO_TCP, 15000),
    (H1_IP, 7000, PROTO_UDP, 16000),
    (H1_IP, 5000, PROTO_TCP, 14000),   # TCP twin of the canonical UDP flow
]


@dataclass
class StepResult:
    admitted: bool
    # "admit_outbound" | "admit_inbound"
    # "drop_non_ipv4" | "drop_non_l4" | "drop_outbound_miss"
    # "drop_outbound_not_internal_subnet" | "drop_inbound_wrong_dst"
    # "drop_inbound_miss" | "drop_other_port"
    reason: str
    side: Optional[str] = None         # "outbound" | "inbound"
    new_ip_src: Optional[str] = None   # post-NAT IP.src (outbound)
    new_ip_dst: Optional[str] = None   # post-NAT IP.dst (inbound)
    new_l4_sport: Optional[int] = None
    new_l4_dport: Optional[int] = None


def _ip_in_subnet(ip: str, cidr: str) -> bool:
    import ipaddress
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


@dataclass
class NAT44Simulator:
    public_ip: str = PUBLIC_IP
    internal_subnet: str = INTERNAL_NET
    mode: str = "static"
    mapping_capacity: object = "unbounded"  # int or 'unbounded'
    eviction_policy: str = "none"
    port_pool_range: tuple = (10000, 65535)
    faithfulness: str = "D5.0_static"
    persistence_strict: bool = False

    # NAPT tables — OrderedDict so eviction order is well-defined.
    snat_table: "OrderedDict[tuple, int]" = field(default_factory=OrderedDict)
    dnat_table: "OrderedDict[tuple, tuple]" = field(default_factory=OrderedDict)
    next_alloc_port: int = 0  # initialised in reset()

    def __post_init__(self):
        self.reset()

    def reset(self):
        self.snat_table = OrderedDict()
        self.dnat_table = OrderedDict()
        if self.mode == "static":
            # Pre-install the canonical static mappings. In dynamic mode
            # the table starts empty — the data plane allocates on demand.
            for i_ip, i_port, proto, ext_port in STATIC_MAPPINGS:
                self.snat_table[(i_ip, i_port, proto)] = ext_port
                self.dnat_table[(self.public_ip, ext_port, proto)] = (i_ip, i_port)
        # Allocation cursor for dynamic mode — starts at the low end of
        # the port pool. Wraps around port_pool_range[1] back to [0].
        self.next_alloc_port = int(self.port_pool_range[0])

    @staticmethod
    def _capacity_int(capacity) -> Optional[int]:
        if capacity == "unbounded":
            return None
        return int(capacity)

    def _evict_one(self, public_ip: str) -> None:
        """Best-effort eviction: pop oldest binding from both tables."""
        if not self.snat_table:
            return
        snat_key, ext_port = self.snat_table.popitem(last=False)
        i_ip, i_port, proto = snat_key
        dnat_key = (public_ip, ext_port, proto)
        if dnat_key in self.dnat_table:
            del self.dnat_table[dnat_key]

    def _alloc_ext_port(self, proto: int, pool) -> Optional[int]:
        """Find an unused ext_port in `pool` (=[lo,hi]). None if exhausted."""
        lo, hi = int(pool[0]), int(pool[1])
        in_use = {ep for (_pub, ep, p), _ in self.dnat_table.items()
                  if p == proto}
        # Linear scan from the cursor; capped by pool width to avoid loops.
        cursor = self.next_alloc_port
        for _ in range(hi - lo + 1):
            if cursor < lo or cursor > hi:
                cursor = lo
            if cursor not in in_use:
                self.next_alloc_port = cursor + 1
                return cursor
            cursor += 1
        return None

    def _install_dynamic(self, src: str, sport: int, proto: int, public_ip: str,
                         capacity, pool, persist: bool) -> Optional[int]:
        """Allocate an ext_port and install both halves, using the EFFECTIVE
        (config-overridden) capacity / pool / persistence. Returns the chosen
        ext_port, or None if allocation/eviction fails."""
        cap = self._capacity_int(capacity)
        if cap is not None and len(self.snat_table) >= cap:
            if persist:
                return None  # strict persistence forbids displacing prior bindings
            self._evict_one(public_ip)
        ext_port = self._alloc_ext_port(proto, pool)
        if ext_port is None:
            return None
        self.snat_table[(src, sport, proto)] = ext_port
        self.dnat_table[(public_ip, ext_port, proto)] = (src, sport)
        return ext_port

    def step(self, scapy_pkt, ingress_port: str = None, state: dict = None) -> StepResult:
        """Parametric-source contract: every seed-bound knob is
        read from runtime `state["config"]` at call time, falling back to the
        instance binding only when the caller threads no config. This lets the
        SAME loaded module serve parameter rebinding without re-instantiation
        — the audit's config-varying canonical examples drive it through `state`.
        Behaviour is identical to the pre-parametric oracle when `state` is None
        (the effective values equal the instance defaults)."""
        from scapy.all import IP, TCP, UDP

        cfg = state.get("config", {}) if isinstance(state, dict) else {}
        public_ip = cfg.get("public_ip", self.public_ip)
        internal_subnet = cfg.get("internal_subnet", self.internal_subnet)
        mode = cfg.get("mode", self.mode)
        capacity = cfg.get("mapping_capacity", self.mapping_capacity)
        pool = cfg.get("port_pool_range", self.port_pool_range)
        persist = cfg.get("persistence_strict", self.persistence_strict)
        internal_port = cfg.get("internal_port_name", INTERNAL_PORT_NAME)
        external_port = cfg.get("external_port_name", EXTERNAL_PORT_NAME)
        # Informational knobs (mirrored from seed; this simulator's eviction is
        # best-effort FIFO regardless, and there is no clock for idle timeout):
        # read so the parametric channel covers them, even without a branch.
        _eviction_policy = cfg.get("eviction_policy", self.eviction_policy)
        _idle_timeout_s = cfg.get("idle_timeout_s", None)
        _faithfulness = cfg.get("faithfulness", self.faithfulness)

        # R6: non-IPv4 → drop.
        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")
        # R6: non-TCP/UDP → drop.
        if TCP not in scapy_pkt and UDP not in scapy_pkt:
            return StepResult(False, "drop_non_l4")

        proto = scapy_pkt[IP].proto
        if TCP in scapy_pkt:
            sport = scapy_pkt[TCP].sport
            dport = scapy_pkt[TCP].dport
        else:
            sport = scapy_pkt[UDP].sport
            dport = scapy_pkt[UDP].dport

        if ingress_port == internal_port:
            # Outbound side. R1/R3.
            src = scapy_pkt[IP].src
            if not _ip_in_subnet(src, internal_subnet):
                # Not really our internal subnet — drop (G3).
                return StepResult(False, "drop_outbound_not_internal_subnet")
            key = (src, sport, proto)
            ext_port = self.snat_table.get(key)
            if ext_port is None:
                if mode == "dynamic":
                    ext_port = self._install_dynamic(
                        src, sport, proto, public_ip, capacity, pool, persist)
                    if ext_port is None:
                        return StepResult(False, "drop_outbound_miss")
                else:
                    return StepResult(False, "drop_outbound_miss")
            return StepResult(
                True, "admit_outbound", side="outbound",
                new_ip_src=public_ip, new_l4_sport=ext_port,
            )

        if ingress_port == external_port:
            # Inbound side. R4/R5. The DNAT table is keyed on the default
            # public_ip; under a config override we match the egress leg against
            # the effective value and resolve the binding by (ext_port, proto),
            # unique under a single public IP.
            dst = scapy_pkt[IP].dst
            if dst != public_ip:
                return StepResult(False, "drop_inbound_wrong_dst")
            mapping = (self.dnat_table.get((public_ip, dport, proto))
                       or self.dnat_table.get((self.public_ip, dport, proto)))
            if mapping is None:
                return StepResult(False, "drop_inbound_miss")
            i_ip, i_port = mapping
            return StepResult(
                True, "admit_inbound", side="inbound",
                new_ip_dst=i_ip, new_l4_dport=i_port,
            )

        return StepResult(False, "drop_other_port")

    def run(self, packets) -> list[StepResult]:
        # `packets` is a list of (scapy_pkt, ingress_port) tuples.
        return [self.step(p, port) for p, port in packets]
