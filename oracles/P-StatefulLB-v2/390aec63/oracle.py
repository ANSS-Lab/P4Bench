"""Pure-Python mirror of the v2 bounded stateful L4 load balancer
pipeline used to generate test expectations. Not loaded by the benchmark
runner.

v2-distinguishing knobs (mirror the `seed:` block of task.yaml):

  - assign = 'hash_5tuple':  backend_idx = ident & 0x3   (4 backends)
  - observe_bind = 'clone_to_monitor': new-flow admissions (cases A and
    C) emit a byte-identical copy on the monitor egress (port 6); case
    B emits no monitor copy.

Slot/backend bit decomposition is required to be bit-disjoint so the
test scaffolding can construct colliding 5-tuples that route to
different backends:

    ident       = src ^ dst ^ ((sport << 16) | dport) ^ proto
    slot        = (ident >> 2) & 0x3FF       (bits 2..11)
    backend_idx =  ident       & 0x3         (bits 0..1)

Other seed parameters are kept consistent with the P-StatefulLB v1
simulator's semantics so v1's regression tests still apply:

  - flow_table_capacity = 1024.
  - eviction_policy = FIFO_collision_displace (one slot per bucket;
    collision displaces the resident).
  - persistence_strict = false.
  - faithfulness = D5.0_exact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VIP = "10.0.100.1"

BACKENDS = [
    ("10.0.2.10", "08:00:00:00:02:01", 2),
    ("10.0.2.20", "08:00:00:00:02:02", 3),
    ("10.0.2.30", "08:00:00:00:02:03", 4),
    ("10.0.2.40", "08:00:00:00:02:04", 5),
]
N_BACKENDS = len(BACKENDS)
CAPACITY = 1024
MONITOR_PORT = 6


def _ip_to_int(addr: str) -> int:
    a, b, c, d = (int(x) for x in addr.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def flow_identity(src_ip_str: str, dst_ip_str: str, sport: int,
                  dport: int, proto: int) -> int:
    """32-bit fingerprint of the TCP 5-tuple. Mirrors the data-plane hash:
        ident = (src ^ dst ^ ((sport<<16)|dport) ^ proto) & 0xFFFFFFFF
    """
    src = _ip_to_int(src_ip_str)
    dst = _ip_to_int(dst_ip_str)
    return (src ^ dst ^ ((sport << 16) | dport) ^ proto) & 0xFFFFFFFF


def flow_slot(identity: int) -> int:
    """Slot index uses ident bits 2..11 (bit-disjoint from backend_idx)."""
    return (identity >> 2) & 0x3FF


def hash5_backend_idx(identity: int) -> int:
    """hash_5tuple backend selection — bits 0..1 of ident, mod 4."""
    return identity & 0x3


@dataclass
class StepResult:
    admitted: bool
    reason: str
    backend_idx: Optional[int] = None
    new_flow: Optional[bool] = None       # True iff R1 fired (admission emits monitor)
    displaced: Optional[bool] = None      # True iff R1 fired AND slot held a different identity
    monitor_emitted: bool = False         # True iff new-flow admission AND observe_bind != none


@dataclass
class StatefulLBV2Simulator:
    backends: list = field(default_factory=lambda: list(BACKENDS))
    vip: str = VIP
    capacity: int = CAPACITY
    assign: str = "hash_5tuple"
    persistence_strict: bool = False
    eviction_policy: str = "FIFO_collision_displace"
    faithfulness: str = "D5.0_exact"
    observe_bind: str = "clone_to_monitor"

    # bucket[i] = (flow_identity, backend_idx) | None
    bucket: list = field(default_factory=list)

    def __post_init__(self):
        if not self.bucket:
            self.bucket = [None] * self.capacity

    def reset(self):
        self.bucket = [None] * self.capacity

    def _classify(self, scapy_pkt):
        from scapy.all import IP, TCP

        if IP not in scapy_pkt:
            return None, "drop_non_ipv4"
        if scapy_pkt[IP].dst != self.vip:
            return None, "drop_non_vip"
        if TCP not in scapy_pkt:
            return None, "drop_non_tcp"
        ident = flow_identity(
            scapy_pkt[IP].src, scapy_pkt[IP].dst,
            scapy_pkt[TCP].sport, scapy_pkt[TCP].dport,
            scapy_pkt[IP].proto,
        )
        return ident, "ok"

    def _pick_backend(self, ident: int) -> int:
        # hash_5tuple is the only assignment exercised by the v2 seed.
        # The dispatch is kept explicit so a future mutation that swaps
        # back to round_robin or consistent_hash slots in cleanly.
        if self.assign == "hash_5tuple":
            return hash5_backend_idx(ident)
        if self.assign == "round_robin":
            raise NotImplementedError("round_robin assignment not used by v2 seed")
        if self.assign == "consistent_hash":
            raise NotImplementedError("consistent_hash assignment not used by v2 seed")
        raise ValueError(f"unknown assign={self.assign!r}")

    def _monitor_on_new_flow(self) -> bool:
        return self.observe_bind in ("clone_to_monitor", "recirc_then_forward")

    def step(self, scapy_pkt) -> StepResult:
        ident, status = self._classify(scapy_pkt)
        if ident is None:
            return StepResult(False, status)

        slot_idx = flow_slot(ident)
        resident = self.bucket[slot_idx]

        if resident is not None and resident[0] == ident:
            # Case B — established connection. No monitor copy.
            return StepResult(True, "admit_established",
                              backend_idx=resident[1],
                              new_flow=False, displaced=False,
                              monitor_emitted=False)

        # Case A (resident is None) or Case C (resident is a different
        # identity). Either way, a new-flow admission fires.
        displaced = resident is not None
        backend_idx = self._pick_backend(ident)
        self.bucket[slot_idx] = (ident, backend_idx)
        return StepResult(True, "admit_new",
                          backend_idx=backend_idx,
                          new_flow=True, displaced=displaced,
                          monitor_emitted=self._monitor_on_new_flow())

    def run(self, packets) -> list[StepResult]:
        return [self.step(p) for p in packets]


def expected_egress_ports(result: StepResult) -> list[int]:
    """Convenience: return the set of egress ports the harness should
    observe for this packet, given the simulator's StepResult."""
    if not result.admitted:
        return []
    backend_port = BACKENDS[result.backend_idx][2]
    if result.monitor_emitted:
        return [backend_port, MONITOR_PORT]
    return [backend_port]


# ── parametric module-level step (parametric-source contract) ──
# The canonical step entrypoint. When `state` carries a `config` dict the
# singleton simulator is (re)built from it so a parameter rebind reconfigures the SAME
# audited module at runtime; otherwise the seed-bound default instance is used.
# A knob absent from config falls back to its constructor (seed) default. This
# top-level `step` is preferred by the oracle loader over the bound class method,
# giving the arity-3 config-capable interface the parametric-source audit
# requires.
_CONFIG_KNOBS = (
    "backends", "vip", "capacity", "assign", "persistence_strict",
    "eviction_policy", "faithfulness", "observe_bind",
)


def _sim_from_config(config):
    kwargs = {}
    for knob in _CONFIG_KNOBS:
        if config and knob in config and config[knob] is not None:
            kwargs[knob] = config[knob]
    return StatefulLBV2Simulator(**kwargs)


_DEFAULT = StatefulLBV2Simulator()
_SIM = None
_SIM_CFG = None


def step(scapy_pkt, in_port: int = 1, state=None):
    global _SIM, _SIM_CFG
    if isinstance(state, dict) and isinstance(state.get("config"), dict):
        cfg = state["config"]
        if cfg != _SIM_CFG:
            _SIM = _sim_from_config(cfg)
            _SIM_CFG = dict(cfg)
        return _SIM.step(scapy_pkt)
    return _DEFAULT.step(scapy_pkt)


def reset():
    global _SIM, _SIM_CFG
    _DEFAULT.reset()
    _SIM = None
    _SIM_CFG = None
