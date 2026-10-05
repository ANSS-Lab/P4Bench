"""Pure-Python mirror of the bounded stateful L4 load balancer ingress
pipeline used to generate test expectations. Not loaded by the benchmark
runner.

Tier-2 variant of P-StatefulLB. Default behaviour:

  - flow_table_capacity = 256 (bounded; vs unbounded at Tier-1).
  - eviction_policy = FIFO_collision_displace: a single slot per bucket;
    a new flow that hashes to an occupied bucket DISPLACES the resident
    flow's binding. (Implementable approximation of FIFO in a single P4
    stage. Pure insertion-order FIFO is not realisable in BMv2 within
    typical pipeline-stage budgets.)
  - persistence_strict = false (counter-based assignment is incompatible
    with strict persistence under churn).
  - assign = round_robin (counter mod N_backends).

The bucket table is keyed by `identity & (capacity - 1)` when capacity is
a power of two (the bridging note recommends sizing capacity to a power
of two so a bitmask suffices) and `identity % capacity` otherwise. Each
bucket stores (flow_identity, backend_idx); a lookup checks BOTH that the
slot is occupied AND that the stored flow_identity matches the probe's.
A mismatch is a miss — the probe's flow displaces whatever was there.

Seed-driven knobs (mirror the `seed:` block of task.yaml):

  - assign:                 'round_robin' | 'consistent_hash'
  - persistence_strict:     bool  — when true the simulator falls back to
                                    an unbounded dict so an admitted flow
                                    is NEVER displaced (the bucket array
                                    is bypassed; this is the only sane
                                    interpretation of strict persistence
                                    on a bounded base).
  - flow_table_capacity:    int   — bucket array size. Powers of two get
                                    a bitmask; other values use modulo.
  - eviction_policy:        str   — informational on the bucket model
                                    (one slot per bucket means LRU and
                                    FIFO_collision_displace are the same
                                    operation). Kept in the seed so the
                                    discrimination harness can record
                                    the swap as a mutation.
  - faithfulness:           'D5.0_exact' | 'D5.2_partition'
                                  — partition adds a slow-path port for
                                    flows whose identity-low-nibble is
                                    0xF (~1/16 of the keyspace).
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional


VIP = "10.0.100.1"

BACKENDS = [
    ("10.0.2.10", "08:00:00:00:02:01", 2),
    ("10.0.2.20", "08:00:00:00:02:02", 3),
    ("10.0.2.30", "08:00:00:00:02:03", 4),
]
N_BACKENDS = len(BACKENDS)
CAPACITY = 256

# Slow-path port — mirrors the medium-tier simulator's convention. Only
# routes flows when faithfulness == 'D5.2_partition'.
SLOW_PATH_PORT = 5
SLOW_PATH_NIBBLE = 0xF  # admit_slow_path iff (identity & 0xF) == SLOW_PATH_NIBBLE


def _ip_to_int(addr: str) -> int:
    a, b, c, d = (int(x) for x in addr.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def flow_identity(src_ip_str: str, dst_ip_str: str, sport: int,
                  dport: int, proto: int) -> int:
    """32-bit fingerprint of the TCP 5-tuple. Mirrors the data-plane hash:
        ident = (srcAddr ^ dstAddr ^ ((sport<<16)|dport) ^ proto) & 0xFFFFFFFF
    """
    src = _ip_to_int(src_ip_str)
    dst = _ip_to_int(dst_ip_str)
    return (src ^ dst ^ ((sport << 16) | dport) ^ proto) & 0xFFFFFFFF


def flow_bucket(identity: int, capacity: int = CAPACITY) -> int:
    """Bucket index. Bitmask when capacity is a power of two, else modulo."""
    if capacity > 0 and (capacity & (capacity - 1)) == 0:
        return identity & (capacity - 1)
    return identity % capacity


def _fnv1a32(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def consistent_hash_idx(src: str, dst: str, sport: int, dport: int,
                        proto: int, n: int) -> int:
    payload = f"{src}|{dst}|{sport}|{dport}|{proto}".encode()
    return _fnv1a32(payload) % n


def slow_path_match(identity: int) -> bool:
    return (identity & 0xF) == SLOW_PATH_NIBBLE


@dataclass
class StepResult:
    admitted: bool
    reason: str
    backend_idx: Optional[int] = None
    new_flow: Optional[bool] = None    # True iff R1 fired (counter advanced)
    displaced: Optional[bool] = None   # True iff R1 fired AND bucket was occupied by a different flow
    slow_path: bool = False            # True iff routed to slow-path port


@dataclass
class StatefulLBBoundedSimulator:
    backends: list = field(default_factory=lambda: list(BACKENDS))
    vip: str = VIP
    capacity: int = CAPACITY
    assign: str = "round_robin"
    persistence_strict: bool = False
    eviction_policy: str = "FIFO_collision_displace"
    faithfulness: str = "D5.0_exact"

    rr_counter: int = 0
    # bucket[i] = (flow_identity, backend_idx) | None — used in default mode.
    bucket: list = field(default_factory=list)
    # Unbounded dict — only consulted in strict-persistence mode. Same key
    # shape as the medium simulator (5-tuple).
    persistent_table: "OrderedDict[tuple, int]" = field(default_factory=OrderedDict)

    def __post_init__(self):
        if not self.bucket:
            self.bucket = [None] * self.capacity

    def reset(self):
        self.rr_counter = 0
        self.bucket = [None] * self.capacity
        self.persistent_table = OrderedDict()

    def _classify(self, scapy_pkt, vip=None):
        from scapy.all import IP, TCP

        vip = self.vip if vip is None else vip
        if IP not in scapy_pkt:
            return None, None, "drop_non_ipv4"
        if scapy_pkt[IP].dst != vip:
            return None, None, "drop_non_vip"
        if TCP not in scapy_pkt:
            return None, None, "drop_non_tcp"
        ident = flow_identity(
            scapy_pkt[IP].src, scapy_pkt[IP].dst,
            scapy_pkt[TCP].sport, scapy_pkt[TCP].dport,
            scapy_pkt[IP].proto,
        )
        flow_key = (
            scapy_pkt[IP].src,
            scapy_pkt[IP].dst,
            scapy_pkt[TCP].sport,
            scapy_pkt[TCP].dport,
            scapy_pkt[IP].proto,
        )
        return ident, flow_key, "ok"

    def _pick_backend(self, flow_key, assign=None) -> int:
        assign = self.assign if assign is None else assign
        if assign == "consistent_hash":
            return consistent_hash_idx(*flow_key, n=len(self.backends))
        return self.rr_counter % len(self.backends)

    def _advance_counter_after_new_flow(self, assign=None):
        assign = self.assign if assign is None else assign
        if assign == "round_robin":
            self.rr_counter += 1

    def step(self, scapy_pkt, ingress_port=None, state: dict = None) -> StepResult:
        """Parametric-source contract: the VIP, faithfulness rung
        and assignment policy are read from runtime `state["config"]` at call
        time, falling back to the instance binding when no config is threaded.
        The SAME loaded module thus serves parameter rebinding without re-instantiation;
        behaviour is identical to the pre-parametric oracle when `state` is None."""
        cfg = state.get("config", {}) if isinstance(state, dict) else {}
        eff_vip = cfg.get("vip", self.vip)
        eff_faith = cfg.get("faithfulness", self.faithfulness)
        eff_assign = cfg.get("assign", self.assign)
        eff_persist = cfg.get("persistence_strict", self.persistence_strict)
        # flow_table_capacity must not exceed the allocated bucket array; the
        # operator only ever SHRINKS it (shrink_capacity_*), so an effective
        # value ≤ len(self.bucket) keeps indexing safe while changing collisions.
        eff_capacity = cfg.get("flow_table_capacity", self.capacity)
        if eff_capacity > len(self.bucket):
            eff_capacity = self.capacity
        # Informational: single-slot buckets make FIFO and LRU coincide, so the
        # eviction_policy knob is threaded but has no behavioural branch here.
        _eff_evict = cfg.get("eviction_policy", self.eviction_policy)

        ident, flow_key, status = self._classify(scapy_pkt, vip=eff_vip)
        if ident is None:
            return StepResult(False, status)

        # Partition mode: route ~1/16 of flows to slow path. Decision is
        # purely a function of identity, so a flow is consistently fast or
        # slow across replays.
        if (eff_faith == "D5.2_partition"
                and slow_path_match(ident)):
            new_flow = True
            if eff_persist:
                if flow_key in self.persistent_table \
                        and self.persistent_table[flow_key] == -1:
                    new_flow = False
                else:
                    self.persistent_table[flow_key] = -1
            return StepResult(
                True, "admit_slow_path",
                backend_idx=None, new_flow=new_flow, slow_path=True,
            )

        # Strict persistence: bypass bucket array entirely. Once admitted,
        # a flow's binding lives forever in the unbounded dict.
        if eff_persist:
            if flow_key in self.persistent_table:
                return StepResult(True, "admit",
                                  backend_idx=self.persistent_table[flow_key],
                                  new_flow=False, displaced=False)
            backend_idx = self._pick_backend(flow_key, eff_assign)
            self.persistent_table[flow_key] = backend_idx
            self._advance_counter_after_new_flow(eff_assign)
            return StepResult(True, "admit",
                              backend_idx=backend_idx,
                              new_flow=True, displaced=False)

        # Default bucket-displacement path.
        b = flow_bucket(ident, eff_capacity)
        slot = self.bucket[b]

        if slot is not None and slot[0] == ident:
            # R2 hit: same flow as resident.
            return StepResult(True, "admit",
                              backend_idx=slot[1],
                              new_flow=False, displaced=False)

        # R1 fires. If the slot was occupied by a DIFFERENT flow, that
        # resident's binding is forgotten (displaced).
        displaced = slot is not None
        backend_idx = self._pick_backend(flow_key, eff_assign)
        self.bucket[b] = (ident, backend_idx)
        self._advance_counter_after_new_flow(eff_assign)
        return StepResult(True, "admit",
                          backend_idx=backend_idx,
                          new_flow=True, displaced=displaced)

    def run(self, packets) -> list[StepResult]:
        return [self.step(p) for p in packets]
