"""Pure-Python mirror of the stateful L4 load balancer ingress pipeline used
to generate test expectations. Not loaded by the benchmark runner.

Behaviour: a single VIP fronts three backends; new flows are
assigned to backends via a configurable policy (round-robin counter or
stable consistent-hash) and the binding is memoised in a flow table keyed
by the TCP 5-tuple. Subsequent packets of an established flow follow the
recorded backend; everything else (non-VIP destination, non-IPv4 frame,
non-TCP IPv4 payload) is dropped.

Seed-driven knobs (mirror the `seed:` block of task.yaml):

  - assign:                 'round_robin' | 'consistent_hash'
  - persistence_strict:     bool                — informational; the simulator
                                                  always preserves bindings
                                                  for the lifetime of the
                                                  table entry. Strict mode
                                                  triggers extra hidden
                                                  tests by the test generator.
  - flow_table_capacity:    int | 'unbounded'   — when bounded, full-table
                                                  inserts evict per policy.
  - eviction_policy:        'none' | 'LRU' | 'FIFO_collision_displace'
                                                — only consulted when
                                                  capacity is bounded.
  - faithfulness:           'D5.0_exact' | 'D5.2_partition'
                                                — partition mode adds a
                                                  slow-path egress port for
                                                  flows that hash into the
                                                  partition-tail bucket.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional


VIP = "10.0.100.1"

# Backend table: index -> (ip, mac, egress_port_int).
BACKENDS = [
    ("10.0.2.10", "08:00:00:00:02:01", 2),
    ("10.0.2.20", "08:00:00:00:02:02", 3),
    ("10.0.2.30", "08:00:00:00:02:03", 4),
]
N_BACKENDS = len(BACKENDS)

# Used only when faithfulness == 'D5.2_partition'. The slow-path port lives
# on s1 alongside the data-plane backends; the harness routes it to a
# scaffolding host. ~1/16 of the consistent-hash space goes there.
SLOW_PATH_PORT = 5
SLOW_PATH_HASH_MASK = 0x0F
SLOW_PATH_HASH_VALUE = 0x0F


def _fnv1a32(data: bytes) -> int:
    """32-bit FNV-1a — stable across Python runs / hash randomisation."""
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def consistent_hash_idx(flow_key, n: int) -> int:
    src, dst, sport, dport, proto = flow_key
    payload = f"{src}|{dst}|{sport}|{dport}|{proto}".encode()
    return _fnv1a32(payload) % n


def slow_path_match(flow_key) -> bool:
    src, dst, sport, dport, proto = flow_key
    payload = f"{src}|{dst}|{sport}|{dport}|{proto}".encode()
    return (_fnv1a32(payload) & SLOW_PATH_HASH_MASK) == SLOW_PATH_HASH_VALUE


@dataclass
class StepResult:
    admitted: bool
    reason: str  # "drop_non_ipv4" | "drop_non_vip" | "drop_non_tcp" |
                 # "admit" | "admit_slow_path"
    backend_idx: Optional[int] = None     # 0..N_BACKENDS-1; None for slow path
    new_flow: Optional[bool] = None       # True iff a fresh binding was installed
    evicted_key: Optional[tuple] = None   # if eviction fired, the displaced key
    slow_path: bool = False               # True iff routed to slow-path port


@dataclass
class StatefulLBSimulator:
    backends: list = field(default_factory=lambda: list(BACKENDS))
    vip: str = VIP
    assign: str = "round_robin"
    persistence_strict: bool = False
    flow_table_capacity: object = "unbounded"  # int or 'unbounded'
    eviction_policy: str = "none"
    faithfulness: str = "D5.0_exact"

    rr_counter: int = 0
    # OrderedDict so we can implement LRU cheaply; insertion order is also
    # the natural FIFO order for FIFO_collision_displace.
    flow_table: "OrderedDict[tuple, int]" = field(default_factory=OrderedDict)

    def reset(self):
        self.rr_counter = 0
        self.flow_table = OrderedDict()

    # ── eligibility + key extraction ────────────────────────────────────────
    def _classify(self, scapy_pkt):
        from scapy.all import IP, TCP

        if IP not in scapy_pkt:
            return None, "drop_non_ipv4"
        if scapy_pkt[IP].dst != self.vip:
            return None, "drop_non_vip"
        if TCP not in scapy_pkt:
            return None, "drop_non_tcp"
        flow_key = (
            scapy_pkt[IP].src,
            scapy_pkt[IP].dst,
            scapy_pkt[TCP].sport,
            scapy_pkt[TCP].dport,
            scapy_pkt[IP].proto,
        )
        return flow_key, "ok"

    # ── assignment policy ───────────────────────────────────────────────────
    def _pick_backend(self, flow_key) -> int:
        if self.assign == "consistent_hash":
            return consistent_hash_idx(flow_key, len(self.backends))
        # Default: round_robin counter.
        return self.rr_counter % len(self.backends)

    def _advance_counter_after_new_flow(self):
        if self.assign == "round_robin":
            self.rr_counter += 1

    # ── eviction policy ─────────────────────────────────────────────────────
    def _capacity(self) -> Optional[int]:
        if self.flow_table_capacity == "unbounded":
            return None
        return int(self.flow_table_capacity)

    def _evict_if_needed(self) -> Optional[tuple]:
        cap = self._capacity()
        if cap is None or len(self.flow_table) < cap:
            return None
        # When the table is full at insert time, evict the oldest entry.
        # LRU and FIFO_collision_displace both pop from the front of the
        # OrderedDict; the difference is that LRU bumps on hit (handled
        # in step()) while FIFO does not.
        evicted_key, _ = self.flow_table.popitem(last=False)
        return evicted_key

    def _bump_lru(self, flow_key):
        if self.eviction_policy == "LRU" and flow_key in self.flow_table:
            self.flow_table.move_to_end(flow_key, last=True)

    # ── per-packet step ─────────────────────────────────────────────────────
    def step(self, scapy_pkt) -> StepResult:
        flow_key, status = self._classify(scapy_pkt)
        if flow_key is None:
            return StepResult(False, status)

        # Partition-mode slow-path takes precedence over backend assignment;
        # the slow-path bucket is identified purely from the 5-tuple hash so
        # a given flow always lands consistently on slow path or fast path.
        if (self.faithfulness == "D5.2_partition"
                and slow_path_match(flow_key)):
            new_flow = flow_key not in self.flow_table
            if new_flow:
                self._evict_if_needed()
                # Sentinel value -1 records "this flow is on slow path";
                # subsequent packets must look up consistently.
                self.flow_table[flow_key] = -1
            self._bump_lru(flow_key)
            return StepResult(
                True, "admit_slow_path",
                backend_idx=None, new_flow=new_flow, slow_path=True,
            )

        if flow_key in self.flow_table:
            backend_idx = self.flow_table[flow_key]
            # Re-look-up safety: if a prior partition state put this flow on
            # slow path (-1), keep it there even if faithfulness flipped
            # mid-run; the simulator is reset between cases so this only
            # matters for prior_inputs of the same test.
            if backend_idx == -1:
                self._bump_lru(flow_key)
                return StepResult(
                    True, "admit_slow_path",
                    backend_idx=None, new_flow=False, slow_path=True,
                )
            self._bump_lru(flow_key)
            return StepResult(True, "admit",
                              backend_idx=backend_idx, new_flow=False)

        # New flow path.
        backend_idx = self._pick_backend(flow_key)
        evicted = self._evict_if_needed()
        self.flow_table[flow_key] = backend_idx
        self._advance_counter_after_new_flow()
        return StepResult(
            True, "admit",
            backend_idx=backend_idx, new_flow=True, evicted_key=evicted,
        )

    def run(self, packets) -> list[StepResult]:
        return [self.step(p) for p in packets]


# ── parametric module-level step (parametric-source contract) ──
# The canonical step entrypoint. When `state` carries a `config` dict the
# singleton simulator is (re)built from it so a parameter rebind reconfigures the SAME
# audited module at runtime; otherwise the seed-bound default instance is used.
# A knob absent from config falls back to its constructor (seed) default. This
# top-level `step` is preferred by the oracle loader over the bound class method,
# giving the arity-3 config-capable interface the parametric-source audit
# requires.
_CONFIG_KNOBS = (
    "backends", "vip", "assign", "persistence_strict", "flow_table_capacity",
    "eviction_policy", "faithfulness",
)


def _sim_from_config(config):
    kwargs = {}
    for knob in _CONFIG_KNOBS:
        if config and knob in config and config[knob] is not None:
            kwargs[knob] = config[knob]
    return StatefulLBSimulator(**kwargs)


_DEFAULT = StatefulLBSimulator()
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
