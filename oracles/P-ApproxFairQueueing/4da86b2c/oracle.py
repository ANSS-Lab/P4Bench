"""Pure-Python mirror of the AFQ ingress pipeline at seed
`afq_per_flow_budget_mut1-default` — multi-axis harden chain on top of the
anchor seed.

Mutation chain applied (parameter rebinding):
  - shrink_window_2x:        window         8 -> 4   (capacity)
  - shrink_sketch_width_4x:  sketch_width   256 -> 64 (capacity)
  - raise_workload_skew:     workload_skew  zipfian -> adversarial_collision

PARAMETRIC-SOURCE CONTRACT: the behaviourally-relevant operator knobs (window, quantum,
fair_share_k, sketch_rows, sketch_width) are read from the runtime
``state['config']`` at evaluation time. ``step(scapy_pkt, ingress_port,
state=None)`` is arity-3 so an audit harness can thread a config dict; when
no config is supplied the mut1-seed defaults below are used so standalone
behaviour is byte-identical to the pre-refactor oracle. No seed value is the
authoritative source of behaviour — the constants below are defaults only.
"""
from dataclasses import dataclass, field
from typing import Optional

# mut1-seed defaults (overridden by state['config'] at runtime).
QUANTUM = 256                # unchanged from anchor
FAIR_SHARE_K = 4             # unchanged
WINDOW = 4                   # harden: shrink_window_2x  (8 -> 4)
N_SLOTS = 64                 # harden: shrink_sketch_width_4x  (256 -> 64)
SKETCH_ROWS = 2
ACCESS_PORT = 1
CORE_PORT = 2
CORE_MAC = "08:00:00:00:02:01"


def hashes(src_addr_int: int, n_slots: int = N_SLOTS) -> tuple[int, int]:
    mask = n_slots - 1 if (n_slots & (n_slots - 1)) == 0 else 0xFFFFFFFF
    h0 = src_addr_int & mask
    h1 = (((src_addr_int >> 8) & 0xFF) ^ ((src_addr_int >> 16) & 0xFF)) & mask
    return h0, h1


def _ip_to_int(addr: str) -> int:
    a, b, c, d = (int(x) for x in addr.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


@dataclass
class StepResult:
    admitted: bool
    reason: str
    round_shift: Optional[int] = None
    bytes_consumed: int = 0


@dataclass
class AFQSimulator:
    quantum: int = QUANTUM
    fair_share_k: int = FAIR_SHARE_K
    window: int = WINDOW
    n_slots: int = N_SLOTS
    sketch_rows: int = SKETCH_ROWS
    access_port: int = ACCESS_PORT
    core_port: int = CORE_PORT
    sketch: list = field(default=None)
    total_admitted_bytes: int = 0

    def __post_init__(self):
        if self.sketch is None:
            self.reset()

    def reset(self):
        self.sketch = [[0] * self.n_slots for _ in range(self.sketch_rows)]
        self.total_admitted_bytes = 0

    def step(self, scapy_pkt, ingress_port: int) -> StepResult:
        from scapy.all import IP, TCP

        if ingress_port != self.access_port:
            return StepResult(False, "wrong_port")
        if IP not in scapy_pkt:
            return StepResult(False, "not_ipv4")
        if TCP not in scapy_pkt:
            return StepResult(False, "not_tcp")

        src_int = _ip_to_int(scapy_pkt[IP].src)
        idxs = []
        for r in range(self.sketch_rows):
            h0, h1 = hashes(src_int, self.n_slots)
            idxs.append(h1 if r % 2 else h0)

        per_row = [self.sketch[r][idxs[r]] for r in range(self.sketch_rows)]
        flow_bytes_estimate = min(per_row)

        total = self.total_admitted_bytes
        current_round = total // (self.quantum * self.fair_share_k)
        flow_round = flow_bytes_estimate // self.quantum
        round_shift = max(0, flow_round - current_round)

        if round_shift >= self.window:
            return StepResult(False, "out_of_window")

        pkt_len = len(bytes(scapy_pkt))
        for r in range(self.sketch_rows):
            self.sketch[r][idxs[r]] += pkt_len
        self.total_admitted_bytes = total + pkt_len

        return StepResult(True, "admit", round_shift=round_shift, bytes_consumed=pkt_len)

    def run(self, sequence) -> list[StepResult]:
        return [self.step(pkt, port) for (pkt, port) in sequence]


# ── config-driven construction (parametric-source invariant) ────────────────

def _sim_from_config(cfg: dict) -> "AFQSimulator":
    cfg = cfg or {}
    return AFQSimulator(
        quantum=int(cfg.get("quantum", QUANTUM)),
        fair_share_k=int(cfg.get("fair_share_k", FAIR_SHARE_K)),
        window=int(cfg.get("window", WINDOW)),
        n_slots=int(cfg.get("sketch_width", N_SLOTS)),
        sketch_rows=int(cfg.get("sketch_rows", SKETCH_ROWS)),
        access_port=int(cfg.get("access_port", ACCESS_PORT)),
        core_port=int(cfg.get("core_port", CORE_PORT)),
    )


_DEFAULT = AFQSimulator()


def new_state(cfg=None):
    return {"config": dict(cfg or {})}


def init_state(cfg=None):
    return new_state(cfg)


def reset():
    global _DEFAULT
    _DEFAULT = AFQSimulator()


def step(scapy_pkt, ingress_port: int = ACCESS_PORT, state=None):
    if isinstance(state, dict):
        cfg = state.get("config", {}) or {}
        sim = state.get("_sim")
        if sim is None:
            sim = _sim_from_config(cfg)
            state["_sim"] = sim
        return sim.step(scapy_pkt, ingress_port)
    global _DEFAULT
    if not isinstance(_DEFAULT, AFQSimulator):
        _DEFAULT = AFQSimulator()
    return _DEFAULT.step(scapy_pkt, ingress_port)
