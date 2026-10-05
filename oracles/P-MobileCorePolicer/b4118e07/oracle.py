"""Composed oracle for P-MobileCorePolicer (GTP-U decap ∘ per-subscriber
count-min heavy-hitter policer ∘ stateful source-NAT44 ∘ LPM forward) at seed
`mobile_core_policer_anchor-default`.

Implements the UPF uplink data plane in the binding order
decap → detect → NAT → route:

  STAGE 0 — GTP-U tunnel termination (P-GTPUEncap). Every access-side packet
    is Ether/IP/UDP(gtpu_udp_port)/GTP-U/inner-IPv4/L4. The outer IP/UDP/GTP-U
    stack is stripped and the inner UE IPv4 packet becomes the working packet.
    Anything that is not a GTP-U-tunnelled inner IPv4 packet drops (R0). All
    downstream stages key on the INNER headers (decap_before_detect).

  STAGE 1 — per-subscriber policing (P-SketchHeavyHitter). A count-min sketch
    keyed on the INNER UE source IP is incremented; the post-increment
    min-across-rows estimate is read. A UE whose estimate reaches
    heavy_threshold is `heavy` and is DROPPED (rate-policed) BEFORE NAT
    (detect_before_nat) — so a policed UE burns no NAT pool port.

  STAGE 2 — source-NAT44 (P-NAT44). Rewrite the inner IP.src -> nat_pool_ip
    and the inner L4.src -> an allocated pool port. The binding
    (orig_inner_src, orig_l4_src, proto) -> pool_port is installed on the first
    packet of a flow and reused thereafter. allocated_port = nat_pool_port_base
    + (live binding count) at install — observable and unit-testable.

  STAGE 3 — LPM forward (P-IPv4Routing). The fib is consulted on the inner
    (post-NAT) IP.dst. No match or ttl == 0 drops; otherwise inner TTL is
    decremented once, Ether.dst is rewritten to the next hop, and the packet
    egresses the internet-facing port.

Load-bearing composite contracts:
  - decap_precedes_detect: the sketch flowkey is the inner UE src, visible
    only after decap (NOT the outer gNB src).
  - detect_precedes_nat: a heavy (policed) UE installs NO nat binding.
  - nat_binding_reuse: the same inner flow reuses its pool port.
  - post_nat_routing: the LPM key is the inner IP.dst after source-NAT.
  - compound_checksum_validity: one inner-IPv4/L4 checksum recompute covers the
    decap + NAT rewrite + TTL decrement.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant. The sketch + nat tables live on the instance and are cleared
by reset(), so a prior_inputs sequence accumulates state.

TTL convention (binding, inherited from the IPv4 anchor): gate inner ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).

Inner-packet extraction is robust to two build paths: (a) a properly-bound
GTP_U_Header (test-generation / runtime evaluation), where the inner IP is the
2nd IP layer; and (b) the oracle audit harness, whose scapy layer_map has no
GTP layer, so it stacks the inner IP directly under UDP(2152) as a Raw payload
— detected by the leading IPv4 version nibble.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
GTPU_UDP_PORT = 2152
ACCESS_PORT = 1
INTERNET_PORT = 2
SKETCH_DEPTH = 2                 # count-min rows R (min-across-rows protection)
SKETCH_WIDTH = 64                # count-min width W per row
COUNTER_MAX = (1 << 32) - 1      # saturating counter
HEAVY_THRESHOLD = 8              # est >= T -> heavy (small, unit-testable)
EPOCH_PACKETS = 4096             # large enough that no test rolls the epoch
NAT_POOL_IP = "203.0.113.1"
NAT_POOL_PORT_BASE = 20000
NAT_CAPACITY = 256
NAT_EVICTION = "none"            # 'none' | 'LRU' | 'FIFO'

# LPM forwarding table (consulted on the inner post-NAT dst):
# (subnet, prefix) -> (egress_port, next_hop_mac).
FIB = [
    (("198.51.100.0", 24), (INTERNET_PORT, "08:00:00:00:02:02")),   # internet dst
    (("8.8.8.0", 24),      (INTERNET_PORT, "08:00:00:00:02:02")),   # internet dst
]


# ── helpers ─────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


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


def _row_hash(row_idx: int, srcaddr_int: int, width: int) -> int:
    """Deterministic per-row independent hash (FNV-style mix with a per-row
    seed) — the oracle only needs deterministic cross-row independence."""
    seeds = [0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F,
             0x165667B1, 0xD3A2646C, 0xFD7046C5, 0xB55A4F09]
    s = seeds[row_idx % len(seeds)]
    x = (srcaddr_int * 0x01000193) ^ s
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    x = (x * 0x85EBCA6B) & 0xFFFFFFFF
    x = (x ^ (x >> 13)) & 0xFFFFFFFF
    x = (x * 0xC2B2AE35) & 0xFFFFFFFF
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    return x % width


def _extract_inner(scapy_pkt, gtpu_udp_port):
    """Return the inner UE IPv4 layer of a GTP-U uplink frame, or None.

    Works from the raw UDP(gtpu_udp_port) payload bytes so it is robust to
    whether scapy has bound a GTP_U_Header to UDP(2152) globally (importing
    scapy.contrib.gtp anywhere installs that bind, which would otherwise make
    parsing order-dependent). Three byte layouts are handled:
      (b) the inner IPv4 packet stacked DIRECTLY under UDP (the oracle audit
          harness, whose scapy layer_map has no GTP layer): the payload begins
          with an IPv4 version nibble 0x4.
      (a/c) a real GTP-U header (version==1, pt==1) followed by the inner IPv4
          T-PDU: skip the 8-byte mandatory header (plus optional 4-byte
          extension when S/PN/E set) and parse the remainder as IP.
    """
    from scapy.all import IP, UDP

    if UDP not in scapy_pkt:
        return None
    udp = scapy_pkt[UDP]
    if int(udp.dport) != int(gtpu_udp_port):
        return None
    payload = bytes(udp.payload)
    if not payload:
        return None

    first = payload[0]
    # (b) inner IPv4 stacked directly under UDP (audit harness path): the
    # leading nibble is the IPv4 version (4). A real GTP-U header's first byte
    # is 0x3X (version=1,pt=1 -> 0b001 1xxxx), nibble 0x3.
    if (first >> 4) == 4:
        try:
            return IP(payload)
        except Exception:
            return None
    # (a/c) real GTP-U header -> skip it, parse the inner IPv4 T-PDU.
    version = (first >> 5) & 0x7
    pt = (first >> 4) & 0x1
    if version != 1 or pt != 1 or len(payload) < 8:
        return None
    flags = first & 0x7                # S | PN | E in the low 3 bits
    hdr_len = 8 + (4 if flags else 0)  # optional seq/npdu/next-ext block
    if len(payload) <= hdr_len:
        return None
    try:
        inner = IP(payload[hdr_len:])
        return inner if (inner.version == 4) else None
    except Exception:
        return None


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None
    ttl_decrement: int = 0
    # post-decap/NAT inner field values (None == field unchanged from input)
    new_ip_src: Optional[str] = None
    new_ip_dst: Optional[str] = None
    new_l4_src: Optional[int] = None
    new_l4_dst: Optional[int] = None
    est_count: int = 0                     # post-inc min-across-rows estimate
    heavy: bool = False
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class MobileCorePolicerSimulator:
    gtpu_udp_port: int = GTPU_UDP_PORT
    access_port: int = ACCESS_PORT
    internet_port: int = INTERNET_PORT
    sketch_depth: int = SKETCH_DEPTH
    sketch_width: int = SKETCH_WIDTH
    heavy_threshold: int = HEAVY_THRESHOLD
    epoch_packets: int = EPOCH_PACKETS
    nat_pool_ip: str = NAT_POOL_IP
    nat_pool_port_base: int = NAT_POOL_PORT_BASE
    nat_capacity: int = NAT_CAPACITY
    nat_eviction: str = NAT_EVICTION
    fib: list = field(default_factory=lambda: list(FIB))

    # count-min sketch buckets: (row, col) -> count
    bucket: dict = field(default_factory=dict)
    # forward NAT bindings: (orig_ip, orig_port, proto) -> pool_port
    fwd: dict = field(default_factory=dict)
    # reverse NAT bindings: (pool_port, proto) -> (orig_ip, orig_port)
    rev: dict = field(default_factory=dict)
    # LRU/FIFO order of forward keys (oldest first)
    order: list = field(default_factory=list)
    n_packets: int = 0
    epoch_id: int = 0

    def reset(self):
        self.bucket = {}
        self.fwd = {}
        self.rev = {}
        self.order = []
        self.n_packets = 0
        self.epoch_id = 0

    # ── sketch ──────────────────────────────────────────────────────────────
    def _inc_and_estimate(self, srcaddr_int: int) -> int:
        cells = []
        for r in range(self.sketch_depth):
            col = _row_hash(r, srcaddr_int, self.sketch_width)
            key = (r, col)
            v = self.bucket.get(key, 0)
            if v < COUNTER_MAX:
                v += 1
            self.bucket[key] = v
            cells.append(v)
        return min(cells)

    def _maybe_epoch_roll(self):
        self.n_packets += 1
        if self.n_packets >= self.epoch_packets:
            self.bucket = {}
            self.n_packets = 0
            self.epoch_id += 1

    # ── NAT allocation ──────────────────────────────────────────────────────
    def _allocate(self, key):
        """Return (pool_port, installed_now)."""
        if key in self.fwd:
            if key in self.order:
                self.order.remove(key)
            self.order.append(key)
            return self.fwd[key], False
        if len(self.fwd) >= self.nat_capacity and self.nat_eviction in ("LRU", "FIFO"):
            victim = self.order.pop(0)
            vp = self.fwd.pop(victim)
            self.rev.pop((vp, victim[2]), None)
        port = self.nat_pool_port_base + len(self.fwd)
        self.fwd[key] = port
        self.rev[(port, key[2])] = (key[0], key[1])
        self.order.append(key)
        return port, True

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, UDP

        # Uplink only: only access-side GTP-U frames are processed.
        if in_port != self.access_port:
            return StepResult(False, "drop_non_gtpu")

        # STAGE 0 — GTP-U decap: expose the inner UE IPv4 packet.
        inner = _extract_inner(scapy_pkt, self.gtpu_udp_port)
        if inner is None or IP not in inner:
            return StepResult(False, "drop_non_gtpu")

        ip = inner[IP]
        ttl = int(ip.ttl)
        proto = int(ip.proto)
        if inner.haslayer(TCP):
            sport, dport = int(inner[TCP].sport), int(inner[TCP].dport)
        elif inner.haslayer(UDP):
            sport, dport = int(inner[UDP].sport), int(inner[UDP].dport)
        else:
            sport, dport = 0, 0

        ilog = [("decap_precedes_detect", {"inner_src": ip.src})]

        # STAGE 1 — per-subscriber policing on the INNER UE src.
        srcaddr_int = _ip_to_int(ip.src)
        est = self._inc_and_estimate(srcaddr_int)
        heavy = est >= self.heavy_threshold
        self._maybe_epoch_roll()
        ilog.append(("detect_precedes_nat", {"est": est, "heavy": heavy}))
        if heavy:
            return StepResult(False, "drop_heavy_policed",
                              est_count=est, heavy=True, invariant_log=ilog)

        # STAGE 2 — source-NAT44 on the inner packet.
        port, _ = self._allocate((ip.src, sport, proto))
        new_src = self.nat_pool_ip
        new_sport = port
        route_dst = ip.dst
        ilog.append(("nat_binding_reuse", {"pool_port": port}))

        # STAGE 3 — LPM forward on the inner (post-NAT) dst.
        ilog.append(("post_nat_routing", {"route_dst": route_dst}))
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired",
                              est_count=est, heavy=False, invariant_log=ilog)
        nh = _lpm_lookup(route_dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm",
                              est_count=est, heavy=False, invariant_log=ilog)
        egress, mac = nh
        ilog.append(("compound_checksum_validity",
                     {"nat": True, "ttl_decremented": True}))
        return StepResult(
            True, "forward_decap_nat", output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, new_ip_src=new_src, new_l4_src=new_sport,
            est_count=est, heavy=False, invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = MobileCorePolicerSimulator()


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
