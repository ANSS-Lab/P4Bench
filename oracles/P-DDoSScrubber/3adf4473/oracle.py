"""Composed oracle for P-DDoSScrubber (stateless ACL ∘ sketch heavy-hitter
∘ SYN-cookie gate) at seed `ddos_scrubber_anchor-default`.

Implements the single-pass DDoS-scrubbing pipeline in the binding order
ACL → sketch-detect → cookie-gate:

  STAGE 1 — ACL classification (P-ACL). The original 5-tuple is matched
    against a stateless ternary table by descending priority. A deny (or a
    miss under default_acl_action == deny) drops the packet BEFORE the sketch
    is updated and BEFORE the cookie decision (acl_priority_over_both).

  STAGE 2 — heavy-hitter detection (P-SketchHeavyHitter). On every surviving
    IPv4 packet the count-min sketch keyed on the SOURCE IP is incremented
    (one cell per row) and the min-across-rows estimate is read. The source
    is `heavy` when its POST-increment estimate reaches heavy_threshold (the
    crossing packet itself is heavy). This stage strictly PRECEDES the cookie
    decision on the same packet (detect_before_challenge).

  STAGE 3 — SYN-cookie gate (P-SYNCookieGuard). For TCP to a protected
    server:
      - a new SYN (SYN set, ACK clear, no established flow) from a HEAVY
        source is rate-dropped (drop_heavy_synflood) — detection wins over
        the challenge;
      - a new SYN from a NON-heavy source is answered with an originated
        SYN-ACK reflected to the ingress untrusted port: IP.src/dst and
        TCP.sport/dport swapped, flags SYN+ACK, seq == cookie, ack ==
        orig_seq + 1. The inbound SYN is consumed; NO per-flow state is
        allocated (no_state_on_unvalidated_syn). decision == challenge_syn_cookie,
        output_port == untrusted_port.
      - a non-SYN packet carrying a VALID cookie (ack - 1 == cookie(5tuple)),
        or a packet of an already-established flow, is L3-forwarded to the
        protected server (forward_validated / forward_benign) with TTL-1.

The cookie is fully specified so a faithful BMv2 implementation reproduces it
bit-exactly with 32-bit wrapping arithmetic:

    cookie = (src_ip + dst_ip + proto + ((sport << 16) | dport) + cookie_secret)
             & 0xffffffff

i.e. `cookie = hash(5tuple) & 0xffffffff` with a concrete, deterministic hash
over all five tuple fields (so a partial-key / constant cookie diverges).

Load-bearing composite contracts:
  - acl_priority_over_both: a denied flow updates no sketch counter and is
    never challenged.
  - detect_before_challenge: the sketch inc + heavy check precede the cookie
    decision; a heavy source's new SYN is dropped before R4 can mint a cookie.
  - cookie_correctness: the SYN-ACK seq encodes the per-5-tuple cookie and a
    returning ACK validates iff ack - 1 == that cookie.
  - no_state_on_unvalidated_syn: a challenged SYN allocates no flow state;
    only a validated ACK pins the flow.

PARAMETRIC-SOURCE CONTRACT: every mutable knob is a
constructor argument with a seed-bound default; step() reads no module-level
mutable constant. The sketch / heavy set / established flows live on the
instance and are cleared by reset(), so a prior_inputs sequence accumulates.

TTL convention (binding, inherited from the IPv4 anchor): gate ttl > 0;
ttl == 0 drops; ttl == 1 forwards with egress ttl == 0 (decrement once).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


U32 = 0xFFFFFFFF


# ── seed-bound defaults (the per-seed content-addressed copy) ───────────────
UNTRUSTED_PORT = 1
PROTECTED_PORT = 2
DEFAULT_ACL_ACTION = "permit"
SKETCH_DEPTH = 2
SKETCH_WIDTH = 64
COUNTER_MAX = (1 << 32) - 1
HEAVY_THRESHOLD = 8
EPOCH_PACKETS = 4096
COOKIE_SECRET = 0

# Stateless ACL: priority + action + ternary src/dst/proto/sport/dport
# (missing field = wildcard). Evaluated on the ORIGINAL tuple.
ACL_RULES = [
    {"priority": 100, "action": "deny", "ipv4_src": "10.0.1.66/32"},   # blocklisted source
]

PROTECTED_SUBNET = "10.0.2.0/24"

# LPM forwarding table: (subnet, prefix) -> (egress_port, next_hop_mac).
FIB = [
    (("10.0.2.0", 24), (PROTECTED_PORT, "08:00:00:00:02:02")),   # protected servers
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


def _in_subnet(addr: str, cidr: str) -> bool:
    return _ipv4_match(addr, cidr)


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


def _row_hash(row_idx: int, key_int: int, width: int) -> int:
    """Deterministic per-row independent hash (FNV-style mix with a per-row
    seed) — the count-min row indexer. A real P4 implementation uses crc with a per-row
    polynomial; the oracle only needs deterministic cross-row independence."""
    seeds = [0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F,
             0x165667B1, 0xD3A2646C, 0xFD7046C5, 0xB55A4F09]
    s = seeds[row_idx % len(seeds)]
    x = (key_int * 0x01000193) ^ s
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    x = (x * 0x85EBCA6B) & 0xFFFFFFFF
    x = (x ^ (x >> 13)) & 0xFFFFFFFF
    x = (x * 0xC2B2AE35) & 0xFFFFFFFF
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    return x % width


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None
    ttl_decrement: int = 0
    # cookie / challenge fields (the SYN-ACK the challenge originates)
    cookie: Optional[int] = None               # the minted/expected 32-bit cookie
    new_ip_src: Optional[str] = None
    new_ip_dst: Optional[str] = None
    new_l4_src: Optional[int] = None
    new_l4_dst: Optional[int] = None
    new_tcp_flags: Optional[str] = None        # 'SA' on a challenge
    new_tcp_seq: Optional[int] = None          # == cookie on a challenge
    new_tcp_ack: Optional[int] = None          # == orig_seq + 1 on a challenge
    est_count: int = 0                         # post-inc min-across-rows estimate
    heavy: bool = False
    acl_verdict: Optional[str] = None          # 'permit' | 'deny'
    invariant_log: list = field(default_factory=list)


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class DDoSScrubberSimulator:
    untrusted_port: int = UNTRUSTED_PORT
    protected_port: int = PROTECTED_PORT
    default_acl_action: str = DEFAULT_ACL_ACTION
    sketch_depth: int = SKETCH_DEPTH
    sketch_width: int = SKETCH_WIDTH
    heavy_threshold: int = HEAVY_THRESHOLD
    epoch_packets: int = EPOCH_PACKETS
    cookie_secret: int = COOKIE_SECRET
    protected_subnet: str = PROTECTED_SUBNET
    acl_rules: list = field(default_factory=lambda: [dict(r) for r in ACL_RULES])
    fib: list = field(default_factory=lambda: list(FIB))

    bucket: dict = field(default_factory=dict)        # (row, col) -> count
    detected_heavy: set = field(default_factory=set)  # set of src-IP ints
    established: set = field(default_factory=set)      # set of 5-tuple keys
    n_packets: int = 0
    epoch_id: int = 0

    def reset(self):
        self.bucket = {}
        self.detected_heavy = set()
        self.established = set()
        self.n_packets = 0
        self.epoch_id = 0

    # ── ACL ───────────────────────────────────────────────────────────────
    def _acl_verdict(self, l4: dict) -> str:
        best, best_p = None, -1
        for r in self.acl_rules:
            if (_ipv4_match(l4["src"], r.get("ipv4_src"))
                    and _ipv4_match(l4["dst"], r.get("ipv4_dst"))
                    and _eq_or_any(l4["proto"], r.get("proto"))
                    and _eq_or_any(l4["sport"], r.get("sport"))
                    and _eq_or_any(l4["dport"], r.get("dport"))):
                p = int(r["priority"])
                if p > best_p:
                    best, best_p = r, p
        return best["action"] if best is not None else self.default_acl_action

    # ── sketch ────────────────────────────────────────────────────────────
    def _inc_and_estimate(self, key_int: int) -> int:
        cells = []
        for r in range(self.sketch_depth):
            col = _row_hash(r, key_int, self.sketch_width)
            k = (r, col)
            v = self.bucket.get(k, 0)
            if v < COUNTER_MAX:
                v += 1
            self.bucket[k] = v
            cells.append(v)
        return min(cells)

    def _maybe_epoch_roll(self):
        self.n_packets += 1
        if self.n_packets >= self.epoch_packets:
            self.bucket = {}
            self.detected_heavy = set()
            self.n_packets = 0
            self.epoch_id += 1

    # ── cookie ──────────────────────────────────────────────────────────────
    def _cookie(self, key: Tuple[str, str, int, int, int]) -> int:
        """cookie = hash(5tuple) & 0xffffffff, a concrete deterministic hash
        over (src, dst, proto, sport, dport) folded with the secret."""
        src, dst, proto, sport, dport = key
        k = ((int(sport) & 0xFFFF) << 16) | (int(dport) & 0xFFFF)
        return (_ip_to_int(src) + _ip_to_int(dst) + int(proto) + k
                + int(self.cookie_secret)) & U32

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, UDP

        # R0 — non-IPv4 dropped (no classify, no count, no challenge).
        if IP not in scapy_pkt:
            return StepResult(False, "drop_non_ipv4")

        ip = scapy_pkt[IP]
        ttl = int(ip.ttl)
        proto = int(ip.proto)
        is_tcp = TCP in scapy_pkt
        if is_tcp:
            tcp = scapy_pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            flags = str(tcp.flags)
            tcp_seq = int(tcp.seq)
            tcp_ack = int(tcp.ack)
        elif UDP in scapy_pkt:
            sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
            flags, tcp_seq, tcp_ack = "", 0, 0
        else:
            sport, dport, flags, tcp_seq, tcp_ack = 0, 0, "", 0, 0
        syn = ("S" in flags)
        ack = ("A" in flags)
        l4 = {"src": ip.src, "dst": ip.dst, "proto": proto,
              "sport": sport, "dport": dport}
        key5 = (ip.src, ip.dst, proto, sport, dport)

        # STAGE 1 — ACL on the ORIGINAL tuple (acl_priority_over_both).
        verdict = self._acl_verdict(l4)
        ilog = [("acl_priority_over_both", {"verdict": verdict})]
        if verdict == "deny":
            return StepResult(False, "drop_acl_deny", acl_verdict="deny",
                              invariant_log=ilog)

        # STAGE 2 — detect_before_challenge: inc THEN read the estimate.
        src_int = _ip_to_int(ip.src)
        est = self._inc_and_estimate(src_int)
        heavy = est >= self.heavy_threshold
        if heavy:
            self.detected_heavy.add(src_int)
        self._maybe_epoch_roll()
        ilog.append(("detect_before_challenge", {"est": est, "heavy": heavy}))

        to_protected = _in_subnet(ip.dst, self.protected_subnet)

        # STAGE 3 — SYN-cookie gate (TCP to a protected server).
        if is_tcp and to_protected:
            established = key5 in self.established
            # New SYN (SYN, not ACK, no established flow).
            if syn and not ack and not established:
                # R3 — heavy source's new SYN is rate-dropped before challenge.
                if heavy:
                    return StepResult(False, "drop_heavy_synflood",
                                      acl_verdict=verdict, est_count=est,
                                      heavy=heavy, invariant_log=ilog)
                # R4 — challenge: originate a SYN-ACK on the ingress untrusted
                # port; consume the SYN; allocate NO flow state.
                cookie = self._cookie(key5)
                ilog.append(("cookie_correctness", {"cookie": cookie}))
                ilog.append(("no_state_on_unvalidated_syn",
                             {"established_after": len(self.established)}))
                return StepResult(
                    True, "challenge_syn_cookie",
                    output_port=self.untrusted_port,
                    cookie=cookie,
                    new_ip_src=ip.dst, new_ip_dst=ip.src,
                    new_l4_src=dport, new_l4_dst=sport,
                    new_tcp_flags="SA",
                    new_tcp_seq=cookie, new_tcp_ack=(tcp_seq + 1) & U32,
                    est_count=est, heavy=heavy, acl_verdict=verdict,
                    invariant_log=ilog)

            # R5a — non-SYN ACK carrying a valid cookie: validate + admit.
            if ack and not syn and not established:
                expect = self._cookie(key5)
                if ((tcp_ack - 1) & U32) == expect:
                    self.established.add(key5)
                    return self._forward(ip, ttl, "forward_validated",
                                         verdict, est, heavy, cookie=expect,
                                         ilog=ilog)
                # invalid cookie -> default deny for protected TCP
                return StepResult(False, "drop_invalid_cookie",
                                  acl_verdict=verdict, est_count=est,
                                  heavy=heavy, invariant_log=ilog)

            # R5b — established flow: benign forward.
            if established:
                return self._forward(ip, ttl, "forward_benign",
                                     verdict, est, heavy, ilog=ilog)

            # Any other crafted TCP to a protected server -> default deny.
            return StepResult(False, "drop_default_deny",
                              acl_verdict=verdict, est_count=est,
                              heavy=heavy, invariant_log=ilog)

        # Non-TCP / non-protected IPv4 that survived the ACL: benign forward
        # toward its destination if routable (the scrubber is transparent
        # outside the challenge surface).
        return self._forward(ip, ttl, "forward_benign", verdict, est, heavy,
                             ilog=ilog)

    def _forward(self, ip, ttl, decision, verdict, est, heavy,
                 cookie=None, ilog=None) -> StepResult:
        ilog = ilog or []
        if ttl == 0:
            return StepResult(False, "drop_ttl_expired", acl_verdict=verdict,
                              est_count=est, heavy=heavy, invariant_log=ilog)
        nh = _lpm_lookup(ip.dst, self.fib)
        if nh is None:
            return StepResult(False, "drop_no_lpm", acl_verdict=verdict,
                              est_count=est, heavy=heavy, invariant_log=ilog)
        egress, mac = nh
        return StepResult(
            True, decision, output_port=egress, next_hop_mac=mac,
            ttl_decrement=1, cookie=cookie, est_count=est, heavy=heavy,
            acl_verdict=verdict, invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# Module-level convenience for adopt/audit.
_DEFAULT = DDoSScrubberSimulator()


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
