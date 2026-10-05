"""Per-task oracle for benchmark/scale_up/syn_cookie_guard_disc.

Implements P-SYNCookieGuard's first-match rule cascade (R1..R9) for the
task's seed:

  R1  non-IPv4                              -> drop
  R2  IPv4, dst not protected               -> forward (passthrough)
  R3  IPv4, dst protected, non-TCP          -> forward (passthrough)
  R4  TCP, dst protected, src whitelisted   -> forward (bypass challenge)
  R5  TCP, dst protected, established flow   -> forward (flow-admit)
  R6  (dormant; syn_rate_activation=false)
  R7  pure SYN, dst protected, no state      -> ORIGINATE SYN-ACK + drop SYN
  R8  pure ACK, dst protected, valid cookie  -> bind flow + forward
  R9  any other TCP to a protected server    -> drop (default deny)

The headline security property (no_state_on_unvalidated_syn): a `bind`
into the established table happens ONLY in R8, after the returning ACK's
acknowledgement number validates against the cookie the switch would have
minted for that 4-tuple. R7 (the SYN path) NEVER allocates established
state — that is what makes the table immune to SYN-flood exhaustion.

Parametric-source contract: every parameter the
pattern's mutation_operators name (cookie_faithfulness, cookie_hash_algo,
cookie_secret, state_capacity, eviction_policy, whitelist,
protected_servers, cookie_validity_epochs, epoch_period_s, ...) is read
from the constructor `config` at runtime, never baked as a module-level
constant. This lets parameter rebinding reuse this same module.

Cookie function (D5.0_truncated_hash, this seed):
    k       = (sport << 16) | dport
    cookie  = (src_ip + dst_ip + k + secret + epoch) mod 2**32
fully specified so a faithful BMv2 implementation reproduces it bit-exactly
with 32-bit wrapping arithmetic. `epoch` is fixed at 0: the v1.0 evaluation
harness injects no `time_tick` events, so the cookie epoch counter never
advances and the validity window is [0, 0]. Epoch-expiry tests are
scaffolded in the pattern but deferred.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


U32 = 0xFFFFFFFF


@dataclass
class StepResult:
    # Audit-facing fields (the oracle audit's comparison reads these).
    decision: str = "drop"                    # 'forward' | 'drop'
    admitted: bool = False
    output_port: Optional[int] = None
    # Generator-facing fields (the test generator builds expected: from these).
    mode: str = "drop"                         # see _MODES below
    cookie: Optional[int] = None               # minted/expected cookie (R7/R8)
    decoded_mss: Optional[int] = None          # D5.1 only
    reason: str = ""
    invariant_log: list = field(default_factory=list)


# mode vocabulary the generator switches on
#   "drop"                  - no output
#   "originate_synack"      - reflect input as a SYN-ACK out the ingress port
#   "forward_to_server"     - L3-forward toward the protected server
#   "forward_passthrough"   - forward a non-protected / non-TCP packet


def _ip2int(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


def _in_set(addr: str, prefixes) -> bool:
    """True if addr is inside any ipv4 address / CIDR in prefixes."""
    a = ipaddress.IPv4Address(addr)
    for p in prefixes or []:
        net = ipaddress.IPv4Network(p, strict=False) if "/" in str(p) \
            else ipaddress.IPv4Network(f"{p}/32", strict=False)
        if a in net:
            return True
    return False


# ──────────────────────────────────────────────────────────────────────
# Scapy / dict field access shim (audit feeds Scapy; generator feeds Scapy)
# ──────────────────────────────────────────────────────────────────────

def _has(pkt, layer: str) -> bool:
    if hasattr(pkt, "haslayer"):
        try:
            return bool(pkt.haslayer(layer))
        except Exception:
            return False
    return isinstance(pkt, dict) and layer in pkt


def _f(pkt, layer: str, name: str, default=None):
    if hasattr(pkt, "haslayer") and pkt.haslayer(layer):
        return getattr(pkt[layer], name, default)
    if isinstance(pkt, dict) and layer in pkt:
        return pkt[layer].get(name, default)
    return default


def _tcp_flag(pkt, bit: str) -> int:
    """Return 1 if a TCP flag char ('S','A','F','R','P','U') is set."""
    flags = _f(pkt, "TCP", "flags", 0)
    if isinstance(flags, str):
        return 1 if bit in flags else 0
    # scapy FlagValue / int
    mask = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
            "A": 0x10, "U": 0x20}[bit]
    try:
        return 1 if (int(flags) & mask) else 0
    except Exception:
        return 1 if bit in str(flags) else 0


def _flow_key(pkt) -> Tuple[str, str, int, int]:
    return (
        _f(pkt, "IP", "src"),
        _f(pkt, "IP", "dst"),
        int(_f(pkt, "TCP", "sport", 0)),
        int(_f(pkt, "TCP", "dport", 0)),
    )


# RFC 4987 §3.6 3-bit MSS bucket table (8 representative MSS values).
_MSS_TABLE = [256, 512, 536, 1024, 1220, 1440, 1460, 8960]


def _encode_mss(mss: int) -> int:
    """Largest bucket index whose MSS value <= the advertised MSS."""
    idx = 0
    for i, v in enumerate(_MSS_TABLE):
        if mss >= v:
            idx = i
    return idx


def _decode_mss(idx: int) -> int:
    return _MSS_TABLE[idx & 0x7]


class SYNCookieSimulator:
    """Stateless SYN-cookie guard reference oracle (flow-admit model)."""

    def __init__(self, **config):
        # Every knob read from config — never a source-level default that
        # could mask a constant-baked oracle.
        self.protected_servers = config["protected_servers"]
        self.whitelist = config.get("whitelist", [])
        self.cookie_faithfulness = config.get("cookie_faithfulness",
                                              "D5.0_truncated_hash")
        self.cookie_secret = int(config["cookie_secret"]) & U32
        self.state_capacity = config.get("state_capacity", "unbounded")
        self.eviction_policy = config.get("eviction_policy", "none")
        self.cookie_validity_epochs = int(config.get("cookie_validity_epochs", 1))
        self.epoch_period_s = int(config.get("epoch_period_s", 64))
        self.track_halfopen = bool(config.get("track_halfopen", False))
        self.halfopen_capacity = int(config.get("halfopen_capacity", 1024))
        self.syn_rate_activation = bool(config.get("syn_rate_activation", False))
        self.syn_rate_threshold = int(config.get("syn_rate_threshold", 128))
        # Forwarding fabric (harness-installed L3 table): dst -> (port, mac).
        self.fwd_table = config["fwd_table"]
        # The switch's egress MAC presented on each port (for emitted frames).
        self.port_mac = config.get("port_mac", {})

        # Runtime state.
        self.epoch = 0                       # never advances (no ticks)
        self.established: Dict[Tuple, Dict[str, Any]] = {}
        self.halfopen: Dict[Tuple, Dict[str, Any]] = {}
        self._seq = 0                        # FIFO insertion order counter

    # ── cookie ───────────────────────────────────────────────────────────
    def _cookie(self, key: Tuple[str, str, int, int], mss_idx: int = 0) -> int:
        src, dst, sport, dport = key
        k = ((sport & 0xFFFF) << 16) | (dport & 0xFFFF)
        base = (_ip2int(src) + _ip2int(dst) + k + self.cookie_secret
                + self.epoch) & U32
        if self.cookie_faithfulness == "D5.1_rfc4987_mss":
            # top 5 bits epoch mod 32, next 3 bits MSS bucket, low 24 keyed hash
            keyed = base & 0xFFFFFF
            return (((self.epoch % 32) & 0x1F) << 27) | ((mss_idx & 0x7) << 24) | keyed
        return base

    def _cookie_valid(self, key, ack_minus_1: int) -> Tuple[bool, Optional[int]]:
        """Recompute the cookie across the validity window. Returns
        (valid, decoded_mss). With epoch fixed at 0 the window is [0,0]."""
        for e in range(self.epoch - self.cookie_validity_epochs + 1,
                       self.epoch + 1):
            if e < 0:
                continue
            if self.cookie_faithfulness == "D5.1_rfc4987_mss":
                # MSS bits are part of the value the client echoes back, so
                # we recover them rather than guess: low 24 bits must match,
                # epoch bits must be in window.
                want_keyed = (_ip2int(key[0]) + _ip2int(key[1])
                              + (((key[2] & 0xFFFF) << 16) | (key[3] & 0xFFFF))
                              + self.cookie_secret + e) & 0xFFFFFF
                if (ack_minus_1 & 0xFFFFFF) == want_keyed \
                        and ((ack_minus_1 >> 27) & 0x1F) == (e % 32):
                    return True, _decode_mss((ack_minus_1 >> 24) & 0x7)
            else:
                saved_epoch, self.epoch = self.epoch, e
                c = self._cookie(key)
                self.epoch = saved_epoch
                if (ack_minus_1 & U32) == c:
                    return True, None
        return False, None

    # ── capacity / eviction ────────────────────────────────────────────────
    def _admit(self, key, decoded_mss=None):
        if self.state_capacity != "unbounded" \
                and len(self.established) >= int(self.state_capacity) \
                and key not in self.established:
            if self.eviction_policy in ("FIFO", "LRU", "timeout"):
                victim = min(self.established,
                             key=lambda k: self.established[k]["order"])
                del self.established[victim]
            else:  # 'none' — table full, drop the admission silently
                return False
        self._seq += 1
        self.established[key] = {"established": True, "order": self._seq,
                                 "decoded_mss": decoded_mss}
        if self.track_halfopen:
            self.halfopen.pop(key, None)
        return True

    # ── the oracle step interface ──────────────────────────────────────────
    def step(self, pkt, ingress_port: int) -> StepResult:
        # R1 — non-IPv4
        if not _has(pkt, "IP"):
            return StepResult(decision="drop", mode="drop", reason="R1 non-ipv4")

        dst = _f(pkt, "IP", "dst")
        src = _f(pkt, "IP", "src")

        # R2 — destination not protected: passthrough
        if not _in_set(dst, self.protected_servers):
            return self._forward(pkt, dst, mode="forward_passthrough",
                                 reason="R2 unprotected")

        # R3 — protected but non-TCP: passthrough
        if not _has(pkt, "TCP"):
            return self._forward(pkt, dst, mode="forward_passthrough",
                                 reason="R3 non-tcp to protected")

        key = _flow_key(pkt)
        syn = _tcp_flag(pkt, "S")
        ack = _tcp_flag(pkt, "A")

        # R4 — whitelisted source bypasses the challenge
        if _in_set(src, self.whitelist):
            return self._forward(pkt, dst, mode="forward_to_server",
                                 reason="R4 whitelist bypass")

        # R5 — established flow: flow-admit forward
        ent = self.established.get(key)
        if ent and ent["established"]:
            ent["order"] = self._bump()
            return self._forward(pkt, dst, mode="forward_to_server",
                                 reason="R5 established")

        # R6 dormant (syn_rate_activation == false for this seed).

        # R7 — pure SYN, no state: originate SYN-ACK, drop the SYN, NO bind
        if syn and not ack:
            mss_idx = 0
            if self.cookie_faithfulness == "D5.1_rfc4987_mss":
                mss_idx = _encode_mss(int(_f(pkt, "TCP", "options_mss",
                                             _f(pkt, "TCP", "mss", 1460)) or 1460))
            cookie = self._cookie(key, mss_idx)
            if self.track_halfopen and len(self.halfopen) < self.halfopen_capacity:
                self.halfopen[key] = {"challenged_at": 0}
            return StepResult(
                decision="forward", admitted=True, output_port=ingress_port,
                mode="originate_synack", cookie=cookie,
                reason="R7 cookie challenge",
                invariant_log=[("no_state_on_unvalidated_syn",
                                {"established_after": len(self.established)})],
            )

        # R8 — pure ACK, no state: validate cookie, admit + forward on success
        if ack and not syn:
            ack_num = int(_f(pkt, "TCP", "ack", 0)) & U32
            valid, dmss = self._cookie_valid(key, (ack_num - 1) & U32)
            if valid:
                if not self._admit(key, dmss):
                    return StepResult(decision="drop", mode="drop",
                                      reason="R8 table full, admission dropped")
                r = self._forward(pkt, dst, mode="forward_to_server",
                                  reason="R8 validated ACK admit")
                r.cookie = (ack_num - 1) & U32
                r.decoded_mss = dmss
                return r
            # invalid cookie -> fall through to R9

        # R9 — default deny
        return StepResult(decision="drop", mode="drop", reason="R9 default deny")

    # ── helpers ────────────────────────────────────────────────────────────
    def _bump(self) -> int:
        self._seq += 1
        return self._seq

    def _forward(self, pkt, dst, mode: str, reason: str) -> StepResult:
        entry = self.fwd_table.get(dst)
        if entry is None:
            return StepResult(decision="drop", mode="drop",
                              reason=f"{reason}: no fwd entry for {dst}")
        return StepResult(decision="forward", admitted=True,
                          output_port=entry["port"], mode=mode, reason=reason)

    # Reset hook for the audit harness (it calls reset() between examples).
    def reset(self):
        self.epoch = 0
        self.established.clear()
        self.halfopen.clear()
        self._seq = 0


# Module-level convenience wrapper so the audit's `oracle.step(pkt, port)`
# fallback also works with a process-wide default instance (rarely used —
# the generator and audit both prefer the class).
_DEFAULT: Optional[SYNCookieSimulator] = None


def configure(**config) -> SYNCookieSimulator:
    global _DEFAULT
    _DEFAULT = SYNCookieSimulator(**config)
    return _DEFAULT


def step(pkt, ingress_port: int, state: Optional[dict] = None) -> StepResult:
    """Module-level step(). If `state` carries a 'config' dict, a fresh
    simulator is built from it (parametric-source contract); otherwise the
    process default configured via configure() is used."""
    global _DEFAULT
    if state and "config" in state:
        sim = state.setdefault("_sim", SYNCookieSimulator(**state["config"]))
        return sim.step(pkt, ingress_port)
    if _DEFAULT is None:
        raise RuntimeError("call configure(**seed) or pass state['config'] first")
    return _DEFAULT.step(pkt, ingress_port)
