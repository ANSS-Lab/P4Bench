"""Python oracle for benchmark/relocate/http_header_route_anchor.

Implements P-HTTPHeaderRoute's rule sequence under the
task's seed (D5.0_anchor_route): a stateless shallow-L7 HTTP/1.1 request
steerer. On a TCP/${http_tcp_port} segment whose first bytes are a recognised
method token (RFC 9112 §3 request-line, RFC 9110 §9 method), the oracle parses,
within a BOUNDED ${parse_window_bytes} byte prefix of the TCP payload, the
classification key and steers per the control-plane http_route_policy table:

  R0  ¬is_http_request                              -> drop
        (not TCP/http_tcp_port, OR no payload, OR leading bytes are not a
         recognised method token — non-HTTP traffic, TLS/HTTPS, HTTP responses,
         SYN/ACK control segments)
  R1  is_http_request ∧ ¬req_well_formed ∧ strict   -> drop          (dormant at lax_default)
  R2  well_formed_req ∧ class.action == block       -> drop          (dormant at route_only)
  R3  well_formed_req ∧ class.action == route        -> L3-forward (MAC rewrite, TTL--, IPv4 csum;
                                                       ipv4.dst == service_vip PRESERVED)
  R4  well_formed_req ∧ class.action == rewrite      -> DNAT-forward (+ipv4.dst, +TCP csum)   (dormant at route_only)
  R5  is_http_request ∧ (no class match ∨ (¬well_formed ∧ lax))
                                                     -> default_action
        (forward_default -> L3-forward to default_backend_port like R3; drop -> closed-world deny)

The pattern is STATELESS — every decision derives from the bounded-prefix header
bytes (method [+host under host_match_enabled] [+path under path_match_enabled])
and the control-plane table; no per-flow state is kept. The headline contract is
http_payload_persistence: on every steered request the HTTP message bytes are
delivered byte-for-byte unmodified; the switch edits only the L2/L3/L4 envelope.

PARAMETRIC-SOURCE CONTRACT: every parameter named in the
pattern's `mutation_operators` surface is a constructor argument with a
seed-bound default; step() reads no module-level mutable constant for those
knobs. Two siblings with different seeds yield byte-identical oracle source —
e.g. a parameter rebind of method_set / parse_window_bytes / host_match_enabled /
action_breadth / malformed_handling / default_action reuses this same module.
Module-level constants are reserved for things no mutation operator touches (the IANA
HTTP scope, the recognised method-token universe, the field-line delimiters).

No P4/BMv2 imports. Scapy packets are parsed defensively (haslayer/getlayer);
the HTTP request line + Host header are parsed from the RAW bytes of the TCP
payload (the audit builder cannot synthesise a payload, so canonical examples
cover only the base-layer-expressible R0 boundaries; the steered paths are
exercised by the test generator which builds real HTTP payloads — same
new-header deferral the P-OverlayGateway note records).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


# ── invariant constants (no mutation operator touches these) ──────────────────────
# The recognised method-token universe (RFC 9110 §9). method_set (a seed knob)
# selects a non-empty subset of these; the universe itself is fixed.
_METHOD_UNIVERSE = (
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
)
_TLS_CONTENT_TYPE = 0x16          # leading byte of a TLS record (ClientHello) — never a method token
_CR = 0x0D
_LF = 0x0A
_SP = 0x20


# ── seed-bound defaults (the per-seed content-addressed copy; rebound per parameter rebinding) ─
HTTP_TCP_PORT = 80
PARSE_WINDOW_BYTES = 64
METHOD_SET = ["GET", "POST"]
HOST_MATCH_ENABLED = False
HOST_MATCH_BREADTH = "exact_host"      # exact_host | registrable_suffix
PATH_MATCH_ENABLED = False
PATH_MATCH_BREADTH = "first_segment"   # first_segment | two_segments
ACTION_BREADTH = "route_only"          # route_only | route_block | route_rewrite | all
MALFORMED_HANDLING = "lax_default"     # strict_drop | lax_default
DEFAULT_ACTION = "forward_default"     # forward_default | drop
DEFAULT_BACKEND_PORT = 4
CASE_NORMALIZATION = False
HOST_HASH_ALGO = "crc16"               # crc16 | crc32 | truncate (key-fold quality; behaviour-equivalent here)
ROUTE_POLICY_CAPACITY = None           # None == unbounded
WORKLOAD_SKEW = "uniform"
SERVICE_VIP = "203.0.113.10"
CLIENT_PORT = 1                        # ingress port carrying client requests

# The http_route_policy rows the seed installs. Each row:
#   {method, host?, path_prefix?, action, egress_port, backend_ip?,
#    backend_mac, src_mac}
# The (method, host_key, path_prefix_key) derived under the configured breadths
# is unique across the list. Anchor seed: method-only route rows (GET, POST).
HTTP_ROUTE_POLICY_ENTRIES = [
    {"method": "GET",  "action": "route", "egress_port": 2,
     "backend_mac": "08:00:00:00:02:02", "src_mac": "08:00:00:00:00:02"},
    {"method": "POST", "action": "route", "egress_port": 3,
     "backend_mac": "08:00:00:00:03:03", "src_mac": "08:00:00:00:00:03"},
]


# ── step result ──────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    next_hop_mac: Optional[str] = None       # backend_mac (Ether.dst on forward)
    src_mac: Optional[str] = None            # egress-port MAC (Ether.src on forward)
    ttl_decrement: int = 0
    new_ip_dst: Optional[str] = None         # DNAT target (rewrite action only; None == unchanged)
    rewrite_tcp_checksum: bool = False       # whether the TCP checksum must be recomputed (DNAT)
    method: Optional[str] = None
    host_key: Optional[str] = None
    path_prefix_key: Optional[str] = None
    invariant_log: list = field(default_factory=list)


# ── bounded-prefix HTTP parse helpers ───────────────────────────────────────

def _leading_method(window: bytes) -> Optional[str]:
    """Return the recognised method token at the FIXED leading offset (offset 0)
    iff the window begins with `<TOKEN> ` (token followed by a single SP), token
    ∈ the recognised universe, case-SENSITIVE (RFC 9110 §9). Otherwise None."""
    for tok in _METHOD_UNIVERSE:
        b = tok.encode("ascii")
        if window[:len(b)] == b and len(window) > len(b) and window[len(b)] == _SP:
            return tok
    return None


def _request_line_terminates(window: bytes) -> bool:
    """The request-line `method SP request-target SP HTTP-version CRLF` must
    terminate (CRLF) within the window."""
    return window.find(b"\r\n") != -1


def _extract_path_prefix(window: bytes, method: str, two_segments: bool
                         ) -> Optional[str]:
    """The request-target's leading absolute-path prefix: bytes after the
    method's trailing SP up to the path boundary. origin-form only (leading
    '/'); asterisk-form / authority-form have no absolute-path -> None."""
    start = len(method.encode("ascii")) + 1            # past `METHOD `
    # request-target runs up to the next SP (before HTTP-version).
    sp = window.find(b" ", start)
    target = window[start:sp] if sp != -1 else window[start:]
    if not target.startswith(b"/"):
        return None                                    # not origin-form
    # split on '/', drop the empty leading element, also cut a '?' query.
    q = target.find(b"?")
    if q != -1:
        target = target[:q]
    segs = [s for s in target.split(b"/") if s != b""]
    if not segs:
        return None
    n = 2 if two_segments else 1
    return "/" + "/".join(s.decode("latin-1") for s in segs[:n])


def _extract_host(window: bytes) -> Optional[str]:
    """The value of the FIRST `Host:` field-line within the window (field-name
    case-insensitive per RFC 9110 §5), read to the terminating CRLF. None if no
    Host field-line appears within the window."""
    lower = window.lower()
    idx = lower.find(b"host:")
    if idx == -1:
        return None
    # Host must be on a field-line (not at request-line offset 0).
    val_start = idx + len(b"host:")
    end = window.find(b"\r\n", val_start)
    raw = window[val_start:end] if end != -1 else window[val_start:]
    if end == -1:
        return None                                    # value does not terminate in window
    return raw.strip().decode("latin-1")


def _host_key(host: str, breadth: str, case_norm: bool) -> str:
    h = host.lower() if case_norm else host
    if breadth == "registrable_suffix":
        labels = h.split(".")
        if len(labels) >= 2:
            h = ".".join(labels[-2:])
    return h


# ── simulator ─────────────────────────────────────────────────────────────────

@dataclass
class HTTPHeaderRouteSimulator:
    http_tcp_port: int = HTTP_TCP_PORT
    parse_window_bytes: int = PARSE_WINDOW_BYTES
    method_set: list = field(default_factory=lambda: list(METHOD_SET))
    host_match_enabled: bool = HOST_MATCH_ENABLED
    host_match_breadth: str = HOST_MATCH_BREADTH
    path_match_enabled: bool = PATH_MATCH_ENABLED
    path_match_breadth: str = PATH_MATCH_BREADTH
    action_breadth: str = ACTION_BREADTH
    malformed_handling: str = MALFORMED_HANDLING
    default_action: str = DEFAULT_ACTION
    default_backend_port: int = DEFAULT_BACKEND_PORT
    case_normalization: bool = CASE_NORMALIZATION
    host_hash_algo: str = HOST_HASH_ALGO
    route_policy_capacity: Optional[int] = ROUTE_POLICY_CAPACITY
    workload_skew: str = WORKLOAD_SKEW
    service_vip: str = SERVICE_VIP
    client_port: int = CLIENT_PORT
    route_policy: list = field(
        default_factory=lambda: [dict(e) for e in HTTP_ROUTE_POLICY_ENTRIES])

    # stateless — reset() is a no-op kept for the audit harness contract.
    def reset(self):
        pass

    # ── classification key derivation ───────────────────────────────────────
    def _class_key(self, method, host, path_prefix):
        parts = [method]
        if self.host_match_enabled:
            parts.append(_host_key(host, self.host_match_breadth,
                                   self.case_normalization))
        if self.path_match_enabled:
            parts.append(path_prefix)
        return tuple(parts)

    def _entry_key(self, e):
        parts = [e["method"]]
        if self.host_match_enabled:
            parts.append(_host_key(e.get("host", ""), self.host_match_breadth,
                                   self.case_normalization))
        if self.path_match_enabled:
            parts.append(e.get("path_prefix"))
        return tuple(parts)

    def _lookup(self, key):
        for e in self.route_policy:
            if self._entry_key(e) == key:
                return e
        return None

    def _action_enabled(self, action: str) -> bool:
        if action == "route":
            return True
        if action == "block":
            return self.action_breadth in ("route_block", "all")
        if action == "rewrite":
            return self.action_breadth in ("route_rewrite", "all")
        return False

    # ── forward construction (R3 / R5-forward / R4) ─────────────────────────
    def _forward(self, e, decision, dnat=False):
        return StepResult(
            True, decision,
            output_port=int(e["egress_port"]),
            next_hop_mac=e["backend_mac"],
            src_mac=e["src_mac"],
            ttl_decrement=1,
            new_ip_dst=(e.get("backend_ip") if dnat else None),
            rewrite_tcp_checksum=bool(dnat),
        )

    def _default(self, ilog):
        if self.default_action == "forward_default":
            de = {"egress_port": self.default_backend_port,
                  "backend_mac": "08:00:00:00:0d:0d",
                  "src_mac": "08:00:00:00:00:0d"}
            r = self._forward(de, "forward_default")
            r.invariant_log = ilog
            return r
        return StepResult(False, "drop_default_deny", invariant_log=ilog)

    # ── step ──────────────────────────────────────────────────────────────
    def step(self, scapy_pkt, in_port: int) -> StepResult:
        from scapy.all import IP, TCP, Raw

        ilog = []

        # ── R0: is_http_request? ────────────────────────────────────────────
        # header_present(http) ∧ tcp.dst == http_tcp_port ∧ leading token ∈ method_set
        if IP not in scapy_pkt or TCP not in scapy_pkt:
            return StepResult(False, "drop_non_http", invariant_log=ilog)
        tcp = scapy_pkt[TCP]
        if int(tcp.dport) != self.http_tcp_port:
            return StepResult(False, "drop_non_http", invariant_log=ilog)
        if Raw not in scapy_pkt:
            # no payload (SYN/ACK control segment) -> not an HTTP request
            return StepResult(False, "drop_non_http", invariant_log=ilog)
        payload = bytes(scapy_pkt[Raw].load)
        if not payload or payload[0] == _TLS_CONTENT_TYPE:
            return StepResult(False, "drop_non_http", invariant_log=ilog)
        window = payload[: self.parse_window_bytes]    # parser_window_safety: never read past the bound
        method = _leading_method(window)
        if method is None or method not in self.method_set:
            return StepResult(False, "drop_non_http", invariant_log=ilog)

        ilog.append(("is_http_request", {"method": method}))

        # ── req_well_formed within the bounded window ───────────────────────
        well_formed = _request_line_terminates(window)
        host = None
        path_prefix = None
        if well_formed and self.host_match_enabled:
            host = _extract_host(window)
            if host is None:
                well_formed = False                    # RFC 9110 §7.2 Host MUST / not in window
        if well_formed and self.path_match_enabled:
            path_prefix = _extract_path_prefix(
                window, method, self.path_match_breadth == "two_segments")
            if path_prefix is None:
                well_formed = False                    # non-origin-form target

        # ── R1 / R5-malformed: malformed handling ───────────────────────────
        if not well_formed:
            if self.malformed_handling == "strict_drop":
                return StepResult(False, "drop_malformed_strict", invariant_log=ilog)
            ilog.append(("parser_window_safety", {"malformed": True}))
            return self._default(ilog)                 # lax_default -> R5

        # ── classification key + table lookup ───────────────────────────────
        key = self._class_key(method, host, path_prefix)
        host_key = key[1] if self.host_match_enabled else None
        path_key = (key[-1] if self.path_match_enabled else None)
        e = self._lookup(key)

        if e is None or not self._action_enabled(e["action"]):
            # well-formed but unclassified (or the matched action is disabled
            # at this action_breadth) -> R5 default
            r = self._default(ilog)
            r.method, r.host_key, r.path_prefix_key = method, host_key, path_key
            return r

        action = e["action"]
        ilog.append(("classification_determinism",
                     {"key": list(key), "action": action}))

        # ── R2 block ─────────────────────────────────────────────────────────
        if action == "block":
            return StepResult(False, "drop_block",
                              method=method, host_key=host_key,
                              path_prefix_key=path_key, invariant_log=ilog)

        # ── R4 rewrite (DNAT) ────────────────────────────────────────────────
        if action == "rewrite":
            r = self._forward(e, "forward_rewrite", dnat=True)
            ilog.append(("envelope_checksum_validity", {"tcp": True, "ipv4": True}))
            r.method, r.host_key, r.path_prefix_key = method, host_key, path_key
            r.invariant_log = ilog
            return r

        # ── R3 route (anchor verdict) ────────────────────────────────────────
        r = self._forward(e, "forward_route", dnat=False)
        ilog.append(("http_payload_persistence", {"preserved": True}))
        ilog.append(("envelope_checksum_validity", {"ipv4": True}))
        r.method, r.host_key, r.path_prefix_key = method, host_key, path_key
        r.invariant_log = ilog
        return r

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# ── parametric-source config wiring ─────────────────────────────────────────
# The mutable knobs are HTTPHeaderRouteSimulator constructor args; the
# module-level step() threads them from runtime state["config"] so a seed rebind
# reuses this same source. When no config is supplied the
# seed-bound defaults above apply. The pattern is stateless so each call simply
# (re)derives the active simulator from the supplied config.
# route_policy_capacity is a forward-declared variant selector (the dataclass
# carries it but the step logic never branches on it — it gates a bounded-table
# sibling regenerated as a different oracle), so — like `faithfulness` — it is
# exercised across oracle regeneration, not config-threaded on this hash.
_CONFIG_KEYS = (
    "http_tcp_port", "parse_window_bytes", "method_set",
    "host_match_enabled", "host_match_breadth",
    "path_match_enabled", "path_match_breadth",
    "action_breadth", "malformed_handling", "default_action",
    "default_backend_port", "case_normalization",
    "service_vip", "client_port",
)


def _hashable(v):
    return tuple(v) if isinstance(v, list) else v


def _simulator_from_config(cfg):
    kwargs = {k: cfg[k] for k in _CONFIG_KEYS if k in (cfg or {})}
    rp = cfg.get("route_policy") or cfg.get("http_route_policy_entries")
    if rp is not None:
        kwargs["route_policy"] = [dict(e) for e in rp]
    return HTTPHeaderRouteSimulator(**kwargs)


_DEFAULT = HTTPHeaderRouteSimulator()
_ACTIVE = _DEFAULT
_ACTIVE_CFG = None


def step(scapy_pkt, in_port: int = 1, state=None):
    """Process one packet. `state["config"]` (when present) supplies the
    seed-bound knobs (and, optionally, the route_policy rows); absent => module
    defaults. Stateless — no cross-packet state is threaded."""
    global _ACTIVE, _ACTIVE_CFG
    cfg = (state or {}).get("config") if isinstance(state, dict) else None
    if cfg is not None:
        key = tuple(sorted((k, _hashable(cfg[k])) for k in _CONFIG_KEYS if k in cfg))
        if key != _ACTIVE_CFG:
            _ACTIVE = _simulator_from_config(cfg)
            _ACTIVE_CFG = key
    else:
        _ACTIVE, _ACTIVE_CFG = _DEFAULT, None
    return _ACTIVE.step(scapy_pkt, in_port)


def reset():
    global _ACTIVE, _ACTIVE_CFG
    _ACTIVE, _ACTIVE_CFG = _DEFAULT, None
    _DEFAULT.reset()
