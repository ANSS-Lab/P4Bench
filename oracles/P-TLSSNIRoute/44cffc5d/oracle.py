"""Python oracle for benchmark/relocate/tls_sni_route_anchor.

Implements P-TLSSNIRoute's rule sequence for the
D5.0_anchor_route seed:

  - R0  non-ClientHello drop  (not TCP/${tls_tcp_port}, or TLS record
                               content_type != 22, or handshake msg_type != 1)
  - R1  malformed strict drop (¬sni_well_formed AND malformed_handling ==
                               strict_drop; dormant at this seed — lax_default)
  - R2  classify -> block     (matched action == block; dormant — route_only)
  - R3  classify -> route     (L3 forward: MAC rewrite + TTL-- + IPv4 csum;
                               the VIP destination is PRESERVED)
  - R4  classify -> rewrite   (DNAT: ipv4.dst = backend_ip + IPv4 csum +
                               TCP csum; dormant — route_only)
  - R5  default catch-all     (well-formed SNI with no policy match, or — under
                               lax_default — a malformed record -> default_action)

The oracle reaches the SNI by walking the BOUNDED, FIXED-OFFSET TLS layout
the pattern is constrained to (record header -> handshake header -> fixed
ClientHello prefix -> a single admissible server_name extension), exactly
as a loop-free v1model parser must. It extracts the clear-text HostName,
derives the bounded fixed-width name key, and exact-matches it against the
control-plane sni_policy table. The TLS payload is never modified — only
the L2/L3 envelope.

PARAMETRIC-SOURCE INVARIANT: every parameter
named in the pattern's mutation_operators surface is read from runtime
`state` — scalars from state["config"], the policy table from
state["sni_policy_entries"]. Seed values NEVER enter this module as
source-level constants, so parameter rebinding reuses
the same audited oracle. The pattern is STATELESS and there is NO
time_tick — every decision derives from the parsed ClientHello + the
table.

step() signature is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────
# StepResult — oracle return shape
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# Packet-introspection helpers (Scapy + dict-style tolerant)
# ──────────────────────────────────────────────────────────────────────

def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet or name in packet.get("_layers", {})
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        return getattr(packet[layer], fname, default)
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    if isinstance(packet, dict) and "_layers" in packet:
        return packet["_layers"].get(layer, {}).get(fname, default)
    return default


def _tcp_dport(packet) -> Optional[int]:
    return _field(packet, "TCP", "dport")


def _tls_payload_bytes(packet) -> Optional[bytes]:
    """Return the raw TLS record bytes (the TCP payload), or None.

    Works for Scapy packets (with the bounded TLSRecord layer OR a Raw
    payload carrying crafted bytes) and for dict-shaped audit inputs that
    carry a `tls_raw_hex` field on a TCP/TLSRecord layer."""
    if hasattr(packet, "haslayer") and packet.haslayer("TCP"):
        try:
            return bytes(packet["TCP"].payload)
        except Exception:
            return None
    if isinstance(packet, dict):
        for key in ("TLSRecord", "TCP", "Raw"):
            layer = packet.get(key) or packet.get("_layers", {}).get(key)
            if layer and "tls_raw_hex" in layer:
                return bytes.fromhex(layer["tls_raw_hex"])
    return None


# ──────────────────────────────────────────────────────────────────────
# Bounded TLS ClientHello parse (RFC 8446 §5.1/§4.1.2, RFC 6066 §3) over
# the raw record bytes, enforcing the fixed-offset / bounded-prefix limits.
# ──────────────────────────────────────────────────────────────────────

@dataclass
class TlsParse:
    is_clienthello: bool
    host_name: Optional[bytes]      # the extracted HostName bytes (key-normalised iff case_normalization)
    well_formed: bool               # SNI reached within bounds AND host_name(0) present
    reason: str = ""


def _parse_clienthello(raw: bytes, max_prefix_bytes: int, max_ext_count: int,
                       case_normalization: bool) -> Optional[TlsParse]:
    """Walk the bounded TLS record to the server_name extension.

    Returns None when the buffer is too short to even hold the TLS record
    header (R0 territory). Otherwise returns a TlsParse whose
    `is_clienthello` reflects the record/handshake type gate (R0) and
    whose `well_formed` reflects whether a host_name(0) SNI is reachable
    within `max_prefix_bytes` prefix bytes / `max_ext_count` extensions
    and every declared length stays inside the buffer (parser_depth_safety).
    """
    if raw is None or len(raw) < 5:
        return None
    # ── TLS record header (RFC 8446 §5.1) ──
    content_type = raw[0]
    # raw[1:3] legacy_record_version; raw[3:5] length
    off = 5
    if off + 4 > len(raw):
        # cannot hold a handshake header
        return TlsParse(is_clienthello=False, host_name=None, well_formed=False,
                        reason="record too short for handshake header")
    # ── Handshake header (RFC 8446 §4) ──
    msg_type = raw[5]
    # raw[6:9] 3-octet handshake length
    if content_type != 22 or msg_type != 1:
        return TlsParse(is_clienthello=False, host_name=None, well_formed=False,
                        reason="not a handshake/client_hello record")

    # ── ClientHello body (RFC 8446 §4.1.2) — fixed prefix then the three
    #    length-prefixed lists, walked only within the byte budget ──
    body_start = 9
    p = body_start
    p += 2                                   # legacy_version
    p += 32                                  # random
    if p >= len(raw):
        return TlsParse(True, None, False, "truncated before session_id")
    sid_len = raw[p]; p += 1
    p += sid_len                             # legacy_session_id
    if p + 2 > len(raw):
        return TlsParse(True, None, False, "truncated before cipher_suites")
    cs_len = int.from_bytes(raw[p:p + 2], "big"); p += 2
    p += cs_len                              # cipher_suites
    if p >= len(raw):
        return TlsParse(True, None, False, "truncated before compression")
    comp_len = raw[p]; p += 1
    p += comp_len                            # legacy_compression_methods
    if p + 2 > len(raw):
        return TlsParse(True, None, False, "truncated before extensions")
    ext_block_start = p + 2                  # after the 2-octet extensions_len
    # Bounded-prefix budget: server_name must be reachable within the byte
    # budget measured from the start of the ClientHello body.
    if (ext_block_start - body_start) > max_prefix_bytes:
        return TlsParse(True, None, False, "extensions block beyond prefix byte budget")
    p += 2                                    # extensions_len (we walk by bound, not by it)

    # ── Bounded extension walk to server_name (0x0000) ──
    ext_seen = 0
    while p + 4 <= len(raw):
        if ext_seen >= max_ext_count:
            return TlsParse(True, None, False, "server_name beyond max_extension_count")
        ext_type = int.from_bytes(raw[p:p + 2], "big")
        ext_len = int.from_bytes(raw[p + 2:p + 4], "big")
        ext_data_start = p + 4
        if ext_data_start + ext_len > len(raw):
            return TlsParse(True, None, False, "extension length runs past buffer")
        if ext_type == 0x0000:               # server_name (RFC 6066 §3)
            return _parse_sni(raw, ext_data_start, ext_len, case_normalization)
        ext_seen += 1
        p = ext_data_start + ext_len
    # No server_name extension within the bound.
    return TlsParse(True, None, False, "no server_name extension within bound")


def _parse_sni(raw: bytes, data_start: int, ext_len: int,
               case_normalization: bool) -> TlsParse:
    """Parse a ServerNameList and extract the first host_name(0) HostName
    (RFC 6066 §3): list_len(2) then ServerName entries of name_type(1) and,
    for host_name(0), a 2-octet HostName length + the HostName bytes."""
    end = data_start + ext_len
    q = data_start
    if q + 2 > end:
        return TlsParse(True, None, False, "server_name extension too short for list length")
    q += 2                                    # ServerNameList length
    if q + 1 > end:
        return TlsParse(True, None, False, "server_name list truncated")
    name_type = raw[q]; q += 1
    if name_type != 0:                        # not host_name(0)
        return TlsParse(True, None, False, "first ServerName is not host_name(0)")
    if q + 2 > end:
        return TlsParse(True, None, False, "HostName length truncated")
    name_len = int.from_bytes(raw[q:q + 2], "big"); q += 2
    if q + name_len > end:
        return TlsParse(True, None, False, "HostName runs past extension")
    host = raw[q:q + name_len]
    if case_normalization:
        host = host.lower()
    return TlsParse(True, host, True, "")


# ──────────────────────────────────────────────────────────────────────
# Key derivation + classification
# ──────────────────────────────────────────────────────────────────────

def _name_key(host_name: bytes, breadth: str) -> str:
    """Derive the classification key from the parsed HostName under the
    configured match breadth. `exact_host` keys on the whole name;
    `suffix_2label` on the registrable two-label suffix; `hashed_full`
    folds the full name (the oracle keys on the dotted string — the data
    plane folds it via name_hash_algo, but the logical key is the same)."""
    dotted = host_name.decode("latin-1")
    if breadth == "suffix_2label":
        parts = dotted.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else dotted
    return dotted                             # exact_host / hashed_full


def _classify(name_key: str, state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cfg = state.get("config", {})
    breadth = cfg.get("name_match_breadth", "exact_host")
    case_norm = bool(cfg.get("case_normalization", False))
    for e in state.get("sni_policy_entries", []):
        ent_key = _name_key(str(e["name_pattern"]).encode("latin-1"), breadth)
        if case_norm:
            ent_key = ent_key.lower()
        if ent_key == name_key:
            return e
    return None


# ──────────────────────────────────────────────────────────────────────
# Output construction
# ──────────────────────────────────────────────────────────────────────

def _l3_forward(packet, egress_port: int, entry: Optional[Dict[str, Any]],
                rewrite_dst: bool):
    """Build the egress packet for route (R3) / rewrite (R4) / default
    forward: MAC rewrite (when an entry is given), TTL--, IPv4 (and on
    rewrite, TCP) checksum recompute. The TLS payload is left untouched."""
    out = packet.copy() if hasattr(packet, "copy") else packet
    try:
        if entry is not None and _has_layer(out, "Ether"):
            out["Ether"].src = entry["src_mac"]
            out["Ether"].dst = entry["backend_mac"]
        if _has_layer(out, "IP"):
            if rewrite_dst and entry and entry.get("backend_ip") not in (None, "none"):
                out["IP"].dst = entry["backend_ip"]
            out["IP"].ttl = max(int(out["IP"].ttl) - 1, 0)
            if hasattr(out["IP"], "chksum"):
                del out["IP"].chksum
            if rewrite_dst and _has_layer(out, "TCP") and hasattr(out["TCP"], "chksum"):
                del out["TCP"].chksum
        if hasattr(out, "build"):
            out = out.__class__(bytes(out))
    except Exception:
        pass
    return {egress_port: [out]}


def _drop(state, reason: str) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("decision", f"drop: {reason}")])


def _default(packet, state, default_action, default_port) -> StepResult:
    """R5 catch-all: forward to the default backend (VIP preserved, no MAC
    rewrite entry) or drop, per default_action."""
    if default_action == "forward_default" and default_port is not None:
        out = _l3_forward(packet, int(default_port), entry=None, rewrite_dst=False)
        return StepResult(output_packets=out, new_state=state, decision="forward",
                          invariant_log=[("classification", "R5 default forward")])
    return _drop(state, "R5: default drop (no policy match)")


# ──────────────────────────────────────────────────────────────────────
# step() — oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    """Execute one packet step under P-TLSSNIRoute's rules.

    `state` carries:
      - config:              dict of scalar seed parameters (tls_tcp_port,
                             max_clienthello_prefix_bytes, max_extension_count,
                             name_match_breadth, action_breadth,
                             malformed_handling, default_action,
                             default_backend_port, case_normalization,
                             local_vip, ...)
      - sni_policy_entries:  the SNI -> backend classification rows
    """
    cfg = state.get("config", {})
    new_state = state                                       # stateless pattern; no time_tick
    tls_port = int(cfg.get("tls_tcp_port", 443))
    max_prefix = int(cfg.get("max_clienthello_prefix_bytes", 128))
    max_ext = int(cfg.get("max_extension_count", 4))
    breadth = cfg.get("name_match_breadth", "exact_host")
    case_norm = bool(cfg.get("case_normalization", False))
    malformed_handling = cfg.get("malformed_handling", "lax_default")
    default_action = cfg.get("default_action", "forward_default")
    default_port = cfg.get("default_backend_port")

    # ── R0: must be a TCP/<tls_port> TLS handshake ClientHello ──────────
    if not _has_layer(packet, "Ether") or not _has_layer(packet, "IP"):
        return _drop(new_state, "R0: missing Ethernet/IPv4")
    if _tcp_dport(packet) != tls_port:
        return _drop(new_state, "R0: not TCP TLS port")
    raw = _tls_payload_bytes(packet)
    parsed = _parse_clienthello(raw, max_prefix, max_ext, case_norm)
    if parsed is None or not parsed.is_clienthello:
        return _drop(new_state, "R0: not a TLS ClientHello handshake record")

    # ── R1 / R5-malformed: ¬sni_well_formed handling ───────────────────
    if not parsed.well_formed:
        if malformed_handling == "strict_drop":
            return _drop(new_state, f"R1: malformed ({parsed.reason})")
        return _default(packet, new_state, default_action, default_port)

    # ── classify ────────────────────────────────────────────────────────
    name_key = _name_key(parsed.host_name, breadth)
    if case_norm:
        name_key = name_key.lower()
    entry = _classify(name_key, new_state)

    if entry is None:
        return _default(packet, new_state, default_action, default_port)

    action = entry["action"]
    if action == "block":                                   # R2
        return _drop(new_state, f"R2: blocklisted SNI ({name_key})")
    if action == "route":                                   # R3 — VIP preserved
        out = _l3_forward(packet, int(entry["egress_port"]), entry, rewrite_dst=False)
        return StepResult(output_packets=out, new_state=new_state, decision="forward",
                          invariant_log=[("classification", f"route {name_key}->p{entry['egress_port']}")])
    if action == "rewrite":                                 # R4 — DNAT
        out = _l3_forward(packet, int(entry["egress_port"]), entry, rewrite_dst=True)
        return StepResult(output_packets=out, new_state=new_state, decision="forward",
                          invariant_log=[("classification", f"rewrite {name_key}->{entry.get('backend_ip')}")])
    return _drop(new_state, f"unknown action {action!r}")
