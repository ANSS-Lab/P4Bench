"""Python oracle for benchmark/relocate/dns_lb_disc.

Implements P-DNSLoadBalancer's rule sequence under the
task's seed:

  - R0   non-DNS-query drop      (not UDP/${dns_udp_port}, or QR!=0, or QDCOUNT<1)
  - R1   malformed strict drop   (QNAME unterminated within max_label_count,
                                   a §4.1.4 compression pointer / reserved
                                   label type, or a label > 63 octets;
                                   active when malformed_handling == strict_drop)
  - R2   classify -> block       (matched class action == block; dormant at this
                                   seed — action_breadth == route_rewrite)
  - R3   classify -> route       (L3 forward: MAC rewrite + TTL-- + IPv4 csum;
                                   anycast VIP destination preserved)
  - R4   classify -> rewrite     (DNAT: ipv4.dst = backend_ip + IPv4 csum +
                                   UDP csum)
  - R5   default catch-all       (no class match, or malformed under
                                   lax_default -> default_action)

The oracle walks the RAW DNS bytes (UDP payload) itself — the length-
prefixed RFC 1035 §3.1 label sequence — rather than a decoded name, so it
detects malformed inputs (pointers, over-bound, over-long labels) exactly
the way a bounded data-plane parser must, and so it never depends on
Scapy's decoder for adversarial inputs.

Per the parametric-source contract: every parameter
named in the pattern's `mutation_operators` surface is read from `state`
at runtime (from `state["config"]` for scalars and
`state["name_class_backend_entries"]` for the table). Seed values never
enter the module as source-level constants — this is what lets
parameter rebinding reuse the same audited oracle.

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


def _udp_dport(packet) -> Optional[int]:
    return _field(packet, "UDP", "dport")


def _raw_dns_bytes(packet) -> Optional[bytes]:
    """Return the raw DNS message bytes (the UDP payload), or None.

    Works for Scapy packets (well-formed DNSQuery layer OR a Raw payload
    carrying crafted/malformed DNS bytes) and for dict-shaped audit
    inputs that carry a `dns_raw_hex` field on a UDP/DNSQuery layer."""
    if hasattr(packet, "haslayer") and packet.haslayer("UDP"):
        try:
            return bytes(packet["UDP"].payload)
        except Exception:
            return None
    if isinstance(packet, dict):
        for key in ("DNSQuery", "UDP", "Raw"):
            layer = packet.get(key) or packet.get("_layers", {}).get(key)
            if layer and "dns_raw_hex" in layer:
                return bytes.fromhex(layer["dns_raw_hex"])
    return None


# ──────────────────────────────────────────────────────────────────────
# DNS message parsing (RFC 1035 §4.1.1 / §4.1.2 / §3.1) over raw bytes
# ──────────────────────────────────────────────────────────────────────

@dataclass
class DnsParse:
    qr: int
    qdcount: int
    labels: List[bytes]            # the parsed QNAME labels (lowercased iff case_normalization)
    qtype: Optional[int]
    well_formed: bool
    reason: str = ""


def _parse_dns(raw: bytes, max_label_count: int, case_normalization: bool) -> Optional[DnsParse]:
    """Parse the DNS header + first question's QNAME/QTYPE from raw bytes,
    enforcing the RFC 1035 §3.1 limits and the bounded label walk.

    Returns None if the buffer is too short to even hold the 12-byte
    header (R0 territory). Otherwise returns a DnsParse whose
    `well_formed` flag reflects §3.1/§4.1.4 validity within
    `max_label_count`."""
    if raw is None or len(raw) < 12:
        return None
    flags = int.from_bytes(raw[2:4], "big")
    qr = (flags >> 15) & 0x1
    qdcount = int.from_bytes(raw[4:6], "big")

    labels: List[bytes] = []
    off = 12
    well_formed = True
    reason = ""
    qtype: Optional[int] = None
    terminated = False
    for _ in range(max_label_count + 1):     # +1 to allow seeing the root terminator at the bound
        if off >= len(raw):
            well_formed = False
            reason = "QNAME runs past end of buffer (truncated)"
            break
        length = raw[off]
        if length == 0:                      # zero-length root label — name terminates
            off += 1
            terminated = True
            break
        if (length & 0xC0) != 0:             # §4.1.4 pointer (0xC0) or reserved label type (0x40/0x80)
            well_formed = False
            reason = "QNAME label-length octet has high bit(s) set (compression pointer / reserved)"
            break
        if length > 63:                      # §3.1 — unreachable with high bits clear, kept explicit
            well_formed = False
            reason = "QNAME label longer than 63 octets"
            break
        if len(labels) >= max_label_count:   # would exceed the parser depth bound
            well_formed = False
            reason = "QNAME exceeds max_label_count labels before root terminator"
            break
        label = raw[off + 1: off + 1 + length]
        if len(label) < length:
            well_formed = False
            reason = "QNAME label runs past end of buffer (truncated)"
            break
        labels.append(label.lower() if case_normalization else label)
        off += 1 + length
    else:
        # loop exhausted without break: name did not terminate within the bound
        well_formed = False
        reason = "QNAME did not terminate within max_label_count labels"

    if well_formed and terminated:
        # QTYPE follows the root terminator (RFC 1035 §4.1.2)
        if off + 2 <= len(raw):
            qtype = int.from_bytes(raw[off:off + 2], "big")
        else:
            well_formed = False
            reason = "QTYPE runs past end of buffer (truncated)"

    return DnsParse(qr=qr, qdcount=qdcount, labels=labels,
                    qtype=qtype, well_formed=well_formed, reason=reason)


def _name_key(labels: List[bytes], breadth: str) -> str:
    """Derive the classification name-key from the parsed labels under the
    configured match breadth. Labels are dotted, lowercased iff the parse
    already case-normalised them."""
    dotted = ".".join(l.decode("latin-1") for l in labels)
    parts = dotted.split(".") if dotted else []
    if breadth == "tld_only":
        return parts[-1] if parts else ""
    if breadth == "suffix_2label":
        return ".".join(parts[-2:]) if len(parts) >= 2 else dotted
    return dotted                            # full_qname


def _classify(name_key: str, qtype: Optional[int], state: Dict[str, Any]
              ) -> Optional[Dict[str, Any]]:
    cfg = state.get("config", {})
    qtype_match = bool(cfg.get("qtype_match_enabled", False))
    case_norm = bool(cfg.get("case_normalization", False))
    breadth = cfg.get("name_match_breadth", "suffix_2label")
    for e in state.get("name_class_backend_entries", []):
        ent_key = _name_key([p.encode() for p in str(e["name_pattern"]).split(".")], breadth)
        if case_norm:
            ent_key = ent_key.lower()
        if ent_key != name_key:
            continue
        if qtype_match and int(e.get("qtype", 0)) != int(qtype if qtype is not None else -1):
            continue
        return e
    return None


# ──────────────────────────────────────────────────────────────────────
# Output construction
# ──────────────────────────────────────────────────────────────────────

def _l3_forward(packet, egress_port: int, entry: Dict[str, Any], rewrite_dst: bool):
    """Build the egress packet for the route (R3) / rewrite (R4) / default
    forward path: MAC rewrite, TTL--, IPv4 (and on rewrite, UDP) checksum
    recompute. The DNS payload is left byte-for-byte unmodified."""
    out = packet.copy() if hasattr(packet, "copy") else packet
    try:
        if _has_layer(out, "Ether"):
            out["Ether"].src = entry["src_mac"]
            out["Ether"].dst = entry["backend_mac"]
        if _has_layer(out, "IP"):
            if rewrite_dst and entry.get("backend_ip") not in (None, "none"):
                out["IP"].dst = entry["backend_ip"]
            out["IP"].ttl = max(int(out["IP"].ttl) - 1, 0)
            # Force Scapy to recompute the IPv4 (and UDP) checksums on rebuild.
            if hasattr(out["IP"], "chksum"):
                del out["IP"].chksum
            if rewrite_dst and _has_layer(out, "UDP") and hasattr(out["UDP"], "chksum"):
                del out["UDP"].chksum
        # Re-serialise so deleted checksums are recomputed.
        if hasattr(out, "build"):
            out = out.__class__(bytes(out))
    except Exception:
        pass
    return {egress_port: [out]}


def _drop(state, reason: str) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("decision", f"drop: {reason}")])


# ──────────────────────────────────────────────────────────────────────
# step() — oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    """Execute one packet step under P-DNSLoadBalancer's rules.

    `state` carries:
      - config:                     dict of scalar seed parameters
                                    (dns_udp_port, max_label_count,
                                     name_match_breadth, qtype_match_enabled,
                                     action_breadth, malformed_handling,
                                     default_action, default_backend_port,
                                     case_normalization, local_vip, ...)
      - name_class_backend_entries: the classification table rows
    """
    cfg = state.get("config", {})
    new_state = state                                     # stateless pattern
    dns_port = int(cfg.get("dns_udp_port", 53))
    max_labels = int(cfg.get("max_label_count", 4))
    case_norm = bool(cfg.get("case_normalization", False))
    breadth = cfg.get("name_match_breadth", "suffix_2label")
    malformed_handling = cfg.get("malformed_handling", "lax_default")
    default_action = cfg.get("default_action", "forward_default")
    default_port = cfg.get("default_backend_port")

    # ── R0: must be a UDP/<dns_port> DNS *query* (QR=0, QDCOUNT>=1) ──────
    if not _has_layer(packet, "Ether") or not _has_layer(packet, "IP"):
        return _drop(new_state, "R0: missing Ethernet/IPv4")
    if _udp_dport(packet) != dns_port:
        return _drop(new_state, "R0: not UDP DNS port")
    raw = _raw_dns_bytes(packet)
    parsed = _parse_dns(raw, max_labels, case_norm)
    if parsed is None:
        return _drop(new_state, "R0: UDP payload too short for a DNS header")
    if parsed.qr != 0:
        return _drop(new_state, "R0: not a query (QR=1)")
    if parsed.qdcount < 1:
        return _drop(new_state, "R0: QDCOUNT < 1 (no question)")

    # ── R1 / R5-malformed: malformed QNAME handling ─────────────────────
    if not parsed.well_formed:
        if malformed_handling == "strict_drop":
            return _drop(new_state, f"R1: malformed ({parsed.reason})")
        # lax_default → fall through to R5 default
        return _default(packet, new_state, default_action, default_port)

    # ── classify ────────────────────────────────────────────────────────
    name_key = _name_key(parsed.labels, breadth)
    if case_norm:
        name_key = name_key.lower()
    entry = _classify(name_key, parsed.qtype, new_state)

    if entry is None:
        # R5 default catch-all
        return _default(packet, new_state, default_action, default_port)

    action = entry["action"]
    if action == "block":                                  # R2
        return _drop(new_state, f"R2: blocklisted name-class ({name_key})")
    if action == "route":                                  # R3 — anycast VIP preserved
        out = _l3_forward(packet, int(entry["egress_port"]), entry, rewrite_dst=False)
        return StepResult(output_packets=out, new_state=new_state, decision="forward",
                          invariant_log=[("classification", f"route {name_key}->p{entry['egress_port']}")])
    if action == "rewrite":                                # R4 — DNAT
        out = _l3_forward(packet, int(entry["egress_port"]), entry, rewrite_dst=True)
        return StepResult(output_packets=out, new_state=new_state, decision="forward",
                          invariant_log=[("classification", f"rewrite {name_key}->{entry.get('backend_ip')}")])
    return _drop(new_state, f"unknown action {action!r}")


def _default(packet, state, default_action, default_port) -> StepResult:
    """R5 catch-all: forward to the default backend (L3 forward, VIP
    preserved) or drop, per default_action."""
    if default_action == "forward_default" and default_port is not None:
        # Default forward keeps the envelope well-formed (TTL--, IPv4 csum);
        # no MAC rewrite entry is configured, so MACs are left as received.
        out = packet.copy() if hasattr(packet, "copy") else packet
        try:
            if _has_layer(out, "IP"):
                out["IP"].ttl = max(int(out["IP"].ttl) - 1, 0)
                if hasattr(out["IP"], "chksum"):
                    del out["IP"].chksum
            if hasattr(out, "build"):
                out = out.__class__(bytes(out))
        except Exception:
            pass
        return StepResult(output_packets={int(default_port): [out]},
                          new_state=state, decision="forward",
                          invariant_log=[("classification", "R5 default forward")])
    return _drop(state, "R5: default drop (no class match)")
