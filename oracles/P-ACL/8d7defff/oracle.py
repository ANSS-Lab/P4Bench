"""Pure-Python oracle for P-ACL (stateless wildcard/priority classification).

Implements the pattern's R0/R1/R2/R3/R4/R5 rule sequence and the
priority_correctness / default_action_correctness / permit_header_preservation
invariants in executable form. Used at test-generation time
and at audit time to derive expected per-test outputs from the pattern's rule set.

PARAMETRIC-SOURCE CONTRACT.

Every mutable knob is read from the runtime `state` dict — never
baked as a module-level constant. The seed's values enter the module
only at evaluation time, via `step(pkt, ingress_port, state)`. Keys:

  rules                 : list[dict]   — each entry: priority, action,
                                         and any subset of
                                         {ipv4_src, ipv4_dst, proto,
                                          sport, dport} as ternary match
                                         constraints. Missing field = any.
  match_field_breadth   : 'tuple5' | 'tuple5_vrf' | 'tuple5_vrf_vlan'
                        | 'tuple5_vrf_vlan_dscp'
  default_action        : 'permit' | 'deny'
  action_breadth        : 'permit_deny' | 'permit_deny_mark'
                        | 'permit_deny_mark_redirect'
  faithfulness          : 'D5.0_first_match_priority' | 'D5.1_partitioned_tcam'
                        | 'D5.2_compressed_rules'
  port_decoder          : list[(dst_cidr, egress_port, host_mac)]
                          — downstream port-decoder (R3 permit branch).
  port_macs             : dict[int → mac] — per-egress source MAC.

Stateless: step() is a pure function of (packet, in_port, state).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _cidr_to_mask(prefix: str) -> tuple[int, int]:
    """Return (network_int, mask_int) from 'a.b.c.d/N'."""
    if "/" in prefix:
        net, n = prefix.split("/")
        n = int(n)
    else:
        net = prefix
        n = 32
    return _ip_to_int(net), (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0


def _ipv4_match(addr: str, cidr: Optional[str]) -> bool:
    if cidr is None:
        return True
    net, mask = _cidr_to_mask(cidr)
    return (_ip_to_int(addr) & mask) == (net & mask)


def _eq_or_any(value, constraint) -> bool:
    return constraint is None or value == constraint


# ────────────────────────────────────────────────────────────────────────────
# Step result
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    reason: str
    # When admitted: the egress decision the downstream forwarder produces.
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None
    next_hop_mac_src: Optional[str] = None
    ttl_decrement: int = 0
    # Invariant witnesses (audit-only). Populated for every step so the
    # oracle audit's invariant_coverage check can see clauses move.
    invariant_log: list = field(default_factory=list)
    # The (priority, action) of the rule that fired; None on table miss.
    matched_priority: Optional[int] = None
    matched_action: Optional[str] = None


# ────────────────────────────────────────────────────────────────────────────
# Rule matching
# ────────────────────────────────────────────────────────────────────────────

def _rule_admits(rule: dict, l4: dict) -> bool:
    """True iff the rule's ternary match_spec admits the packet's 5-tuple."""
    if not _ipv4_match(l4["src"], rule.get("ipv4_src")):
        return False
    if not _ipv4_match(l4["dst"], rule.get("ipv4_dst")):
        return False
    if not _eq_or_any(l4["proto"], rule.get("proto")):
        return False
    if not _eq_or_any(l4["sport"], rule.get("sport")):
        return False
    if not _eq_or_any(l4["dport"], rule.get("dport")):
        return False
    return True


def _highest_priority_match(rules: list[dict], l4: dict) -> Optional[dict]:
    best = None
    best_p = -1
    for r in rules:
        if _rule_admits(r, l4):
            p = int(r["priority"])
            if p > best_p:
                best = r
                best_p = p
    return best


# ────────────────────────────────────────────────────────────────────────────
# Port-decoder lookup
# ────────────────────────────────────────────────────────────────────────────

def _port_decoder_lookup(dst_ip: str, port_decoder: list, port_macs: dict):
    """LPM lookup over the downstream port-decoder. Returns (port, host_mac) or None."""
    best = None
    best_len = -1
    for entry in port_decoder:
        cidr = entry["cidr"]
        n = int(cidr.split("/")[1]) if "/" in cidr else 32
        if _ipv4_match(dst_ip, cidr) and n > best_len:
            best = entry
            best_len = n
    if best is None:
        return None
    return best["egress_port"], best["host_mac"]


# ────────────────────────────────────────────────────────────────────────────
# Step function
# ────────────────────────────────────────────────────────────────────────────

def step(scapy_pkt, in_port: int, state: dict) -> StepResult:
    """Execute one packet step under the P-ACL rule sequence."""
    from scapy.all import IP, TCP, UDP, ICMP

    rules = state["rules"]
    default_action = state.get("default_action", "deny")
    port_decoder = state.get("port_decoder", [])
    port_macs = state.get("port_macs", {})

    # ── R0/R0b: non-IPv4 frames follow the default policy. ──────────────────
    if IP not in scapy_pkt:
        if default_action == "permit":
            log = [("default_action_correctness",
                    {"default_action": "permit", "decision": "forward_unreachable"})]
            # Non-IPv4 has no IPv4 destination — port-decoder can't map it.
            # Per R3's port-decoder default_action=drop fallthrough, this is
            # an unreachable destination. Treat as drop in this seed.
            return StepResult(admitted=False, reason="drop_non_ipv4_default_permit_unmappable",
                              invariant_log=log)
        return StepResult(admitted=False, reason="drop_non_ipv4_default_deny",
                          invariant_log=[("default_action_correctness",
                                          {"default_action": "deny", "decision": "drop"})])

    ip = scapy_pkt[IP]
    proto = int(ip.proto)
    if TCP in scapy_pkt:
        sport, dport = int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
    elif UDP in scapy_pkt:
        sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
    else:
        sport, dport = 0, 0
    l4 = {"src": ip.src, "dst": ip.dst, "proto": proto, "sport": sport, "dport": dport}

    # ── R1/R2/R3/R4 (combined): find the highest-priority matching rule. ────
    matched = _highest_priority_match(rules, l4)

    if matched is None:
        # ── R5/R5b: table miss → ${default_action}. ─────────────────────────
        log = [("default_action_correctness",
                {"default_action": default_action, "decision": "drop" if default_action == "deny" else "forward"}),
               ("priority_correctness", {"matched": None, "candidates": 0})]
        if default_action == "deny":
            return StepResult(admitted=False, reason="drop_default_deny_no_match",
                              invariant_log=log)
        # default_action == permit on table miss
        admitted = _try_forward(ip, port_decoder, port_macs)
        if admitted is None:
            return StepResult(admitted=False, reason="drop_permit_unmappable_dst",
                              invariant_log=log)
        port, dst_mac, src_mac = admitted
        return StepResult(admitted=True, reason="admit_default_permit_no_match",
                          output_port=port,
                          next_hop_mac_dst=dst_mac, next_hop_mac_src=src_mac,
                          ttl_decrement=1, invariant_log=log,
                          matched_priority=None, matched_action=None)

    # ── R2: deny ────────────────────────────────────────────────────────────
    action = matched["action"]
    matched_p = int(matched["priority"])
    candidates = sum(1 for r in rules if _rule_admits(r, l4))
    log = [
        ("priority_correctness",
         {"matched_priority": matched_p, "candidates": candidates}),
        ("no_priority_ambiguity",
         {"ties_at_matched_priority":
              sum(1 for r in rules
                  if _rule_admits(r, l4) and int(r["priority"]) == matched_p)}),
    ]

    if action == "deny":
        return StepResult(admitted=False, reason="drop_deny_match",
                          invariant_log=log,
                          matched_priority=matched_p, matched_action="deny")

    # ── R1: permit → forward via the downstream port-decoder. ───────────────
    if action == "permit":
        admitted = _try_forward(ip, port_decoder, port_macs)
        if admitted is None:
            return StepResult(admitted=False, reason="drop_permit_unmappable_dst",
                              invariant_log=log,
                              matched_priority=matched_p, matched_action="permit")
        port, dst_mac, src_mac = admitted
        log.append(("permit_header_preservation",
                    {"src_preserved": True, "dst_preserved": True,
                     "dscp_preserved": True, "totalLen_preserved": True}))
        return StepResult(admitted=True, reason="admit_permit_match",
                          output_port=port,
                          next_hop_mac_dst=dst_mac, next_hop_mac_src=src_mac,
                          ttl_decrement=1, invariant_log=log,
                          matched_priority=matched_p, matched_action="permit")

    # ── R3 (mark) and R4 (redirect) — not exercised at action_breadth=permit_deny.
    # Kept for parametric-source correctness across the P-ACL operator surface.
    if action == "mark":
        admitted = _try_forward(ip, port_decoder, port_macs)
        if admitted is None:
            return StepResult(admitted=False, reason="drop_mark_unmappable_dst",
                              invariant_log=log,
                              matched_priority=matched_p, matched_action="mark")
        port, dst_mac, src_mac = admitted
        log.append(("mark_only_modifies_dscp", {"dscp_rewritten": True}))
        return StepResult(admitted=True, reason="admit_mark_match",
                          output_port=port,
                          next_hop_mac_dst=dst_mac, next_hop_mac_src=src_mac,
                          ttl_decrement=1, invariant_log=log,
                          matched_priority=matched_p, matched_action="mark")
    if action == "redirect":
        port = int(matched.get("egress_port", 0))
        dst_mac = matched.get("dst_mac", "ff:ff:ff:ff:ff:ff")
        src_mac = port_macs.get(port, "00:00:00:00:00:00")
        log.append(("redirect_routes_to_named_port", {"egress_port": port}))
        return StepResult(admitted=True, reason="admit_redirect_match",
                          output_port=port,
                          next_hop_mac_dst=dst_mac, next_hop_mac_src=src_mac,
                          ttl_decrement=1, invariant_log=log,
                          matched_priority=matched_p, matched_action="redirect")

    return StepResult(admitted=False, reason=f"drop_unknown_action_{action}",
                      invariant_log=log,
                      matched_priority=matched_p, matched_action=action)


def _try_forward(ip, port_decoder, port_macs):
    """Apply the downstream port-decoder. Returns (port, dst_mac, src_mac) or None."""
    found = _port_decoder_lookup(ip.dst, port_decoder, port_macs)
    if found is None:
        return None
    port, host_mac = found
    src_mac = port_macs.get(port, "00:00:00:00:00:00")
    return port, host_mac, src_mac


def reset():
    """No-op: P-ACL is stateless."""
    return
