"""Composed oracle for P-RouterACL (IPv4 unicast router ∘ stateless ACL).

Implements the pattern's two-stage pipeline — an ACL classification stage
that yields a verdict ∈ {permit, deny, mark, redirect} (or the
${acl_default_action} on a classifier miss), feeding an IPv4 longest-prefix
forwarder for the {permit, mark} verdicts. The composition's load-bearing
contract is STAGE ORDERING: a denied packet is never routed (R5), a
redirect verdict overrides the FIB egress (R6), and a mark verdict rewrites
DSCP then routes (R7). See patterns/P-RouterACL/pattern.yaml.

The classification ground truth reuses P-ACL's priority-match semantics and
the routed-path ground truth reuses P-IPv4Routing's LPM/TTL/L2-rewrite
semantics; this module fuses the two and adds the verdict→dispatch glue.

PARAMETRIC-SOURCE CONTRACT.

Every mutable knob is read from the runtime `state` dict — never baked
as a module-level constant. The seed's values enter the module only at
evaluation time, via `step(pkt, ingress_port, state)`. Keys in state:

  acl_rules            : list[dict] — each: priority, action, and any subset
                         of {ipv4_src, ipv4_dst, proto, sport, dport} as
                         ternary constraints (missing field = any). For
                         action=='redirect': egress_port (+ optional
                         redirect_mac). For action=='mark': dscp.
  acl_default_action   : 'permit' | 'deny'
  action_breadth       : 'permit_deny' | 'permit_deny_mark'
                       | 'permit_deny_mark_redirect'
  match_field_breadth  : 'tuple5' | 'tuple5_vrf' | ...
  routes               : list[dict] — each: prefix, prefix_len, port,
                         port_mac, nexthop_mac.
  martian_filter_enabled : bool
  multipath_mode       : 'none' | 'ecmp_hash_3tuple' | 'ecmp_hash_5tuple'

TTL convention (binding, inherited from the P-IPv4Routing anchor): gate
`ttl > 0` — a packet with ttl == 0 drops; a packet with ttl == 1 forwards
with egress ttl == 0. This subsumes benchmark/redesign/ipv4_routing_anchor.

Stateless: step() is a pure function of (packet, in_port, state). The
StepResult exposes both the P-ACL-style attributes (admitted / output_port /
next_hop_mac_* / ttl_decrement / dscp_out) that the test generator reads and
a `decision` attribute ('forward'/'drop') that the oracle audit `_compare`
reads.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ────────────────────────────────────────────────────────────────────────────
# Address helpers
# ────────────────────────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in str(ip).split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _cidr_to_mask(prefix: str) -> tuple[int, int]:
    if "/" in prefix:
        net, n = prefix.split("/")
        n = int(n)
    else:
        net, n = prefix, 32
    return _ip_to_int(net), (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0


def _ipv4_match(addr: str, cidr: Optional[str]) -> bool:
    if cidr is None:
        return True
    net, mask = _cidr_to_mask(cidr)
    return (_ip_to_int(addr) & mask) == (net & mask)


def _eq_or_any(value, constraint) -> bool:
    return constraint is None or value == constraint


def _is_martian_src(src: str) -> bool:
    s = _ip_to_int(src)

    def inb(prefix, plen):
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        return (s & mask) == (_ip_to_int(prefix) & mask)

    return (inb("127.0.0.0", 8) or inb("0.0.0.0", 8)
            or inb("224.0.0.0", 4) or src == "255.255.255.255")


# ────────────────────────────────────────────────────────────────────────────
# Step result
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    reason: str
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None
    next_hop_mac_src: Optional[str] = None
    ttl_decrement: int = 0
    dscp_out: Optional[int] = None        # set only on a mark-then-route firing
    l2_rewritten: bool = False            # False on the redirect path (R6)
    invariant_log: list = field(default_factory=list)
    matched_priority: Optional[int] = None
    matched_action: Optional[str] = None

    @property
    def decision(self) -> str:            # for the oracle audit's comparison
        return "forward" if self.admitted else "drop"


# ────────────────────────────────────────────────────────────────────────────
# ACL classification (reused from P-ACL)
# ────────────────────────────────────────────────────────────────────────────

def _rule_admits(rule: dict, l4: dict) -> bool:
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


def _highest_priority_match(rules: list, l4: dict) -> Optional[dict]:
    best, best_p = None, -1
    for r in rules:
        if _rule_admits(r, l4):
            p = int(r["priority"])
            if p > best_p:
                best, best_p = r, p
    return best


# ────────────────────────────────────────────────────────────────────────────
# FIB lookup (reused from P-IPv4Routing)
# ────────────────────────────────────────────────────────────────────────────

def _prefix_net(r: dict) -> str:
    """Bare network address of a route, tolerating a 'a.b.c.d/N' prefix."""
    p = str(r["prefix"])
    return p.split("/")[0] if "/" in p else p


def _lpm_match(dst: str, routes: list) -> Optional[dict]:
    d = _ip_to_int(dst)
    best, best_len = None, -1
    for r in routes:
        plen = int(r["prefix_len"])
        mask = ((1 << plen) - 1) << (32 - plen) if plen else 0
        if (d & mask) == (_ip_to_int(_prefix_net(r)) & mask) and plen > best_len:
            best, best_len = r, plen
    return best


def _is_directed_broadcast(dst: str, routes: list) -> bool:
    d = _ip_to_int(dst)
    for r in routes:
        plen = int(r["prefix_len"])
        if plen >= 32 or plen == 0:
            continue
        net = _ip_to_int(_prefix_net(r)) & (((1 << plen) - 1) << (32 - plen))
        if d == (net | ((1 << (32 - plen)) - 1)):
            return True
    return False


# ────────────────────────────────────────────────────────────────────────────
# Step function — the composed R0..R10 sequence
# ────────────────────────────────────────────────────────────────────────────

def step(scapy_pkt, in_port: int = 1, state: Optional[dict] = None) -> StepResult:
    from scapy.all import IP, TCP, UDP

    state = state or {}
    acl_rules = state.get("acl_rules", [])
    acl_default = state.get("acl_default_action", "permit")
    action_breadth = state.get("action_breadth", "permit_deny")
    routes = state.get("routes", [])
    martian_on = bool(state.get("martian_filter_enabled", False))

    # ── R0: non-IPv4 → drop ─────────────────────────────────────────────────
    if IP not in scapy_pkt:
        return StepResult(False, "R0_non_ipv4_drop")

    ip = scapy_pkt[IP]
    version = int(getattr(ip, "version", 4))
    ihl = int(getattr(ip, "ihl", 5) or 5)
    ttl = int(getattr(ip, "ttl", 0))
    src, dst = ip.src, ip.dst
    proto = int(ip.proto)
    if TCP in scapy_pkt:
        sport, dport = int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
    elif UDP in scapy_pkt:
        sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)
    else:
        sport, dport = 0, 0
    l4 = {"src": src, "dst": dst, "proto": proto, "sport": sport, "dport": dport}

    # ── R1: invalid IPv4 header → drop ──────────────────────────────────────
    if version != 4 or ihl < 5:
        return StepResult(False, "R1_invalid_header_drop")

    # ── R2: TTL exhausted (gate ttl > 0; ttl==1 forwards to 0) ──────────────
    if ttl <= 0:
        return StepResult(False, "R2_ttl_exhausted_drop")

    # ── R3: limited-broadcast dst → drop ────────────────────────────────────
    if dst == "255.255.255.255":
        return StepResult(False, "R3_limited_broadcast_dst_drop")

    # ── R4: martian source (gated) → drop ───────────────────────────────────
    if martian_on and _is_martian_src(src):
        return StepResult(False, "R4_martian_src_drop")

    # ── ACL classification: verdict = matched action, or default on miss ────
    matched = _highest_priority_match(acl_rules, l4)
    candidates = sum(1 for r in acl_rules if _rule_admits(r, l4))
    if matched is not None:
        verdict = matched["action"]
        matched_p = int(matched["priority"])
        ties = sum(1 for r in acl_rules
                   if _rule_admits(r, l4) and int(r["priority"]) == matched_p)
        log = [("priority_correctness",
                {"matched_priority": matched_p, "candidates": candidates}),
               ("no_priority_ambiguity", {"ties_at_matched_priority": ties})]
    else:
        verdict = acl_default
        matched_p = None
        log = [("default_action_correctness",
                {"default_action": acl_default, "candidates": 0})]

    # ── R5: deny verdict → drop (never routed) ──────────────────────────────
    if verdict == "deny":
        log.append(("acl_precedes_routing", {"denied": True, "routed": False}))
        return StepResult(False, "R5_acl_deny", invariant_log=log,
                          matched_priority=matched_p, matched_action="deny")

    # ── R6: redirect verdict → policy port, overrides FIB, no L2 rewrite ────
    if verdict == "redirect" and action_breadth == "permit_deny_mark_redirect":
        port = int(matched.get("egress_port", 0))
        dst_mac = matched.get("redirect_mac")     # left for the policy waypoint
        log.append(("redirect_overrides_fib", {"egress_port": port}))
        return StepResult(True, "R6_acl_redirect", output_port=port,
                          next_hop_mac_dst=dst_mac, next_hop_mac_src=None,
                          ttl_decrement=1, l2_rewritten=False,
                          invariant_log=log,
                          matched_priority=matched_p, matched_action="redirect")

    # ── {permit, mark} → routing stage ──────────────────────────────────────
    # R9: directed-broadcast dst on an admitted packet → drop
    if _is_directed_broadcast(dst, routes):
        return StepResult(False, "R9_directed_broadcast_dst_drop",
                          invariant_log=log,
                          matched_priority=matched_p, matched_action=verdict)

    route = _lpm_match(dst, routes)
    # R10: admitted but unroutable → drop
    if route is None:
        log.append(("acl_precedes_routing", {"denied": False, "routed": False}))
        return StepResult(False, "R10_no_route_drop", invariant_log=log,
                          matched_priority=matched_p, matched_action=verdict)

    # R7/R8: route the packet (singleton next-hop at multipath none → i=0)
    dscp_out = None
    is_mark = (verdict == "mark"
               and action_breadth in ("permit_deny_mark",
                                       "permit_deny_mark_redirect"))
    if is_mark:
        dscp_out = int(matched.get("dscp", 0))
        log.append(("mark_then_route_single_checksum", {"dscp": dscp_out}))
        log.append(("mark_only_modifies_dscp", {"dscp_rewritten": True}))
        reason = "R7_acl_mark_then_route"
    else:
        log.append(("permit_does_not_mark", {"dscp_preserved": True}))
        log.append(("ip_addr_preservation", {"src_preserved": True,
                                              "dst_preserved": True}))
        reason = "R8_acl_permit_route"
    log.append(("ttl_quantum_one", {"decrement": 1}))
    log.append(("lpm_longest_match_correctness",
                {"prefix": f"{route['prefix']}/{route['prefix_len']}"}))
    log.append(("ether_rewrite_correctness",
                {"src": route["port_mac"], "dst": route["nexthop_mac"]}))

    return StepResult(True, reason,
                      output_port=int(route["port"]),
                      next_hop_mac_dst=route["nexthop_mac"],
                      next_hop_mac_src=route["port_mac"],
                      ttl_decrement=1, dscp_out=dscp_out, l2_rewritten=True,
                      invariant_log=log,
                      matched_priority=matched_p, matched_action=verdict)


def reset():
    """No-op: P-RouterACL is stateless (both stages)."""
    return
