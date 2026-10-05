"""Python oracle for benchmark/composition/natacl_anchor.

Implements P-NATACL — the IPv4 NAPT ∘ stateless TCAM ACL COMPOSITE — at the
task's seed (faithfulness = D5.0_static_nat_permit_acl):

  - static control-plane NAT mappings (no data-plane allocation),
  - a small permit/deny ACL with default = permit,
  - acl_match_stage = internal_side (the ACL classifies on the internal
    addresses both directions: the original src tuple outbound, the
    de-NAT-ed dst tuple inbound),
  - action_breadth = permit_deny (no DSCP mark at the anchor).

The composite chains the two audited halves' behaviour (P-ACL verdict ∘
P-NAT44 translation) under content-addressing — the ACL
verdict over the stage-selected tuple gates the NAT translation, with the
composition glue handling the three interactions neither half exhibits
alone:

  R1   non-IPv4 drop
  R2   non-TCP/UDP drop (NAPT scope, RFC 3022 §4)
  R3   OUTBOUND ACL DENY — drop BEFORE any NAT lookup/allocation
        (acl_precedes_nat_state); fires even when a mapping exists
  R4   OUTBOUND permit/mark + SNAT hit — apply optional DSCP mark + the
        stored SNAT rewrite, dec TTL, forward external
  R5   OUTBOUND permit/mark dynamic install (not reached at the static
        anchor) — allocate ext_port, install the pair, mark+SNAT, forward
  R6   OUTBOUND permit miss drop (static, or dynamic pool exhausted)
  R7   INBOUND wrong-dst drop (dst != public_ip)
  R8   INBOUND no-mapping default-deny drop (unsolicited)
  R9   INBOUND DNAT-then-ACL deny — DNAT, then the ACL denies the
        de-NAT-ed internal tuple → drop
  R10  INBOUND DNAT permit/mark — DNAT dst/dport back to the internal
        endpoint, optional mark, dec TTL, forward internal

The three load-bearing composite properties this oracle realises:
  * acl_precedes_nat_state — a DENIED outbound flow allocates no NAT
    binding (R3 drops before R5); at the static anchor no allocation
    happens at all, so the property holds trivially but is still exercised
    by the "deny a flow that HAS a mapping" test.
  * acl_match_stage_consistency — the ACL verdict is computed over the
    tuple named by acl_match_stage (internal_side here), the same stage
    both directions.
  * compound_rewrite_checksum_validity — when a mark fires alongside the
    NAT rewrite, a single checksum recompute covers both (no mark at the
    permit_deny anchor, so exercised only at +mark seeds).

Per the parametric-source contract: every parameter
named in the pattern's mutation_operators surface is read from `state`
(the entity tables + the scalar knobs under state["config"]) at runtime —
seed values never enter as source-level constants, so parameter
rebinding reuses this audited module without
regeneration. The module also accepts a 2-arg step(packet, ingress_port)
call (audit-harness convention) by falling back to the anchor default
config below.

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


PROTO_TCP = 6
PROTO_UDP = 17

INTERNAL_PORT_NAMES = {"s1.internal", "internal", 1}
EXTERNAL_PORT_NAMES = {"s1.external", "external", 2}


# ──────────────────────────────────────────────────────────────────────
# Anchor-band default config (used when step() is called without `state`,
# e.g. the audit harness's 2-arg call). Mirrors the seed binding exactly.
# ──────────────────────────────────────────────────────────────────────

ANCHOR_CONFIG: Dict[str, Any] = {
    "public_ip": "203.0.113.10",
    "internal_subnet": "192.168.1.0/24",
    "mode": "static",
    "acl_match_stage": "internal_side",
    "default_action": "permit",
    "action_breadth": "permit_deny",
    "port_pool_range": [10000, 65535],
    # NOTE: mapping_capacity / eviction_policy are NOT carried here. This static
    # NAT oracle never reads them — they are dynamic-NAT knobs whose operators
    # (shrink_mapping_capacity_4x, add_timeout_eviction, ...) REGENERATE a
    # different (dynamic-mapping) oracle rather than re-configuring this one
    # (variant-selectors). Keeping them in the static oracle's
    # config dict would falsely present them as config-read knobs to the audit's config-read check.
    # Static NAT pairs: (internal_ip, internal_port, proto) -> ext_port
    "static_mappings": [
        ["192.168.1.5", 5000, PROTO_UDP, 14000],
        ["192.168.1.5", 6000, PROTO_TCP, 15000],
        ["192.168.1.5", 7000, PROTO_UDP, 16000],
    ],
    # ACL rules: highest priority match wins. Missing field = wildcard.
    # action in {permit, deny, mark}; mark carries action_args.dscp.
    "rules": [
        {"priority": 100, "action": "deny",
         "ipv4_src": "192.168.1.5/32", "proto": PROTO_UDP, "sport": 7000},
    ],
    # Egress port names (NAT owns egress; the ACL never picks a port).
    "internal_port": "s1.internal",
    "external_port": "s1.external",
    # L2 rewrite peers (the downstream forwarder's next-hop MACs).
    "external_peer_mac": "00:00:00:00:08:08",   # h2 (external)
    "internal_peer_mac": "00:00:00:00:01:05",   # h1 (internal)
}


# ──────────────────────────────────────────────────────────────────────
# StepResult — oracle return shape
# ──────────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    admitted: bool
    reason: str
    side: Optional[str] = None             # "outbound" | "inbound"
    output_port: Optional[str] = None
    new_ip_src: Optional[str] = None
    new_ip_dst: Optional[str] = None
    new_l4_sport: Optional[int] = None
    new_l4_dport: Optional[int] = None
    new_dscp: Optional[int] = None
    ttl_decrement: int = 0
    new_eth_dst: Optional[str] = None
    # The (priority, action) of the ACL rule that fired; None on table miss.
    matched_priority: Optional[int] = None
    matched_action: Optional[str] = None
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _ip_in_subnet(ip: str, cidr: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


def _ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def _ipv4_match(addr: str, cidr: Optional[str]) -> bool:
    if cidr is None:
        return True
    net = ipaddress.ip_network(cidr, strict=False)
    return ipaddress.ip_address(addr) in net


def _eq_or_any(value, constraint) -> bool:
    return constraint is None or value == constraint


def _rule_admits(rule: dict, view: dict) -> bool:
    """True iff the rule's ternary match_spec admits the (stage-selected) view."""
    if not _ipv4_match(view["src"], rule.get("ipv4_src")):
        return False
    if not _ipv4_match(view["dst"], rule.get("ipv4_dst")):
        return False
    if not _eq_or_any(view["proto"], rule.get("proto")):
        return False
    if not _eq_or_any(view["sport"], rule.get("sport")):
        return False
    if not _eq_or_any(view["dport"], rule.get("dport")):
        return False
    return True


def _acl_verdict(rules: list, view: dict, default_action: str):
    """Highest-priority match over `view`. Returns (action, priority,
    n_candidates) — action is `default_action` (priority None) on a miss."""
    best = None
    best_p = -1
    candidates = 0
    for r in rules:
        if _rule_admits(r, view):
            candidates += 1
            p = int(r["priority"])
            if p > best_p:
                best, best_p = r, p
    if best is None:
        return default_action, None, candidates, None
    return best["action"], best_p, candidates, best


# ──────────────────────────────────────────────────────────────────────
# State construction (entity tables) from config
# ──────────────────────────────────────────────────────────────────────

def _build_tables(cfg: dict):
    """Build the SNAT/DNAT lookup tables from the static_mappings config."""
    public_ip = cfg["public_ip"]
    snat = {}   # (internal_ip, internal_port, proto) -> ext_port
    dnat = {}   # (public_ip, ext_port, proto) -> (internal_ip, internal_port)
    for i_ip, i_port, proto, ext_port in cfg.get("static_mappings", []):
        snat[(i_ip, int(i_port), int(proto))] = int(ext_port)
        dnat[(public_ip, int(ext_port), int(proto))] = (i_ip, int(i_port))
    return snat, dnat


def _internal_view_outbound(ip_src, ip_dst, proto, sport, dport):
    return {"src": ip_src, "dst": ip_dst, "proto": proto,
            "sport": sport, "dport": dport}


def _internal_view_inbound(ip_src, internal_ip, proto, sport, internal_port):
    # After DNAT the internal-side view has the internal endpoint in the
    # dst position; the external peer stays in the src position.
    return {"src": ip_src, "dst": internal_ip, "proto": proto,
            "sport": sport, "dport": internal_port}


# ──────────────────────────────────────────────────────────────────────
# Step function
# ──────────────────────────────────────────────────────────────────────

def step(scapy_pkt, ingress_port=1, state: Optional[dict] = None) -> StepResult:
    from scapy.all import IP, TCP, UDP

    cfg = ANCHOR_CONFIG if state is None else state.get("config", ANCHOR_CONFIG)
    public_ip = cfg["public_ip"]
    internal_subnet = cfg["internal_subnet"]
    rules = cfg.get("rules", [])
    default_action = cfg.get("default_action", "permit")
    action_breadth = cfg.get("action_breadth", "permit_deny")
    acl_match_stage = cfg.get("acl_match_stage", "internal_side")
    snat, dnat = _build_tables(cfg)

    internal = ingress_port in INTERNAL_PORT_NAMES or ingress_port == cfg.get("internal_port")
    external = ingress_port in EXTERNAL_PORT_NAMES or ingress_port == cfg.get("external_port")

    # ── R1: non-IPv4 → drop ────────────────────────────────────────────────
    if IP not in scapy_pkt:
        return StepResult(False, "drop_non_ipv4")
    # ── R2: non-TCP/UDP → drop ──────────────────────────────────────────────
    if TCP not in scapy_pkt and UDP not in scapy_pkt:
        return StepResult(False, "drop_non_l4")

    ip = scapy_pkt[IP]
    proto = int(ip.proto)
    if TCP in scapy_pkt:
        sport, dport = int(scapy_pkt[TCP].sport), int(scapy_pkt[TCP].dport)
    else:
        sport, dport = int(scapy_pkt[UDP].sport), int(scapy_pkt[UDP].dport)

    def _mark_dscp(rule):
        if action_breadth == "permit_deny_mark" and rule is not None \
                and rule.get("action") == "mark":
            return int(rule.get("action_args", {}).get("dscp", 0))
        return None

    # ── OUTBOUND (internal zone) ────────────────────────────────────────────
    if internal:
        src = ip.src
        if not _ip_in_subnet(src, internal_subnet):
            return StepResult(False, "drop_outbound_not_internal_subnet")

        # ACL verdict over the stage-selected tuple.
        if acl_match_stage == "wire_side":
            # Translated tuple (post-NAT). At the static anchor the ext_port
            # is known from the mapping; if unmapped, fall back to original.
            ext_port = snat.get((src, sport, proto))
            view = _internal_view_outbound(
                public_ip, ip.dst, proto,
                ext_port if ext_port is not None else sport, dport)
        else:  # internal_side
            view = _internal_view_outbound(src, ip.dst, proto, sport, dport)

        action, mp, cand, rule = _acl_verdict(rules, view, default_action)
        log = [
            ("acl_match_stage_consistency",
             {"stage": acl_match_stage, "view": view, "action": action}),
            ("priority_correctness", {"matched_priority": mp, "candidates": cand}),
            ("default_action_correctness",
             {"matched": mp is not None, "default_action": default_action}),
        ]

        # R3: deny BEFORE any NAT lookup/allocation.
        if action == "deny":
            log.append(("acl_precedes_nat_state",
                        {"denied": True, "allocated": False}))
            return StepResult(False, "drop_outbound_acl_deny",
                              side="outbound", matched_priority=mp,
                              matched_action="deny", invariant_log=log)

        # action ∈ {permit, mark} → proceed to NAT.
        key = (src, sport, proto)
        ext_port = snat.get(key)
        if ext_port is None and cfg.get("mode") == "dynamic":
            # R5 (dynamic install) — not reached at the static anchor.
            lo, hi = cfg.get("port_pool_range", [10000, 65535])
            in_use = {ep for (_p, ep, pr) in dnat if pr == proto}
            ext_port = next((p for p in range(int(lo), int(hi) + 1)
                             if p not in in_use), None)
            if ext_port is not None:
                snat[key] = ext_port
                dnat[(public_ip, ext_port, proto)] = (src, sport)
        if ext_port is None:
            # R6: permit but no mapping (static) / pool exhausted.
            return StepResult(False, "drop_outbound_miss",
                              side="outbound", matched_priority=mp,
                              matched_action=action, invariant_log=log)

        return StepResult(
            True, "admit_outbound", side="outbound",
            output_port=cfg.get("external_port", "s1.external"),
            new_ip_src=public_ip, new_l4_sport=ext_port,
            new_dscp=_mark_dscp(rule), ttl_decrement=1,
            new_eth_dst=cfg.get("external_peer_mac"),
            matched_priority=mp, matched_action=action, invariant_log=log)

    # ── INBOUND (external zone) ─────────────────────────────────────────────
    if external:
        dst = ip.dst
        # R7: wrong dst.
        if dst != public_ip:
            return StepResult(False, "drop_inbound_wrong_dst", side="inbound")
        # R8: no mapping (unsolicited) → default-deny, ACL not consulted.
        mapping = dnat.get((dst, dport, proto))
        if mapping is None:
            return StepResult(False, "drop_inbound_miss", side="inbound")
        internal_ip, internal_port = mapping

        # ACL verdict on the stage-selected tuple (de-NAT-ed for internal_side).
        if acl_match_stage == "wire_side":
            view = {"src": ip.src, "dst": dst, "proto": proto,
                    "sport": sport, "dport": dport}
        else:  # internal_side — classify on the de-NAT-ed tuple.
            view = _internal_view_inbound(ip.src, internal_ip, proto,
                                          sport, internal_port)
        action, mp, cand, rule = _acl_verdict(rules, view, default_action)
        log = [
            ("acl_match_stage_consistency",
             {"stage": acl_match_stage, "view": view, "action": action}),
            ("priority_correctness", {"matched_priority": mp, "candidates": cand}),
            ("bidirectional_translation",
             {"dnat_to": [internal_ip, internal_port]}),
        ]
        # R9: DNAT then ACL deny.
        if action == "deny":
            return StepResult(False, "drop_inbound_acl_deny", side="inbound",
                              matched_priority=mp, matched_action="deny",
                              invariant_log=log)
        # R10: DNAT permit/mark.
        return StepResult(
            True, "admit_inbound", side="inbound",
            output_port=cfg.get("internal_port", "s1.internal"),
            new_ip_dst=internal_ip, new_l4_dport=internal_port,
            new_dscp=_mark_dscp(rule), ttl_decrement=1,
            new_eth_dst=cfg.get("internal_peer_mac"),
            matched_priority=mp, matched_action=action, invariant_log=log)

    return StepResult(False, "drop_other_port")


def reset():
    """No-op for the static anchor (no data-plane state mutated across packets)."""
    return


def run(packets, state: Optional[dict] = None):
    """`packets` is a list of (scapy_pkt, ingress_port) tuples."""
    return [step(p, port, state) for p, port in packets]
