"""Python oracle for P-PURRFastReroute (TPL pattern).

step(scapy_packet, ingress_port, state) -> StepResult

`state` is a dict that carries all pattern parameters touched by
P-PURRFastReroute.mutation_operators (per the parametric-source
contract). The oracle reads every knob from `state` so that parameter
rebinding reuses the same audited module without regeneration.

Pattern rules implemented (first-match):

  R0  ¬header_present(ipv4)                           → drop
  R1  FRR-table miss                                  → ${default_action_on_miss}
  R2  FRR hit ∧ primary not down                      → forward primary
  R3  FRR hit ∧ primary down ∧ ¬(cascaded ∧ backup down)
                                                     → forward backup
  R4  cascaded ∧ primary down ∧ backup down           → drop

State keys consumed:

  frr_groups            : list of (dst_ip|prefix_str, prefix_len,
                                   primary_port, backup_port,
                                   primary_mac, backup_mac)
  port_down             : iterable of port ids currently down
  frr_match_kind        : 'exact' | 'lpm'
  frr_table_capacity    : int | 'unbounded'
  port_down_capacity    : int
  liveness_source       : 'control_plane_table' | 'dataplane_register'
                          (oracle treats both as a port_down set)
  cascaded_backup       : bool
  ttl_decrement_strict  : bool
  default_action_on_miss: 'drop' | 'use_default_route'
  faithfulness          : descriptive only; not consulted

The MAC rewrite convention:

  hdr.ethernet.src ← prior hdr.ethernet.dst (the ingress dst-MAC)
  hdr.ethernet.dst ← frr_group.{primary,backup}_mac

This is the "swap-src-to-prior-dst" convention. The
pattern's bridging_notes flag it as a topology-specific choice, but at
the D5.0_basic_pair anchor it is the contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Iterable, Tuple, List


# ---------------------------------------------------------------------------
# StepResult
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    admitted: bool
    reason: str
    output_port: Optional[int] = None
    next_hop_mac_dst: Optional[str] = None
    next_hop_mac_src: Optional[str] = None
    ttl_decrement: int = 0


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------

def _ip_to_int(ip: str) -> int:
    a, b, c, d = (int(p) for p in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _exact_match(dst_ip: str, prefix_ip: str, prefix_len: int) -> bool:
    return prefix_len == 32 and _ip_to_int(dst_ip) == _ip_to_int(prefix_ip)


def _lpm_match(dst_ip: str, prefix_ip: str, prefix_len: int) -> bool:
    if prefix_len == 0:
        return True
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return (_ip_to_int(dst_ip) & mask) == (_ip_to_int(prefix_ip) & mask)


# ---------------------------------------------------------------------------
# FRR lookup
# ---------------------------------------------------------------------------

def _frr_lookup(dst_ip: str, frr_groups: List[tuple],
                match_kind: str) -> Optional[tuple]:
    """Return the matching (primary_port, backup_port, primary_mac,
    backup_mac) tuple, or None on miss. For 'lpm' the longest-prefix
    entry wins; for 'exact' only /32 host entries match."""
    if match_kind == "exact":
        for entry in frr_groups:
            prefix_ip, prefix_len, pp, bp, pm, bm = entry
            if _exact_match(dst_ip, prefix_ip, prefix_len):
                return (pp, bp, pm, bm)
        return None

    # lpm — pick longest matching prefix
    best = None
    best_len = -1
    for entry in frr_groups:
        prefix_ip, prefix_len, pp, bp, pm, bm = entry
        if prefix_len <= best_len:
            continue
        if _lpm_match(dst_ip, prefix_ip, prefix_len):
            best = (pp, bp, pm, bm)
            best_len = prefix_len
    return best


# ---------------------------------------------------------------------------
# Oracle entry point (step interface)
# ---------------------------------------------------------------------------

def step(scapy_packet, ingress_port: int, state: dict) -> StepResult:
    """One-step transition from (packet, ingress_port, state) per the
    P-PURRFastReroute rule sequence. `state` is read but not mutated:
    the link `port_down` set is updated only by the control plane (or
    by a dataplane register write that the harness simulates outside
    the oracle); the oracle treats both liveness sources as a
    pre-populated set in `state['port_down']`."""

    from scapy.all import IP

    frr_groups        = state["frr_groups"]
    port_down         = set(state.get("port_down") or [])
    match_kind        = state.get("frr_match_kind", "lpm")
    cascaded          = bool(state.get("cascaded_backup", False))
    ttl_strict        = bool(state.get("ttl_decrement_strict", True))
    default_on_miss   = state.get("default_action_on_miss", "drop")

    # R0 — non-IPv4 unconditionally dropped.
    if IP not in scapy_packet:
        return StepResult(False, "drop_non_ipv4")

    ip = scapy_packet[IP]
    dst_ip = str(ip.dst)

    # R1 — FRR-table miss.
    hit = _frr_lookup(dst_ip, frr_groups, match_kind)
    if hit is None:
        if default_on_miss == "drop":
            return StepResult(False, "drop_frr_miss")
        # use_default_route is the only other admissible value; it's only
        # realisable at frr_match_kind == lpm with a 0.0.0.0/0 entry —
        # and that case would have already hit above. Treat as drop.
        return StepResult(False, "drop_frr_miss")

    primary_port, backup_port, primary_mac, backup_mac = hit
    primary_down = primary_port in port_down
    backup_down  = backup_port  in port_down

    if not primary_down:
        # R2 — primary path
        prior_dst_mac = str(scapy_packet["Ether"].dst)
        ttl_delta = 1 if ttl_strict else 0
        return StepResult(
            admitted=True,
            reason="forward_primary",
            output_port=primary_port,
            next_hop_mac_dst=primary_mac,
            next_hop_mac_src=prior_dst_mac,
            ttl_decrement=ttl_delta,
        )

    # primary is down
    if cascaded and backup_down:
        # R4 — both down, cascaded mode → drop
        return StepResult(False, "drop_double_down")

    # R3 — backup path (anchor mode always takes this on primary_down)
    prior_dst_mac = str(scapy_packet["Ether"].dst)
    ttl_delta = 1 if ttl_strict else 0
    return StepResult(
        admitted=True,
        reason="forward_backup",
        output_port=backup_port,
        next_hop_mac_dst=backup_mac,
        next_hop_mac_src=prior_dst_mac,
        ttl_decrement=ttl_delta,
    )


# Compatibility alias for callers that use the older name.
def oracle_step(scapy_packet, ingress_port: int, state: dict) -> StepResult:
    return step(scapy_packet, ingress_port, state)
