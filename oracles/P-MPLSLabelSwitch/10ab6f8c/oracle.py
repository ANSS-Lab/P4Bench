"""Per-task oracle for benchmark/redesign/mpls_label_switch_anchor.

Implements the P-MPLSLabelSwitch transit-LSR rule sequence
under the canonical D.swap_only seed: top-label SWAP via the LFIB, MPLS-TTL
decrement, Ethernet rewrite, with the label stack below the top and the
encapsulated payload preserved.

  - R0  non-MPLS drop
  - R1  top-label TTL ≤ 1 drop (RFC 3032 §2.4)
  - R2  LFIB miss (unknown / reserved top label) drop
  - R3  swap: top label → out_label, dec top TTL, Ether rewrite, forward

The LFIB is read from state["config"]["lfib"] (parametric-source contract)
and normalised so the oracle is GENUINELY responsive to a
config-rebound LFIB rather than silently falling back to the module default.
Two LFIB shapes are consumed (see `_normalize_lfib`):

  (a) dict keyed by int label → {op, out_label, port, port_mac, nexthop_mac}
      — the canonical-example / module-default shape;
  (b) list of per-entry dicts → {in_label, op, out_label, egress_port,
      port_mac, next_hop_mac} — the SEED FIB-family shape (the
      mpls_label_switch seeds). `egress_port`/`next_hop_mac` are the seed's
      field spellings for `port`/`nexthop_mac`.

Accepting only shape (a) — `{int(k): v for k, v in cfg['lfib'].items()}` —
would raise AttributeError on the seed's LIST lfib and drop back to
_DEFAULT_CONFIG — a SOURCE-BAKED LFIB that any config-rebinding sibling would
silently keep. step() is the standard oracle form.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


_DEFAULT_CONFIG = {
    "lfib": {
        100: {"op": "swap", "out_label": 200, "port": 2,
              "port_mac": "08:00:00:00:02:00", "nexthop_mac": "08:00:00:00:02:02"},
        300: {"op": "swap", "out_label": 400, "port": 3,
              "port_mac": "08:00:00:00:03:00", "nexthop_mac": "08:00:00:00:03:03"},
    },
}


def _normalize_lfib(lfib) -> Dict[int, Dict[str, Any]]:
    """Normalise an LFIB of either shape into a dict keyed by int in-label,
    each value carrying {op, out_label, port, port_mac, nexthop_mac}.

      (a) dict {label: {op, out_label, port, port_mac, nexthop_mac}}  — used
          as-is (keys coerced to int);
      (b) list [{in_label, op, out_label, egress_port, port_mac,
          next_hop_mac}, ...]  — re-keyed by in_label; egress_port/next_hop_mac
          are mapped onto port/nexthop_mac.

    This is what makes the oracle config-RESPONSIVE to a rebound LFIB instead
    of crashing on the seed's list shape and falling back to the default.
    """
    out: Dict[int, Dict[str, Any]] = {}
    if isinstance(lfib, dict):
        for k, v in lfib.items():
            e = dict(v)
            if e.get("port") is None and e.get("egress_port") is not None:
                e["port"] = e["egress_port"]
            if e.get("nexthop_mac") is None and e.get("next_hop_mac") is not None:
                e["nexthop_mac"] = e["next_hop_mac"]
            out[int(k)] = e
        return out
    # list / iterable of per-entry dicts
    for entry in lfib:
        e = dict(entry)
        label = int(e["in_label"])
        if e.get("port") is None and e.get("egress_port") is not None:
            e["port"] = e["egress_port"]
        if e.get("nexthop_mac") is None and e.get("next_hop_mac") is not None:
            e["nexthop_mac"] = e["next_hop_mac"]
        out[label] = e
    return out


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    # normalise lfib to a dict keyed by int label, spanning the dict-keyed
    # (canonical/default) shape and the seed's list-of-entries shape.
    cfg["lfib"] = _normalize_lfib(cfg["lfib"])
    return cfg


def _has_mpls(packet) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer("MPLS"))
        except Exception:
            return False
    return isinstance(packet, dict) and "MPLS" in packet


def _top_mpls(packet):
    """Return the top (first) MPLS layer object, or None."""
    if hasattr(packet, "getlayer"):
        try:
            return packet.getlayer("MPLS")
        except Exception:
            return None
    if isinstance(packet, dict):
        return packet.get("MPLS")
    return None


def _drop(state, reason):
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("drop", reason)])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)
    lfib = cfg["lfib"]

    if not _has_mpls(packet):
        return _drop(new_state, "R0_non_mpls")

    top = _top_mpls(packet)
    label = int(getattr(top, "label", top.get("label") if isinstance(top, dict) else 0))
    ttl = int(getattr(top, "ttl", top.get("ttl") if isinstance(top, dict) else 0))

    if ttl <= 1:
        return _drop(new_state, "R1_mpls_ttl_exhausted")

    entry = lfib.get(label)
    if entry is None or entry.get("op") not in ("swap",):
        return _drop(new_state, "R2_lfib_miss")

    # R3 — swap
    out = packet.copy() if hasattr(packet, "copy") else dict(packet)
    out_top = _top_mpls(out)
    try:
        out_top.label = int(entry["out_label"])
        out_top.ttl = ttl - 1
        out["Ether"].src = entry["port_mac"]
        out["Ether"].dst = entry["nexthop_mac"]
    except Exception:
        pass
    return StepResult(
        output_packets={int(entry["port"]): [out]},
        new_state=new_state,
        decision="forward",
        invariant_log=[("R3_swap", {"port": int(entry["port"]),
                                    "in_label": label, "out_label": int(entry["out_label"]),
                                    "ttl": ttl - 1})],
    )
