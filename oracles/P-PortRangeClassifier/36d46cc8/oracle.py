"""Per-task oracle for benchmark/redesign/port_range_classifier_anchor.

P-PortRangeClassifier under the canonical seed: a STATELESS multi-field (MF)
classifier (RFC 2475) that classifies IPv4 TCP/UDP packets by their L4
destination port (and, at wider breadth, source port / protocol / packet
length) into service classes via CLOSED numeric intervals — the v1model
`range` match_kind, the only match_kind expressing an arbitrary interval
natively.

Per packet:
  R0  no L4 port (not TCP and not UDP, incl. non-IPv4 / ICMP / ARP)
        -> default_action: forward_default_class -> default class port; deny -> drop
  R1  highest-priority range rule whose interval(s) admit the packet, action=forward
        -> forward to rule.class_port  (headers unchanged)
  R2  ...action=deny                            -> drop
  R3  ...action=mark                            -> set DSCP (preserve ECN) + forward to class_port
  R4  no rule matches
        -> default_action: forward_default_class -> default class port; deny -> drop

"Range match" of a rule R for a packet P (all configured fields must hold):
  R.dport_lo <= dport(P) <= R.dport_hi                         (always; inclusive)
  AND R.proto == proto(P)                 when breadth includes proto
  AND R.sport_lo <= sport(P) <= R.sport_hi   when breadth includes sport
  AND R.len_lo  <= len(P)   <= R.len_hi      when breadth includes len

First-match is BY PRIORITY (largest `priority` wins among matching rules), NOT
list order. The closed (inclusive) interval is the load-bearing contract: a
strict `<`/`>` test or a ternary-prefix expansion that over-covers the bound
is wrong.

Config is read from state["config"] (parametric-source
contract); seed values enter only at evaluation time. Entry point: step(packet, ingress_port, state).
The StepResult exposes `output_port` (the matched class's egress port, None on
drop) so the oracle audit grades the class assignment directly, plus
`output_packets` so test generation can bake the egress transformation block.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    output_port: Optional[int] = None
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


_DEFAULT_CONFIG = {
    # Canonical: IANA well-known / registered bands, dynamic+non-L4 to default.
    "range_rules": [
        {"priority": 10, "dport_lo": 0,    "dport_hi": 1023,  "action": "forward", "class_port": 2},
        {"priority": 10, "dport_lo": 1024, "dport_hi": 49151, "action": "forward", "class_port": 3},
    ],
    "match_field_breadth": "dport",          # dport | dport_proto | sport_dport_proto | sport_dport_proto_len
    "default_action": "forward_default_class",   # forward_default_class | deny
    "default_class_port": 4,
}


def _config(state):
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


def _l4(packet):
    """Return (proto, sport, dport) or None if the packet has no L4 port."""
    if getattr(packet, "haslayer", lambda x: False)("TCP"):
        t = packet["TCP"]
        return 6, int(getattr(t, "sport", 0)), int(getattr(t, "dport", 0))
    if getattr(packet, "haslayer", lambda x: False)("UDP"):
        u = packet["UDP"]
        return 17, int(getattr(u, "sport", 0)), int(getattr(u, "dport", 0))
    return None


def _ip_len(packet) -> int:
    if not getattr(packet, "haslayer", lambda x: False)("IP"):
        return 0
    ip = packet["IP"]
    ln = getattr(ip, "len", None)
    return int(ln) if ln else len(bytes(ip))


def _in(lo, hi, v) -> bool:
    """Closed-interval membership: lo <= v <= hi (inclusive both ends)."""
    return int(lo) <= int(v) <= int(hi)


def _rule_matches(rule, breadth, proto, sport, dport, plen) -> bool:
    # Destination-port range — always part of the key.
    if not _in(rule["dport_lo"], rule["dport_hi"], dport):
        return False
    if breadth in ("dport_proto", "sport_dport_proto", "sport_dport_proto_len"):
        rp = rule.get("proto", "any")
        if rp != "any" and int(rp) != int(proto):
            return False
    if breadth in ("sport_dport_proto", "sport_dport_proto_len"):
        if "sport_lo" in rule and rule.get("sport_lo") != "any":
            if not _in(rule["sport_lo"], rule["sport_hi"], sport):
                return False
    if breadth == "sport_dport_proto_len":
        if "len_lo" in rule and rule.get("len_lo") != "any":
            if not _in(rule["len_lo"], rule["len_hi"], plen):
                return False
    return True


def _best_rule(cfg, proto, sport, dport, plen):
    """Highest-priority matching rule (largest priority wins), or None."""
    breadth = cfg.get("match_field_breadth", "dport")
    best = None
    for rule in cfg.get("range_rules", []):
        if _rule_matches(rule, breadth, proto, sport, dport, plen):
            if best is None or int(rule.get("priority", 0)) > int(best.get("priority", 0)):
                best = rule
    return best


def _default(cfg, state, packet, reason):
    if cfg.get("default_action") == "deny":
        return StepResult(new_state=state, decision="drop", output_port=None,
                          invariant_log=[("default", {"action": "deny", "why": reason})])
    port = int(cfg.get("default_class_port", 0))
    out = packet.copy()
    return StepResult(output_packets={port: [out]}, new_state=state,
                      decision="forward", output_port=port,
                      invariant_log=[("default", {"action": "forward_default_class",
                                                   "port": port, "why": reason})])


def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    new_state = dict(state)          # stateless classifier: state is untouched

    l4 = _l4(packet)
    if l4 is None:                   # R0: no L4 port (ARP / ICMP / non-TCP-UDP)
        return _default(cfg, new_state, packet, "no_l4_port")
    proto, sport, dport = l4
    plen = _ip_len(packet)

    rule = _best_rule(cfg, proto, sport, dport, plen)
    if rule is None:                 # R4: table miss
        return _default(cfg, new_state, packet, "no_range_match")

    action = rule.get("action", "forward")
    if action == "deny":             # R2
        return StepResult(new_state=new_state, decision="drop", output_port=None,
                          invariant_log=[("classify", {"rule": rule.get("priority"),
                                                        "action": "deny", "dport": dport})])

    port = int(rule["class_port"])
    out = packet.copy()
    if action == "mark":             # R3: DSCP remark, preserve ECN, then forward
        tos = int(getattr(out["IP"], "tos", 0))
        dscp = int(rule.get("dscp", 0)) & 0x3F
        out["IP"].tos = (dscp << 2) | (tos & 0x3)

    log = ("classify", {"priority": rule.get("priority"), "action": action,
                        "dport": dport, "class_port": port})
    return StepResult(output_packets={port: [out]}, new_state=new_state,
                      decision="forward", output_port=port, invariant_log=[log])
