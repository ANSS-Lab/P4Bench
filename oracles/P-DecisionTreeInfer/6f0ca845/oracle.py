"""Python oracle for benchmark/relocate/decision_tree_infer_anchor.

Implements P-DecisionTreeInfer's rule sequence under the
task's seed (D5.0_anchor_single_tree):

  - R0   unclassifiable        (missing a required feature header -> the
                                packet is not IPv4, so the configured
                                ipv4.* features are absent) -> unclassified_action
  - R1   class -> drop         (resolved leaf class has verdict == drop;
                                dormant at this seed — action_breadth == forward_only)
  - R2   class -> mark         (verdict == mark: DSCP stamp + IPv4 csum;
                                dormant at this seed)
  - R3   class -> forward      (verdict == forward: steer the UNCHANGED packet
                                to the class egress port)

The oracle evaluates the trained model the IIsy / Planter encode-based way
in spirit — but as a plain tree walk over the quantised feature values —
and is the ground-truth source the per-test `expected:` blocks were derived
from. The model is a pure function of the configured header features, so the
NF is STATELESS (the headline `inference_determinism` invariant).

Per the parametric-source contract: every parameter
named in the pattern's `mutation_operators` surface is read from `state`
at runtime (scalars from `state["config"]`, the model from
`state["model_artifact"]`, the class policy from
`state["class_action_entries"]`). Seed values never enter the module as
source-level constants — this is what lets parameter rebinding
reuse the same audited oracle across the faithfulness
ladder (single tree -> forest, deeper trees, more features, +drop/+mark).

step() signature is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

from collections import Counter
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


# Map a pattern feature reference (e.g. "ipv4.ttl") to a (Scapy layer,
# field) pair. Only the header fields an instance can actually parse are
# supported; an unknown ref makes the packet unclassifiable.
_FEATURE_FIELD = {
    "ipv4.ttl":        ("IP", "ttl"),
    "ipv4.tos":        ("IP", "tos"),
    "ipv4.diffserv":   ("IP", "tos"),       # diffserv is the IPv4 ToS/DSCP byte
    "ipv4.totallen":   ("IP", "len"),
    "ipv4.protocol":   ("IP", "proto"),
    "ipv4.id":         ("IP", "id"),
    "tcp.srcport":     ("TCP", "sport"),
    "tcp.dstport":     ("TCP", "dport"),
    "tcp.flags":       ("TCP", "flags"),
    "udp.srcport":     ("UDP", "sport"),
    "udp.dstport":     ("UDP", "dport"),
}


def _quantise(value: int, bit_width: int) -> int:
    """Quantise a feature value to `bit_width` bits by truncating to its
    low N bits (value & ((1<<N)-1)). For an 8-bit-native field at
    bit_width=8 this is the identity; for a wider field it keeps the low
    byte(s)."""
    mask = (1 << int(bit_width)) - 1
    return int(value) & mask


def _read_features(packet, feature_set: List[str], bit_width: int
                   ) -> Optional[List[int]]:
    """Read + quantise the configured feature fields. Returns None if any
    feature's enclosing header is absent (the packet is unclassifiable —
    R0 territory; `feature_read_safety` forbids reading absent fields)."""
    if not _has_layer(packet, "IP"):
        return None
    feats: List[int] = []
    for ref in feature_set:
        spec = _FEATURE_FIELD.get(str(ref).strip().lower())
        if spec is None:
            return None
        layer, fname = spec
        if not _has_layer(packet, layer):
            return None
        raw = _field(packet, layer, fname)
        if raw is None:
            return None
        try:
            feats.append(_quantise(int(raw), bit_width))
        except Exception:
            return None
    return feats


# ──────────────────────────────────────────────────────────────────────
# Encode-based inference (IIsy / Planter, in spirit) — a tree walk
# ──────────────────────────────────────────────────────────────────────

def _walk_tree(node: Dict[str, Any], feats: List[int],
               default_class: Any) -> int:
    """Walk one decision tree to a leaf class. A node is either a leaf
    ({leaf_class: int}) or a split ({feature, threshold, tie_break, left,
    right}); tie_break 'le' sends x<=t left, 'lt' sends x<t left."""
    cur = node
    # Bounded by tree structure — finite by construction (no_loop).
    for _ in range(64):
        if cur is None:
            return _resolve_default(default_class)
        if "leaf_class" in cur:
            return int(cur["leaf_class"])
        fidx = int(cur["feature"])
        if fidx < 0 or fidx >= len(feats):
            return _resolve_default(default_class)
        fval = feats[fidx]
        thr = int(cur["threshold"])
        tie = str(cur.get("tie_break", "le"))
        go_left = (fval <= thr) if tie == "le" else (fval < thr)
        cur = cur.get("left") if go_left else cur.get("right")
    return _resolve_default(default_class)


def _resolve_default(default_class: Any) -> int:
    # `most_common` is resolved by the caller (it depends on the trees);
    # any non-int default falls back to class 0 here.
    try:
        return int(default_class)
    except Exception:
        return 0


def _most_common_label(trees: List[Dict[str, Any]]) -> int:
    """The most-common leaf label across all trees — the IIsy/Planter
    decision-table default action."""
    labels: List[int] = []

    def collect(node):
        if node is None:
            return
        if "leaf_class" in node:
            labels.append(int(node["leaf_class"]))
            return
        collect(node.get("left"))
        collect(node.get("right"))

    for t in trees:
        collect(t.get("root", t))
    if not labels:
        return 0
    return Counter(labels).most_common(1)[0][0]


def _infer(feats: List[int], state: Dict[str, Any]) -> int:
    """Evaluate the model -> leaf class. Single tree returns its leaf;
    an ensemble aggregates per-tree votes per `vote_aggregation`."""
    cfg = state.get("config", {})
    trees = state.get("model_artifact", []) or []
    ensemble = int(cfg.get("ensemble_size", 1))
    default_class = cfg.get("default_class", "most_common")
    if default_class == "most_common":
        default_class = _most_common_label(trees)

    if not trees:
        return _resolve_default(default_class)

    votes: List[int] = []
    for t in trees[: max(ensemble, 1)]:
        votes.append(_walk_tree(t.get("root", t), feats, default_class))
    if len(votes) == 1:
        return votes[0]

    agg = str(cfg.get("vote_aggregation", "majority"))
    if agg in ("majority", "weighted_majority", "sum_threshold"):
        # Anchor/family use plain plurality; weighted/threshold reduce to
        # the same arg-max when no per-tree weights are supplied.
        return Counter(votes).most_common(1)[0][0]
    return Counter(votes).most_common(1)[0][0]


def _class_action(leaf_class: int, state: Dict[str, Any]
                  ) -> Optional[Dict[str, Any]]:
    for e in state.get("class_action_entries", []):
        if int(e.get("leaf_class", -1)) == int(leaf_class):
            return e
    return None


# ──────────────────────────────────────────────────────────────────────
# Output construction
# ──────────────────────────────────────────────────────────────────────

def _forward_unchanged(packet, egress_port: int):
    """R3 / unclassified-forward: steer the packet UNCHANGED to a port
    (forward_only verdict — no header edit, payload byte-for-byte intact)."""
    out = packet.copy() if hasattr(packet, "copy") else packet
    return {int(egress_port): [out]}


def _forward_marked(packet, egress_port: int, mark_value: int):
    """R2: stamp the predicted class id into the IPv4 DSCP/diffserv byte
    and recompute the IPv4 checksum, then forward."""
    out = packet.copy() if hasattr(packet, "copy") else packet
    try:
        if _has_layer(out, "IP"):
            out["IP"].tos = int(mark_value)
            if hasattr(out["IP"], "chksum"):
                del out["IP"].chksum
        if hasattr(out, "build"):
            out = out.__class__(bytes(out))
    except Exception:
        pass
    return {int(egress_port): [out]}


def _drop(state, reason: str) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=[("decision", f"drop: {reason}")])


# ──────────────────────────────────────────────────────────────────────
# step() — oracle interface
# ──────────────────────────────────────────────────────────────────────

def step(packet, ingress_port: int, state: Dict[str, Any]) -> StepResult:
    """Execute one packet step under P-DecisionTreeInfer's rules.

    `state` carries:
      - config:                 dict of scalar seed parameters
                                (feature_set, feature_bit_width,
                                 ensemble_size, vote_aggregation,
                                 default_class, action_breadth,
                                 unclassified_action, default_egress_port)
      - model_artifact:         the trained model (list of trees)
      - class_action_entries:   the leaf_class -> action rows
    """
    cfg = state.get("config", {})
    new_state = state                                     # stateless pattern
    feature_set = cfg.get("feature_set", [])
    bit_width = int(cfg.get("feature_bit_width", 8))
    unclassified_action = cfg.get("unclassified_action", "forward_default")
    default_egress_port = cfg.get("default_egress_port")

    # ── R0: classifiable? (every configured feature header present) ─────
    feats = _read_features(packet, feature_set, bit_width)
    if feats is None:
        if unclassified_action == "forward_default" and default_egress_port is not None:
            out = _forward_unchanged(packet, int(default_egress_port))
            return StepResult(output_packets=out, new_state=new_state,
                              decision="forward",
                              invariant_log=[("decision", "R0 unclassifiable -> default")])
        return _drop(new_state, "R0: unclassifiable, unclassified_action=drop")

    # ── inference ───────────────────────────────────────────────────────
    leaf_class = _infer(feats, new_state)
    entry = _class_action(leaf_class, new_state)
    if entry is None:
        # No action row for the resolved class — treat as unclassified
        # default (a well-formed model installs an action per class).
        if unclassified_action == "forward_default" and default_egress_port is not None:
            out = _forward_unchanged(packet, int(default_egress_port))
            return StepResult(output_packets=out, new_state=new_state,
                              decision="forward",
                              invariant_log=[("decision", f"no action for class {leaf_class} -> default")])
        return _drop(new_state, f"no class_action for class {leaf_class}")

    verdict = str(entry.get("verdict", "forward"))
    egress = int(entry.get("egress_port", 0)) if entry.get("egress_port") is not None else 0

    if verdict == "drop":                                  # R1
        return _drop(new_state, f"R1: class {leaf_class} (drop verdict)")
    if verdict == "mark":                                  # R2
        out = _forward_marked(packet, egress, int(entry.get("mark_value", 0)))
        return StepResult(output_packets=out, new_state=new_state, decision="forward",
                          invariant_log=[("classification", f"mark class {leaf_class} -> p{egress}")])
    # R3 — forward (the anchor verdict)
    out = _forward_unchanged(packet, egress)
    return StepResult(output_packets=out, new_state=new_state, decision="forward",
                      invariant_log=[("classification", f"forward class {leaf_class} -> p{egress}")])
