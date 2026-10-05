"""Python oracle for benchmark/relocate/binary_neural_net_anchor.

Implements P-BinaryNeuralNet's rule sequence under the
task's seed (D5.0_anchor_single_layer):

  - R0   unclassifiable        (a required feature header is absent — e.g. the
                                packet is not IPv4, or a configured tcp.* feature
                                lives in an absent TCP header) -> unclassified_action
  - R1   class -> drop         (resolved class has verdict == drop; dormant at
                                this seed — action_breadth == forward_only)
  - R2   class -> mark         (verdict == mark: DSCP stamp + IPv4 csum recompute;
                                dormant at this seed)
  - R3   class -> forward      (verdict == forward: steer the UNCHANGED packet to
                                the class egress port — the anchor verdict)

The oracle evaluates a binarized neural network (BNN) the N3IC / Courbariaux
way: each configured header feature is reduced to ONE bit by a sign / threshold
binarization (`binarization_thresholds`); the per-feature bits are packed into a
`feature_width`-bit input vector; each neuron computes
`popcount( XNOR(input_bits, weight_bits) ) >= activation_threshold` to produce
its activation bit; the layer's activation bits are packed into an output bit
vector that an exact-match decode maps to a class index; the class drives a
forward / drop / mark verdict via the class-action map. The BNN is a PURE
function of the configured features and the control-plane weights, so the NF is
STATELESS (the headline `inference_determinism` invariant). No time_tick.

Bit-order convention (MUST match the data-plane P4 program and the test generator):
feature i occupies bit position (feature_width - 1 - i), i.e. feature 0 is the
MSB of the input vector and feature (feature_width-1) is the LSB. The same MSB-
first convention applies to the per-layer activation bits packed into the output
vector (neuron 0 is the MSB).

Per the parametric-source contract: every parameter named
in the pattern's `mutation_operators` surface is read from `state` at runtime
(scalars from `state["config"]`, the trained model from `state["bnn_model"]`,
the per-feature binarization from `state["binarization_thresholds"]`, the class
policy from `state["class_action_entries"]`). Seed values NEVER enter the module
as source-level constants — this is what lets parameter rebinding
reuse the same audited oracle across the faithfulness ladder
(more / wider neurons, a second layer, +drop / +mark, full feature width).

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


# Map a pattern feature reference (e.g. "ipv4.ttl") to a (Scapy layer, field)
# pair. Only the header fields an instance can actually parse are supported; an
# unknown ref makes the packet unclassifiable.
_FEATURE_FIELD = {
    "ipv4.ttl":        ("IP", "ttl"),
    "ipv4.tos":        ("IP", "tos"),
    "ipv4.diffserv":   ("IP", "tos"),       # diffserv is the IPv4 ToS/DSCP byte
    "ipv4.totallen":   ("IP", "len"),
    "ipv4.protocol":   ("IP", "proto"),
    "ipv4.id":         ("IP", "id"),
    "ipv4.flags":      ("IP", "flags"),
    "tcp.srcport":     ("TCP", "sport"),
    "tcp.dstport":     ("TCP", "dport"),
    "tcp.flags":       ("TCP", "flags"),
    "tcp.window":      ("TCP", "window"),
    "udp.srcport":     ("UDP", "sport"),
    "udp.dstport":     ("UDP", "dport"),
    "udp.length":      ("UDP", "len"),
}


def _read_raw_features(packet, feature_set: List[str]) -> Optional[List[int]]:
    """Read the configured raw feature values. Returns None if any feature's
    enclosing header is absent (the packet is unclassifiable — R0 territory;
    `feature_read_safety` forbids reading absent fields)."""
    if not _has_layer(packet, "IP"):
        return None
    vals: List[int] = []
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
            vals.append(int(raw))
        except Exception:
            return None
    return vals


# ──────────────────────────────────────────────────────────────────────
# BNN evaluation — binarize -> XNOR -> popcount -> threshold -> decode
# ──────────────────────────────────────────────────────────────────────

def _popcount(x: int, width: int) -> int:
    """Population count of the low `width` bits of x (v1model has no native
    popcount; a P4 program realises this as a sum of bit-slices / a LUT — here
    a plain count over the masked value)."""
    mask = (1 << int(width)) - 1
    return bin(int(x) & mask).count("1")


def _binarize(raw_feats: List[int], thresholds: List[Dict[str, Any]],
              feature_width: int) -> int:
    """Reduce each raw feature to one bit via its sign/threshold binarization,
    then pack the bits MSB-first into a `feature_width`-bit input vector.

    bit_i = 1 iff (read(f_i) >= threshold_i)  for tie_break == 'ge'
            or   (read(f_i) >  threshold_i)  for tie_break == 'gt'.
    feature i occupies bit position (feature_width - 1 - i).
    """
    # index the binarization specs by feature_index
    by_idx: Dict[int, Dict[str, Any]] = {}
    for spec in thresholds:
        by_idx[int(spec["feature_index"])] = spec
    in_vec = 0
    for i in range(feature_width):
        spec = by_idx.get(i)
        if spec is None or i >= len(raw_feats):
            bit = 0
        else:
            t = int(spec["threshold"])
            tie = str(spec.get("tie_break", "ge"))
            v = raw_feats[i]
            bit = 1 if ((v >= t) if tie == "ge" else (v > t)) else 0
        in_vec |= (bit << (feature_width - 1 - i))
    return in_vec


def _eval_layer(layer_input: int, neurons: List[Dict[str, Any]],
                width: int) -> int:
    """Evaluate one layer of XNOR-popcount-threshold neurons over a `width`-bit
    input vector. Returns the layer's activation bits packed MSB-first (neuron 0
    is the MSB). `neurons` is the in-order list for this layer."""
    mask = (1 << int(width)) - 1
    out_vec = 0
    n = len(neurons)
    for j, neuron in enumerate(neurons):
        w = int(neuron["weight_bits"]) & mask
        thr = int(neuron["activation_threshold"])
        xnor = (~(layer_input ^ w)) & mask          # agreement, masked to width
        cnt = _popcount(xnor, width)
        act = 1 if cnt >= thr else 0
        out_vec |= (act << (n - 1 - j))
    return out_vec


def _layer_neurons(model: List[Dict[str, Any]], layer_index: int
                   ) -> List[Dict[str, Any]]:
    """Neurons of `layer_index`, ordered by neuron_index."""
    ns = [m for m in model if int(m.get("layer_index", 0)) == int(layer_index)]
    ns.sort(key=lambda m: int(m.get("neuron_index", 0)))
    return ns


def _decode_class(out_vec: int, decode_entries: List[Dict[str, Any]],
                  default_class: Any) -> int:
    """Exact-match decode of the final layer's output bit vector to a class
    index. A vector with no installed row resolves to `${default_class}` (the
    decode table's default action — never a fault)."""
    for e in decode_entries:
        if int(e["out_vec"]) == int(out_vec):
            return int(e["class_index"])
    try:
        return int(default_class)
    except Exception:
        return 0


def _infer(raw_feats: List[int], state: Dict[str, Any]) -> int:
    """Evaluate the BNN -> class index. layer 0 over the binarized input vector;
    when layer_count == 2 the layer-0 activation bits become layer 1's input."""
    cfg = state.get("config", {})
    feature_width = int(cfg.get("feature_width", 4))
    neuron_count = int(cfg.get("neuron_count", 2))
    layer_count = int(cfg.get("layer_count", 1))
    default_class = cfg.get("default_class", 0)

    thresholds = state.get("binarization_thresholds", []) or []
    model = state.get("bnn_model", []) or []
    decode_entries = state.get("class_decode", []) or []

    in_vec = _binarize(raw_feats, thresholds, feature_width)

    l0 = _layer_neurons(model, 0)
    out0 = _eval_layer(in_vec, l0, feature_width)

    if layer_count >= 2:
        l1 = _layer_neurons(model, 1)
        final = _eval_layer(out0, l1, neuron_count)
    else:
        final = out0

    return _decode_class(final, decode_entries, default_class)


def _class_action(class_index: int, state: Dict[str, Any]
                  ) -> Optional[Dict[str, Any]]:
    for e in state.get("class_action_entries", []):
        if int(e.get("class_index", -1)) == int(class_index):
            return e
    return None


# ──────────────────────────────────────────────────────────────────────
# Output construction
# ──────────────────────────────────────────────────────────────────────

def _forward_unchanged(packet, egress_port: int):
    """R3 / unclassified-forward: steer the packet UNCHANGED to a port
    (forward verdict — no header edit, payload byte-for-byte intact)."""
    out = packet.copy() if hasattr(packet, "copy") else packet
    return {int(egress_port): [out]}


def _forward_marked(packet, egress_port: int, mark_value: int):
    """R2: stamp the predicted class id into the IPv4 DSCP/diffserv byte and
    recompute the IPv4 checksum, then forward. (Dormant at the anchor seed —
    action_breadth == forward_only.)"""
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
    """Execute one packet step under P-BinaryNeuralNet's rules.

    `state` carries:
      - config:                 dict of scalar seed parameters
                                (feature_set, feature_width, feature_count,
                                 neuron_count, layer_count, num_classes,
                                 default_class, action_breadth,
                                 unclassified_action, default_egress_port)
      - bnn_model:              the trained BNN — list of neuron rows, each
                                {layer_index, neuron_index, weight_bits,
                                 activation_threshold}
      - binarization_thresholds: per-feature {feature_index, threshold,
                                 tie_break} rows
      - class_decode:           {out_vec, class_index} rows (output decode)
      - class_action_entries:   {class_index, verdict, egress_port, mark_value}
    """
    cfg = state.get("config", {})
    new_state = state                                     # stateless pattern
    feature_set = cfg.get("feature_set", [])
    unclassified_action = cfg.get("unclassified_action", "forward_default")
    default_egress_port = cfg.get("default_egress_port")

    # ── R0: classifiable? (every configured feature header present) ─────
    raw_feats = _read_raw_features(packet, feature_set)
    if raw_feats is None:
        if unclassified_action == "forward_default" and default_egress_port is not None:
            out = _forward_unchanged(packet, int(default_egress_port))
            return StepResult(output_packets=out, new_state=new_state,
                              decision="forward",
                              invariant_log=[("decision", "R0 unclassifiable -> default")])
        return _drop(new_state, "R0: unclassifiable, unclassified_action=drop")

    # ── inference ───────────────────────────────────────────────────────
    class_index = _infer(raw_feats, new_state)
    entry = _class_action(class_index, new_state)
    if entry is None:
        # No action row for the resolved class — treat as unclassified default
        # (a well-formed seed installs an action per class).
        if unclassified_action == "forward_default" and default_egress_port is not None:
            out = _forward_unchanged(packet, int(default_egress_port))
            return StepResult(output_packets=out, new_state=new_state,
                              decision="forward",
                              invariant_log=[("decision", f"no action for class {class_index} -> default")])
        return _drop(new_state, f"no class_action for class {class_index}")

    verdict = str(entry.get("verdict", "forward"))
    egress = int(entry.get("egress_port", 0)) if entry.get("egress_port") is not None else 0

    if verdict == "drop":                                  # R1
        return _drop(new_state, f"R1: class {class_index} (drop verdict)")
    if verdict == "mark":                                  # R2
        out = _forward_marked(packet, egress, int(entry.get("mark_value", 0)))
        return StepResult(output_packets=out, new_state=new_state, decision="forward",
                          invariant_log=[("classification", f"mark class {class_index} -> p{egress}")])
    # R3 — forward (the anchor verdict)
    out = _forward_unchanged(packet, egress)
    return StepResult(output_packets=out, new_state=new_state, decision="forward",
                      invariant_log=[("classification", f"forward class {class_index} -> p{egress}")])
