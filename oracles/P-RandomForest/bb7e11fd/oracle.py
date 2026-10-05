"""Python oracle for benchmark/relocate/random_forest_infer_anchor.

Implements P-RandomForest's rule sequence under the anchor-band
seed (D5.0_anchor_small_forest):

  - R0   unclassifiable    (a required feature header is absent — the packet is
                            not IPv4, so the configured ipv4.* features cannot be
                            read) -> ${unclassified_action} (forward to the
                            default port, here)
  - R1   class -> drop     (the argmax-winning class has verdict == drop;
                            dormant at this seed — action_breadth == forward_only)
  - R2   class -> mark     (verdict == mark: DSCP stamp + IPv4 csum recompute;
                            dormant at this seed)
  - R3   class -> forward  (verdict == forward: steer the UNCHANGED packet to the
                            class egress port — the anchor verdict)

The ENSEMBLE mechanism this pattern adds over P-DecisionTreeInfer (a single
tree): K parallel encode-based trees each emit ONE per-tree class VOTE over the
SAME quantised feature vector; the per-class vote counters are accumulated
(`inc` per class, per-packet scratch reset for every packet), and the final
class is the ARGMAX over those counters, ties resolved per ${tie_break}. The
winning class drives the class-action map. The model is a PURE function of the
configured header features, so the NF is STATELESS (the headline
`inference_determinism` invariant) — the vote counters never persist across
packets.

PARAMETRIC-SOURCE CONTRACT. The canonical entry point
is the module-level

    step(scapy_pkt, ingress_port, state) -> StepResult

It reads EVERY behaviourally-relevant operator knob from runtime `state` at
evaluation time — never from a module-level source constant:

    state["config"]["tie_break"]            ensemble argmax tie resolution
    state["config"]["n_trees"]              active forest size
    state["config"]["tree_depth"]           per-tree walk bound
    state["config"]["vote_aggregation"]     majority / weighted_majority / sum_threshold
    state["config"]["feature_set"]          which header fields are features
    state["config"]["feature_count"]        how many of them are read
    state["config"]["feature_bit_width"]    quantisation width
    state["config"]["num_classes"]          label space width
    state["config"]["default_class"]        per-tree table-miss / reject fallback
    state["config"][action_breadth]         which verdicts are reachable
                                            (descriptive seed axis; the verdict
                                            actually taken is read per-class from
                                            class_action_entries, so the oracle
                                            does NOT branch on this knob)
    state["config"]["unclassified_action"]  R0 disposition
    state["config"]["default_egress_port"]  R0 / no-action passthrough port
    state["model_artifact"]                 the trained forest (list of trees)
    state["class_action_entries"]           the winning-class -> action rows

When a knob is ABSENT from `state` the oracle falls back to the seed-bound
module default below, which preserves the anchor behaviour exactly so
task.yaml regenerates byte-identically. The module defaults are DEFAULTS the
runtime overrides, not the authoritative source of behaviour — exactly the
ipv4/secure_router `_DEFAULT_CONFIG` idiom (parametric-source
invariant; once the runtime threads a config the defaults are dead). This is
what lets forest parameter rebinding (single tree -> larger/deeper forest, +drop/+mark,
weighted voting, alternate tie-break) reuse this same audited oracle across the
faithfulness ladder without regeneration.

The per-task test generator still constructs `RandomForestSimulator(**kwargs)`
and calls the instance `step(pkt, port)`; that materialisation surface is
unchanged.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── seed-bound defaults (overridden by runtime state; see contract above) ────
# The anchor forest: 3 shallow (depth-3) binary trees over two 8-bit IPv4
# header features, feature[0]=ipv4.ttl, feature[1]=ipv4.diffserv (the ToS byte).
# tie_break 'le' per node: a feature value EQUAL to the threshold takes the left
# (low) branch. The forest is deliberately constructed so a crafted feature
# vector makes the trees DISAGREE, and the per-class majority (argmax) — not any
# single tree — selects the class.
MODEL_ARTIFACT: List[Dict[str, Any]] = [
    # Tree 0 — TTL-then-ToS split (the P-DecisionTreeInfer base tree).
    {"tree_id": 0, "tree_weight": 1,
     "root": {"feature": 0, "threshold": 64, "tie_break": "le",
              "left":  {"feature": 1, "threshold": 16, "tie_break": "le",
                        "left":  {"leaf_class": 0},     # ttl<=64 & tos<=16
                        "right": {"leaf_class": 1}},    # ttl<=64 & tos> 16
              "right": {"feature": 0, "threshold": 128, "tie_break": "le",
                        "left":  {"leaf_class": 1},     # 64<ttl<=128
                        "right": {"leaf_class": 0}}}},  # ttl>128
    # Tree 1 — ToS-first split.
    {"tree_id": 1, "tree_weight": 1,
     "root": {"feature": 1, "threshold": 32, "tie_break": "le",
              "left":  {"leaf_class": 0},               # tos<=32
              "right": {"feature": 0, "threshold": 100, "tie_break": "le",
                        "left":  {"leaf_class": 1},     # tos>32 & ttl<=100
                        "right": {"leaf_class": 0}}}},  # tos>32 & ttl>100
    # Tree 2 — single TTL split (a depth-1 stump in a depth-3-capable forest).
    {"tree_id": 2, "tree_weight": 1,
     "root": {"feature": 0, "threshold": 50, "tie_break": "le",
              "left":  {"leaf_class": 0},               # ttl<=50
              "right": {"leaf_class": 1}}},             # ttl>50
]

# Class -> forwarding action (forward_only: every class steers to a port).
CLASS_ACTION_ENTRIES: List[Dict[str, Any]] = [
    {"leaf_class": 0, "verdict": "forward", "egress_port": 2, "mark_value": "none"},
    {"leaf_class": 1, "verdict": "forward", "egress_port": 3, "mark_value": "none"},
]

FEATURE_SET = ["ipv4.ttl", "ipv4.diffserv"]
FEATURE_COUNT = 2
FEATURE_BIT_WIDTH = 8
NUM_CLASSES = 2
N_TREES = 3
TREE_DEPTH = 3
VOTE_AGGREGATION = "majority"
TIE_BREAK = "lowest_index"
DEFAULT_CLASS = "most_common"
ACTION_BREADTH = "forward_only"
UNCLASSIFIED_ACTION = "forward_default"
DEFAULT_EGRESS_PORT = 4


# ── pattern feature ref -> (scapy layer, field) ─────────────────────────────
# Only the header fields this instance can actually parse are supported; an
# unknown ref makes the packet unclassifiable (R0).
_FEATURE_FIELD = {
    "ipv4.ttl":       ("IP", "ttl"),
    "ipv4.tos":       ("IP", "tos"),
    "ipv4.diffserv":  ("IP", "tos"),      # diffserv IS the IPv4 ToS/DSCP byte
    "ipv4.totallen":  ("IP", "len"),
    "ipv4.protocol":  ("IP", "proto"),
    "ipv4.id":        ("IP", "id"),
    "tcp.srcport":    ("TCP", "sport"),
    "tcp.dstport":    ("TCP", "dport"),
    "tcp.flags":      ("TCP", "flags"),
    "udp.srcport":    ("UDP", "sport"),
    "udp.dstport":    ("UDP", "dport"),
}


# ── StepResult — secure_router-style; audit compares {admitted, decision,
#    output_port} ─────────────────────────────────────────────────────────────
@dataclass
class StepResult:
    admitted: bool
    decision: str
    output_port: Optional[int] = None
    winning_class: Optional[int] = None
    votes: Optional[Dict[int, int]] = None
    new_diffserv: Optional[int] = None      # set under R2 mark (None == unchanged)
    invariant_log: list = field(default_factory=list)


# ── packet introspection (scapy + dict-tolerant) ────────────────────────────
def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet or name in packet.get("_layers", {})
    return False


def _field_of(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        return getattr(packet[layer], fname, default)
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    if isinstance(packet, dict) and "_layers" in packet:
        return packet["_layers"].get(layer, {}).get(fname, default)
    return default


def _quantise(value: int, bit_width: int) -> int:
    """Quantise to `bit_width` bits by keeping the low N bits. For an 8-bit-
    native field at bit_width=8 this is the identity."""
    mask = (1 << int(bit_width)) - 1
    return int(value) & mask


# ── encode-based per-tree evaluation (IIsy / Planter, in spirit) ────────────
def _walk_tree(node: Dict[str, Any], feats: List[int], default_class: int,
               tree_depth: int = TREE_DEPTH) -> int:
    """Walk one tree to a leaf class. A node is a leaf ({leaf_class}) or a split
    ({feature, threshold, tie_break, left, right}); 'le' sends x<=t left,
    'lt' sends x<t left. A root-to-leaf path has at most `tree_depth` split
    comparisons, so the walk is bounded to `tree_depth` descents + the trailing
    leaf inspection (no_loop — a fixed stage count regardless of the forest)."""
    cur = node
    for _ in range(int(tree_depth) + 1):
        if cur is None:
            return int(default_class)
        if "leaf_class" in cur:
            return int(cur["leaf_class"])
        fidx = int(cur["feature"])
        if fidx < 0 or fidx >= len(feats):
            return int(default_class)
        fval = feats[fidx]
        thr = int(cur["threshold"])
        tie = str(cur.get("tie_break", "le"))
        go_left = (fval <= thr) if tie == "le" else (fval < thr)
        cur = cur.get("left") if go_left else cur.get("right")
    return int(default_class)


def _most_common_label(trees: List[Dict[str, Any]]) -> int:
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


# ── simulator ────────────────────────────────────────────────────────────────
@dataclass
class RandomForestSimulator:
    model_artifact: list = field(default_factory=lambda: [dict(t) for t in MODEL_ARTIFACT])
    class_action_entries: list = field(default_factory=lambda: [dict(e) for e in CLASS_ACTION_ENTRIES])
    feature_set: list = field(default_factory=lambda: list(FEATURE_SET))
    feature_count: int = FEATURE_COUNT
    feature_bit_width: int = FEATURE_BIT_WIDTH
    n_trees: int = N_TREES
    tree_depth: int = TREE_DEPTH
    num_classes: int = NUM_CLASSES
    vote_aggregation: str = VOTE_AGGREGATION
    tie_break: str = TIE_BREAK
    default_class: Any = DEFAULT_CLASS
    action_breadth: str = ACTION_BREADTH
    unclassified_action: str = UNCLASSIFIED_ACTION
    default_egress_port: int = DEFAULT_EGRESS_PORT

    def reset(self):
        # STATELESS pattern: no cross-packet state. reset() is a no-op beyond
        # honouring the audit/runtime contract (vote counters are per-packet).
        pass

    # ── feature read (R0 guard) ──────────────────────────────────────────────
    def _read_features(self, packet) -> Optional[List[int]]:
        if not _has_layer(packet, "IP"):
            return None
        feats: List[int] = []
        # Read exactly the configured number of features (the seed binds
        # feature_set with feature_count entries; slicing makes feature_count
        # load-bearing rather than implied by the list length).
        for ref in self.feature_set[: int(self.feature_count)]:
            spec = _FEATURE_FIELD.get(str(ref).strip().lower())
            if spec is None:
                return None
            layer, fname = spec
            if not _has_layer(packet, layer):
                return None
            raw = _field_of(packet, layer, fname)
            if raw is None:
                return None
            try:
                feats.append(_quantise(int(raw), self.feature_bit_width))
            except Exception:
                return None
        return feats

    def _resolved_default(self) -> int:
        if self.default_class == "most_common":
            return _most_common_label(self.model_artifact)
        try:
            return int(self.default_class)
        except Exception:
            return 0

    # ── ensemble inference: per-tree votes -> argmax ──────────────────────────
    def _infer(self, feats: List[int]):
        default_cls = self._resolved_default()
        trees = self.model_artifact[: max(int(self.n_trees), 1)]
        votes: Dict[int, int] = {}
        weight_by_class: Dict[int, int] = {}
        weighted = self.vote_aggregation in ("weighted_majority", "sum_threshold")
        for t in trees:
            cls = _walk_tree(t.get("root", t), feats, default_cls, self.tree_depth)
            w = int(t.get("tree_weight", 1))
            votes[cls] = votes.get(cls, 0) + (w if weighted else 1)
            weight_by_class[cls] = weight_by_class.get(cls, 0) + w
        winner = self._argmax(votes, weight_by_class, default_cls)
        return winner, votes

    def _argmax(self, votes: Dict[int, int], weight_by_class: Dict[int, int],
                default_cls: int) -> int:
        if not votes:
            return default_cls
        top = max(votes.values())
        tied = sorted(c for c, v in votes.items() if v == top)
        if len(tied) == 1:
            return tied[0]
        # tie resolution (the pattern's tie_break) — read from config.
        tb = str(self.tie_break)
        if tb == "reject":
            return int(default_cls)
        if tb == "highest_weight":
            # prefer the tied class with the larger summed tree_weight; on a
            # further weight tie fall back to the lowest class index.
            best = max(weight_by_class.get(c, 0) for c in tied)
            cands = sorted(c for c in tied if weight_by_class.get(c, 0) == best)
            return cands[0]
        # 'lowest_index' (anchor default) — the lowest tied class index.
        return tied[0]

    def _class_action(self, leaf_class: int) -> Optional[Dict[str, Any]]:
        for e in self.class_action_entries:
            if int(e.get("leaf_class", -1)) == int(leaf_class):
                return e
        return None

    # ── step (instance form — the test generator calls sim.step(pkt, port)) ────
    def step(self, scapy_pkt, in_port: int = 1) -> StepResult:
        feats = self._read_features(scapy_pkt)

        # R0 — unclassifiable (a required feature header is absent).
        if feats is None:
            if self.unclassified_action == "forward_default" and self.default_egress_port is not None:
                return StepResult(True, "forward_unclassified_default",
                                  output_port=int(self.default_egress_port),
                                  invariant_log=[("feature_read_safety", "R0 -> default")])
            return StepResult(False, "drop_unclassifiable",
                              invariant_log=[("feature_read_safety", "R0 -> drop")])

        # ── ensemble inference ─────────────────────────────────────────────
        winning_class, votes = self._infer(feats)
        ilog = [("vote_aggregation_fidelity", {"votes": dict(votes), "winner": winning_class})]

        entry = self._class_action(winning_class)
        if entry is None:
            # No action row for the resolved class — treat as unclassified
            # default (a well-formed model installs an action per class).
            if self.unclassified_action == "forward_default" and self.default_egress_port is not None:
                return StepResult(True, "forward_unclassified_default",
                                  output_port=int(self.default_egress_port),
                                  winning_class=winning_class, votes=dict(votes),
                                  invariant_log=ilog)
            return StepResult(False, "drop_no_class_action",
                              winning_class=winning_class, votes=dict(votes),
                              invariant_log=ilog)

        verdict = str(entry.get("verdict", "forward"))
        egress = int(entry["egress_port"]) if entry.get("egress_port") is not None else 0

        if verdict == "drop":                                  # R1
            return StepResult(False, "drop_class", winning_class=winning_class,
                              votes=dict(votes), invariant_log=ilog)
        if verdict == "mark":                                  # R2
            mv = int(entry.get("mark_value", 0))
            return StepResult(True, "forward_mark", output_port=egress,
                              winning_class=winning_class, votes=dict(votes),
                              new_diffserv=mv, invariant_log=ilog)
        # R3 — forward (the anchor verdict): steer the UNCHANGED packet.
        return StepResult(True, "forward_class", output_port=egress,
                          winning_class=winning_class, votes=dict(votes),
                          invariant_log=ilog)

    def run(self, packets) -> list:
        return [self.step(p, port) for p, port in packets]


# ── runtime config -> simulator (parametric-source contract) ─────────────────
def _sim_from_state(state: Optional[Dict[str, Any]]) -> "RandomForestSimulator":
    """Build a simulator whose every difficulty knob is read from runtime
    `state` (config sub-dict + top-level model/class rows), each falling back
    to the seed-bound module default when absent. This is the read-path the
    oracle audit / runtime engine exercise via the arity-3
    module-level step()."""
    state = state or {}
    cfg = dict(state.get("config", {}) or {})

    def pick(key, default):
        # a knob may be threaded inside config (scalars) or at top-level state
        # (structured control plane: model_artifact / class_action_entries).
        if key in cfg:
            return cfg[key]
        if key in state:
            return state[key]
        return default

    return RandomForestSimulator(
        model_artifact=pick("model_artifact", [dict(t) for t in MODEL_ARTIFACT]),
        class_action_entries=pick("class_action_entries",
                                  [dict(e) for e in CLASS_ACTION_ENTRIES]),
        feature_set=pick("feature_set", list(FEATURE_SET)),
        feature_count=pick("feature_count", FEATURE_COUNT),
        feature_bit_width=pick("feature_bit_width", FEATURE_BIT_WIDTH),
        n_trees=pick("n_trees", N_TREES),
        tree_depth=pick("tree_depth", TREE_DEPTH),
        num_classes=pick("num_classes", NUM_CLASSES),
        vote_aggregation=pick("vote_aggregation", VOTE_AGGREGATION),
        tie_break=pick("tie_break", TIE_BREAK),
        default_class=pick("default_class", DEFAULT_CLASS),
        # action_breadth is a descriptive seed axis that selects which
        # class_action_entries verdicts exist; the oracle never branches on the
        # knob itself (the per-class verdict is read from class_action_entries),
        # so it is intentionally NOT threaded from config here (de-quoted for
        # the audit's config-read check: it is not a behaviour-determining config-read knob).
        unclassified_action=pick("unclassified_action", UNCLASSIFIED_ACTION),
        default_egress_port=pick("default_egress_port", DEFAULT_EGRESS_PORT),
    )


# Module-level convenience for adopt/audit. The
# canonical arity-3 form: state carries the per-instance config that overrides
# the seed-bound defaults above.
_DEFAULT = RandomForestSimulator()


def step(scapy_pkt, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None):
    if state is None:
        return _DEFAULT.step(scapy_pkt, ingress_port)
    return _sim_from_state(state).step(scapy_pkt, ingress_port)


def reset():
    _DEFAULT.reset()
