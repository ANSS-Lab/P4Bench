"""Python oracle for benchmark/relocate/netcache_kv_disc.

Implements P-NetCacheKV's rule sequence under the
task's seed (get_put_delete, invalidate_on_write, behavioural
input form):

  - R0  non-KV passthrough (no NetCache header) — client→backend, backend→client
  - R1  GET hit   (key cached AND not invalidated) -> ORIGINATE response,
                   reflected to the client (ingress) port; no backend forward
  - R2  GET miss  (key not cached, or invalidated)  -> forward to backend
  - R3  write-to-cached-key (PUT/DELETE) -> invalidate the slot + forward backend
  - R4  write-to-non-cached-key          -> forward backend (no state change)
  - R5  unsupported-write passthrough    -> forward backend (n/a at this seed —
                                            get_put_delete handles PUT+DELETE)

State model (harness-realizable):
  - The value store is CONTROL-PLANE-installed: `state["cache_entries"]` is the
    set of (key -> value) the controller cached, all initially VALID. The data
    plane mutates only the per-slot validity, on writes — modelled here as the
    mutable `state["invalidated"]` key set (empty at cold start). This matches
    the BMv2 reality that table entries are installable but register
    pre-population is not, so validity is a zero-init "invalidated" flag that a
    write SETS (valid -> invalid), never a register the control plane primes.

Origination scoring (the P-SYNCookieGuard convention): the GET
hit response is reflected out the requesting client's INGRESS port, which the
v1.0 engine excludes from egress scoring (engine.py drops `p == input_port`
from `received`). The hit is therefore observed as the ABSENCE of a backend
forward (decision reported as forward-to-ingress, scored as `drop`), and a GET
miss as a forward to the backend port — the channel through which the
write-invalidation coherence and cross-key independence properties are graded.

Per parametric-source contract: every parameter named in the
pattern's mutation_operators is read from `state` at runtime (config scalars
from state["config"], the cached set from state["cache_entries"]); seed values
never enter as source-level constants, so parameter rebinding reuses this module.

step() is the standard oracle form: step(packet, ingress_port,
state) -> StepResult. Packet introspection is string-name based so it tolerates
a Scapy packet built from any custom_headers module instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# NetCache application op codes (mirror custom_headers.py)
OP_GET = 0
OP_PUT = 1
OP_DELETE = 2
OP_GET_RESPONSE = 3


# ── StepResult — oracle return shape ───────────────────────────

@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ── Packet-introspection helpers (Scapy + dict tolerant) ────────────────

def _has(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "getlayer"):
        try:
            lay = packet.getlayer(layer)
            if lay is not None:
                return getattr(lay, fname, default)
        except Exception:
            pass
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


# ── State lookups ───────────────────────────────────────────────────────

def _role(ingress_port: int, state: Dict[str, Any]) -> str:
    cfg = state.get("config", {})
    if ingress_port in cfg.get("client_ports", []):
        return "client"
    if ingress_port in cfg.get("backend_ports", []):
        return "backend"
    return "unknown"


def _cached_value(key: int, state: Dict[str, Any]) -> Optional[int]:
    """Return the installed value for `key`, or None if not in the cache set."""
    for e in state.get("cache_entries", []):
        if int(e["key"]) == int(key):
            return int(e["value"])
    return None


def _is_invalidated(key: int, state: Dict[str, Any]) -> bool:
    return int(key) in {int(k) for k in state.get("invalidated", [])}


# ── step() — oracle interface ──────────────────────────────────

def step(packet, ingress_port: int, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = dict(state or {})
    state.setdefault("invalidated", [])
    cfg = state.get("config", {})
    backend_port = int(cfg.get("backend_port", cfg.get("backend_ports", [2])[0]))
    op_breadth = cfg.get("cache_op_breadth", "get_put_delete")
    role = _role(ingress_port, state)

    # R0 — non-KV traffic and server replies pass through.
    if not _has(packet, "NetCache"):
        if role == "backend":
            # server -> client reply transits back toward the client
            tgt = int(cfg.get("client_ports", [1])[0])
            return _fwd(state, tgt, "R0: non-KV backend reply -> client")
        return _fwd(state, backend_port, "R0: non-KV client traffic -> backend")

    op = int(_field(packet, "NetCache", "op", OP_GET))
    key = int(_field(packet, "NetCache", "key", 0))

    # R6 — in-band re-validation on the backend reply path (server GET_RESPONSE).
    if role == "backend":
        client_port = int(cfg.get("client_ports", [1])[0])
        if (op == OP_GET_RESPONSE and bool(cfg.get("in_band_revalidation", False))
                and _cached_value(key, state) is not None):
            inv = [int(k) for k in state.get("invalidated", []) if int(k) != int(key)]
            state["invalidated"] = inv                      # re-validate: clear the invalidation for this key
            return _fwd(state, client_port, "R6: re-validate on server reply + forward to client",
                        inv=[("R6_revalidate_on_server_reply", {"key": key}),
                             ("revalidation_coherence", {"key": key})])
        # otherwise a server reply (or other backend-side NetCache msg) just transits to the client
        return _fwd(state, client_port, "R0: server reply passthrough -> client")

    # Only client-facing requests are cache-acted upon below.
    if role != "client":
        return _fwd(state, int(cfg.get("client_ports", [1])[0]),
                    "R0: NetCache message on a non-client port -> passthrough")

    # ── GET ────────────────────────────────────────────────────────────
    if op == OP_GET:
        val = _cached_value(key, state)
        hit = (val is not None) and (not _is_invalidated(key, state))
        if hit:
            # R1 — originate the response; reflect to the client (ingress) port.
            resp = _build_response(packet, key, val)
            return StepResult(
                output_packets={int(ingress_port): [resp]},
                new_state=state,
                decision="forward",                     # to ingress -> excluded -> scored as drop
                invariant_log=[
                    ("R1_get_hit_respond", {"key": key, "value": val}),
                    ("cache_hit_value_correct", {"key": key, "value": val}),
                    ("bounded_origination_latency", {"key": key}),
                ],
            )
        # R2 — miss (uncached or invalidated): forward to backend.
        return _fwd(state, backend_port, "R2: GET miss -> backend",
                    inv=[("R2_get_miss_forward",
                          {"key": key, "invalidated": _is_invalidated(key, state)}),
                         ("request_no_orphan", {"key": key})])

    # ── PUT / DELETE (writes) ──────────────────────────────────────────
    if op == OP_PUT or (op == OP_DELETE and op_breadth == "get_put_delete"):
        if op_breadth == "get_only":
            return _fwd(state, backend_port, "R5: write under get_only -> passthrough")
        val = _cached_value(key, state)
        if val is not None and cfg.get("coherence_policy", "invalidate_on_write") == "invalidate_on_write":
            # R3 — invalidate the cached slot for this key, then forward.
            inv = list(state.get("invalidated", []))
            if int(key) not in {int(k) for k in inv}:
                inv.append(int(key))
            state["invalidated"] = inv
            return _fwd(state, backend_port, "R3: write to cached key -> invalidate + forward",
                        inv=[("R3_write_invalidate_forward", {"key": key}),
                             ("write_invalidation_coherence", {"key": key})])
        # R4 — write to a non-cached key: forward only, do not touch cache state.
        return _fwd(state, backend_port, "R4: write to non-cached key -> forward only",
                    inv=[("R4_write_no_cached_key_forward", {"key": key}),
                         ("no_cross_key_contamination", {"key": key})])

    # DELETE under get_put (DELETE unsupported) -> passthrough; GET_RESPONSE etc.
    return _fwd(state, backend_port, "R5: unsupported op -> passthrough")


# ── Output construction ──────────────────────────────────────────────────

def _build_response(packet, key: int, value: int):
    """Reflect the request into a GET_RESPONSE toward the client (swap L2/L3/L4)."""
    try:
        from scapy.all import Ether, IP, UDP
        nc_layers()
        eth = packet.getlayer("Ether")
        ip = packet.getlayer("IP")
        udp = packet.getlayer("UDP")
        NetCache = globals()["NetCache"]
        resp = (Ether(src=eth.dst, dst=eth.src)
                / IP(src=ip.dst, dst=ip.src)
                / UDP(sport=udp.dport, dport=udp.sport)
                / NetCache(op=OP_GET_RESPONSE, key=key, value=value))
        return resp
    except Exception:
        # dict / non-scapy fallback
        return {"NetCache": {"op": OP_GET_RESPONSE, "key": key, "value": value}}


def nc_layers():
    if "NetCache" in globals():
        return globals()["NetCache"]
    from scapy.packet import Packet, bind_layers
    from scapy.fields import ByteField, LongField, IntField
    from scapy.all import UDP

    class NetCache(Packet):
        name = "NetCache"
        fields_desc = [ByteField("op", 0), LongField("key", 0), IntField("value", 0)]

    bind_layers(UDP, NetCache, dport=8888)
    globals()["NetCache"] = NetCache
    return NetCache


# ── helpers ──────────────────────────────────────────────────────────────

def _fwd(state, port: int, reason: str, inv=None) -> StepResult:
    return StepResult(output_packets={int(port): ["<forwarded>"]}, new_state=state,
                      decision="forward",
                      invariant_log=(inv or []) + [("forward_reason", reason)])


def _drop(state, reason, inv=None) -> StepResult:
    return StepResult(output_packets={}, new_state=state, decision="drop",
                      invariant_log=(inv or []) + [("drop_reason", reason)])


def reset():
    return None
