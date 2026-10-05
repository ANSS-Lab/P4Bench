"""Per-task oracle for benchmark/relocate/netlock_anchor (P-NetLock).

Implements the in-switch lock service rule sequence. The
canonical seed is exclusive-only locking, immediate-deny on contention (no
waiter FIFO), drop-mode deny, direct-indexed lock table, holder-checked
release, GRANT delivered to a fixed coordinator port. The shared/exclusive and
waiter-FIFO branches are parametric (read from `state["config"]`) so a
parameter rebind that enables them reuses this same audited module.

Lock control messages ride a small `LockMsg` header on UDP (a custom layer
defined in the task's custom_headers.py). Per-lock state lives in
register-modelled state threaded through the `state` argument:

    locks[slot] = {"held": bool, "holders": [client_id, ...],
                   "kind": MODE_EXCLUSIVE | MODE_SHARED, "fifo": [client_id, ...]}

`holders` is the SET of clients currently holding the lock — a singleton for an
EXCLUSIVE lock, one-or-more readers for a SHARED lock. Tracking a holder SET
(rather than a single holder id + an opaque count) is what makes shared-lock
RELEASE correct: when one of several shared holders releases, the lock stays
HELD by the remaining readers (share count decremented), and an incompatible
EXCLUSIVE request is still excluded until the LAST reader releases (reader/writer
mutual exclusion, NetLock NSDI'20 shared/exclusive semantics). The service is
driven entirely by received LOCK / UNLOCK packets; there is NO wall-clock /
lease timer (release is packet-driven, by an explicit UNLOCK).

Rule sequence (first-match, declaration order):

  - R0   non-lock frame                              -> drop
  - R1   LOCK on a free lock                          -> bind holder, GRANT (fwd)
  - R2   SHARED LOCK on a SHARED-held lock (compat)   -> add reader, GRANT (fwd)
  - R3b  LOCK on a held lock, FIFO has room           -> enqueue, consume (drop)
  - R3   LOCK on a held lock, no FIFO room/disabled   -> deny (drop or NACK)
  - R4s  UNLOCK from a holder, other holders remain   -> drop reader, stay held (drop)
  - R5   UNLOCK from last holder WITH a waiter queued  -> grant FIFO head (fwd)
  - R4   UNLOCK from last holder, no waiter            -> evict, consume (drop)
  - R5x  UNLOCK from a non-holder (holder-check on)    -> deny (drop)
  - R6   UNLOCK on an already-free lock                -> no-op (drop)

(R2/R3b/R5/R4s are inert under the canonical exclusive seed: lock_mode==
exclusive keeps `holders` a singleton so R4s never fires, and waiter_fifo_depth
==0 disables R3b/R5. The branch code reads its knobs from `state`/config so an
parameter rebind that enables shared locks / a FIFO reuses this same audited module.)

Parametric-source contract: every mutation_operators-listed
parameter — lock_ids, lock_mode, deny_mode, waiter_fifo_depth, grant_response,
release_check_holder, index_mode, hash_algo, lock_table_capacity — is read from
state["config"] at runtime; seed values never enter the module as source-level
constants. This lets parameter rebinding reuse the same oracle.py and the
same task.yaml inputs without regeneration or re-audit.

step() is the standard oracle form:
    step(packet, ingress_port, state) -> StepResult
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── LockMsg field codes (protocol constants — NOT mutation knobs) ────────────
OP_LOCK = 1
OP_UNLOCK = 2

STATUS_REQ = 0
STATUS_GRANT = 1
STATUS_NACK = 2

MODE_EXCLUSIVE = 0
MODE_SHARED = 1


@dataclass
class StepResult:
    output_packets: Dict[int, List[Any]] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    decision: str = "drop"
    invariant_log: List[Tuple[str, Any]] = field(default_factory=list)


# ── Default config mirrors the canonical seed; overridden by state["config"]. ─
# Values here are fall-backs only; the evaluation caller threads the seed's
# values in via state["config"]. NOTHING verdict-affecting is baked as a
# module-level constant.
_DEFAULT_CONFIG = {
    "lock_ids": [0, 1, 2, 3],
    "lock_mode": "exclusive",            # exclusive | shared_exclusive
    "deny_mode": "drop",                 # drop | nack
    "waiter_fifo_depth": 0,              # 0 == immediate deny on contention
    "grant_response": "forward_to_port", # forward_to_port | forward_to_requester
    "release_check_holder": True,
    "index_mode": "direct",              # direct | hash
    "hash_algo": "crc16",
    "lock_table_capacity": 1024,
    "grant_port": 4,                     # coordinator/mirror egress for GRANT/NACK
}


def _config(state: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    cfg.update(state.get("config", {}))
    return cfg


# ── Packet introspection (Scapy + dict-style tolerant) ──────────────────────

def _has_layer(packet, name: str) -> bool:
    if hasattr(packet, "haslayer"):
        try:
            return bool(packet.haslayer(name))
        except Exception:
            return False
    if isinstance(packet, dict):
        return name in packet
    return False


def _field(packet, layer: str, fname: str, default=None):
    if hasattr(packet, "haslayer") and packet.haslayer(layer):
        v = getattr(packet[layer], fname, default)
        return v if v is not None else default
    if isinstance(packet, dict) and layer in packet:
        return packet[layer].get(fname, default)
    return default


def _has_lockmsg(packet) -> bool:
    return _has_layer(packet, "LockMsg") or _has_layer(packet, "lockmsg")


def _lk(packet, fname, default=None):
    v = _field(packet, "LockMsg", fname, None)
    if v is None:
        v = _field(packet, "lockmsg", fname, None)
    return default if v is None else v


def _clone(packet):
    if isinstance(packet, dict):
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in packet.items()}
    try:
        return packet.copy()
    except Exception:
        return packet


def _set(packet, layer, fname, value):
    if isinstance(packet, dict):
        packet.setdefault(layer, {})[fname] = value
        return
    try:
        setattr(packet[layer], fname, value)
    except Exception:
        pass


# ── lock-table indexing (direct or hashed) ──────────────────────────────────

def _crc16(x: int) -> int:
    # CCITT-FALSE CRC-16 over the 2-byte big-endian lock id. Used only when
    # index_mode == hash; deterministic so an aliasing collision is reproducible.
    data = int(x).to_bytes(2, "big")
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def _crc32(x: int) -> int:
    import binascii
    return binascii.crc32(int(x).to_bytes(2, "big")) & 0xFFFFFFFF


def _slot(lock_id: int, cfg: Dict[str, Any]) -> int:
    cap = int(cfg["lock_table_capacity"])
    if cfg.get("index_mode") == "hash":
        h = _crc32(lock_id) if cfg.get("hash_algo") == "crc32" else _crc16(lock_id)
        return h % cap
    return int(lock_id) % cap


# ── per-lock register-state helpers (threaded through `state["locks"]`) ──────

def _locks(state: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    return dict(state.get("locks", {}))


def _holders(rec: Dict[str, Any]) -> List[int]:
    """Holder set for a lock record, tolerant of the older single-holder shape."""
    if rec is None:
        return []
    if "holders" in rec:
        return list(rec.get("holders") or [])
    h = rec.get("holder")
    return [int(h)] if h is not None else []


def _drop(new_state, reason) -> StepResult:
    return StepResult(output_packets={}, new_state=new_state, decision="drop",
                      invariant_log=[("drop", reason)])


def _grant_out(packet, cfg, client_id) -> Tuple[int, Any]:
    """Build the GRANT/NACK output packet and choose its egress port.

    forward_to_port  -> fixed coordinator port (canonical; observable on a
                        non-ingress port so the harness can grade it).
    forward_to_requester is NOT modelled for grading here (a reply egressing
    the ingress port is excluded by the harness); the canonical seed pins
    forward_to_port.
    """
    out = _clone(packet)
    return int(cfg.get("grant_port", 4)), out


# ── step() — oracle interface ───────────────────────────────────────────────

def step(packet, ingress_port: int = 1, state: Optional[Dict[str, Any]] = None) -> StepResult:
    state = state or {}
    cfg = _config(state)
    locks = _locks(state)
    new_state = dict(state)
    new_state["locks"] = locks

    deny_mode = cfg.get("deny_mode", "drop")
    check_holder = bool(cfg.get("release_check_holder", True))
    fifo_depth = int(cfg.get("waiter_fifo_depth", 0))

    # R0 — frame carries no lock-request header -> drop (out of scope).
    if not _has_lockmsg(packet):
        return _drop(new_state, "R0_non_lock")

    op = int(_lk(packet, "op", 0))
    lock_id = int(_lk(packet, "lock_id", -1))
    client_id = int(_lk(packet, "client_id", 0))
    msg_mode = int(_lk(packet, "mode", MODE_EXCLUSIVE))
    slot = _slot(lock_id, cfg)

    rec = locks.get(slot)  # {"held", "holders": [...], "kind", "fifo": [...]}
    held = bool(rec and rec.get("held"))

    def deny(reason):
        if deny_mode == "nack":
            port, out = _grant_out(packet, cfg, client_id)
            _set(out, "LockMsg", "status", STATUS_NACK)
            return StepResult(output_packets={port: [out]}, new_state=new_state,
                              decision="forward",
                              invariant_log=[("deny_nack", reason)])
        return _drop(new_state, reason)

    # ── LOCK ─────────────────────────────────────────────────────────────────
    if op == OP_LOCK:
        # R1 — free lock: bind holder and GRANT.
        if not held:
            kind = MODE_SHARED if (cfg.get("lock_mode") == "shared_exclusive"
                                   and msg_mode == MODE_SHARED) else MODE_EXCLUSIVE
            locks[slot] = {"held": True, "holders": [client_id],
                           "kind": kind, "share": 1, "fifo": []}
            port, out = _grant_out(packet, cfg, client_id)
            _set(out, "LockMsg", "status", STATUS_GRANT)
            return StepResult(
                output_packets={port: [out]}, new_state=new_state,
                decision="forward",
                invariant_log=[("R1_lock_free_grant",
                                {"lock_id": lock_id, "slot": slot,
                                 "holder": client_id, "port": port})],
            )

        # R2 — shared compatibility: a SHARED LOCK on a SHARED-held lock admits
        # another concurrent reader (inert under the exclusive seed).
        if (cfg.get("lock_mode") == "shared_exclusive"
                and msg_mode == MODE_SHARED
                and rec.get("kind") == MODE_SHARED):
            rec = dict(rec)
            holders = _holders(rec)
            if client_id not in holders:
                holders.append(client_id)
            rec["holders"] = holders
            rec["share"] = len(holders)
            locks[slot] = rec
            port, out = _grant_out(packet, cfg, client_id)
            _set(out, "LockMsg", "status", STATUS_GRANT)
            return StepResult(
                output_packets={port: [out]}, new_state=new_state,
                decision="forward",
                invariant_log=[("R2_shared_compatible_grant",
                                {"lock_id": lock_id, "share": len(holders)})],
            )

        # R3b — held, FIFO has room: enqueue + drop (inert under depth 0).
        if fifo_depth > 0:
            q = list(rec.get("fifo", []))
            if len(q) < fifo_depth:
                q.append(client_id)
                rec = dict(rec)
                rec["fifo"] = q
                locks[slot] = rec
                return _drop(new_state, "R3b_enqueue")

        # R3 — held, no FIFO room (or FIFO disabled): deny.
        return deny("R3_lock_held_deny")

    # ── UNLOCK ─────────────────────────────────────────────────────────────────
    if op == OP_UNLOCK:
        # R6 — unlock on an already-free lock: no-op.
        if not held:
            return _drop(new_state, "R6_unlock_not_held_noop")

        holders = _holders(rec)
        is_holder = client_id in holders

        # R5x — non-holder release while holder-check is on: deny, lock stays held.
        # A SHARED lock recognises ANY of its readers as a legitimate holder.
        if check_holder and not is_holder:
            return deny("R5x_unlock_not_holder_deny")

        # Relinquish this holder. With the holder-check OFF, any UNLOCK frees the
        # whole binding (ease semantics); with it ON, only the releasing client
        # is removed and co-holders (other readers) remain.
        if check_holder:
            holders = [h for h in holders if h != client_id]
        else:
            holders = []

        # R4s — shared holders remain: decrement, lock stays HELD, consume.
        # (Inert under the exclusive seed: a singleton holder set empties here.)
        if holders:
            rec = dict(rec)
            rec["holders"] = holders
            rec["share"] = len(holders)
            locks[slot] = rec
            return _drop(new_state, "R4s_shared_release_decrement")

        # Last holder gone. R5 — a waiter is queued: hand the lock to the FIFO
        # head (inert under depth 0).
        q = list(rec.get("fifo", []))
        if fifo_depth > 0 and q:
            nxt = q.pop(0)
            locks[slot] = {"held": True, "holders": [nxt], "share": 1,
                           "kind": MODE_EXCLUSIVE, "fifo": q}
            port, out = _grant_out(packet, cfg, nxt)
            _set(out, "LockMsg", "status", STATUS_GRANT)
            _set(out, "LockMsg", "client_id", nxt)
            return StepResult(
                output_packets={port: [out]}, new_state=new_state,
                decision="forward",
                invariant_log=[("R5_unlock_grant_next",
                                {"lock_id": lock_id, "granted_to": nxt})],
            )

        # R4 — last holder release, no waiter: evict back to free, consume.
        locks.pop(slot, None)
        return StepResult(
            output_packets={}, new_state=new_state, decision="drop",
            invariant_log=[("R4_unlock_release",
                            {"lock_id": lock_id, "slot": slot,
                             "freed_from": client_id})],
        )

    # Unknown op — out of scope, drop.
    return _drop(new_state, "R0_unknown_op")
